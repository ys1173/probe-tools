package icmp

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
)

// These tests send real ICMP. Run them with GO_PRIVILEGED=1 scripts/go test; each skips when the socket it needs cannot
// be opened. They reach the host's own non-loopback address (the policy's self-address list is cleared for the test)
// and the default gateway, never anything further away unless noted.

var caps = Capabilities()

func needCap(t *testing.T, names ...string) {
	t.Helper()
	for _, n := range names {
		if !caps[n] {
			t.Skipf("capability %s not available here", n)
		}
	}
}

func withKind(t *testing.T, k sockKind) {
	t.Helper()
	forceKind = k
	t.Cleanup(func() { forceKind = kindAuto })
}

func testEnv(t *testing.T) *check.Env {
	t.Helper()
	p, err := policy.New(policy.Config{Mode: policy.ModeOpen})
	if err != nil {
		t.Fatal(err)
	}
	p.SelfAddrs = func() ([]netip.Prefix, error) { return nil, nil }
	return &check.Env{Policy: p, Capabilities: caps}
}

func runCheck(t *testing.T, env *check.Env, name string, params any) (any, *protocol.Error) {
	t.Helper()
	r := check.NewRegistry()
	Register(r)
	f, _ := r.Get(name)
	raw, _ := json.Marshal(params)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	res, err := f(ctx, env, raw)
	if res != nil {
		if _, jerr := json.Marshal(res); jerr != nil {
			t.Fatalf("result does not encode: %v", jerr)
		}
	}
	return res, err
}

func ownIPv4(t *testing.T) string {
	t.Helper()
	for _, a := range policy.InterfaceAddrs() {
		if a.Is4() && !a.IsLoopback() && !a.IsLinkLocalUnicast() {
			return a.String()
		}
	}
	t.Skip("no non-loopback IPv4 address")
	return ""
}

func gatewayIPv4(t *testing.T) string {
	t.Helper()
	f, err := os.Open("/proc/net/route")
	if err != nil {
		t.Skip("no /proc/net/route")
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fl := strings.Fields(sc.Text())
		if len(fl) > 7 && fl[1] == "00000000" && fl[7] == "00000000" {
			b, err := hex.DecodeString(fl[2])
			if err == nil && len(b) == 4 {
				var a [4]byte
				binary.BigEndian.PutUint32(a[:], binary.LittleEndian.Uint32(b))
				if gw := netip.AddrFrom4(a); !gw.IsUnspecified() {
					return gw.String()
				}
			}
		}
	}
	t.Skip("no IPv4 default gateway")
	return ""
}

func TestCapabilitiesKeys(t *testing.T) {
	for _, k := range []string{"raw_icmp", "unpriv_icmp", "raw_icmp6", "unpriv_icmp6", "path_mtu"} {
		if _, ok := caps[k]; !ok {
			t.Errorf("missing %s", k)
		}
	}
	t.Logf("capabilities: %v", caps)
}

func TestPingDenied(t *testing.T) {
	env := testEnv(t)
	for _, name := range []string{protocol.CheckPing, protocol.CheckTraceroute, protocol.CheckPathMTU} {
		_, err := runCheck(t, env, name, map[string]any{"target": "127.0.0.1"})
		if err == nil || err.Code != protocol.CodeDenied {
			t.Errorf("%s to loopback: %v", name, err)
		}
	}
}

func TestPingSelf(t *testing.T) {
	for _, c := range []struct {
		kind sockKind
		cap  string
	}{{kindDgram, "unpriv_icmp"}, {kindRaw, "raw_icmp"}} {
		t.Run(c.kind.String(), func(t *testing.T) {
			needCap(t, c.cap)
			withKind(t, c.kind)
			addr := ownIPv4(t)
			res, err := runCheck(t, testEnv(t), protocol.CheckPing, protocol.PingParams{Target: addr, Count: 3, IntervalMS: 200})
			if err != nil {
				t.Fatal(err)
			}
			r := res.(PingResult)
			if r.Socket != c.kind.String() || r.Sent != 3 || r.Received != 3 || r.LossPct != 0 || len(r.Replies) != 3 ||
				r.Replies[0].TTL == 0 || r.Address != addr {
				t.Fatalf("result %+v", r)
			}
		})
	}
}

func TestPingConcurrentDoNotMix(t *testing.T) {
	needCap(t, "raw_icmp")
	withKind(t, kindRaw)
	addr := ownIPv4(t)
	env := testEnv(t)
	type out struct {
		r   any
		err *protocol.Error
	}
	ch := make(chan out, 3)
	for i := 0; i < 3; i++ {
		go func() {
			r, err := runCheck(t, env, protocol.CheckPing, protocol.PingParams{Target: addr, Count: 4, IntervalMS: 200})
			ch <- out{r, err}
		}()
	}
	for i := 0; i < 3; i++ {
		o := <-ch
		if o.err != nil {
			t.Fatal(o.err)
		}
		r := o.r.(PingResult)
		seen := map[int]bool{}
		for _, rep := range r.Replies {
			if seen[rep.Seq] {
				t.Fatalf("duplicate seq %d: %+v", rep.Seq, r)
			}
			seen[rep.Seq] = true
		}
		if r.Received != 4 {
			t.Fatalf("result %+v", r)
		}
	}
}

func TestPingBudget(t *testing.T) {
	needCap(t, "unpriv_icmp")
	addr := ownIPv4(t)
	r := check.NewRegistry()
	Register(r)
	f, _ := r.Get(protocol.CheckPing)
	raw, _ := json.Marshal(protocol.PingParams{Target: addr, Count: 10, IntervalMS: 1000})
	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	t0 := time.Now()
	res, err := f(ctx, testEnv(t), raw)
	if err != nil {
		t.Fatal(err)
	}
	pr := res.(PingResult)
	if time.Since(t0) > 2500*time.Millisecond || pr.Sent >= 10 || pr.Sent == 0 || pr.Received != pr.Sent || pr.Note == "" {
		t.Fatalf("result %+v after %v", pr, time.Since(t0))
	}
}

// TestPingUnreachable pings an unused address on the local subnet. The host's own neighbour discovery fails and it
// answers with ICMP host unreachable, which must show up as an ICMP error, not as plain loss.
func TestPingUnreachable(t *testing.T) {
	own := netip.MustParseAddr(ownIPv4(t))
	b := own.As4()
	b[3] = 250
	if b == own.As4() {
		b[3] = 251
	}
	target := netip.AddrFrom4(b).String()
	for _, c := range []struct {
		kind sockKind
		cap  string
	}{{kindDgram, "unpriv_icmp"}, {kindRaw, "raw_icmp"}} {
		t.Run(c.kind.String(), func(t *testing.T) {
			needCap(t, c.cap)
			withKind(t, c.kind)
			res, err := runCheck(t, testEnv(t), protocol.CheckPing, protocol.PingParams{Target: target, Count: 1, TimeoutMS: 5000})
			if err != nil {
				t.Fatal(err)
			}
			r := res.(PingResult)
			if r.Received != 0 {
				t.Skipf("%s answered; the address is in use", target)
			}
			if len(r.ICMPErrors) == 0 {
				t.Skipf("no ICMP error came back for %s (host did not report neighbour failure): %+v", target, r)
			}
			if !strings.Contains(r.ICMPErrors[0].Message, "unreachable") || r.ICMPErrors[0].From == "" {
				t.Fatalf("errors %+v", r.ICMPErrors)
			}
			t.Logf("%+v", r.ICMPErrors)
		})
	}
}

func TestTracerouteSelf(t *testing.T) {
	needCap(t, "raw_icmp")
	addr := ownIPv4(t)
	for _, mode := range []string{"icmp", "udp", "tcp"} {
		t.Run(mode, func(t *testing.T) {
			res, err := runCheck(t, testEnv(t), protocol.CheckTraceroute, protocol.TracerouteParams{Target: addr, Mode: mode,
				Port: 1, MaxHops: 5, Queries: 2, WaitMS: 500})
			if err != nil {
				t.Fatal(err)
			}
			r := res.(TracerouteResult)
			if !r.Reached || !r.Complete || len(r.Hops) != 1 || r.Hops[0].Probes[0].Addr != addr || r.Mode != mode {
				t.Fatalf("result %+v", r)
			}
		})
	}
}

func TestTracerouteGateway(t *testing.T) {
	needCap(t, "raw_icmp")
	gw := gatewayIPv4(t)
	for _, mode := range []string{"icmp", "udp", "tcp"} {
		t.Run(mode, func(t *testing.T) {
			res, err := runCheck(t, testEnv(t), protocol.CheckTraceroute, protocol.TracerouteParams{Target: gw, Mode: mode,
				MaxHops: 3, Queries: 1, WaitMS: 500})
			if err != nil {
				t.Fatal(err)
			}
			r := res.(TracerouteResult)
			t.Logf("%s: %+v", mode, r)
			if len(r.Hops) == 0 || !r.Complete {
				t.Fatalf("result %+v", r)
			}
			if mode == "icmp" && !r.Reached {
				t.Fatalf("gateway did not answer echo: %+v", r)
			}
		})
	}
}

// TestTracerouteInternet exercises time-exceeded matching against a real path. It needs outbound internet access, so it
// only logs when nothing answers.
func TestTracerouteInternet(t *testing.T) {
	needCap(t, "raw_icmp")
	if testing.Short() {
		t.Skip("short")
	}
	for _, mode := range []string{"icmp", "udp", "tcp"} {
		res, err := runCheck(t, testEnv(t), protocol.CheckTraceroute, protocol.TracerouteParams{Target: "1.1.1.1", Mode: mode,
			MaxHops: 4, Queries: 1, WaitMS: 800})
		if err != nil {
			t.Fatal(err)
		}
		r := res.(TracerouteResult)
		routers := 0
		for _, h := range r.Hops {
			for _, p := range h.Probes {
				if p.Addr != "" && p.Addr != r.Address {
					routers++
				}
			}
		}
		t.Logf("%s: routers answering %d: %+v", mode, routers, r.Hops)
	}
}

func TestTracerouteBudget(t *testing.T) {
	needCap(t, "raw_icmp")
	// An address that drops everything: nothing answers, every hop waits out the full wait.
	r := check.NewRegistry()
	Register(r)
	f, _ := r.Get(protocol.CheckTraceroute)
	raw, _ := json.Marshal(protocol.TracerouteParams{Target: "192.0.2.1", MaxHops: 30, Queries: 1, WaitMS: 500})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	t0 := time.Now()
	res, err := f(ctx, testEnv(t), raw)
	if err != nil {
		t.Fatal(err)
	}
	tr := res.(TracerouteResult)
	if tr.Complete {
		t.Skipf("the trace ended by itself (no route or an unreachable answer), so the budget was not reached: %+v", tr)
	}
	if time.Since(t0) > 2*time.Second || tr.Note == "" {
		t.Fatalf("result %+v after %v", tr, time.Since(t0))
	}
}

func TestTracerouteNeedsRaw(t *testing.T) {
	env := testEnv(t)
	env.Capabilities = map[string]bool{"raw_icmp": false}
	_, err := runCheck(t, env, protocol.CheckTraceroute, protocol.TracerouteParams{Target: "192.0.2.1"})
	if err == nil || err.Code != protocol.CodeUnavailable || !strings.Contains(err.Message, "NET_RAW") {
		t.Fatalf("got %v", err)
	}
}

func TestPathMTU(t *testing.T) {
	needCap(t, "path_mtu")
	for _, c := range []struct {
		kind sockKind
		cap  string
	}{{kindDgram, "unpriv_icmp"}, {kindRaw, "raw_icmp"}} {
		t.Run(c.kind.String(), func(t *testing.T) {
			needCap(t, c.cap)
			withKind(t, c.kind)
			// The host's own address goes over loopback (MTU 65536), so the largest size passes at once.
			own := ownIPv4(t)
			res, err := runCheck(t, testEnv(t), protocol.CheckPathMTU, protocol.PathMTUParams{Target: own, MaxSize: 9000})
			if err != nil {
				t.Fatal(err)
			}
			if r := res.(PathMTUResult); r.PathMTU != 9000 || r.Attempts != 2 || r.MaxSizeTested != 9000 {
				t.Fatalf("own address: %+v", r)
			}
			// The gateway is behind the container's interface: sizes above its MTU fail locally with EMSGSIZE.
			gw := gatewayIPv4(t)
			res, err = runCheck(t, testEnv(t), protocol.CheckPathMTU, protocol.PathMTUParams{Target: gw, MaxSize: 9000})
			if err != nil {
				t.Fatal(err)
			}
			r := res.(PathMTUResult)
			t.Logf("gateway: %+v", r)
			if r.PathMTU < 576 || r.PathMTU > 9000 || r.MaxSizeTested != 9000 {
				t.Fatalf("gateway: %+v", r)
			}
		})
	}
}

// TestPingUnavailable runs only where neither socket kind can be opened, e.g. a container without NET_RAW and with an
// empty ping_group_range.
func TestPingUnavailable(t *testing.T) {
	if caps["raw_icmp"] || caps["unpriv_icmp"] {
		t.Skip("this host can open ICMP sockets")
	}
	env := testEnv(t)
	env.Capabilities = nil // unknown: the check must try and fail by itself
	_, err := runCheck(t, env, protocol.CheckPing, protocol.PingParams{Target: "192.0.2.1"})
	if err == nil || err.Code != protocol.CodeUnavailable || !strings.Contains(err.Message, "NET_RAW") {
		t.Fatalf("got %v", err)
	}
}
