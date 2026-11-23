package pathtest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
)

const nonce = "abcdef0123456789_nonce-x"

func testEnv(t *testing.T, min, max int) *check.Env {
	t.Helper()
	p, err := policy.New(policy.Config{Mode: policy.ModeOpen})
	if err != nil {
		t.Fatal(err)
	}
	p.SelfAddrs = func() ([]netip.Prefix, error) { return nil, nil }
	return &check.Env{Policy: p, ListenPortMin: min, ListenPortMax: max}
}

// freeRange finds a small range of ports that are currently free for both TCP and UDP.
func freeRange(t *testing.T, n int) (int, int) {
	t.Helper()
	for base := 41000; base < 60000; base += n + 7 {
		ok := true
		for p := base; p < base+n && ok; p++ {
			l, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
			if err != nil {
				ok = false
				break
			}
			u, err := net.ListenPacket("udp", fmt.Sprintf(":%d", p))
			l.Close()
			if err != nil {
				ok = false
				break
			}
			u.Close()
		}
		if ok {
			return base, base + n - 1
		}
	}
	t.Fatal("no free port range")
	return 0, 0
}

func call(t *testing.T, env *check.Env, name string, params any) (any, *protocol.Error) {
	t.Helper()
	r := check.NewRegistry()
	Register(r)
	f, ok := r.Get(name)
	if !ok {
		t.Fatalf("%s not registered", name)
	}
	raw, _ := json.Marshal(params)
	return f(context.Background(), env, raw)
}

func start(t *testing.T, env *check.Env, proto string, port, durMS int) protocol.ListenStartResult {
	t.Helper()
	res, err := call(t, env, protocol.CheckListenStart, protocol.ListenStartParams{Protocol: proto, Port: port, Nonce: nonce, DurationMS: durMS})
	if err != nil {
		t.Fatalf("listen_start: %v", err)
	}
	return res.(protocol.ListenStartResult)
}

func collect(t *testing.T, env *check.Env, id string, waitMS int) protocol.ListenCollectResult {
	t.Helper()
	res, err := call(t, env, protocol.CheckListenCollect, protocol.ListenCollectParams{ListenID: id, WaitMS: waitMS})
	if err != nil {
		t.Fatalf("listen_collect: %v", err)
	}
	return res.(protocol.ListenCollectResult)
}

func loopDial(port int) dialFunc {
	return func(ctx context.Context, network string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", port))
	}
}

func TestMatchPayload(t *testing.T) {
	payload := protocol.PathTestPayload(nonce)
	p := []byte(payload)
	for _, c := range []struct {
		in   string
		want bool
	}{{payload, true}, {payload + "\n", true}, {payload + "\r\n", true}, {payload + " ", false}, {"x" + payload, false},
		{"", false}, {payload[:10], false}, {nonce, false}, {nonce + "\n", false}, {"probe-path-test  " + nonce, false}} {
		if got := matchPayload([]byte(c.in), p); got != c.want {
			t.Errorf("matchPayload(%q) = %v", c.in, got)
		}
	}
}

// TestBareNonceIsOtherTraffic checks the listener accepts only the fixed payload: the nonce alone, as the old protocol
// sent it, is counted as other traffic.
func TestBareNonceIsOtherTraffic(t *testing.T) {
	min, max := freeRange(t, 2)
	env := testEnv(t, min, max)
	ls := start(t, env, "tcp", 0, 10000)
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ls.Port))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte(nonce + "\n"))
	c.Close()
	cr := collect(t, env, ls.ListenID, 500)
	if cr.Received || cr.OtherArrivals != 1 {
		t.Fatalf("collect %+v", cr)
	}
}

func TestReadArrivalStopsAtNewline(t *testing.T) {
	got := readArrival(strings.NewReader("hello\nmore"), 64)
	// strings.Reader returns everything in one read; what matters is the cap and the stop on EOF.
	if !strings.HasPrefix(string(got), "hello\n") {
		t.Fatalf("got %q", got)
	}
	got = readArrival(strings.NewReader(strings.Repeat("a", 100)), 64)
	if len(got) != 64 {
		t.Fatalf("read %d bytes, want 64", len(got))
	}
}

func TestDialOutcome(t *testing.T) {
	op := func(e error) error { return &net.OpError{Op: "dial", Net: "tcp", Err: &osSyscallErr{e}} }
	for _, c := range []struct {
		err  error
		want string
	}{
		{op(syscall.ECONNREFUSED), "refused"},
		{op(syscall.EHOSTUNREACH), "unreachable"},
		{op(syscall.ENETUNREACH), "unreachable"},
		{op(syscall.ETIMEDOUT), "timeout"},
		{context.DeadlineExceeded, "timeout"},
		{errors.New("something else"), "error"},
	} {
		if got := dialOutcome(c.err, context.Background()); got != c.want {
			t.Errorf("dialOutcome(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

type osSyscallErr struct{ err error }

func (e *osSyscallErr) Error() string { return e.err.Error() }
func (e *osSyscallErr) Unwrap() error { return e.err }

func TestTCPMatch(t *testing.T) {
	min, max := freeRange(t, 3)
	env := testEnv(t, min, max)
	ls := start(t, env, "tcp", 0, 10000)
	if ls.Port < min || ls.Port > max || ls.ListenID == "" {
		t.Fatalf("bad listen_start result %+v", ls)
	}
	for _, a := range ls.Addresses {
		if a == "127.0.0.1" || a == "::1" {
			t.Fatalf("loopback reported: %v", ls.Addresses)
		}
	}
	res, perr := sendTCP(context.Background(), loopDial(ls.Port), nonce)
	if perr != nil {
		t.Fatal(perr)
	}
	sr := res.(protocol.PathSendResult)
	if sr.Outcome != "connected" || sr.RemoteIP != "127.0.0.1" || sr.LocalAddr == "" {
		t.Fatalf("send result %+v", sr)
	}
	cr := collect(t, env, ls.ListenID, 3000)
	if !cr.Received || !strings.HasPrefix(cr.From, "127.0.0.1:") || cr.OtherArrivals != 0 || cr.FirstBytes != nil {
		t.Fatalf("collect %+v", cr)
	}
	// Collected listeners are gone.
	if _, err := call(t, env, protocol.CheckListenCollect, protocol.ListenCollectParams{ListenID: ls.ListenID}); err == nil || err.Code != protocol.CodeNotFound {
		t.Fatalf("second collect: %v", err)
	}
}

func TestTCPNonMatch(t *testing.T) {
	min, max := freeRange(t, 2)
	env := testEnv(t, min, max)
	ls := start(t, env, "tcp", min, 10000)
	if ls.Port != min {
		t.Fatalf("port %d, want %d", ls.Port, min)
	}
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", ls.Port))
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("GET / HTTP/1.0\x1b[31m\r\n"))
	c.Close()
	cr := collect(t, env, ls.ListenID, 500)
	if cr.Received || cr.OtherArrivals != 1 || cr.FirstBytes == nil || !cr.FirstBytes.Untrusted ||
		!strings.Contains(cr.FirstBytes.Text, `\u001b`) {
		t.Fatalf("collect %+v (first %+v)", cr, cr.FirstBytes)
	}
}

func TestUDPMatchAndOther(t *testing.T) {
	min, max := freeRange(t, 2)
	env := testEnv(t, min, max)
	ls := start(t, env, "udp", 0, 10000)
	u, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", ls.Port))
	if err != nil {
		t.Fatal(err)
	}
	u.Write([]byte("noise"))
	u.Close()
	res, perr := sendUDP(context.Background(), loopDial(ls.Port), nonce)
	if perr != nil {
		t.Fatal(perr)
	}
	if sr := res.(protocol.PathSendResult); sr.Outcome != "sent" {
		t.Fatalf("send result %+v", sr)
	}
	cr := collect(t, env, ls.ListenID, 2000)
	// Three copies of the payload were sent; repeats of it are not other traffic.
	if !cr.Received || cr.OtherArrivals != 1 || cr.FirstBytes == nil || cr.FirstBytes.Text != "noise" {
		t.Fatalf("collect %+v", cr)
	}
}

func TestUDPRefused(t *testing.T) {
	// Find a UDP port nothing listens on.
	u, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := u.LocalAddr().(*net.UDPAddr).Port
	u.Close()
	res, perr := sendUDP(context.Background(), loopDial(port), nonce)
	if perr != nil {
		t.Fatal(perr)
	}
	if sr := res.(protocol.PathSendResult); sr.Outcome != "refused" {
		t.Fatalf("send result %+v", sr)
	}
}

func TestTCPRefused(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	res, perr := sendTCP(context.Background(), loopDial(port), nonce)
	if perr != nil {
		t.Fatal(perr)
	}
	if sr := res.(protocol.PathSendResult); sr.Outcome != "refused" || sr.RemoteIP != "127.0.0.1" {
		t.Fatalf("send result %+v", sr)
	}
}

func TestListenStartErrors(t *testing.T) {
	min, max := freeRange(t, 2)
	env := testEnv(t, min, max)

	_, err := call(t, env, protocol.CheckListenStart, protocol.ListenStartParams{Protocol: "tcp", Port: max + 1, Nonce: nonce})
	if err == nil || err.Code != protocol.CodeDenied || !strings.Contains(err.Message, "outside listen_ports") {
		t.Fatalf("out of range: %v", err)
	}

	busy, lerr := net.Listen("tcp", fmt.Sprintf(":%d", min))
	if lerr != nil {
		t.Fatal(lerr)
	}
	defer busy.Close()
	_, err = call(t, env, protocol.CheckListenStart, protocol.ListenStartParams{Protocol: "tcp", Port: min, Nonce: nonce})
	if err == nil || err.Code != protocol.CodeUnavailable || !strings.Contains(err.Message, fmt.Sprintf("port %d could not be opened on this probe", min)) {
		t.Fatalf("busy port: %v", err)
	}

	off := testEnv(t, 0, 0)
	if _, err = call(t, off, protocol.CheckListenStart, protocol.ListenStartParams{Protocol: "tcp", Nonce: nonce}); err == nil || err.Code != protocol.CodeUnavailable {
		t.Fatalf("listening off: %v", err)
	}

	if _, err = call(t, env, protocol.CheckListenCollect, protocol.ListenCollectParams{ListenID: "nope"}); err == nil || err.Code != protocol.CodeNotFound {
		t.Fatalf("unknown id: %v", err)
	}
}

func TestListenerLimit(t *testing.T) {
	min, max := freeRange(t, 6)
	env := testEnv(t, min, max)
	var ids []string
	for i := 0; i < maxListeners; i++ {
		ids = append(ids, start(t, env, "udp", 0, 10000).ListenID)
	}
	_, err := call(t, env, protocol.CheckListenStart, protocol.ListenStartParams{Protocol: "udp", Nonce: nonce})
	if err == nil || err.Code != protocol.CodeBusy {
		t.Fatalf("fifth listener: %v", err)
	}
	for _, id := range ids {
		collect(t, env, id, 1) // wait_ms 0 means the default of 3 s
	}
	start(t, env, "udp", 0, 10000) // room again
}

func TestExpiry(t *testing.T) {
	min, max := freeRange(t, 2)
	env := testEnv(t, min, max)
	ls := start(t, env, "tcp", 0, 1000)
	time.Sleep(1300 * time.Millisecond)
	if _, err := call(t, env, protocol.CheckListenCollect, protocol.ListenCollectParams{ListenID: ls.ListenID}); err == nil || err.Code != protocol.CodeNotFound {
		t.Fatalf("collect after expiry: %v", err)
	}
	// The port is free again.
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", ls.Port))
	if err != nil {
		t.Fatalf("port still held after expiry: %v", err)
	}
	l.Close()
}

func TestCollectWaitsForArrival(t *testing.T) {
	min, max := freeRange(t, 2)
	env := testEnv(t, min, max)
	ls := start(t, env, "tcp", 0, 10000)
	go func() {
		time.Sleep(300 * time.Millisecond)
		sendTCP(context.Background(), loopDial(ls.Port), nonce)
	}()
	t0 := time.Now()
	cr := collect(t, env, ls.ListenID, 5000)
	if !cr.Received || time.Since(t0) > 3*time.Second {
		t.Fatalf("collect %+v after %v", cr, time.Since(t0))
	}
}

func TestPathSendPolicy(t *testing.T) {
	env := testEnv(t, 0, 0)
	_, err := call(t, env, protocol.CheckPathSend, protocol.PathSendParams{Address: "127.0.0.1", Port: 9, Protocol: "tcp", Nonce: nonce})
	if err == nil || err.Code != protocol.CodeDenied {
		t.Fatalf("loopback send: %v", err)
	}
	p, perr := policy.New(policy.Config{Mode: policy.ModeClosed, AllowCIDRs: []string{"192.0.2.0/24"}})
	if perr != nil {
		t.Fatal(perr)
	}
	env.Policy = p
	_, err = call(t, env, protocol.CheckPathSend, protocol.PathSendParams{Address: "198.51.100.1", Port: 9, Protocol: "udp", Nonce: nonce})
	if err == nil || err.Code != protocol.CodeDenied {
		t.Fatalf("closed-policy send: %v", err)
	}
}

// TestEndToEnd goes through the registered checks and the policy, using this host's own non-loopback address (allowed
// because the test clears the policy's self-address list).
func TestEndToEnd(t *testing.T) {
	var addr string
	for _, a := range ownAddresses() {
		if ip, err := netip.ParseAddr(a); err == nil && ip.Is4() {
			addr = a
			break
		}
	}
	if addr == "" {
		t.Skip("no non-loopback IPv4 address")
	}
	min, max := freeRange(t, 3)
	env := testEnv(t, min, max)
	for _, proto := range []string{"tcp", "udp"} {
		ls := start(t, env, proto, 0, 10000)
		res, err := call(t, env, protocol.CheckPathSend, protocol.PathSendParams{Address: addr, Port: ls.Port, Protocol: proto, Nonce: nonce})
		if err != nil {
			t.Fatalf("%s path_send: %v", proto, err)
		}
		sr := res.(protocol.PathSendResult)
		if sr.RemoteIP != addr || (proto == "tcp" && sr.Outcome != "connected") || (proto == "udp" && sr.Outcome != "sent") {
			t.Fatalf("%s send %+v", proto, sr)
		}
		cr := collect(t, env, ls.ListenID, 2000)
		if !cr.Received || !strings.HasPrefix(cr.From, addr+":") {
			t.Fatalf("%s collect %+v", proto, cr)
		}
	}
}
