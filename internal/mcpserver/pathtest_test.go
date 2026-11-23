package mcpserver

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"probetools/internal/protocol"
)

// pathScript is what the fake probes answer for each step of a path_test.
type pathScript struct {
	listen  protocol.ProbeResult
	send    protocol.ProbeResult
	collect protocol.ProbeResult
}

func (s pathScript) run(_ context.Context, _, check string, _ json.RawMessage) protocol.ProbeResult {
	switch check {
	case protocol.CheckListenStart:
		return s.listen
	case protocol.CheckPathSend:
		return s.send
	case protocol.CheckListenCollect:
		return s.collect
	}
	return errResult(protocol.CodeNotFound)
}

func listening(proto string) protocol.ProbeResult {
	return okResult(protocol.ListenStartResult{ListenID: "L1", Protocol: proto, Port: 40007, Addresses: []string{"10.1.0.2"}})
}

func sendOutcome(o string) protocol.ProbeResult {
	return okResult(protocol.PathSendResult{Outcome: o, LocalAddr: "10.1.0.1:50000", RemoteIP: "10.1.0.2"})
}

func arrived(from string) protocol.ProbeResult {
	return okResult(protocol.ListenCollectResult{Received: true, From: from, Bytes: 24})
}

func nothing() protocol.ProbeResult {
	return okResult(protocol.ListenCollectResult{})
}

func TestPathTestVerdicts(t *testing.T) {
	cases := []struct {
		name     string
		proto    string
		script   pathScript
		verdict  string
		noSend   bool
		waitMS   int
		observed string
	}{
		{"reached", "tcp", pathScript{listening("tcp"), sendOutcome("connected"), arrived("10.1.0.1:50000")}, VerdictReached, false, 3000, "10.1.0.1:50000"},
		{"reached udp", "udp", pathScript{listening("udp"), sendOutcome("sent"), arrived("10.1.0.1:50000")}, VerdictReached, false, 3000, "10.1.0.1:50000"},
		{"nat", "tcp", pathScript{listening("tcp"), sendOutcome("connected"), arrived("203.0.113.9:61000")}, VerdictReachedViaNAT, false, 3000, "203.0.113.9:61000"},
		{"intercepted", "tcp", pathScript{listening("tcp"), sendOutcome("connected"), nothing()}, VerdictIntercepted, false, 3000, ""},
		{"refused", "tcp", pathScript{listening("tcp"), sendOutcome("refused"), nothing()}, VerdictRefusedInPath, false, 3000, ""},
		{"timeout", "tcp", pathScript{listening("tcp"), sendOutcome("timeout"), nothing()}, VerdictBlockedOrDropped, false, 3000, ""},
		{"unreachable", "tcp", pathScript{listening("tcp"), sendOutcome("unreachable"), nothing()}, VerdictBlockedOrDropped, false, 3000, ""},
		{"udp dropped", "udp", pathScript{listening("udp"), sendOutcome("sent"), nothing()}, VerdictBlockedOrDropped, false, 3000, ""},
		{"listen unavailable", "tcp", pathScript{listen: errResult(protocol.CodeUnavailable)}, VerdictListenFailed, true, 0, ""},
		{"listen busy", "tcp", pathScript{listen: errResult(protocol.CodeBusy)}, VerdictListenFailed, true, 0, ""},
		{"denied", "tcp", pathScript{listening("tcp"), errResult(protocol.CodeDenied), nothing()}, VerdictDeniedByPolicy, false, 1, ""},
		{"send error", "tcp", pathScript{listening("tcp"), errResult(protocol.CodeInternal), nothing()}, VerdictSendFailed, false, 3000, ""},
		{"collect error", "tcp", pathScript{listening("tcp"), sendOutcome("connected"), errResult(protocol.CodeNotFound)}, VerdictInconclusive, false, 3000, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			th := startHub(t, 5*time.Second)
			th.router.run = c.script.run
			cs := th.session(t, sydToken)
			var out pathTestOutput
			decode(t, call(t, cs, "path_test", map[string]any{"from": "syd-1", "to": "syd-2", "protocol": c.proto}), &out)
			if out.Verdict != c.verdict {
				t.Fatalf("verdict = %q, want %q (summary: %s)", out.Verdict, c.verdict, out.Summary)
			}
			if out.Summary == "" || out.From != "syd-1" || out.To != "syd-2" || out.Protocol != c.proto {
				t.Errorf("output = %+v", out)
			}
			if out.ObservedSource != c.observed {
				t.Errorf("observed_source = %q, want %q", out.ObservedSource, c.observed)
			}
			// The receiver's first address, without its prefix length.
			if out.AddressUsed != "10.1.0.2" {
				t.Errorf("address_used = %q", out.AddressUsed)
			}
			starts := th.router.callsTo(protocol.CheckListenStart)
			if len(starts) != 1 || starts[0].probe != "syd-2" {
				t.Fatalf("listen_start calls = %+v", starts)
			}
			var lp protocol.ListenStartParams
			_ = json.Unmarshal(starts[0].params, &lp)
			if !regexp.MustCompile(`^[A-Za-z0-9_-]{24}$`).MatchString(lp.Nonce) || lp.Protocol != c.proto || lp.DurationMS != pathListenDurationMS {
				t.Errorf("listen_start params = %+v", lp)
			}
			sends := th.router.callsTo(protocol.CheckPathSend)
			collects := th.router.callsTo(protocol.CheckListenCollect)
			if c.noSend {
				if len(sends) != 0 || len(collects) != 0 {
					t.Errorf("ran send/collect after listen failed: %d %d", len(sends), len(collects))
				}
				if out.Listen == nil || out.Listen.OK {
					t.Errorf("listen = %+v", out.Listen)
				}
				return
			}
			if len(sends) != 1 || sends[0].probe != "syd-1" {
				t.Fatalf("path_send calls = %+v", sends)
			}
			var sp protocol.PathSendParams
			_ = json.Unmarshal(sends[0].params, &sp)
			if sp.Nonce != lp.Nonce || sp.Port != 40007 || sp.Address != "10.1.0.2" || sp.Protocol != c.proto || sp.TimeoutMS != 5000 {
				t.Errorf("path_send params = %+v (nonce %q)", sp, lp.Nonce)
			}
			if len(collects) != 1 || collects[0].probe != "syd-2" {
				t.Fatalf("listen_collect calls = %+v", collects)
			}
			var cp protocol.ListenCollectParams
			_ = json.Unmarshal(collects[0].params, &cp)
			if cp.ListenID != "L1" || cp.WaitMS != c.waitMS {
				t.Errorf("listen_collect params = %+v, want wait %d", cp, c.waitMS)
			}
			if out.Port != 40007 || out.Sender == nil || out.Receiver == nil || out.Listen == nil {
				t.Errorf("output = %+v", out)
			}
			if !strings.Contains(th.logs.String(), `"verdict":"`+c.verdict+`"`) {
				t.Errorf("verdict not audited: %s", th.logs.String())
			}
		})
	}
}

func TestPathTestTypedLegs(t *testing.T) {
	th := startHub(t, 5*time.Second)
	th.router.run = pathScript{listening("tcp"), sendOutcome("connected"),
		okResult(protocol.ListenCollectResult{OtherArrivals: 1, FirstBytes: &protocol.Untrusted{Text: "GET /", Untrusted: true}})}.run
	cs := th.session(t, fullToken)
	res := call(t, cs, "path_test", map[string]any{"from": "syd-1", "to": "syd-2", "to_address": "192.0.2.2", "port": 40007})
	var raw struct {
		Verdict  string `json:"verdict"`
		Summary  string `json:"summary"`
		Receiver struct {
			Result protocol.ListenCollectResult `json:"result"`
		} `json:"receiver"`
		Sender struct {
			Result protocol.PathSendResult `json:"result"`
		} `json:"sender"`
		AddressUsed string `json:"address_used"`
	}
	decode(t, res, &raw)
	if raw.Verdict != VerdictIntercepted || raw.AddressUsed != "192.0.2.2" {
		t.Errorf("out = %+v", raw)
	}
	if raw.Receiver.Result.FirstBytes == nil || !raw.Receiver.Result.FirstBytes.Untrusted || raw.Sender.Result.Outcome != "connected" {
		t.Errorf("legs = %+v", raw)
	}
	if !strings.Contains(raw.Summary, "1 other") {
		t.Errorf("summary does not mention other arrivals: %s", raw.Summary)
	}
	var lp protocol.ListenStartParams
	_ = json.Unmarshal(th.router.callsTo(protocol.CheckListenStart)[0].params, &lp)
	if lp.Port != 40007 {
		t.Errorf("requested port not passed on: %+v", lp)
	}
}

// A client without tcp_connect may still name one of the receiver's own addresses, in any spelling netip accepts.
func TestPathTestToAddressOfReceiver(t *testing.T) {
	th := startHub(t, 5*time.Second)
	th.router.run = pathScript{listening("tcp"), sendOutcome("connected"), arrived("10.1.0.1:50000")}.run
	var out pathTestOutput
	decode(t, call(t, th.session(t, sydToken), "path_test",
		map[string]any{"from": "syd-1", "to": "syd-2", "to_address": "::ffff:192.0.2.2"}), &out)
	if out.AddressUsed != "192.0.2.2" {
		t.Errorf("address_used = %q", out.AddressUsed)
	}
}

// The default address is one on the sender's subnet, not merely the receiver's first; when none is and the path is
// not reached, the summary says the hub chose it and lists the others.
func TestPathTestDefaultAddress(t *testing.T) {
	cases := []struct {
		name     string
		from, to []string
		script   pathScript
		want     string
		wantNote bool
	}{
		{"same /24 not first", []string{"10.1.0.1/24"}, []string{"172.16.9.9/16", "10.1.0.2/24"},
			pathScript{listening("tcp"), sendOutcome("timeout"), nothing()}, "10.1.0.2", true},
		{"same /64", []string{"2001:db8:1:1::5/64"}, []string{"10.9.9.9", "2001:db8:1:1::9/64"},
			pathScript{listening("tcp"), sendOutcome("connected"), arrived("[2001:db8:1:1::5]:5000")}, "2001:db8:1:1::9", false},
		{"no shared subnet", []string{"10.1.0.1/24"}, []string{"172.16.9.9/16", "192.0.2.2"},
			pathScript{listening("tcp"), sendOutcome("timeout"), nothing()}, "172.16.9.9", true},
		{"reached needs no note", []string{"10.1.0.1/24"}, []string{"172.16.9.9/16"},
			pathScript{listening("tcp"), sendOutcome("connected"), arrived("10.1.0.1:50000")}, "172.16.9.9", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			th := startHub(t, 5*time.Second)
			th.router.run = c.script.run
			for i := range th.router.probes {
				switch th.router.probes[i].Name {
				case "syd-1":
					th.router.probes[i].Addresses = c.from
				case "syd-2":
					th.router.probes[i].Addresses = c.to
				}
			}
			var out pathTestOutput
			decode(t, call(t, th.session(t, sydToken), "path_test", map[string]any{"from": "syd-1", "to": "syd-2"}), &out)
			if out.AddressUsed != c.want {
				t.Errorf("address_used = %q, want %q", out.AddressUsed, c.want)
			}
			note := strings.Contains(out.Summary, "chose "+c.want+" automatically")
			if note != c.wantNote {
				t.Errorf("note in summary = %v, want %v: %s", note, c.wantNote, out.Summary)
			}
			if c.wantNote && !strings.Contains(out.Summary, "("+strings.Join(bare(c.to), ", ")+")") {
				t.Errorf("summary does not list the receiver's addresses: %s", out.Summary)
			}
		})
	}

	// A caller-chosen address gets no note.
	th := startHub(t, 5*time.Second)
	th.router.run = pathScript{listening("tcp"), sendOutcome("timeout"), nothing()}.run
	var out pathTestOutput
	decode(t, call(t, th.session(t, sydToken), "path_test", map[string]any{"from": "syd-1", "to": "syd-2", "to_address": "192.0.2.2"}), &out)
	if strings.Contains(out.Summary, "automatically") {
		t.Errorf("note on a given address: %s", out.Summary)
	}
}

func bare(addrs []string) []string {
	var out []string
	for _, a := range addrs {
		ip, _ := parseAddr(a)
		out = append(out, ip.String())
	}
	return out
}

func TestPathTestRefusals(t *testing.T) {
	th := startHub(t, 5*time.Second)
	th.router.run = pathScript{listening("tcp"), sendOutcome("connected"), nothing()}.run
	syd := th.session(t, sydToken)
	full := th.session(t, fullToken)
	cases := []struct {
		name   string
		client string
		args   map[string]any
		want   string
	}{
		{"out of scope", "syd", map[string]any{"from": "syd-1", "to": "mel-1"}, `probe_unknown: no probe named "mel-1" in your scope`},
		{"unknown to limited client", "syd", map[string]any{"from": "syd-1", "to": "nope"}, `probe_unknown: no probe named "nope" in your scope`},
		{"to_address elsewhere", "syd", map[string]any{"from": "syd-1", "to": "syd-2", "to_address": "192.0.2.99"}, "forbidden: to_address must be one of the receiver's addresses"},
		{"to_address name", "syd", map[string]any{"from": "syd-1", "to": "syd-2", "to_address": "syd-2.example"}, "forbidden: to_address must be one of the receiver's addresses"},
		{"to_address sender's", "syd", map[string]any{"from": "syd-1", "to": "syd-2", "to_address": "10.1.0.1"}, "forbidden: to_address must be one of the receiver's addresses"},
		{"unknown", "full", map[string]any{"from": "syd-1", "to": "nope"}, "probe_unknown"},
		{"offline", "full", map[string]any{"from": "lon-1", "to": "syd-1"}, "probe_offline"},
		{"same probe", "full", map[string]any{"from": "syd-1", "to": "syd-1"}, "invalid_params"},
		{"bad protocol", "full", map[string]any{"from": "syd-1", "to": "syd-2", "protocol": "icmp"}, "invalid_params"},
		{"bad to_address", "full", map[string]any{"from": "syd-1", "to": "syd-2", "to_address": "a b"}, "invalid_params: to_address"},
		{"bad port", "full", map[string]any{"from": "syd-1", "to": "syd-2", "port": 70000}, "invalid_params"},
	}
	for _, c := range cases {
		cs := full
		if c.client == "syd" {
			cs = syd
		}
		wantToolError(t, call(t, cs, "path_test", c.args), c.want)
	}
	if n := len(th.router.callsTo(protocol.CheckListenStart)); n != 0 {
		t.Errorf("a refused path_test opened %d listeners", n)
	}
}

// The listener is always collected (and so closed), even when the call's budget runs out during the send.
func TestPathTestCollectsAfterBudget(t *testing.T) {
	th := startHub(t, 200*time.Millisecond)
	th.router.run = func(ctx context.Context, probe, check string, p json.RawMessage) protocol.ProbeResult {
		if check == protocol.CheckPathSend {
			<-ctx.Done()
			return errResult(protocol.CodeCancelled)
		}
		return pathScript{listening("tcp"), protocol.ProbeResult{}, nothing()}.run(ctx, probe, check, p)
	}
	cs := th.session(t, fullToken)
	var out pathTestOutput
	decode(t, call(t, cs, "path_test", map[string]any{"from": "syd-1", "to": "syd-2"}), &out)
	if out.Verdict != VerdictSendFailed {
		t.Errorf("verdict = %q (%s)", out.Verdict, out.Summary)
	}
	collects := th.router.callsTo(protocol.CheckListenCollect)
	if len(collects) != 1 {
		t.Fatalf("listen_collect ran %d times", len(collects))
	}
	var cp protocol.ListenCollectParams
	_ = json.Unmarshal(collects[0].params, &cp)
	if cp.WaitMS != 1 {
		t.Errorf("collect after the budget waited %d ms", cp.WaitMS)
	}
}

// A router that ignores its context cannot hold path_test past its budget.
func TestPathTestStuckRouter(t *testing.T) {
	th := startHub(t, 200*time.Millisecond)
	release := make(chan struct{})
	defer close(release)
	th.router.run = func(ctx context.Context, probe, check string, p json.RawMessage) protocol.ProbeResult {
		if check == protocol.CheckPathSend {
			<-release
		}
		return pathScript{listening("tcp"), protocol.ProbeResult{}, nothing()}.run(ctx, probe, check, p)
	}
	cs := th.session(t, fullToken)
	start := time.Now()
	var out pathTestOutput
	decode(t, call(t, cs, "path_test", map[string]any{"from": "syd-1", "to": "syd-2"}), &out)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("path_test took %v with a 200ms budget", d)
	}
	if out.Verdict != VerdictSendFailed || out.Sender == nil || out.Sender.Error == nil || out.Sender.Error.Code != protocol.CodeTimeout {
		t.Errorf("out = %+v", out)
	}
	if n := len(th.router.callsTo(protocol.CheckListenCollect)); n != 1 {
		t.Errorf("listen_collect ran %d times", n)
	}
}

func TestParseAddr(t *testing.T) {
	if !hasAddress([]string{"10.0.0.1/24", "fe80::1%eth0"}, "10.0.0.1") {
		t.Error("prefix form not matched")
	}
	if !hasAddress([]string{"fe80::1/64"}, hostOf("[fe80::1%eth0]:4000")) {
		t.Error("zoned IPv6 not matched")
	}
	if !hasAddress([]string{"10.0.0.1"}, "::ffff:10.0.0.1") {
		t.Error("mapped IPv4 not matched")
	}
	if hasAddress([]string{"10.0.0.1"}, "10.0.0.2") {
		t.Error("wrong address matched")
	}
	if got := firstAddress([]string{"bogus", "10.0.0.5/24"}); got != "10.0.0.5" {
		t.Errorf("firstAddress = %q", got)
	}
}
