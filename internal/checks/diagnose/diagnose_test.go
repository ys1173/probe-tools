package diagnose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"probetools/internal/check"
	"probetools/internal/checks/app"
	"probetools/internal/policy"
	"probetools/internal/protocol"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func newEnv(t *testing.T, names map[string][]netip.Addr) *check.Env {
	t.Helper()
	p, err := policy.New(policy.Config{Mode: policy.ModeOpen})
	if err != nil {
		t.Fatal(err)
	}
	p.SelfAddrs = func() ([]netip.Prefix, error) { return nil, nil }
	p.Resolver = fakeResolver(names)
	return &check.Env{Policy: p}
}

// fakeRun answers each check with a canned result or error and records the parameters it was given.
type fakeRun struct {
	mu      sync.Mutex
	results map[string]any
	errs    map[string]*protocol.Error
	calls   map[string]json.RawMessage
	block   map[string]bool // wait for the context to end, as a hung check would
}

func (f *fakeRun) run(ctx context.Context, name string, params any) (any, *protocol.Error) {
	raw, _ := json.Marshal(params)
	f.mu.Lock()
	if f.calls == nil {
		f.calls = map[string]json.RawMessage{}
	}
	f.calls[name] = raw
	block := f.block[name]
	f.mu.Unlock()
	if block {
		<-ctx.Done()
		return nil, protocol.Errorf(protocol.CodeTimeout, "deadline")
	}
	if e := f.errs[name]; e != nil {
		return nil, e
	}
	r, ok := f.results[name]
	if !ok {
		return nil, protocol.Errorf(protocol.CodeNotFound, "no check %s", name)
	}
	return r, nil
}

func (f *fakeRun) called(name string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.calls[name]
	return ok
}

// Results as Env.Run might return them: a decoded map for some, a typed value for others.
func pingOK() any {
	return map[string]any{"sent": 3.0, "received": 3.0, "loss_pct": 0.0, "avg_ms": 1.5}
}
func pingLost() any {
	return struct {
		Sent     int     `json:"sent"`
		Received int     `json:"received"`
		LossPct  float64 `json:"loss_pct"`
	}{3, 0, 100}
}
func tcpOutcome(port int, outcome string) any {
	return map[string]any{"target": "x", "address": "192.0.2.1", "ports": []any{map[string]any{"port": port, "outcome": outcome, "connect_ms": 12.5}}}
}
func tlsResult(verified, match bool, days int) any {
	return map[string]any{"outcome": "ok", "version": "TLS 1.3", "verified": verified, "hostname_match": match,
		"chain": []any{map[string]any{"days_left": days}}}
}
func httpResult(status int) any {
	return map[string]any{"outcome": "ok", "status": status, "timings": map[string]any{"total_ms": 80.0}}
}

func runDiag(t *testing.T, env *check.Env, f *fakeRun, params protocol.DiagnoseParams) map[string]any {
	t.Helper()
	env.Run = f.run
	return runWith(t, context.Background(), env, params)
}

func runWith(t *testing.T, ctx context.Context, env *check.Env, params protocol.DiagnoseParams) map[string]any {
	t.Helper()
	raw, _ := json.Marshal(params)
	out, perr := diagnose(ctx, env, raw)
	if perr != nil {
		t.Fatalf("diagnose: %v", perr)
	}
	b, _ := json.Marshal(out)
	var m map[string]any
	json.Unmarshal(b, &m)
	return m
}

func statuses(m map[string]any) string {
	var s []string
	for _, l := range m["layers"].([]any) {
		lm := l.(map[string]any)
		s = append(s, lm["layer"].(string)+"="+lm["status"].(string))
	}
	return strings.Join(s, " ")
}

var webNames = map[string][]netip.Addr{"web.example": {netip.MustParseAddr("192.0.2.10")}}

func TestDiagnoseAllFine(t *testing.T) {
	f := &fakeRun{results: map[string]any{"ping": pingOK(), "tcp_connect": tcpOutcome(443, "open"), "tls_check": tlsResult(true, true, 60), "http_check": httpResult(200)}}
	m := runDiag(t, newEnv(t, webNames), f, protocol.DiagnoseParams{Target: "https://web.example/health"})
	if got := statuses(m); got != "dns=ok ping=ok tcp=ok tls=ok http=ok" {
		t.Fatalf("layers: %s", got)
	}
	if m["first_failure"] != "" || m["verdict"] != "DNS, ICMP, TCP 443, TLS and HTTP are fine from this probe." {
		t.Fatalf("verdict: %q first_failure %q", m["verdict"], m["first_failure"])
	}
	var hp protocol.HTTPCheckParams
	json.Unmarshal(f.calls["http_check"], &hp)
	if hp.URL != "https://web.example/health" || hp.VerifyTLS == nil || !*hp.VerifyTLS {
		t.Fatalf("http params: %s", f.calls["http_check"])
	}
	var pp protocol.PingParams
	json.Unmarshal(f.calls["ping"], &pp)
	if pp.Count != 3 || pp.Target != "web.example" {
		t.Fatalf("ping params: %s", f.calls["ping"])
	}
}

func TestDiagnoseTCPTimeoutWithSilentPing(t *testing.T) {
	f := &fakeRun{results: map[string]any{"ping": pingLost(), "tcp_connect": tcpOutcome(443, "timeout")}}
	m := runDiag(t, newEnv(t, webNames), f, protocol.DiagnoseParams{Target: "web.example", Port: 443})
	if got := statuses(m); got != "dns=ok ping=no_reply tcp=failed tls=skipped http=skipped" {
		t.Fatalf("layers: %s", got)
	}
	want := "TCP 443 times out from this probe; DNS is fine; ICMP gets no reply, which is often just filtering."
	if m["first_failure"] != "tcp" || m["verdict"] != want {
		t.Fatalf("verdict %q", m["verdict"])
	}
	if f.called("tls_check") || f.called("http_check") {
		t.Fatal("ran layers after a TCP failure")
	}
}

func TestDiagnoseDNSFailures(t *testing.T) {
	f := &fakeRun{}
	m := runDiag(t, newEnv(t, nil), f, protocol.DiagnoseParams{Target: "missing.example", Port: 80})
	if got := statuses(m); got != "dns=failed ping=skipped tcp=skipped tls=skipped http=skipped" || m["first_failure"] != "dns" {
		t.Fatalf("unresolved: %s %v", got, m["first_failure"])
	}
	if !strings.Contains(m["verdict"].(string), "missing.example does not resolve") {
		t.Fatalf("verdict %q", m["verdict"])
	}

	f = &fakeRun{}
	m = runDiag(t, newEnv(t, map[string][]netip.Addr{"meta.example": {netip.MustParseAddr("169.254.169.254")}}), f, protocol.DiagnoseParams{Target: "meta.example"})
	if got := statuses(m); !strings.HasPrefix(got, "dns=denied ") || m["first_failure"] != "dns" || !strings.Contains(m["verdict"].(string), "policy does not allow") {
		t.Fatalf("denied: %s %q", got, m["verdict"])
	}
	if f.called("ping") {
		t.Fatal("pinged a denied target")
	}
}

func TestDiagnosePingUnavailableIsNotAFailure(t *testing.T) {
	f := &fakeRun{errs: map[string]*protocol.Error{"ping": protocol.Errorf(protocol.CodeUnavailable, "no NET_RAW")},
		results: map[string]any{"tcp_connect": tcpOutcome(22, "open")}}
	m := runDiag(t, newEnv(t, nil), f, protocol.DiagnoseParams{Target: "192.0.2.5", Port: 22})
	if got := statuses(m); got != "dns=skipped ping=no_reply tcp=ok tls=skipped http=skipped" || m["first_failure"] != "" {
		t.Fatalf("layers: %s", got)
	}
	if m["verdict"] != "TCP 22 is fine from this probe; ICMP could not be tested from this probe." {
		t.Fatalf("verdict %q", m["verdict"])
	}
}

func TestDiagnoseAddressWithoutPort(t *testing.T) {
	f := &fakeRun{results: map[string]any{"ping": pingOK()}}
	m := runDiag(t, newEnv(t, nil), f, protocol.DiagnoseParams{Target: "192.0.2.5"})
	if got := statuses(m); got != "dns=skipped ping=ok tcp=skipped tls=skipped http=skipped" {
		t.Fatalf("layers: %s", got)
	}
}

func TestDiagnoseCertificateProblemStillTriesHTTP(t *testing.T) {
	f := &fakeRun{results: map[string]any{"ping": pingOK(), "tcp_connect": tcpOutcome(443, "open"), "tls_check": tlsResult(false, true, -3), "http_check": httpResult(200)}}
	m := runDiag(t, newEnv(t, webNames), f, protocol.DiagnoseParams{Target: "https://web.example/"})
	if got := statuses(m); got != "dns=ok ping=ok tcp=ok tls=failed http=ok" || m["first_failure"] != "tls" {
		t.Fatalf("layers: %s", got)
	}
	if m["verdict"] != "The certificate expired 3 days ago; DNS, ICMP, TCP 443 and HTTP are fine." {
		t.Fatalf("verdict %q", m["verdict"])
	}
	var hp protocol.HTTPCheckParams
	json.Unmarshal(f.calls["http_check"], &hp)
	if hp.VerifyTLS == nil || *hp.VerifyTLS {
		t.Fatalf("HTTP after a certificate failure must not verify: %s", f.calls["http_check"])
	}
}

func TestDiagnoseHTTPStatus(t *testing.T) {
	f := &fakeRun{results: map[string]any{"ping": pingOK(), "tcp_connect": tcpOutcome(8080, "open"), "http_check": httpResult(503)}}
	m := runDiag(t, newEnv(t, webNames), f, protocol.DiagnoseParams{Target: "http://web.example:8080/"})
	if got := statuses(m); got != "dns=ok ping=ok tcp=ok tls=skipped http=failed" || m["first_failure"] != "http" {
		t.Fatalf("layers: %s", got)
	}
	if m["verdict"] != "HTTP answers with status 503; DNS, ICMP and TCP 8080 are fine." {
		t.Fatalf("verdict %q", m["verdict"])
	}
}

func TestDiagnoseRespectsDeadline(t *testing.T) {
	f := &fakeRun{results: map[string]any{"ping": pingOK()}, block: map[string]bool{"tcp_connect": true}}
	env := newEnv(t, webNames)
	env.Run = f.run
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	m := runWith(t, ctx, env, protocol.DiagnoseParams{Target: "https://web.example/"})
	if time.Since(start) > 2*time.Second {
		t.Fatal("did not stop at the deadline")
	}
	if got := statuses(m); got != "dns=ok ping=ok tcp=error tls=skipped http=skipped" {
		t.Fatalf("layers: %s", got)
	}
	if m["first_failure"] != "" || m["verdict"] != "DNS and ICMP are fine from this probe; TCP 443 could not be tested." {
		t.Fatalf("verdict %q", m["verdict"])
	}
}

func TestDiagnoseRedirectDeniedAtHTTP(t *testing.T) {
	denied := map[string]any{"outcome": "denied", "status": 302, "error": map[string]any{"code": "denied"}}
	f := &fakeRun{results: map[string]any{"ping": pingOK(), "tcp_connect": tcpOutcome(80, "open"), "http_check": denied}}
	m := runDiag(t, newEnv(t, webNames), f, protocol.DiagnoseParams{Target: "http://web.example/"})
	want := "A redirect led to an address the probe's policy does not allow; DNS, ICMP and TCP 80 are fine."
	if m["first_failure"] != "http" || m["verdict"] != want {
		t.Fatalf("verdict %q", m["verdict"])
	}
}

func TestDiagnoseDeniedAddress(t *testing.T) {
	f := &fakeRun{errs: map[string]*protocol.Error{"ping": protocol.Errorf(protocol.CodeUnavailable, "no NET_RAW")}}
	m := runDiag(t, newEnv(t, nil), f, protocol.DiagnoseParams{Target: "127.0.0.1"})
	if got := statuses(m); got != "dns=denied ping=skipped tcp=skipped tls=skipped http=skipped" || m["first_failure"] != "dns" ||
		m["verdict"] != "This probe's policy does not allow 127.0.0.1, so it was not tested." {
		t.Fatalf("%s %q", got, m["verdict"])
	}
	if f.called("ping") {
		t.Fatal("pinged a denied address")
	}
}

func TestDiagnoseBadTargets(t *testing.T) {
	env := newEnv(t, nil)
	env.Run = (&fakeRun{}).run
	for _, target := range []string{"ftp://x.example/", "http://user:pw@x.example/", "a b", "http://x.example:99999/"} {
		raw, _ := json.Marshal(protocol.DiagnoseParams{Target: target})
		if _, perr := diagnose(context.Background(), env, raw); perr == nil || perr.Code != protocol.CodeInvalidParams {
			t.Fatalf("%q: %v", target, perr)
		}
	}
}

// Diagnose against the real application checks, so that the fields it reads are the fields they write. Ping is faked.
func TestDiagnoseWithRealChecks(t *testing.T) {
	ip := hostIP(t)
	reg := check.NewRegistry()
	app.Register(reg)
	env := newEnv(t, map[string][]netip.Addr{"web.test": {ip}})
	env.Run = func(ctx context.Context, name string, params any) (any, *protocol.Error) {
		if name == protocol.CheckPing {
			return pingLost(), nil
		}
		f, ok := reg.Get(name)
		if !ok {
			return nil, protocol.Errorf(protocol.CodeNotFound, "%s", name)
		}
		raw, _ := json.Marshal(params)
		return f(ctx, env, raw)
	}
	plain := serve(t, ip, false)
	m := runWith(t, context.Background(), env, protocol.DiagnoseParams{Target: fmt.Sprintf("http://web.test:%d/", plain)})
	if got := statuses(m); got != "dns=ok ping=no_reply tcp=ok tls=skipped http=ok" || m["first_failure"] != "" {
		t.Fatalf("http: %s %q", got, m["verdict"])
	}

	// The test server's certificate is not trusted here: TLS fails on verification and HTTP still answers.
	secure := serve(t, ip, true)
	m = runWith(t, context.Background(), env, protocol.DiagnoseParams{Target: fmt.Sprintf("https://web.test:%d/", secure)})
	if got := statuses(m); got != "dns=ok ping=no_reply tcp=ok tls=failed http=ok" || m["first_failure"] != "tls" {
		t.Fatalf("https: %s %q", got, m["verdict"])
	}

	closed := freePort(t, ip)
	m = runWith(t, context.Background(), env, protocol.DiagnoseParams{Target: "web.test", Port: closed})
	if got := statuses(m); got != "dns=ok ping=no_reply tcp=failed tls=skipped http=skipped" || !strings.Contains(m["verdict"].(string), "is refused") {
		t.Fatalf("refused: %s %q", got, m["verdict"])
	}
}

func hostIP(t *testing.T) netip.Addr {
	t.Helper()
	raw, _ := net.InterfaceAddrs()
	for _, a := range raw {
		if pre, err := netip.ParsePrefix(a.String()); err == nil && pre.Addr().Is4() && !pre.Addr().IsLoopback() && !pre.Addr().IsLinkLocalUnicast() {
			return pre.Addr()
		}
	}
	t.Skip("no non-loopback IPv4 address to run test servers on")
	return netip.Addr{}
}

func serve(t *testing.T, ip netip.Addr, tls bool) int {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener.Close()
	srv.Listener = ln
	if tls {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return ln.Addr().(*net.TCPAddr).Port
}

func freePort(t *testing.T, ip netip.Addr) int {
	ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// One diagnose job resolves its target in the DNS layer and again in every nested check; the policy charges the job
// once per address, so the whole run fits a limit of one. The next job is over the limit and says so.
func TestDiagnoseRateLimitPerJob(t *testing.T) {
	ip := hostIP(t)
	reg := check.NewRegistry()
	app.Register(reg)
	env := newEnv(t, map[string][]netip.Addr{"web.test": {ip}})
	env.Policy.SetRateLimit(1)
	env.Run = func(ctx context.Context, name string, params any) (any, *protocol.Error) {
		if name == protocol.CheckPing {
			// The real ping resolves through the policy too; do the same without needing raw sockets.
			var p protocol.PingParams
			raw, _ := json.Marshal(params)
			json.Unmarshal(raw, &p)
			if _, e := env.Policy.Resolve(ctx, p.Target, p.Family); e != nil {
				return nil, e
			}
			return pingLost(), nil
		}
		f, ok := reg.Get(name)
		if !ok {
			return nil, protocol.Errorf(protocol.CodeNotFound, "%s", name)
		}
		raw, _ := json.Marshal(params)
		return f(ctx, env, raw)
	}
	plain := serve(t, ip, false)
	target := protocol.DiagnoseParams{Target: fmt.Sprintf("http://web.test:%d/", plain)}
	m := runWith(t, policy.WithJob(context.Background()), env, target)
	if got := statuses(m); got != "dns=ok ping=no_reply tcp=ok tls=skipped http=ok" {
		t.Fatalf("first job: %s %q", got, m["verdict"])
	}
	m = runWith(t, policy.WithJob(context.Background()), env, target)
	layers := m["layers"].([]any)
	dnsLayer := layers[0].(map[string]any)
	ping := layers[1].(map[string]any)
	if got := statuses(m); got != "dns=error ping=skipped tcp=skipped tls=skipped http=skipped" ||
		!strings.Contains(dnsLayer["summary"].(string), "rate limit") || !strings.Contains(ping["summary"].(string), "rate limit") {
		t.Fatalf("second job: %s %v", got, layers)
	}

	// An address target is put to the policy without a lookup, and is charged too.
	addr := protocol.DiagnoseParams{Target: ip.String()}
	m = runWith(t, policy.WithJob(context.Background()), env, addr)
	if got := statuses(m); got != "dns=error ping=skipped tcp=skipped tls=skipped http=skipped" {
		t.Fatalf("address target: %s %q", got, m["verdict"])
	}
	if s := m["layers"].([]any)[1].(map[string]any)["summary"].(string); !strings.Contains(s, "rate limit") {
		t.Fatalf("skip reason %q", s)
	}
}
