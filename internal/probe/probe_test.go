package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
)

const (
	testToken  = "tok-one-time-123"
	testSecret = "s3cret-value-xyz"
)

// fakeHub serves enrolment and the WebSocket link the way the real hub does, and hands each accepted session to the
// test.
type fakeHub struct {
	t        *testing.T
	srv      *httptest.Server
	enrolls  atomic.Int32
	conns    chan *hubConn
	authSeen chan string
	// reject, when set, decides how to refuse a connection: an HTTP status before the upgrade, or a close code after
	// hello. Zero values accept.
	reject func(n int) (httpStatus int, close websocket.StatusCode)
	dials  atomic.Int32
}

type hubConn struct {
	c     *websocket.Conn
	hello protocol.Hello
}

func newFakeHub(t *testing.T) *fakeHub { return newFakeHubTLS(t, false) }

func newFakeHubTLS(t *testing.T, useTLS bool) *fakeHub {
	h := &fakeHub{t: t, conns: make(chan *hubConn, 8), authSeen: make(chan string, 8)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, func(w http.ResponseWriter, r *http.Request) {
		var req protocol.EnrollRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token != testToken {
			http.Error(w, "unknown or used token", http.StatusForbidden)
			return
		}
		h.enrolls.Add(1)
		json.NewEncoder(w).Encode(protocol.EnrollResponse{ProbeID: "p1", Name: "alpha", Site: "lab", Secret: testSecret})
	})
	mux.HandleFunc("GET "+protocol.PathConnect, func(w http.ResponseWriter, r *http.Request) {
		n := int(h.dials.Add(1))
		select {
		case h.authSeen <- r.Header.Get("Authorization"):
		default:
		}
		var closeCode websocket.StatusCode
		if h.reject != nil {
			status, code := h.reject(n)
			if status != 0 {
				http.Error(w, "no", status)
				return
			}
			closeCode = code
		}
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.WireVersion}})
		if err != nil {
			return
		}
		c.SetReadLimit(maxFrameBytes)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, data, err := c.Read(ctx)
		if err != nil {
			c.CloseNow()
			return
		}
		var hello protocol.Hello
		json.Unmarshal(data, &hello)
		if closeCode != 0 {
			c.Close(closeCode, "refused")
			return
		}
		wel, _ := json.Marshal(protocol.Welcome{Type: protocol.TypeWelcome, Name: "alpha", Site: "lab"})
		if err := c.Write(ctx, websocket.MessageText, wel); err != nil {
			return
		}
		h.conns <- &hubConn{c: c, hello: hello}
	})
	if useTLS {
		h.srv = httptest.NewTLSServer(mux)
	} else {
		h.srv = httptest.NewServer(mux)
	}
	t.Cleanup(h.srv.Close)
	return h
}

// url is ws://... or wss://... to match the server.
func (h *fakeHub) url() string { return "ws" + strings.TrimPrefix(h.srv.URL, "http") }

func (h *fakeHub) next(t *testing.T) *hubConn {
	t.Helper()
	select {
	case c := <-h.conns:
		t.Cleanup(func() { c.c.CloseNow() })
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not connect")
		return nil
	}
}

// ignoreFrames keeps reading so the probe's close handshake completes, for tests that do not read results.
func (c *hubConn) ignoreFrames() { c.c.CloseRead(context.Background()) }

func (c *hubConn) send(t *testing.T, v any) {
	t.Helper()
	data, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := c.c.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("hub write: %v", err)
	}
}

func (c *hubConn) job(t *testing.T, id, name string, params any, deadlineMS int) {
	t.Helper()
	raw, _ := json.Marshal(params)
	c.send(t, protocol.Job{Type: protocol.TypeJob, ID: id, Check: name, Params: raw, DeadlineMS: deadlineMS})
}

func (c *hubConn) result(t *testing.T, within time.Duration) protocol.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within)
	defer cancel()
	_, data, err := c.c.Read(ctx)
	if err != nil {
		t.Fatalf("no result from probe: %v", err)
	}
	var r protocol.Result
	if err := json.Unmarshal(data, &r); err != nil || r.Type != protocol.TypeResult {
		t.Fatalf("not a result: %s", data)
	}
	return r
}

// results reads n results and returns them by job id.
func (c *hubConn) results(t *testing.T, n int) map[string]protocol.Result {
	t.Helper()
	out := map[string]protocol.Result{}
	for range n {
		r := c.result(t, 5*time.Second)
		out[r.ID] = r
	}
	return out
}

// waitFor polls cond for up to 3 s.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatal("condition not met in time")
}

func code(r protocol.Result) string {
	if r.Error == nil {
		return "ok"
	}
	return r.Error.Code
}

// syncBuffer collects log output from many goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeChecks is a registry of checks whose behaviour the tests control.
type fakeChecks struct {
	reg       *check.Registry
	started   chan string
	release   chan struct{} // closes to let "stuck" and "wait" return
	stuckDone chan struct{}
}

func newFakeChecks(t *testing.T) *fakeChecks {
	fc := &fakeChecks{reg: check.NewRegistry(), started: make(chan string, 16), release: make(chan struct{}), stuckDone: make(chan struct{}, 16)}
	t.Cleanup(func() {
		select {
		case <-fc.release:
		default:
			close(fc.release)
		}
	})
	fc.reg.Register("echo", func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		var m map[string]any
		json.Unmarshal(params, &m)
		return map[string]any{"params": m, "probe": env.ProbeName}, nil
	})
	// block honours its context and returns a partial result when it ends.
	fc.reg.Register("block", func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		fc.started <- "block"
		<-ctx.Done()
		return map[string]bool{"partial": true}, nil
	})
	// wait finishes when the test releases it, whatever its context says.
	fc.reg.Register("wait", func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		fc.started <- "wait"
		<-fc.release
		return map[string]bool{"finished": true}, nil
	})
	// stuck ignores its context entirely.
	fc.reg.Register("stuck", func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		fc.started <- "stuck"
		<-fc.release
		fc.stuckDone <- struct{}{}
		return "late", nil
	})
	fc.reg.Register("boom", func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		panic("kaboom secret detail")
	})
	fc.reg.Register("big", func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		return strings.Repeat("x", 1<<20), nil
	})
	fc.reg.Register("nested", func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		v, perr := env.Run(ctx, "echo", map[string]string{"target": "inner"})
		if perr != nil {
			return nil, perr
		}
		_, missing := env.Run(ctx, "no_such_check", nil)
		_, boom := env.Run(ctx, "boom", nil)
		return map[string]any{"inner": v, "missing": missing.Code, "boom": boom.Code}, nil
	})
	// resolve puts its target to the policy, which charges the rate limit; times says how often within the one job.
	fc.reg.Register("resolve", func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		var p struct {
			Target string `json:"target"`
			Times  int    `json:"times"`
		}
		json.Unmarshal(params, &p)
		var addrs []netip.Addr
		for range max(p.Times, 1) {
			var perr *protocol.Error
			if addrs, perr = env.Policy.Resolve(ctx, p.Target, ""); perr != nil {
				return nil, perr
			}
		}
		return addrs, nil
	})
	fc.reg.Register(protocol.CheckListenStart, func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		return map[string]int{"min": env.ListenPortMin, "max": env.ListenPortMax}, nil
	})
	return fc
}

type testProbe struct {
	hub    *fakeHub
	cfg    Config
	fc     *fakeChecks
	logs   *syncBuffer
	cancel context.CancelFunc
	done   chan error
	env    map[string]string
	sleeps chan time.Duration
	opts   runOptions
}

func newTestProbe(t *testing.T, hub *fakeHub) *testProbe {
	cfg, err := ParseConfig([]byte(`
hub_url: `+hub.url()+`
insecure_plaintext: true
targets: {mode: open}
listen_ports: "40000-40010"
`), func(k string) string {
		if k == "PROBE_STATE_DIR" {
			return filepath.Join(t.TempDir(), "state")
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	tp := &testProbe{hub: hub, cfg: cfg, fc: newFakeChecks(t), logs: &syncBuffer{}, env: map[string]string{DefaultEnrollTokenEnv: testToken},
		sleeps: make(chan time.Duration, 64)}
	tm := realTimers()
	tm.jitter = func(d time.Duration) time.Duration { return d }
	tp.opts = runOptions{timers: tm, getenv: func(k string) string { return tp.env[k] }}
	return tp
}

// recordSleeps makes every wait return at once and reports its length.
func (tp *testProbe) recordSleeps() {
	tp.opts.timers.sleep = func(ctx context.Context, d time.Duration) error {
		tp.sleeps <- d
		if ctx.Err() != nil {
			return ctx.Err()
		}
		time.Sleep(5 * time.Millisecond)
		return ctx.Err()
	}
}

func (tp *testProbe) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	tp.cancel = cancel
	done := make(chan error, 1)
	tp.done = done
	logger := NewLogger(tp.logs, "debug")
	go func() { done <- run(ctx, tp.cfg, tp.fc.reg, map[string]bool{"raw_icmp": false}, logger, tp.opts) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("probe did not stop")
		}
	})
}

func (tp *testProbe) stop(t *testing.T) error {
	t.Helper()
	tp.cancel()
	select {
	case err := <-tp.done:
		tp.done <- err // keep it for the cleanup
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("probe did not stop")
		return nil
	}
}

func TestEnrolSavesIdentityAndSkipsNextStart(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	hub.next(t).ignoreFrames()
	if auth := <-hub.authSeen; auth != "Bearer p1."+testSecret {
		t.Fatalf("authorization header %q", auth)
	}
	if err := tp.stop(t); err != nil {
		t.Fatal(err)
	}

	path := IdentityPath(tp.cfg.StateDir)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode %v, want 0600", fi.Mode().Perm())
	}
	di, _ := os.Stat(tp.cfg.StateDir)
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("state dir mode %v, want 0700", di.Mode().Perm())
	}
	id, err := LoadIdentity(path)
	if err != nil || id.ProbeID != "p1" || id.Name != "alpha" || id.Site != "lab" || id.Secret != testSecret || id.HubURL != tp.cfg.HubURL {
		t.Fatalf("saved identity %+v %v", id, err)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(tp.cfg.StateDir, ".identity-*")); len(leftovers) != 0 {
		t.Fatalf("temporary files left: %v", leftovers)
	}

	// Second start: no token in the environment, so it must use the saved identity.
	delete(tp.env, DefaultEnrollTokenEnv)
	tp.start(t)
	hub.next(t).ignoreFrames()
	tp.stop(t)
	if n := hub.enrolls.Load(); n != 1 {
		t.Fatalf("enrolled %d times, want 1", n)
	}
	logs := tp.logs.String()
	if strings.Contains(logs, testToken) || strings.Contains(logs, testSecret) {
		t.Fatalf("token or secret leaked into logs:\n%s", logs)
	}
}

func TestEnrolRefusedTokenIsFinal(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.env[DefaultEnrollTokenEnv] = "wrong-token"
	tp.start(t)
	select {
	case err := <-tp.done:
		tp.done <- err
		if err == nil || !strings.Contains(err.Error(), "HTTP 403") {
			t.Fatalf("want refusal error, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe kept retrying a refused token")
	}
}

func TestMissingTokenRefused(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	delete(tp.env, DefaultEnrollTokenEnv)
	err := run(context.Background(), tp.cfg, tp.fc.reg, nil, NewLogger(tp.logs, "info"), tp.opts)
	if err == nil || !strings.Contains(err.Error(), DefaultEnrollTokenEnv) {
		t.Fatalf("want missing-token error, got %v", err)
	}
}

func TestHubURLMismatchRefused(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	if err := SaveIdentity(tp.cfg.StateDir, Identity{HubURL: "wss://old-hub.example.com", ProbeID: "p0", Secret: "x"}); err != nil {
		t.Fatal(err)
	}
	err := run(context.Background(), tp.cfg, tp.fc.reg, nil, NewLogger(tp.logs, "info"), tp.opts)
	if err == nil || !strings.Contains(err.Error(), "delete "+IdentityPath(tp.cfg.StateDir)) {
		t.Fatalf("want hub mismatch error telling the operator to delete the file, got %v", err)
	}
	if hub.enrolls.Load() != 0 || hub.dials.Load() != 0 {
		t.Fatal("must not contact the hub")
	}
	// The same hub with different case and a trailing slash is not a mismatch.
	if !sameHub("WSS://Hub.Example.com/", "wss://hub.example.com") {
		t.Fatal("sameHub too strict")
	}
}

func TestHello(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	h := hub.next(t).hello
	if h.Type != protocol.TypeHello || h.Version != Version || h.OS != runtime.GOOS || h.Arch != runtime.GOARCH {
		t.Fatalf("hello header %+v", h)
	}
	if host, _ := os.Hostname(); h.Hostname != host {
		t.Fatalf("hostname %q", h.Hostname)
	}
	if !reflect.DeepEqual(h.Checks, tp.fc.reg.Names()) {
		t.Fatalf("checks %v", h.Checks)
	}
	if v, ok := h.Capabilities["raw_icmp"]; !ok || v {
		t.Fatalf("capabilities %v", h.Capabilities)
	}
	if h.Policy.Mode != policy.ModeOpen || h.ListenPorts != "40000-40010" {
		t.Fatalf("policy %+v listen %q", h.Policy, h.ListenPorts)
	}
	for _, a := range h.Addresses {
		if strings.HasPrefix(a, "127.") || a == "::1" || strings.HasPrefix(a, "fe80") {
			t.Fatalf("hello lists loopback or link-local address %s", a)
		}
	}
}

func TestJobResult(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	c := hub.next(t)
	before := time.Now()
	c.job(t, "j1", "echo", map[string]string{"target": "example.com"}, 3000)
	r := c.result(t, 2*time.Second)
	if r.ID != "j1" || r.Error != nil {
		t.Fatalf("result %+v", r)
	}
	var got struct {
		Params map[string]string `json:"params"`
		Probe  string            `json:"probe"`
	}
	json.Unmarshal(r.Data, &got)
	if got.Params["target"] != "example.com" || got.Probe != "alpha" {
		t.Fatalf("data %s", r.Data)
	}
	if r.StartedAt.Before(before.Add(-time.Second)) || r.DurationMS < 0 {
		t.Fatalf("started_at %v duration %d", r.StartedAt, r.DurationMS)
	}

	// listen_start sees the listen range from the config.
	c.job(t, "j2", protocol.CheckListenStart, map[string]any{}, 3000)
	r = c.result(t, 2*time.Second)
	if string(r.Data) != `{"max":40010,"min":40000}` {
		t.Fatalf("listen range %s", r.Data)
	}

	if !strings.Contains(tp.logs.String(), `"job_id":"j1","check":"echo","target":"example.com","code":"ok"`) {
		t.Fatalf("job not logged as expected:\n%s", tp.logs.String())
	}
}

func TestUnknownCheck(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "rm_rf", nil, 3000)
	if r := c.result(t, 2*time.Second); code(r) != protocol.CodeNotFound || r.ID != "j1" {
		t.Fatalf("result %+v", r)
	}
}

func TestBusyOnConcurrency(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.cfg.Limits.MaxConcurrent = 1
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "block", map[string]string{"target": "a.example"}, 10000)
	<-tp.fc.started
	c.job(t, "j2", "echo", map[string]string{"target": "b.example"}, 3000)
	r := c.result(t, 2*time.Second)
	if r.ID != "j2" || code(r) != protocol.CodeBusy {
		t.Fatalf("want j2 busy, got %+v", r)
	}
	c.send(t, protocol.Cancel{Type: protocol.TypeCancel, ID: "j1"})
	if r := c.result(t, 2*time.Second); r.ID != "j1" || code(r) != protocol.CodeCancelled {
		t.Fatalf("want j1 cancelled, got %+v", r)
	}
	// The slot is free again once the check's goroutine has returned.
	waitFor(t, func() bool {
		c.job(t, "j3", "echo", map[string]string{"target": "b.example"}, 3000)
		return code(c.result(t, 2*time.Second)) == "ok"
	})
}

func TestNestedRunNotCountedAgainstConcurrency(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.cfg.Limits.MaxConcurrent = 1
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "nested", map[string]string{"target": "x.example"}, 3000)
	r := c.result(t, 2*time.Second)
	if code(r) != "ok" {
		t.Fatalf("nested: %+v", r)
	}
	var got struct {
		Inner   map[string]any `json:"inner"`
		Missing string         `json:"missing"`
		Boom    string         `json:"boom"`
	}
	json.Unmarshal(r.Data, &got)
	if got.Inner["probe"] != "alpha" || got.Missing != protocol.CodeNotFound || got.Boom != protocol.CodeInternal {
		t.Fatalf("nested data %s", r.Data)
	}
}

func TestBusyOnRate(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.cfg.Limits.PerTargetPerMinute = 2
	tp.cfg.Limits.MaxConcurrent = 32
	tp.start(t)
	c := hub.next(t)
	// The limit is on the address: a job that resolves it three times pays once, and other spellings of the address
	// (v4-mapped, NAT64) share its bucket. Jobs run one at a time so the order of charges is fixed.
	run := func(id string, params map[string]any) protocol.Result {
		t.Helper()
		c.job(t, id, "resolve", params, 3000)
		return c.result(t, 5*time.Second)
	}
	if r := run("a1", map[string]any{"target": "203.0.113.5", "times": 3}); code(r) != "ok" {
		t.Fatalf("a1: %+v", r)
	}
	if r := run("a2", map[string]any{"target": "::ffff:203.0.113.5"}); code(r) != "ok" {
		t.Fatalf("a2: %+v", r)
	}
	r := run("a3", map[string]any{"target": "64:ff9b::cb00:7105"})
	if code(r) != protocol.CodeBusy || !strings.Contains(r.Error.Message, "rate limit for") {
		t.Fatalf("a3 must be over the limit: %+v", r)
	}
	if r := run("b1", map[string]any{"target": "203.0.113.6"}); code(r) != "ok" {
		t.Fatalf("b1: %+v", r)
	}
	// Checks that resolve nothing are not limited.
	for i := range 4 {
		c.job(t, "l"+string(rune('0'+i)), protocol.CheckListenStart, map[string]any{}, 3000)
		c.job(t, "e"+string(rune('0'+i)), "echo", map[string]string{"url": "https://user:pw@a.example:8443/x"}, 3000)
	}
	for id, r := range c.results(t, 8) {
		if code(r) != "ok" {
			t.Fatalf("%s must not be rate limited: %+v", id, r)
		}
	}
	if strings.Contains(tp.logs.String(), "pw@") {
		t.Fatal("url user info reached the logs")
	}
	if !strings.Contains(tp.logs.String(), `"target":"a.example"`) {
		t.Fatalf("job log lines should name the target:\n%s", tp.logs.String())
	}
}

func TestCancel(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "block", map[string]string{"target": "a.example"}, 20000)
	<-tp.fc.started
	c.send(t, protocol.Cancel{Type: protocol.TypeCancel, ID: "j1"})
	r := c.result(t, 2*time.Second)
	if r.ID != "j1" || code(r) != protocol.CodeCancelled || r.Data != nil {
		t.Fatalf("result %+v", r)
	}
	// A cancel for nothing is ignored.
	c.send(t, protocol.Cancel{Type: protocol.TypeCancel, ID: "nope"})
	c.job(t, "j2", "echo", nil, 3000)
	if r := c.result(t, 2*time.Second); r.ID != "j2" {
		t.Fatalf("result %+v", r)
	}
}

func TestDeadline(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	c := hub.next(t)

	// A check that honours its context returns its partial result at the deadline.
	start := time.Now()
	c.job(t, "j1", "block", map[string]string{"target": "a.example"}, 300)
	r := c.result(t, 3*time.Second)
	if code(r) != "ok" || string(r.Data) != `{"partial":true}` {
		t.Fatalf("partial result %+v", r)
	}
	if el := time.Since(start); el > 300*time.Millisecond+deadlineGrace {
		t.Fatalf("partial result took %v", el)
	}
	<-tp.fc.started

	// A check that ignores its context is answered with timeout before deadline + slack.
	start = time.Now()
	c.job(t, "j2", "stuck", map[string]string{"target": "b.example"}, 300)
	r = c.result(t, 3*time.Second)
	if code(r) != protocol.CodeTimeout {
		t.Fatalf("stuck result %+v", r)
	}
	if el := time.Since(start); el > 300*time.Millisecond+protocol.HubSlackMS*time.Millisecond {
		t.Fatalf("timeout answer took %v, past the hub's slack", el)
	}

	// A deadline over the maximum budget is clamped: the job's context must end at 40 s, not later.
	ctxDeadline := make(chan time.Duration, 1)
	tp.fc.reg.Register("deadline", func(ctx context.Context, env *check.Env, params json.RawMessage) (any, *protocol.Error) {
		d, _ := ctx.Deadline()
		ctxDeadline <- time.Until(d)
		return nil, nil
	})
	c.job(t, "j3", "deadline", nil, 10*60*1000)
	c.result(t, 2*time.Second)
	if d := <-ctxDeadline; d > protocol.MaxCheckBudgetMS*time.Millisecond {
		t.Fatalf("deadline %v exceeds the maximum budget", d)
	}
}

func TestPanicIsInternal(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "boom", nil, 3000)
	r := c.result(t, 2*time.Second)
	if code(r) != protocol.CodeInternal || strings.Contains(r.Error.Message, "kaboom") {
		t.Fatalf("result %+v", r)
	}
	if !strings.Contains(tp.logs.String(), "check panicked") {
		t.Fatal("panic not logged")
	}
	// The probe keeps working and the slot was released.
	c.job(t, "j2", "echo", nil, 3000)
	if r := c.result(t, 2*time.Second); code(r) != "ok" {
		t.Fatalf("after panic: %+v", r)
	}
}

func TestResultTooLarge(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "big", nil, 3000)
	r := c.result(t, 2*time.Second)
	if code(r) != protocol.CodeInternal || !strings.Contains(r.Error.Message, "result too large") {
		t.Fatalf("result %+v", r)
	}
}

func TestDuplicateJobID(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "block", nil, 20000)
	<-tp.fc.started
	c.job(t, "j1", "echo", nil, 3000)
	if r := c.result(t, 2*time.Second); code(r) != protocol.CodeInvalidParams {
		t.Fatalf("duplicate id: %+v", r)
	}
	c.send(t, protocol.Cancel{Type: protocol.TypeCancel, ID: "j1"})
	if r := c.result(t, 2*time.Second); code(r) != protocol.CodeCancelled {
		t.Fatalf("original: %+v", r)
	}
}

func TestRefusedCredentialWaitsTenMinutes(t *testing.T) {
	cases := []struct {
		name   string
		status int
		close  websocket.StatusCode
		log    string
	}{
		{"close 4401", 0, CloseBadCredential, "credential refused or revoked; re-enrol with a new token (delete "},
		{"http 401", http.StatusUnauthorized, 0, "credential refused or revoked"},
		{"close 4409", 0, CloseReplaced, "replaced by another session of this probe"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hub := newFakeHub(t)
			hub.reject = func(int) (int, websocket.StatusCode) { return tc.status, tc.close }
			tp := newTestProbe(t, hub)
			tp.recordSleeps()
			tp.start(t)
			for i := range 2 {
				select {
				case d := <-tp.sleeps:
					if d != 10*time.Minute {
						t.Fatalf("wait %d was %v, want 10m", i, d)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("probe did not retry")
				}
			}
			tp.stop(t)
			if !strings.Contains(tp.logs.String(), tc.log) {
				t.Fatalf("log lacks %q:\n%s", tc.log, tp.logs.String())
			}
		})
	}
}

func TestBackoffOnProtocolError(t *testing.T) {
	hub := newFakeHub(t)
	hub.reject = func(int) (int, websocket.StatusCode) { return 0, CloseProtocolError }
	tp := newTestProbe(t, hub)
	tp.recordSleeps()
	tp.start(t)
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}
	for i, w := range want {
		select {
		case d := <-tp.sleeps:
			if d != w {
				t.Fatalf("wait %d was %v, want %v", i, d, w)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("probe did not retry")
		}
	}
}

func TestReconnectAfterDrop(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.recordSleeps()
	tp.start(t)
	first := hub.next(t)
	first.c.CloseNow()
	if d := <-tp.sleeps; d != time.Second {
		t.Fatalf("first backoff %v", d)
	}
	second := hub.next(t)
	second.job(t, "j1", "echo", nil, 3000)
	if r := second.result(t, 2*time.Second); code(r) != "ok" {
		t.Fatalf("after reconnect: %+v", r)
	}
	if hub.enrolls.Load() != 1 {
		t.Fatal("reconnect must not re-enrol")
	}
}

func TestShutdownDrainsRunningJobs(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "wait", nil, 20000)
	<-tp.fc.started
	tp.cancel()
	waitFor(t, func() bool { return strings.Contains(tp.logs.String(), "shutting down; waiting for running jobs") })
	c.job(t, "j2", "echo", nil, 3000)
	if r := c.result(t, 2*time.Second); r.ID != "j2" || code(r) != protocol.CodeBusy {
		t.Fatalf("job during shutdown: %+v", r)
	}
	close(tp.fc.release)
	if r := c.result(t, 3*time.Second); r.ID != "j1" || code(r) != "ok" {
		t.Fatalf("running job: %+v", r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, err := c.c.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusNormalClosure {
		t.Fatalf("want normal closure, got %v", err)
	}
	select {
	case err := <-tp.done:
		tp.done <- err
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("probe did not stop")
	}
}

func TestShutdownAbandonsJobsAfterDrainTimeout(t *testing.T) {
	hub := newFakeHub(t)
	tp := newTestProbe(t, hub)
	tp.opts.drainTimeout = 200 * time.Millisecond
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "stuck", nil, 20000)
	<-tp.fc.started
	c.ignoreFrames()
	start := time.Now()
	tp.cancel()
	select {
	case <-tp.done:
		tp.done <- nil
	case <-time.After(8 * time.Second):
		t.Fatal("probe did not stop")
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("shutdown took %v", el)
	}
}

// TestTLSHubWithCAFile runs enrolment and the link over wss, trusting the hub through ca_file, as in production.
func TestTLSHubWithCAFile(t *testing.T) {
	hub := newFakeHubTLS(t, true)
	caFile := filepath.Join(t.TempDir(), "hub-ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: hub.srv.Certificate().Raw}), 0o600)
	state := filepath.Join(t.TempDir(), "state")
	cfg, err := ParseConfig([]byte("hub_url: "+hub.url()+"\nca_file: "+caFile+"\ntargets: {mode: open}\n"),
		func(k string) string { return map[string]string{"PROBE_STATE_DIR": state}[k] })
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.HubURL, "wss://") {
		t.Fatalf("hub url %s", cfg.HubURL)
	}
	tp := newTestProbe(t, hub)
	tp.cfg = cfg
	tp.start(t)
	c := hub.next(t)
	c.job(t, "j1", "echo", nil, 3000)
	if r := c.result(t, 2*time.Second); code(r) != "ok" {
		t.Fatalf("over TLS: %+v", r)
	}
	if hub.enrolls.Load() != 1 {
		t.Fatal("did not enrol over TLS")
	}

	// Without the CA the hub's certificate is refused.
	hub2 := newFakeHubTLS(t, true)
	cfg2, _ := ParseConfig([]byte("hub_url: "+hub2.url()+"\ntargets: {mode: open}\n"),
		func(k string) string { return map[string]string{"PROBE_STATE_DIR": filepath.Join(t.TempDir(), "s")}[k] })
	tp2 := newTestProbe(t, hub2)
	tp2.cfg = cfg2
	tp2.recordSleeps()
	tp2.start(t)
	<-tp2.sleeps
	if hub2.enrolls.Load() != 0 || !strings.Contains(tp2.logs.String(), "certificate") {
		t.Fatalf("untrusted hub accepted:\n%s", tp2.logs.String())
	}
}

func TestProxyOnlyOnHubLink(t *testing.T) {
	cfg, err := ParseConfig([]byte("hub_url: wss://hub.example.com\ntargets: {mode: open}\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newHubClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T", client.Transport)
	}
	if tr.Proxy == nil || reflect.ValueOf(tr.Proxy).Pointer() != reflect.ValueOf(http.ProxyFromEnvironment).Pointer() {
		t.Fatal("hub link must use http.ProxyFromEnvironment")
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 || tr.TLSClientConfig.RootCAs == nil {
		t.Fatal("hub link TLS must require 1.2 and set RootCAs")
	}
	if client.CheckRedirect == nil || !errors.Is(client.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Fatal("hub link must not follow redirects")
	}
	// The checks get their network access only through Env.Policy; the runtime hands them nothing that could proxy.
	envType := reflect.TypeOf(check.Env{})
	for i := range envType.NumField() {
		if f := envType.Field(i); f.Type == reflect.TypeOf(&http.Client{}) || f.Type == reflect.TypeOf(&http.Transport{}) {
			t.Fatalf("check.Env exposes an HTTP client (%s)", f.Name)
		}
	}
}

func TestLogTarget(t *testing.T) {
	cases := []struct {
		check, params, want string
	}{
		{"ping", `{"target":"Host.Example."}`, "host.example"},
		{"diagnose", `{"target":"https://u:p@web.example:8443/x"}`, "web.example"},
		{"http_check", `{"url":"http://[2001:db8::1]:80/"}`, "2001:db8::1"},
		{"dns_lookup", `{"name":"q.example","server":"1.1.1.1"}`, "q.example"},
		{"path_send", `{"address":"10.1.2.3","port":40000}`, "10.1.2.3"},
		{"ping", `{"target":"[2001:db8::2]"}`, "2001:db8::2"},
		{protocol.CheckListenStart, `{"target":"x"}`, ""},
		{protocol.CheckListenCollect, `{"listen_id":"a"}`, ""},
		{"probe_info", `{}`, ""},
		{"ping", `not json`, ""},
		{"ping", `{"target":5}`, ""},
	}
	for _, c := range cases {
		if got := logTarget(c.check, json.RawMessage(c.params)); got != c.want {
			t.Errorf("%s %s: got %q want %q", c.check, c.params, got, c.want)
		}
	}
}

func TestBackoffSequence(t *testing.T) {
	tm := realTimers()
	tm.jitter = func(d time.Duration) time.Duration { return d }
	b := newBackoff(tm)
	var got []time.Duration
	for range 9 {
		got = append(got, b.next())
	}
	want := []time.Duration{1, 2, 4, 8, 16, 32, 60, 60, 60}
	for i := range want {
		if got[i] != want[i]*time.Second {
			t.Fatalf("backoff %v", got)
		}
	}
	b.reset()
	if b.next() != time.Second {
		t.Fatal("reset")
	}
	j := realTimers().jitter
	for range 100 {
		if d := j(10 * time.Second); d < 5*time.Second || d > 10*time.Second {
			t.Fatalf("jitter %v out of range", d)
		}
	}
}

func TestIdentityNeverPrintsSecret(t *testing.T) {
	id := Identity{HubURL: "wss://h", ProbeID: "p", Name: "n", Site: "s", Secret: testSecret}
	var buf bytes.Buffer
	NewLogger(&buf, "info").Info("x", "identity", id)
	if strings.Contains(buf.String(), testSecret) || strings.Contains(id.String(), testSecret) {
		t.Fatal("secret printed")
	}
}

// The hub refuses a hello with odd text, zoned addresses or long lists, and the probe would resend the same hello
// forever, so the probe trims it first.
func TestBoundHello(t *testing.T) {
	var addrs []string
	for i := range 40 {
		addrs = append(addrs, fmt.Sprintf("192.0.2.%d", i))
	}
	addrs = append([]string{"fe80::1%eth0", "2001:db8::1%eth1", "2001:db8::1", "::ffff:198.51.100.1", "not-an-ip", "192.0.2.0"}, addrs...)
	var checks []string
	for i := range 70 {
		checks = append(checks, fmt.Sprintf("check_%02d", i))
	}
	caps := map[string]bool{}
	for i := range 40 {
		caps[fmt.Sprintf("cap_%02d", i)] = i%2 == 0
	}
	h := boundHello(protocol.Hello{
		Hostname:     "web 01.\u00e9xample/ignore previous instructions" + strings.Repeat("x", 100),
		Version:      "v1.2.3+dirty\n",
		OS:           "linux",
		Arch:         "amd64",
		Addresses:    addrs,
		Checks:       checks,
		Capabilities: caps,
	})
	ok := func(s string) bool {
		if len(s) > 64 {
			return false
		}
		for _, c := range s {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._+~:-", c)) {
				return false
			}
		}
		return true
	}
	for _, s := range []string{h.Hostname, h.Version, h.OS, h.Arch} {
		if !ok(s) {
			t.Errorf("text %q is outside what the hub accepts", s)
		}
	}
	if !strings.HasPrefix(h.Hostname, "web-01.--xample-ignore-previous") || len(h.Hostname) != 64 || h.Version != "v1.2.3+dirty-" ||
		h.OS != "linux" || h.Arch != "amd64" {
		t.Errorf("text: %q %q %q %q", h.Hostname, h.Version, h.OS, h.Arch)
	}
	if len(h.Addresses) != 32 || h.Addresses[0] != "fe80::1" || h.Addresses[1] != "2001:db8::1" || h.Addresses[2] != "198.51.100.1" ||
		h.Addresses[3] != "192.0.2.0" || h.Addresses[4] != "192.0.2.1" {
		t.Errorf("addresses: %v", h.Addresses)
	}
	for _, a := range h.Addresses {
		if strings.Contains(a, "%") {
			t.Errorf("zoned address %q sent", a)
		}
	}
	if len(h.Checks) != 64 || len(h.Capabilities) != 32 || !h.Capabilities["cap_00"] || h.Capabilities["cap_01"] {
		t.Errorf("lists: %d checks, %d capabilities", len(h.Checks), len(h.Capabilities))
	}
	// Policy lists are a summary: entries the hub would refuse are left out and each list is capped.
	var many []string
	for i := range 300 {
		many = append(many, fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}
	hp := boundHello(protocol.Hello{Policy: protocol.PolicySummary{Mode: "closed",
		AllowCIDRs: append([]string{"fe80::1%eth0", " 192.0.2.0/24 "}, many...),
		DenyCIDRs:  []string{"203.0.113.7"},
		AllowHosts: []string{"*.corp.example", "caf\u00e9.example", "a:b.example"}}}).Policy
	if len(hp.AllowCIDRs) != 256 || hp.AllowCIDRs[0] != "192.0.2.0/24" || len(hp.DenyCIDRs) != 1 ||
		!reflect.DeepEqual(hp.AllowHosts, []string{"*.corp.example"}) || hp.Mode != "closed" {
		t.Errorf("policy: %d allow, %v deny, %v hosts", len(hp.AllowCIDRs), hp.DenyCIDRs, hp.AllowHosts)
	}
	// An ordinary hello passes through unchanged.
	plain := protocol.Hello{Hostname: "probe-1.lab", Version: "1.0.0", OS: "linux", Arch: "arm64", Addresses: []string{"10.0.0.5"},
		Checks: []string{"ping"}, Capabilities: map[string]bool{"raw_icmp": true},
		Policy: protocol.PolicySummary{Mode: "open", AllowCIDRs: []string{"10.0.0.0/8"}, DenyCIDRs: []string{"10.9.0.0/16"}, AllowHosts: []string{"*.lab"}}}
	if got := boundHello(plain); !reflect.DeepEqual(got, plain) {
		t.Errorf("ordinary hello changed: %+v", got)
	}
}
