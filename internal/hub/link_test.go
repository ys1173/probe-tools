package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"probetools/internal/protocol"
)

type testEnv struct {
	t     *testing.T
	store *Store
	hub   *Hub
	srv   *httptest.Server
	logs  *syncBuffer
}

// syncBuffer collects log output from several goroutines.
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

func newEnv(t *testing.T, opts Options) *testEnv {
	t.Helper()
	st := newTestStore(t)
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := New(st, logger, opts)
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(func() {
		srv.CloseClientConnections()
		h.Close()
		srv.Close()
	})
	return &testEnv{t: t, store: st, hub: h, srv: srv, logs: logs}
}

func (e *testEnv) enroll(name, site string) protocol.EnrollResponse {
	e.t.Helper()
	tok, err := e.store.CreateToken(context.Background(), name, site, time.Hour, false)
	if err != nil {
		e.t.Fatal(err)
	}
	enr, err := e.store.Enroll(context.Background(), tok.Value)
	if err != nil {
		e.t.Fatal(err)
	}
	return enr.EnrollResponse
}

func (e *testEnv) wsURL() string {
	return "ws" + strings.TrimPrefix(e.srv.URL, "http") + protocol.PathConnect
}

func (e *testEnv) dial(auth string, subprotocols []string) (*websocket.Conn, *http.Response, error) {
	hdr := http.Header{}
	if auth != "" {
		hdr.Set("Authorization", auth)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return websocket.Dial(ctx, e.wsURL(), &websocket.DialOptions{HTTPHeader: hdr, Subprotocols: subprotocols})
}

// fakeProbe is the probe end of a link, driven by the test.
type fakeProbe struct {
	t      *testing.T
	conn   *websocket.Conn
	frames chan []byte
	closed chan error // receives the read error when the link ends
}

func testHello() protocol.Hello {
	return protocol.Hello{Type: protocol.TypeHello, Version: "test", OS: "linux", Arch: "amd64", Hostname: "box",
		Addresses: []string{"192.0.2.1"}, Checks: []string{"ping"}, Capabilities: map[string]bool{"raw_icmp": true},
		Policy: protocol.PolicySummary{Mode: "open"}, ListenPorts: "40000-40010"}
}

// connect opens a session and completes hello/welcome. With read false the probe never reads after welcome, so it
// answers no pings.
func (e *testEnv) connect(enr protocol.EnrollResponse, read bool) *fakeProbe {
	e.t.Helper()
	conn, _, err := e.dial("Bearer "+enr.ProbeID+"."+enr.Secret, []string{protocol.WireVersion})
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { conn.CloseNow() })
	if conn.Subprotocol() != protocol.WireVersion {
		e.t.Fatalf("subprotocol %q", conn.Subprotocol())
	}
	fp := &fakeProbe{t: e.t, conn: conn, frames: make(chan []byte, 16), closed: make(chan error, 1)}
	fp.send(testHello())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := conn.Read(ctx)
	if err != nil {
		e.t.Fatal(err)
	}
	var w protocol.Welcome
	json.Unmarshal(b, &w)
	if w.Type != protocol.TypeWelcome || w.Name != enr.Name || w.Site != enr.Site {
		e.t.Fatalf("welcome %s", b)
	}
	if read {
		go fp.readLoop()
	}
	// The session is registered just after welcome is written; wait for it.
	e.waitFor(func() bool { st, _ := e.hub.Probe(enr.Name); return st.Online }, "probe online")
	return fp
}

func (fp *fakeProbe) readLoop() {
	for {
		_, b, err := fp.conn.Read(context.Background())
		if err != nil {
			fp.closed <- err
			return
		}
		fp.frames <- b
	}
}

func (fp *fakeProbe) send(v any) {
	fp.t.Helper()
	b, _ := json.Marshal(v)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := fp.conn.Write(ctx, websocket.MessageText, b); err != nil {
		fp.t.Fatal(err)
	}
}

// next returns the next frame from the hub, decoded into a map and the raw bytes.
func (fp *fakeProbe) next() (string, []byte) {
	fp.t.Helper()
	select {
	case b := <-fp.frames:
		var env protocol.Envelope
		json.Unmarshal(b, &env)
		return env.Type, b
	case err := <-fp.closed:
		fp.t.Fatalf("link closed: %v", err)
	case <-time.After(5 * time.Second):
		fp.t.Fatal("no frame from hub")
	}
	return "", nil
}

func (fp *fakeProbe) job() protocol.Job {
	fp.t.Helper()
	typ, b := fp.next()
	if typ != protocol.TypeJob {
		fp.t.Fatalf("expected job, got %s", b)
	}
	var j protocol.Job
	json.Unmarshal(b, &j)
	return j
}

func (fp *fakeProbe) expectClose(code websocket.StatusCode) {
	fp.t.Helper()
	select {
	case err := <-fp.closed:
		if got := websocket.CloseStatus(err); got != code {
			fp.t.Fatalf("close status %d (%v), want %d", got, err, code)
		}
	case <-time.After(10 * time.Second):
		fp.t.Fatalf("link not closed; want %d", code)
	}
}

func (e *testEnv) waitFor(cond func() bool, what string) {
	e.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			e.t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (e *testEnv) runAsync(ctx context.Context, probe string, deadline time.Duration) chan protocol.ProbeResult {
	ch := make(chan protocol.ProbeResult, 1)
	go func() { ch <- e.hub.Run(ctx, probe, "ping", json.RawMessage(`{"target":"192.0.2.9"}`), deadline) }()
	return ch
}

func waitResult(t *testing.T, ch chan protocol.ProbeResult) protocol.ProbeResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return")
	}
	return protocol.ProbeResult{}
}

func TestHealthz(t *testing.T) {
	e := newEnv(t, Options{})
	resp, err := http.Get(e.srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(b) != "ok" {
		t.Fatalf("%d %q", resp.StatusCode, b)
	}
}

func TestConnectAuth(t *testing.T) {
	e := newEnv(t, Options{})
	enr := e.enroll("p1", "s1")
	revoked := e.enroll("p2", "s1")
	e.store.RevokeProbe(context.Background(), "p2")

	cases := []struct {
		name   string
		auth   string
		protos []string
		want   int
	}{
		{"no auth", "", []string{protocol.WireVersion}, 401},
		{"malformed", "Bearer nodot", []string{protocol.WireVersion}, 401},
		{"bad secret", "Bearer " + enr.ProbeID + ".wrong", []string{protocol.WireVersion}, 401},
		{"unknown id", "Bearer deadbeef." + enr.Secret, []string{protocol.WireVersion}, 401},
		{"revoked", "Bearer " + revoked.ProbeID + "." + revoked.Secret, []string{protocol.WireVersion}, 401},
		{"no subprotocol", "Bearer " + enr.ProbeID + "." + enr.Secret, nil, 400},
		{"wrong subprotocol", "Bearer " + enr.ProbeID + "." + enr.Secret, []string{"probe.v0"}, 400},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn, resp, err := e.dial(c.auth, c.protos)
			if err == nil {
				conn.CloseNow()
				t.Fatal("connected")
			}
			if resp == nil || resp.StatusCode != c.want {
				t.Fatalf("resp %v, want %d", resp, c.want)
			}
		})
	}
	if strings.Contains(e.logs.String(), enr.Secret) {
		t.Fatal("secret logged")
	}
}

func TestHelloWelcomeAndStatus(t *testing.T) {
	e := newEnv(t, Options{})
	b := e.enroll("b-probe", "site-b")
	e.enroll("a-probe", "site-a")
	e.connect(b, true)

	ps := e.hub.Probes()
	if len(ps) != 2 || ps[0].Name != "a-probe" || ps[1].Name != "b-probe" {
		t.Fatalf("probes %+v", ps)
	}
	if ps[0].Online {
		t.Fatal("a-probe online")
	}
	st := ps[1]
	if !st.Online || st.ConnectedAt.IsZero() || st.LastSeen.IsZero() || st.Hostname != "box" || st.ListenPorts != "40000-40010" ||
		st.Policy.Mode != "open" || !st.Capabilities["raw_icmp"] || st.Site != "site-b" {
		t.Fatalf("status %+v", st)
	}
	rec, _ := e.store.ActiveProbe(context.Background(), "b-probe")
	if rec.LastHello == nil || rec.LastHello.Hostname != "box" {
		t.Fatalf("last_hello not stored: %+v", rec)
	}
	if _, ok := e.hub.Probe("nope"); ok {
		t.Fatal("unknown probe found")
	}
}

func TestHelloTimeout(t *testing.T) {
	e := newEnv(t, Options{HelloTimeout: 200 * time.Millisecond})
	enr := e.enroll("p", "s")
	conn, _, err := e.dial("Bearer "+enr.ProbeID+"."+enr.Secret, []string{protocol.WireVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	_, _, err = conn.Read(context.Background())
	if websocket.CloseStatus(err) != statusProtocol {
		t.Fatalf("read err %v, want 4400", err)
	}
}

func TestFirstFrameNotHello(t *testing.T) {
	e := newEnv(t, Options{})
	enr := e.enroll("p", "s")
	conn, _, err := e.dial("Bearer "+enr.ProbeID+"."+enr.Secret, []string{protocol.WireVersion})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()
	conn.Write(context.Background(), websocket.MessageText, []byte(`{"type":"result","id":"x"}`))
	_, _, err = conn.Read(context.Background())
	if websocket.CloseStatus(err) != statusProtocol {
		t.Fatalf("read err %v, want 4400", err)
	}
}

func TestRunResult(t *testing.T) {
	e := newEnv(t, Options{})
	enr := e.enroll("p", "s")
	fp := e.connect(enr, true)

	ch := e.runAsync(context.Background(), "p", 3*time.Second)
	j := fp.job()
	if j.Check != "ping" || j.DeadlineMS != 3000 || string(j.Params) != `{"target":"192.0.2.9"}` || j.ID == "" {
		t.Fatalf("job %+v", j)
	}
	started := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	fp.send(protocol.Result{Type: protocol.TypeResult, ID: j.ID, Data: json.RawMessage(`{"rtt_ms":[1,2]}`), StartedAt: started, DurationMS: 42})
	r := waitResult(t, ch)
	if !r.OK || r.Probe != "p" || r.Site != "s" || r.DurationMS != 42 || !r.StartedAt.Equal(started) || r.Error != nil {
		t.Fatalf("result %+v", r)
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"result":{"rtt_ms":[1,2]}`) {
		t.Fatalf("result json %s", b)
	}

	// An error result is passed through.
	ch = e.runAsync(context.Background(), "p", time.Second)
	j = fp.job()
	fp.send(protocol.Result{Type: protocol.TypeResult, ID: j.ID, Error: protocol.Errorf(protocol.CodeDenied, "nope"), StartedAt: started})
	r = waitResult(t, ch)
	if r.OK || r.Error == nil || r.Error.Code != protocol.CodeDenied {
		t.Fatalf("error result %+v", r)
	}

	// A result nobody waits for is logged and ignored; the session carries on.
	fp.send(protocol.Result{Type: protocol.TypeResult, ID: "stale", Data: json.RawMessage(`{}`)})
	ch = e.runAsync(context.Background(), "p", time.Second)
	j = fp.job()
	fp.send(protocol.Result{Type: protocol.TypeResult, ID: j.ID, Data: json.RawMessage(`{}`)})
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("after stale: %+v", r)
	}
	if !strings.Contains(e.logs.String(), "result for unknown job ignored") {
		t.Fatal("stale result not logged")
	}
}

func TestRunUnknownAndOffline(t *testing.T) {
	e := newEnv(t, Options{})
	e.enroll("off", "s-off")
	start := time.Now()
	r := e.hub.Run(context.Background(), "ghost", "ping", nil, time.Second)
	if r.Error == nil || r.Error.Code != protocol.CodeProbeUnknown || r.Probe != "ghost" || r.Site != "" {
		t.Fatalf("unknown: %+v", r)
	}
	r = e.hub.Run(context.Background(), "off", "ping", nil, 30*time.Second)
	if r.Error == nil || r.Error.Code != protocol.CodeProbeOffline || r.Site != "s-off" {
		t.Fatalf("offline: %+v", r)
	}
	if time.Since(start) > time.Second {
		t.Fatal("offline did not fail fast")
	}
}

func TestRunDeadlineSendsCancel(t *testing.T) {
	e := newEnv(t, Options{Slack: 50 * time.Millisecond})
	enr := e.enroll("p", "s")
	fp := e.connect(enr, true)

	ch := e.runAsync(context.Background(), "p", 200*time.Millisecond)
	j := fp.job()
	typ, b := fp.next()
	var c protocol.Cancel
	json.Unmarshal(b, &c)
	if typ != protocol.TypeCancel || c.ID != j.ID {
		t.Fatalf("expected cancel for %s, got %s", j.ID, b)
	}
	r := waitResult(t, ch)
	if r.Error == nil || r.Error.Code != protocol.CodeTimeout {
		t.Fatalf("result %+v", r)
	}
	// The late result is ignored and the link still works.
	fp.send(protocol.Result{Type: protocol.TypeResult, ID: j.ID, Error: protocol.Errorf(protocol.CodeCancelled, "cancelled")})
	ch = e.runAsync(context.Background(), "p", time.Second)
	j = fp.job()
	fp.send(protocol.Result{Type: protocol.TypeResult, ID: j.ID, Data: json.RawMessage(`{}`)})
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("second run: %+v", r)
	}
}

func TestRunContextCancel(t *testing.T) {
	e := newEnv(t, Options{})
	enr := e.enroll("p", "s")
	fp := e.connect(enr, true)

	ctx, cancel := context.WithCancel(context.Background())
	ch := e.runAsync(ctx, "p", 10*time.Second)
	j := fp.job()
	cancel()
	typ, b := fp.next()
	if typ != protocol.TypeCancel || !strings.Contains(string(b), j.ID) {
		t.Fatalf("expected cancel, got %s", b)
	}
	r := waitResult(t, ch)
	if r.Error == nil || r.Error.Code != protocol.CodeCancelled {
		t.Fatalf("result %+v", r)
	}
	ch = e.runAsync(context.Background(), "p", time.Second)
	j = fp.job()
	fp.send(protocol.Result{Type: protocol.TypeResult, ID: j.ID, Data: json.RawMessage(`{}`)})
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("second run: %+v", r)
	}
}

func TestRunDisconnectMidJob(t *testing.T) {
	e := newEnv(t, Options{})
	enr := e.enroll("p", "s")
	fp := e.connect(enr, true)

	ch := e.runAsync(context.Background(), "p", 10*time.Second)
	fp.job()
	fp.conn.CloseNow()
	r := waitResult(t, ch)
	if r.Error == nil || r.Error.Code != protocol.CodeProbeOffline || r.Error.Message != "probe disconnected during the check" {
		t.Fatalf("result %+v", r)
	}
	e.waitFor(func() bool { st, _ := e.hub.Probe("p"); return !st.Online }, "probe offline")
	rec, _ := e.store.ActiveProbe(context.Background(), "p")
	if rec.LastSeen.IsZero() {
		t.Fatal("last_seen not saved")
	}
}

func TestSecondSessionReplacesFirst(t *testing.T) {
	e := newEnv(t, Options{})
	enr := e.enroll("p", "s")
	first := e.connect(enr, true)
	second := e.connect(enr, true)
	first.expectClose(statusReplaced)

	ch := e.runAsync(context.Background(), "p", time.Second)
	j := second.job()
	second.send(protocol.Result{Type: protocol.TypeResult, ID: j.ID, Data: json.RawMessage(`{}`)})
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("run on new session: %+v", r)
	}
	// The old session's cleanup must not have removed the new one.
	if st, _ := e.hub.Probe("p"); !st.Online {
		t.Fatal("probe offline after replacement")
	}
}

func TestRevocationClosesSession(t *testing.T) {
	e := newEnv(t, Options{RevocationInterval: 50 * time.Millisecond})
	enr := e.enroll("p", "s")
	fp := e.connect(enr, true)
	// Revoke from a second store on the same file, as the admin command does from another process.
	other, err := OpenStorePath(e.store.path())
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.RevokeProbe(context.Background(), "p"); err != nil {
		t.Fatal(err)
	}
	fp.expectClose(statusRevoked)
	if _, _, err := e.dial("Bearer "+enr.ProbeID+"."+enr.Secret, []string{protocol.WireVersion}); err == nil {
		t.Fatal("revoked probe reconnected")
	}
}

func TestReplaceEnrolmentClosesOldSession(t *testing.T) {
	e := newEnv(t, Options{RevocationInterval: time.Hour})
	enr := e.enroll("p", "s")
	fp := e.connect(enr, true)
	tok, _ := e.store.CreateToken(context.Background(), "p", "s", time.Hour, true)
	resp := postEnroll(t, e.srv.URL, tok.Value)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("enrol %d", resp.StatusCode)
	}
	fp.expectClose(statusRevoked)
}

func TestPingTimeoutDrops(t *testing.T) {
	e := newEnv(t, Options{PingInterval: 50 * time.Millisecond})
	enr := e.enroll("p", "s")
	e.connect(enr, false) // never reads, so never answers a ping
	e.waitFor(func() bool { st, _ := e.hub.Probe("p"); return !st.Online }, "silent probe dropped")
	if r := e.hub.Run(context.Background(), "p", "ping", nil, time.Second); r.Error == nil || r.Error.Code != protocol.CodeProbeOffline {
		t.Fatalf("run after drop: %+v", r)
	}
}

func TestPingKeepsLiveProbe(t *testing.T) {
	e := newEnv(t, Options{PingInterval: 30 * time.Millisecond})
	enr := e.enroll("p", "s")
	e.connect(enr, true)
	before, _ := e.hub.Probe("p")
	time.Sleep(300 * time.Millisecond)
	st, _ := e.hub.Probe("p")
	if !st.Online || !st.LastSeen.After(before.LastSeen) {
		t.Fatalf("status %+v (before %v)", st, before.LastSeen)
	}
}

func TestCloseClosesSessions(t *testing.T) {
	e := newEnv(t, Options{})
	enr := e.enroll("p", "s")
	fp := e.connect(enr, true)
	e.hub.Close()
	fp.expectClose(statusGoingAway)
	if _, ok := e.hub.Probe("p"); !ok {
		t.Fatal("probe gone from list")
	}
}
