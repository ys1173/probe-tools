package hub

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/time/rate"

	"probetools/internal/protocol"
)

func TestClientKey(t *testing.T) {
	cases := map[string]string{
		"192.0.2.7:1234":             "192.0.2.7",
		"[::ffff:192.0.2.7]:1234":    "192.0.2.7",
		"[2001:db8:1:2:aaaa::1]:443": "2001:db8:1:2::/64",
		"[2001:db8:1:2:bbbb::9]:443": "2001:db8:1:2::/64",
		"[2001:db8:1:3::1]:443":      "2001:db8:1:3::/64",
		"[fe80::1%eth0]:1":           "fe80::/64",
		"not-an-address":             "not-an-address",
	}
	for in, want := range cases {
		if got := clientKey(in); got != want {
			t.Errorf("clientKey(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIPLimiterBoundedFailsClosed(t *testing.T) {
	const max = 100
	now := time.Unix(1_000_000, 0)
	l := newIPLimiter(rate.Every(time.Hour), 1, max)
	for i := range max {
		if !l.allowAt(fmt.Sprintf("k%d", i), now) {
			t.Fatalf("key %d refused before the table was full", i)
		}
	}
	// Full of limiters that have not refilled: a new key is refused rather than the table being reset.
	if l.allowAt("new", now.Add(2*time.Second)) {
		t.Fatal("new key allowed in a full table")
	}
	if len(l.m) != max {
		t.Fatalf("table has %d entries", len(l.m))
	}
	// Existing keys keep their state: k0 has used its only token.
	if l.allowAt("k0", now.Add(3*time.Second)) {
		t.Fatal("k0 was reset")
	}

	// Once the limiters have refilled they are idle and can be evicted.
	later := now.Add(2 * time.Hour)
	if !l.allowAt("new", later) {
		t.Fatal("new key refused after the others went idle")
	}
	if len(l.m) > max {
		t.Fatalf("table grew to %d", len(l.m))
	}
}

func TestIPLimiterSweepIsThrottled(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newIPLimiter(rate.Every(time.Millisecond), 1, 2)
	l.allowAt("a", now)
	l.allowAt("b", now)
	// A sweep now finds nothing idle and sets the next sweep a second away.
	if l.allowAt("c", now) {
		t.Fatal("c allowed in a full table")
	}
	// a and b have refilled, but no sweep is due yet.
	if l.allowAt("c", now.Add(10*time.Millisecond)) {
		t.Fatal("swept again within sweepInterval")
	}
	if !l.allowAt("c", now.Add(sweepInterval)) {
		t.Fatal("no sweep after sweepInterval")
	}
}

func TestSlots(t *testing.T) {
	s := newSlots(3, 2)
	r1, st := s.acquire("a")
	r2, _ := s.acquire("a")
	if _, st = s.acquire("a"); st != http.StatusTooManyRequests {
		t.Fatalf("third for a: %d, want 429", st)
	}
	r3, _ := s.acquire("b")
	if _, st = s.acquire("c"); st != http.StatusServiceUnavailable {
		t.Fatalf("over total: %d, want 503", st)
	}
	r1()
	r1() // releasing twice must not free two slots
	if s.inUse() != 2 {
		t.Fatalf("in use %d after one release", s.inUse())
	}
	r2()
	r3()
	if s.inUse() != 0 || len(s.perKey) != 0 {
		t.Fatalf("slots not released: %d %v", s.inUse(), s.perKey)
	}
}

func TestLogThrottle(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	lt := newLogThrottle(time.Minute, 2)
	if ok, _ := lt.admit("a", now); !ok {
		t.Fatal("first line suppressed")
	}
	for range 5 {
		if ok, _ := lt.admit("a", now.Add(time.Second)); ok {
			t.Fatal("line within the minute let through")
		}
	}
	if ok, n := lt.admit("a", now.Add(time.Minute)); !ok || n != 5 {
		t.Fatalf("after a minute: %v %d, want true 5", ok, n)
	}
	lt.admit("b", now.Add(time.Minute))
	// The table is full and nothing in it is idle; new keys share the overflow entry.
	if ok, _ := lt.admit("c", now.Add(time.Minute)); !ok {
		t.Fatal("first overflow line suppressed")
	}
	if ok, _ := lt.admit("d", now.Add(time.Minute)); ok {
		t.Fatal("second overflow line let through")
	}
	if len(lt.m) > 3 {
		t.Fatalf("throttle table grew to %d", len(lt.m))
	}
}

func TestIDPrefix(t *testing.T) {
	if got := idPrefix("0123456789abcdef"); got != "01234567" {
		t.Errorf("got %q", got)
	}
	if got := idPrefix("\x1b[31m\n日本"); got != "??31m???" {
		t.Errorf("got %q", got)
	}
}

// slowEnroll starts an enrolment request whose body never finishes, and returns the connection.
func slowEnroll(t *testing.T, base string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	fmt.Fprintf(conn, "POST %s HTTP/1.1\r\nHost: hub\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"tok", protocol.PathEnroll)
	return conn
}

func TestEnrollSlowBodyTimesOut(t *testing.T) {
	e := newEnv(t, Options{EnrollReadTimeout: 300 * time.Millisecond})
	conn := slowEnroll(t, e.srv.URL)
	start := time.Now()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("no response to a stalled body: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v", d)
	}
	e.waitFor(func() bool { return e.hub.enrollSlots.inUse() == 0 }, "slot released")
}

func TestEnrollConcurrencyCaps(t *testing.T) {
	post := func(e *testEnv) int {
		resp := postEnroll(t, e.srv.URL, "guess")
		resp.Body.Close()
		return resp.StatusCode
	}

	// Per client: every request here comes from 127.0.0.1.
	e := newEnv(t, Options{EnrollMaxPerClient: 2, EnrollMaxConcurrent: 10})
	slowEnroll(t, e.srv.URL)
	slowEnroll(t, e.srv.URL)
	e.waitFor(func() bool { return e.hub.enrollSlots.inUse() == 2 }, "two slow enrolments running")
	if got := post(e); got != http.StatusTooManyRequests {
		t.Fatalf("over the per-client cap: %d, want 429", got)
	}

	// In total.
	e = newEnv(t, Options{EnrollMaxPerClient: 10, EnrollMaxConcurrent: 2})
	slowEnroll(t, e.srv.URL)
	slowEnroll(t, e.srv.URL)
	e.waitFor(func() bool { return e.hub.enrollSlots.inUse() == 2 }, "two slow enrolments running")
	if got := post(e); got != http.StatusServiceUnavailable {
		t.Fatalf("over the total cap: %d, want 503", got)
	}
}

func TestConnectFailureLimit(t *testing.T) {
	e := newEnv(t, Options{ConnectFailRate: rate.Every(time.Hour), ConnectFailBurst: 3})
	good := e.enroll("p1", "s1")
	status := func(auth string) int {
		t.Helper()
		conn, resp, err := e.dial(auth, []string{protocol.WireVersion})
		if err == nil {
			conn.CloseNow()
			return http.StatusSwitchingProtocols
		}
		if resp == nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	// A valid credential is never charged.
	for range 5 {
		if got := status("Bearer " + good.ProbeID + "." + good.Secret); got != http.StatusSwitchingProtocols {
			t.Fatalf("valid credential: %d", got)
		}
	}
	bad := "Bearer <script>evil-probe-id-that-is-long." + strings.Repeat("x", 20)
	var codes []int
	for range 5 {
		codes = append(codes, status(bad))
	}
	if want := []int{401, 401, 401, 429, 429}; fmt.Sprint(codes) != fmt.Sprint(want) {
		t.Fatalf("codes %v, want %v", codes, want)
	}
	// Over the limit, a valid credential is still accepted: the key may be a NAT or a proxy shared with real probes.
	if got := status("Bearer " + good.ProbeID + "." + good.Secret); got != http.StatusSwitchingProtocols {
		t.Fatalf("valid credential over the limit: %d, want 101", got)
	}

	logs := e.logs.String()
	if n := strings.Count(logs, `"msg":"connection refused"`); n != 1 {
		t.Errorf("%d refusal lines in a minute, want 1:\n%s", n, logs)
	}
	if strings.Contains(logs, "evil-probe") || strings.Contains(logs, "script>") {
		t.Errorf("attacker-supplied probe id logged:\n%s", logs)
	}
	if !strings.Contains(logs, `"probe_id_prefix":"?script?"`) {
		t.Errorf("no sanitised prefix logged:\n%s", logs)
	}
}

// Junk logins from a key shared with real probes (one NAT address, one TLS-terminating proxy) must not lock them out.
func TestConnectJunkDoesNotLockOutSharedKey(t *testing.T) {
	e := newEnv(t, Options{ConnectFailRate: rate.Every(time.Hour), ConnectFailBurst: 20})
	good := e.enroll("p1", "s1")
	other := e.enroll("p2", "s1")
	revoked := e.enroll("p3", "s1")
	e.store.RevokeProbe(context.Background(), "p3")
	status := func(auth string) int {
		t.Helper()
		conn, resp, err := e.dial(auth, []string{protocol.WireVersion})
		if err == nil {
			conn.CloseNow()
			return http.StatusSwitchingProtocols
		}
		if resp == nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	for i := range 20 {
		if got := status("Bearer junk" + strconv.Itoa(i) + ".nope"); got != http.StatusUnauthorized {
			t.Fatalf("junk attempt %d: %d, want 401", i, got)
		}
	}
	// Over the limit every kind of failure gets the same 429, whether or not the id exists.
	for name, auth := range map[string]string{
		"unknown id":   "Bearer junk.nope",
		"wrong secret": "Bearer " + other.ProbeID + ".wrong",
		"revoked":      "Bearer " + revoked.ProbeID + "." + revoked.Secret,
		"malformed":    "Bearer nodot",
		"none":         "",
	} {
		if got := status(auth); got != http.StatusTooManyRequests {
			t.Fatalf("%s over the limit: %d, want 429", name, got)
		}
	}
	// A valid credential from the same key connects.
	fp := e.connect(good, true)
	fp.conn.Close(websocket.StatusNormalClosure, "")
	if got := status("Bearer " + other.ProbeID + "." + other.Secret); got != http.StatusSwitchingProtocols {
		t.Fatalf("second valid probe over the limit: %d, want 101", got)
	}
	if n := strings.Count(e.logs.String(), `"msg":"connection refused"`); n != 1 {
		t.Errorf("%d refusal lines in a minute, want 1", n)
	}
}

// slowRequest sends a request that declares a small body (well under the 256 KiB net/http would give up on by itself)
// and sends only part of it, then reads until the hub closes the connection. It returns the status line's code and how
// long the close took; it fails the test if the connection is still open after 5 s.
func slowRequest(t *testing.T, base, method, path, auth string) (int, time.Duration) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	start := time.Now()
	hdr := ""
	if auth != "" {
		hdr = "Authorization: " + auth + "\r\n"
	}
	fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: hub\r\n%sContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"tok", method, path, hdr)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	out, err := io.ReadAll(conn)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("%s %s: connection still open after 5 s (read %q)", method, path, out)
	}
	// EOF or a reset both mean the hub closed the connection.
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(out))), nil)
	if err != nil {
		t.Fatalf("%s %s: no response before the close: %v (%q)", method, path, err, out)
	}
	resp.Body.Close()
	return resp.StatusCode, time.Since(start)
}

// Requests refused without reading their body must not leave net/http draining it with no deadline.
func TestSlowBodyRefusalsAreClosed(t *testing.T) {
	const deadline = 300 * time.Millisecond
	e := newEnv(t, Options{RequestReadTimeout: deadline, EnrollRate: rate.Every(time.Hour), EnrollBurst: 1})
	resp := postEnroll(t, e.srv.URL, "guess") // spends the one enrolment attempt
	resp.Body.Close()
	cases := []struct {
		name, method, path, auth string
		want                     int
	}{
		{"rate-limited enrol", "POST", protocol.PathEnroll, "", http.StatusTooManyRequests},
		{"bad credential", "GET", protocol.PathConnect, "Bearer deadbeef.wrong", http.StatusUnauthorized},
		{"no credential", "GET", protocol.PathConnect, "", http.StatusUnauthorized},
		{"healthz with a body", "GET", "/healthz", "", http.StatusOK},
		{"unknown path", "POST", "/nope", "", http.StatusNotFound},
		{"wrong method", "PUT", protocol.PathEnroll, "", http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, took := slowRequest(t, e.srv.URL, c.method, c.path, c.auth)
			if got != c.want {
				t.Fatalf("status %d, want %d", got, c.want)
			}
			if took > deadline+2*time.Second {
				t.Fatalf("closed after %v; the deadline is %v", took, deadline)
			}
		})
	}
}

// Refusals say Connection: close, so net/http answers at once instead of first draining the body the handler never
// read; the long default deadline here would make a drain visible.
func TestSlowBodyRefusalsAnswerAtOnce(t *testing.T) {
	e := newEnv(t, Options{EnrollRate: rate.Every(time.Hour), EnrollBurst: 1})
	resp := postEnroll(t, e.srv.URL, "guess")
	resp.Body.Close()
	cases := []struct{ name, method, path, auth string }{
		{"rate-limited enrol", "POST", protocol.PathEnroll, ""},
		{"bad credential", "GET", protocol.PathConnect, "Bearer deadbeef.wrong"},
		{"healthz with a body", "GET", "/healthz", ""},
		{"unknown path", "POST", "/nope", ""},
		{"wrong method", "PUT", protocol.PathEnroll, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", strings.TrimPrefix(e.srv.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			hdr := ""
			if c.auth != "" {
				hdr = "Authorization: " + c.auth + "\r\n"
			}
			fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: hub\r\n%sContent-Length: 1000\r\n\r\n{\"tok", c.method, c.path, hdr)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
			if err != nil {
				t.Fatalf("no prompt response: %v", err)
			}
			resp.Body.Close()
			if !resp.Close {
				t.Fatalf("status %d without Connection: close", resp.StatusCode)
			}
		})
	}
}

// The request read deadline is lifted before the upgrade, so a live session outlasts it.
func TestSessionOutlivesRequestDeadline(t *testing.T) {
	const deadline = 200 * time.Millisecond
	e := newEnv(t, Options{RequestReadTimeout: deadline})
	enr := e.enroll("p", "s")
	fp := e.connect(enr, true)
	time.Sleep(3 * deadline)
	ch := e.runAsync(context.Background(), "p", 3*time.Second)
	j := fp.job()
	// The hub must still read what the probe sends.
	fp.send(protocol.Result{Type: protocol.TypeResult, ID: j.ID, Data: json.RawMessage(`{}`)})
	if r := waitResult(t, ch); !r.OK {
		t.Fatalf("result after the deadline: %+v", r)
	}
	if st, _ := e.hub.Probe("p"); !st.Online {
		t.Fatal("probe dropped")
	}
}
