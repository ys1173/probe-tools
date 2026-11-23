package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
)

// Close codes on the probe link, from DESIGN.md.
const (
	CloseBadCredential = websocket.StatusCode(4401) // unknown, wrong or revoked credential
	CloseReplaced      = websocket.StatusCode(4409) // a newer session of the same probe took over
	CloseProtocolError = websocket.StatusCode(4400) // the other side broke the protocol
)

const (
	maxFrameBytes    = 1 << 20
	backoffMin       = time.Second
	backoffMax       = 60 * time.Second
	stableSession    = time.Minute      // a session that lasted this long resets the backoff
	refusedRetry     = 10 * time.Minute // wait after 4401 or 4409; retrying sooner cannot help
	welcomeTimeout   = 10 * time.Second
	dialTimeout      = 30 * time.Second
	writeTimeout     = 10 * time.Second
	drainTimeout     = 5 * time.Second
	idleTimeout      = 70 * time.Second // the hub pings every 20 s; three missed pings means the link is dead
	enrollAndDialTLS = tls.VersionTLS12
)

// timers lets tests replace waiting and randomness.
type timers struct {
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
	now    func() time.Time
}

func realTimers() timers {
	return timers{
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		// Equal jitter: somewhere in [d/2, d], so probes that lost the hub together do not return together.
		jitter: func(d time.Duration) time.Duration {
			half := d / 2
			if half <= 0 {
				return d
			}
			return half + rand.N(half+1)
		},
		now: time.Now,
	}
}

// backoff doubles from backoffMin to backoffMax.
type backoff struct {
	t timers
	n int
}

func newBackoff(t timers) *backoff { return &backoff{t: t} }

func (b *backoff) next() time.Duration {
	d := backoffMin << b.n
	if d > backoffMax || d <= 0 {
		d = backoffMax
	} else {
		b.n++
	}
	return b.t.jitter(d)
}

func (b *backoff) reset() { b.n = 0 }

// newHubClient builds the HTTP client for enrolment and the WebSocket link. It is the only client in the probe that
// honours HTTPS_PROXY and friends: checks reach their targets directly, through the policy.
func newHubClient(cfg Config) (*http.Client, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.CAFile != "" {
		certs, err := loadCAFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		for _, c := range certs {
			pool.AddCert(c)
		}
	}
	// A fresh Transport rather than a clone of the default: the WebSocket upgrade needs HTTP/1.1, and leaving
	// ForceAttemptHTTP2 off with a custom TLS config keeps it there.
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: enrollAndDialTLS, RootCAs: pool},
		TLSHandshakeTimeout: 15 * time.Second,
		MaxIdleConns:        2,
		IdleConnTimeout:     90 * time.Second,
	}
	return &http.Client{
		Transport: tr,
		// The hub never redirects; following one could send the credential somewhere else.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}

// buildHello describes this probe to the hub. Addresses are read afresh for each session, since interfaces change.
func buildHello(cfg Config, reg *check.Registry, caps map[string]bool, pol *policy.Policy) protocol.Hello {
	hostname, _ := os.Hostname()
	var addrs []string
	for _, a := range policy.InterfaceAddrs() {
		// Loopback and link-local addresses cannot be reached from another probe, so they are useless for path_test.
		if a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
			continue
		}
		addrs = append(addrs, a.String())
	}
	return boundHello(protocol.Hello{
		Type:         protocol.TypeHello,
		Version:      Version,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		Hostname:     hostname,
		Addresses:    addrs,
		Checks:       reg.Names(),
		Capabilities: caps,
		Policy:       pol.Summary(),
		ListenPorts:  listenPortsString(cfg),
	})
}

// Limits the hub enforces on a hello. A hello outside them is refused with close code 4400, and the probe would retry
// the same hello forever, so the probe trims its own hello to fit rather than relying on the host being ordinary.
const (
	maxHelloText  = 64
	maxHelloAddrs = 32
	maxHelloCheck = 64
	maxHelloCaps  = 32
	// maxHelloPolicy caps each policy list in the hello. The lists are only a summary shown to agents; the probe
	// enforces its whole policy whatever it reports.
	maxHelloPolicy = 256
)

// boundHello makes h acceptable to the hub: text fields reduced to [A-Za-z0-9._+~:-] (other characters become '-') and
// 64 characters, addresses without a zone and deduplicated, policy entries limited to the shapes the hub accepts, and
// every list cut to the hub's cap.
func boundHello(h protocol.Hello) protocol.Hello {
	h.Hostname = helloText(h.Hostname)
	h.Version = helloText(h.Version)
	h.OS = helloText(h.OS)
	h.Arch = helloText(h.Arch)

	seen := map[string]bool{}
	addrs := []string{}
	for _, s := range h.Addresses {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		s = a.Unmap().WithZone("").String()
		if seen[s] || len(addrs) == maxHelloAddrs {
			continue
		}
		seen[s] = true
		addrs = append(addrs, s)
	}
	h.Addresses = addrs

	if len(h.Checks) > maxHelloCheck {
		h.Checks = append([]string(nil), h.Checks[:maxHelloCheck]...)
	}

	keys := make([]string, 0, len(h.Capabilities))
	for k := range h.Capabilities {
		keys = append(keys, k)
	}
	sort.Strings(keys) // so the same capabilities survive the cut every time
	c := make(map[string]bool, min(len(keys), maxHelloCaps))
	for _, k := range keys[:min(len(keys), maxHelloCaps)] {
		c[k] = h.Capabilities[k]
	}
	h.Capabilities = c

	h.Policy.AllowCIDRs = helloCIDRs(h.Policy.AllowCIDRs)
	h.Policy.DenyCIDRs = helloCIDRs(h.Policy.DenyCIDRs)
	var hosts []string
	for _, n := range h.Policy.AllowHosts {
		if len(hosts) < maxHelloPolicy && validPolicyHost(n) {
			hosts = append(hosts, n)
		}
	}
	h.Policy.AllowHosts = hosts
	return h
}

// helloCIDRs keeps the entries the hub accepts (an address or CIDR without a zone), up to maxHelloPolicy.
func helloCIDRs(list []string) []string {
	var out []string
	for _, c := range list {
		if len(out) == maxHelloPolicy {
			break
		}
		c = strings.TrimSpace(c)
		if strings.Contains(c, "/") {
			if _, err := netip.ParsePrefix(c); err != nil {
				continue
			}
		} else if a, err := netip.ParseAddr(c); err != nil || a.Zone() != "" {
			continue
		}
		out = append(out, c)
	}
	return out
}

func validPolicyHost(n string) bool {
	if n == "" || len(n) > 253 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '*' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func helloText(s string) string {
	b := []byte(s)
	if len(b) > maxHelloText {
		b = b[:maxHelloText]
	}
	for i, c := range b {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("._+~:-", c) >= 0) {
			b[i] = '-'
		}
	}
	return string(b)
}

// listenPortsString reports the listen range in one canonical "lo-hi" form whatever spelling the config used.
func listenPortsString(cfg Config) string {
	if cfg.ListenPortMin == 0 {
		return ""
	}
	return fmt.Sprintf("%d-%d", cfg.ListenPortMin, cfg.ListenPortMax)
}

// link keeps one WebSocket session to the hub open, reconnecting as needed.
type link struct {
	hubURL    string
	stateDir  string
	id        Identity
	client    *http.Client
	logger    *slog.Logger
	disp      *dispatcher
	hello     func() protocol.Hello
	t         timers
	welcomeTO time.Duration
	idleTO    time.Duration
	drainTO   time.Duration
}

// sessionEnd says how a session finished, which decides how long to wait before the next.
type sessionEnd struct {
	established bool          // the hub sent welcome
	lasted      time.Duration // from welcome to the end
	code        websocket.StatusCode
	httpStatus  int
	shutdown    bool
	err         error
}

// run connects and reconnects until ctx ends. It returns nil on shutdown.
func (l *link) run(ctx context.Context) error {
	b := newBackoff(l.t)
	for ctx.Err() == nil {
		end := l.session(ctx)
		if end.shutdown || ctx.Err() != nil {
			return nil
		}
		if end.established && end.lasted >= stableSession {
			b.reset()
		}
		var wait time.Duration
		switch {
		case end.code == CloseBadCredential || end.httpStatus == http.StatusUnauthorized || end.httpStatus == http.StatusForbidden:
			wait = refusedRetry
			l.logger.Error(fmt.Sprintf("credential refused or revoked; re-enrol with a new token (delete %s)", IdentityPath(l.stateDir)),
				"close_code", int(end.code), "http_status", end.httpStatus, "retry_in_ms", wait.Milliseconds())
		case end.code == CloseReplaced || end.httpStatus == http.StatusConflict:
			wait = refusedRetry
			l.logger.Error("replaced by another session of this probe", "close_code", int(end.code), "retry_in_ms", wait.Milliseconds())
		default:
			wait = b.next()
			attrs := []any{"retry_in_ms", wait.Milliseconds()}
			if end.code != -1 {
				attrs = append(attrs, "close_code", int(end.code))
			}
			if end.httpStatus != 0 {
				attrs = append(attrs, "http_status", end.httpStatus)
			}
			if end.err != nil {
				attrs = append(attrs, "error", end.err.Error())
			}
			if end.established {
				attrs = append(attrs, "session_ms", end.lasted.Milliseconds())
				l.logger.Warn("link to hub lost", attrs...)
			} else {
				l.logger.Warn("could not connect to hub", attrs...)
			}
		}
		if err := l.t.sleep(ctx, wait); err != nil {
			return nil
		}
	}
	return nil
}

// wsWriter serialises writes to the socket: results from many jobs race to be sent.
type wsWriter struct {
	mu   sync.Mutex
	conn *websocket.Conn
	ctx  context.Context // the connection's lifetime, never a job's
}

func (w *wsWriter) send(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	ctx, cancel := context.WithTimeout(w.ctx, writeTimeout)
	defer cancel()
	return w.conn.Write(ctx, websocket.MessageText, data)
}

// session runs one connection from dial to close.
func (l *link) session(ctx context.Context) sessionEnd {
	endpoint, err := hubEndpoint(l.hubURL, protocol.PathConnect, false)
	if err != nil {
		return sessionEnd{code: -1, err: err}
	}
	var lastSeen atomic.Int64
	touch := func() { lastSeen.Store(l.t.now().UnixNano()) }
	touch()

	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	conn, resp, err := websocket.Dial(dialCtx, endpoint, &websocket.DialOptions{
		HTTPClient:   l.client,
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + l.id.ProbeID + "." + l.id.Secret}},
		Subprotocols: []string{protocol.WireVersion},
		OnPingReceived: func(context.Context, []byte) bool {
			touch()
			return true
		},
	})
	cancelDial()
	if err != nil {
		end := sessionEnd{code: -1, err: err}
		if resp != nil {
			end.httpStatus = resp.StatusCode
		}
		return end
	}
	defer conn.CloseNow()
	if conn.Subprotocol() != protocol.WireVersion {
		conn.Close(CloseProtocolError, "subprotocol "+protocol.WireVersion+" required")
		return sessionEnd{code: -1, err: fmt.Errorf("hub did not agree to subprotocol %s", protocol.WireVersion)}
	}
	conn.SetReadLimit(maxFrameBytes)

	// The connection's context is separate from ctx so that a shutdown signal does not tear the socket down before
	// running jobs have sent their results.
	connCtx, cancelConn := context.WithCancel(context.Background())
	defer cancelConn()
	w := &wsWriter{conn: conn, ctx: connCtx}

	if err := w.send(l.hello()); err != nil {
		return sessionEnd{code: websocket.CloseStatus(err), err: fmt.Errorf("sending hello: %w", err)}
	}
	welcome, end, ok := l.readWelcome(ctx, conn)
	if !ok {
		return end
	}
	start := l.t.now()
	touch()
	attrs := []any{"name", welcome.Name, "site", welcome.Site}
	if welcome.Name != l.id.Name || welcome.Site != l.id.Site {
		attrs = append(attrs, "enrolled_name", l.id.Name, "enrolled_site", l.id.Site)
	}
	l.logger.Info("connected to hub", attrs...)

	sess := newSession(w.send)
	readDone := make(chan error, 1)
	go func() { readDone <- l.readLoop(connCtx, conn, sess, touch) }()
	go l.watchdog(connCtx, conn, &lastSeen)

	select {
	case err := <-readDone:
		sess.abort()
		return sessionEnd{established: true, lasted: l.t.now().Sub(start), code: websocket.CloseStatus(err), err: err}
	case <-ctx.Done():
		l.disp.stopAccepting()
		l.logger.Info("shutting down; waiting for running jobs", "running", sess.count(), "wait_ms", l.drainTO.Milliseconds())
		drained := make(chan struct{})
		go func() { sess.wg.Wait(); close(drained) }()
		t := time.NewTimer(l.drainTO)
		select {
		case <-drained:
		case <-t.C:
			l.logger.Warn("jobs still running at shutdown were abandoned", "running", sess.count())
		}
		t.Stop()
		sess.abort()
		conn.Close(websocket.StatusNormalClosure, "probe shutting down")
		return sessionEnd{shutdown: true, established: true, lasted: l.t.now().Sub(start), code: -1}
	}
}

// readWelcome waits for the hub's answer to hello.
func (l *link) readWelcome(ctx context.Context, conn *websocket.Conn) (protocol.Welcome, sessionEnd, bool) {
	wctx, cancel := context.WithTimeout(ctx, l.welcomeTO)
	defer cancel()
	_, data, err := conn.Read(wctx)
	if err != nil {
		if ctx.Err() != nil {
			return protocol.Welcome{}, sessionEnd{shutdown: true, code: -1}, false
		}
		if wctx.Err() != nil {
			err = fmt.Errorf("no welcome from hub within %s", l.welcomeTO)
		}
		return protocol.Welcome{}, sessionEnd{code: websocket.CloseStatus(err), err: err}, false
	}
	var wel protocol.Welcome
	if err := json.Unmarshal(data, &wel); err != nil || wel.Type != protocol.TypeWelcome {
		conn.Close(CloseProtocolError, "expected welcome")
		return protocol.Welcome{}, sessionEnd{code: -1, err: errors.New("hub's first frame was not welcome")}, false
	}
	return wel, sessionEnd{}, true
}

// readLoop handles frames from the hub until the connection ends.
func (l *link) readLoop(ctx context.Context, conn *websocket.Conn, sess *session, touch func()) error {
	for {
		typ, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		touch()
		if typ != websocket.MessageText {
			l.logger.Warn("ignoring non-text frame from hub")
			continue
		}
		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			l.logger.Warn("ignoring frame that is not JSON")
			continue
		}
		switch env.Type {
		case protocol.TypeJob:
			var job protocol.Job
			if err := json.Unmarshal(data, &job); err != nil {
				l.logger.Warn("ignoring malformed job frame")
				continue
			}
			l.disp.handleJob(sess, job)
		case protocol.TypeCancel:
			var c protocol.Cancel
			if err := json.Unmarshal(data, &c); err != nil {
				l.logger.Warn("ignoring malformed cancel frame")
				continue
			}
			if !sess.cancel(c.ID) {
				l.logger.Debug("cancel for a job that is not running", "job_id", logText(c.ID))
			}
		case protocol.TypeWelcome:
			// A repeated welcome is harmless.
		default:
			// Ignored rather than fatal, so a newer hub can add message types without breaking older probes.
			l.logger.Warn("ignoring frame of unknown type", "type", logText(env.Type))
		}
	}
}

// watchdog drops a connection that has gone silent: without it, a hub that vanished without closing TCP would leave
// the probe waiting forever instead of reconnecting.
func (l *link) watchdog(ctx context.Context, conn *websocket.Conn, lastSeen *atomic.Int64) {
	tick := time.NewTicker(l.idleTO / 4)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if l.t.now().Sub(time.Unix(0, lastSeen.Load())) > l.idleTO {
				l.logger.Warn("no traffic from hub; dropping the link", "idle_ms", l.idleTO.Milliseconds())
				conn.CloseNow()
				return
			}
		}
	}
}
