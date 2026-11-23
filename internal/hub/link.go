package hub

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"probetools/internal/protocol"
)

// Close codes on the probe link, from DESIGN.md.
const (
	statusProtocol  websocket.StatusCode = 4400 // protocol error
	statusRevoked   websocket.StatusCode = 4401 // unknown, wrong or revoked credential
	statusReplaced  websocket.StatusCode = 4409 // a newer session of the same probe took over
	statusGoingAway                      = websocket.StatusGoingAway
)

// maxFrame is the largest frame either side may send.
const maxFrame = 1 << 20

// session is one probe's live WebSocket.
type session struct {
	hub         *Hub
	probe       ProbeRecord
	conn        *websocket.Conn
	hello       protocol.Hello
	connectedAt time.Time
	log         *slog.Logger

	seen atomic.Int64 // unix nanoseconds of the last frame or pong

	writeMu sync.Mutex

	mu      sync.Mutex
	pending map[string]chan protocol.Result // jobs waiting for a result, by job id

	done      chan struct{} // closed when the session has ended
	endOnce   sync.Once
	closeOnce sync.Once
}

// end marks the session over, waking every Run waiting on it.
func (s *session) end() { s.endOnce.Do(func() { close(s.done) }) }

func (s *session) touch()              { s.seen.Store(time.Now().UnixNano()) }
func (s *session) lastSeen() time.Time { return time.Unix(0, s.seen.Load()).UTC() }

// write sends one frame. Writes are serialised, and each has its own timeout rather than a caller's context: a write
// cut short by a cancelled context would tear down the whole connection.
func (s *session) write(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), s.hub.opts.WriteTimeout)
	defer cancel()
	return s.conn.Write(ctx, websocket.MessageText, b)
}

// closeWith closes the session with a close code. The close handshake can take seconds, so it runs in the background;
// the reader loop ends when the connection does.
func (s *session) closeWith(code websocket.StatusCode, reason string) {
	s.closeOnce.Do(func() {
		go func() {
			s.conn.Close(code, reason)
		}()
		// If the peer never answers the close, drop the connection anyway.
		time.AfterFunc(6*time.Second, func() { s.conn.CloseNow() })
	})
}

// handleConnect authenticates a probe and runs its session until it ends.
func (h *Hub) handleConnect(w http.ResponseWriter, r *http.Request) {
	log := h.log.With("remote", r.RemoteAddr)

	// The credential is always checked first, and only failures count against a client. Many probes can share one
	// client key (a site behind one NAT address, every probe behind a TLS-terminating proxy), so a valid credential is
	// accepted however many bad ones came from its key: junk from a neighbour must not lock real probes out. A key over
	// its failure limit gets the same 429 for every failure, so the 429 says nothing about whether the id exists.
	key := clientKey(r.RemoteAddr)
	authFailed := func(reason, id string) {
		if !h.connectFails.allow(key) {
			h.logRefusal(h.connectLog, "connection refused", key, r, "reason", "rate_limited")
			w.Header().Set("Retry-After", "60")
			refuse(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		attrs := []any{"reason", reason}
		if id != "" {
			// The id is the caller's text, not yet tied to any probe; log only enough to match it with a real one.
			attrs = append(attrs, "probe_id_prefix", idPrefix(id))
		}
		h.logRefusal(h.connectLog, "connection refused", key, r, attrs...)
		refuse(w, "unauthorized", http.StatusUnauthorized)
	}

	// Authenticate before upgrading, so a bad credential costs a plain HTTP 401 and no WebSocket.
	id, secret, ok := parseProbeAuth(r.Header.Get("Authorization"))
	if !ok {
		authFailed(ReasonMalformedAuth, "")
		return
	}
	probe, err := h.store.Authenticate(r.Context(), id, secret)
	var ee *EnrollError
	if errors.As(err, &ee) {
		authFailed(ee.Reason, id)
		return
	}
	if err != nil {
		log.Error("connection failed", "err", err)
		refuse(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !offersSubprotocol(r, protocol.WireVersion) {
		log.Warn("connection refused", "reason", "wrong_subprotocol", "probe", probe.Name,
			"offered", protocol.UntrustedString(r.Header.Get("Sec-WebSocket-Protocol"), 128).Text)
		refuse(w, "subprotocol "+protocol.WireVersion+" required", http.StatusBadRequest)
		return
	}

	// Lift the request read deadline Handler set: from here the link has its own hello timeout and pings, and the
	// deadline would cut a live session.
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Time{}); err != nil {
		log.Error("connection refused", "reason", "no_read_deadline", "probe", probe.Name, "err", err)
		refuse(w, "internal error", http.StatusInternalServerError)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{protocol.WireVersion}})
	if err != nil {
		// Accept has written its own refusal; don't leave the connection without a deadline.
		rc.SetReadDeadline(time.Now().Add(h.opts.RequestReadTimeout))
		log.Warn("websocket upgrade failed", "probe", probe.Name, "err", err)
		return
	}
	conn.SetReadLimit(maxFrame)

	s := &session{
		hub:     h,
		probe:   probe,
		conn:    conn,
		log:     h.log.With("probe", probe.Name, "site", probe.Site, "probe_id", probe.ID),
		pending: map[string]chan protocol.Result{},
		done:    make(chan struct{}),
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		conn.Close(statusGoingAway, "hub shutting down")
		return
	}
	h.conns[s] = true
	h.connWG.Add(1)
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.conns, s)
		h.mu.Unlock()
		h.connWG.Done()
	}()
	defer s.end()
	defer conn.CloseNow()

	// No deadline on the read itself: an expired read context drops the socket without a close frame, and the probe
	// should see 4400.
	helloTimer := time.AfterFunc(h.opts.HelloTimeout, func() {
		s.log.Warn("no hello in time; closing")
		s.closeWith(statusProtocol, "no hello")
	})
	hello, err := readHello(conn)
	helloTimer.Stop()
	reason := "expected hello"
	if err == nil {
		// Hello fields reach agents through list_probes, so they are checked here rather than trusted.
		if hello, err = validateHello(hello); err != nil {
			reason = "invalid hello"
		}
	}
	if err != nil {
		s.log.Warn("bad first frame", "reason", reason, "err", err)
		s.closeWith(statusProtocol, reason)
		// Keep reading so the close handshake can complete.
		for {
			if _, _, err := conn.Read(context.Background()); err != nil {
				return
			}
		}
	}
	s.hello = hello
	s.connectedAt = time.Now().UTC()
	s.touch()

	if err := s.write(protocol.Welcome{Type: protocol.TypeWelcome, Name: probe.Name, Site: probe.Site}); err != nil {
		s.log.Warn("sending welcome failed", "err", err)
		return
	}

	// Register only after welcome, so no job can reach the probe before it.
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		s.closeWith(statusGoingAway, "hub shutting down")
		return
	}
	old := h.sessions[probe.ID]
	h.sessions[probe.ID] = s
	h.mu.Unlock()
	if old != nil {
		old.log.Info("session replaced by a newer one")
		old.closeWith(statusReplaced, "replaced by a newer session")
	}
	defer func() {
		h.mu.Lock()
		if h.sessions[probe.ID] == s {
			delete(h.sessions, probe.ID)
		}
		h.mu.Unlock()
		if err := h.store.SetLastSeen(context.Background(), probe.ID, s.lastSeen()); err != nil {
			s.log.Warn("saving last_seen failed", "err", err)
		}
	}()

	if err := h.store.SetHello(r.Context(), probe.ID, hello, s.lastSeen()); err != nil {
		s.log.Warn("saving hello failed", "err", err)
	}
	s.log.Info("probe connected", "version", protocol.UntrustedString(hello.Version, 64).Text,
		"hostname", protocol.UntrustedString(hello.Hostname, 128).Text)

	pingDone := make(chan struct{})
	go func() {
		defer close(pingDone)
		s.pingLoop()
	}()
	err = s.readLoop()
	s.end()
	conn.CloseNow()
	<-pingDone
	s.log.Info("probe disconnected", "close_status", int(websocket.CloseStatus(err)))
}

// readHello reads the first frame, which must be a hello.
func readHello(conn *websocket.Conn) (protocol.Hello, error) {
	var h protocol.Hello
	typ, b, err := conn.Read(context.Background())
	if err != nil {
		return h, err
	}
	if typ != websocket.MessageText {
		return h, errors.New("binary frame")
	}
	if err := json.Unmarshal(b, &h); err != nil {
		return h, err
	}
	if h.Type != protocol.TypeHello {
		return h, errors.New("first frame is not hello")
	}
	return h, nil
}

// readLoop handles frames until the connection ends. Results go to the Run waiting for them.
func (s *session) readLoop() error {
	for {
		typ, b, err := s.conn.Read(context.Background())
		if err != nil {
			return err
		}
		s.touch()
		if typ != websocket.MessageText {
			s.closeWith(statusProtocol, "binary frame")
			continue
		}
		var env protocol.Envelope
		if err := json.Unmarshal(b, &env); err != nil {
			s.log.Warn("unparseable frame", "err", err)
			s.closeWith(statusProtocol, "bad frame")
			continue
		}
		switch env.Type {
		case protocol.TypeResult:
			var res protocol.Result
			if err := json.Unmarshal(b, &res); err != nil {
				s.log.Warn("bad result frame", "err", err)
				s.closeWith(statusProtocol, "bad result")
				continue
			}
			s.deliver(res)
		default:
			s.log.Warn("ignoring unexpected frame", "type", protocol.UntrustedString(env.Type, 32).Text)
		}
	}
}

func (s *session) deliver(res protocol.Result) {
	s.mu.Lock()
	ch, ok := s.pending[res.ID]
	delete(s.pending, res.ID)
	s.mu.Unlock()
	if !ok {
		// Usually a result that arrived after the hub gave up on the job.
		s.log.Info("result for unknown job ignored", "job_id", protocol.UntrustedString(res.ID, 64).Text)
		return
	}
	ch <- res // buffered, and only one result is ever delivered per job
}

// pingLoop pings the probe and drops it after it misses MissedPongs pongs in a row.
func (s *session) pingLoop() {
	t := time.NewTicker(s.hub.opts.PingInterval)
	defer t.Stop()
	missed := 0
	for {
		select {
		case <-t.C:
		case <-s.done:
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), s.hub.opts.PingInterval)
		err := s.conn.Ping(ctx)
		cancel()
		select {
		case <-s.done:
			return
		default:
		}
		if err == nil {
			missed = 0
			s.touch()
			continue
		}
		missed++
		s.log.Info("missed pong", "missed", missed)
		if missed >= s.hub.opts.MissedPongs {
			s.log.Warn("probe not answering pings; dropping")
			// The probe is not responding, so there is no point waiting for a close handshake.
			s.conn.CloseNow()
			return
		}
	}
}

// parseProbeAuth splits "Bearer <probe_id>.<secret>".
func parseProbeAuth(h string) (id, secret string, ok bool) {
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	id, secret, ok = strings.Cut(strings.TrimSpace(h[len(prefix):]), ".")
	if !ok || id == "" || secret == "" || len(id) > 128 || len(secret) > 256 {
		return "", "", false
	}
	return id, secret, true
}

func offersSubprotocol(r *http.Request, want string) bool {
	for _, v := range r.Header.Values("Sec-WebSocket-Protocol") {
		for _, p := range strings.Split(v, ",") {
			if strings.TrimSpace(p) == want {
				return true
			}
		}
	}
	return false
}
