package hub

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"probetools/internal/protocol"
)

// Options tune the probe side. Zero values take the defaults; tests shorten the intervals.
type Options struct {
	PingInterval       time.Duration // how often the hub pings each probe; default 20 s
	MissedPongs        int           // pongs a probe may miss before it is dropped; default 2
	HelloTimeout       time.Duration // time a probe has to send hello after connecting; default 10 s
	RevocationInterval time.Duration // how often live sessions are checked against the database; default 5 s
	Slack              time.Duration // how long past a job's deadline the hub waits for its result; default protocol.HubSlackMS
	WriteTimeout       time.Duration // the longest one frame may take to send; default 5 s, so a stalled probe cannot push a call past the hub's budget
	RequestReadTimeout time.Duration // the longest any request on the probe listener may take to send its body; default 10 s

	EnrollRate          rate.Limit    // enrolment attempts per client (IPv4 address or IPv6 /64); default 10 a minute
	EnrollBurst         int           // default 10
	EnrollReadTimeout   time.Duration // the longest an enrolment request may take to send its body; default 10 s
	EnrollMaxConcurrent int           // enrolment requests handled at once, in total; default 32, beyond that 503
	EnrollMaxPerClient  int           // enrolment requests handled at once per client; default 4, beyond that 429

	ConnectFailRate  rate.Limit // failed link authentications allowed per client; default 20 a minute
	ConnectFailBurst int        // default 20
}

func (o *Options) defaults() {
	if o.PingInterval <= 0 {
		o.PingInterval = 20 * time.Second
	}
	if o.MissedPongs <= 0 {
		o.MissedPongs = 2
	}
	if o.HelloTimeout <= 0 {
		o.HelloTimeout = 10 * time.Second
	}
	if o.RevocationInterval <= 0 {
		o.RevocationInterval = 5 * time.Second
	}
	if o.Slack <= 0 {
		o.Slack = protocol.HubSlackMS * time.Millisecond
	}
	if o.WriteTimeout <= 0 {
		o.WriteTimeout = 5 * time.Second
	}
	if o.RequestReadTimeout <= 0 {
		o.RequestReadTimeout = 10 * time.Second
	}
	if o.EnrollRate <= 0 {
		o.EnrollRate = rate.Every(6 * time.Second)
	}
	if o.EnrollBurst <= 0 {
		o.EnrollBurst = 10
	}
	if o.EnrollReadTimeout <= 0 {
		o.EnrollReadTimeout = 10 * time.Second
	}
	if o.EnrollMaxConcurrent <= 0 {
		o.EnrollMaxConcurrent = 32
	}
	if o.EnrollMaxPerClient <= 0 {
		o.EnrollMaxPerClient = 4
	}
	if o.ConnectFailRate <= 0 {
		o.ConnectFailRate = rate.Every(3 * time.Second)
	}
	if o.ConnectFailBurst <= 0 {
		o.ConnectFailBurst = 20
	}
}

// Hub is the probe side of the hub: it enrols probes, holds their WebSocket sessions and routes jobs to them. It
// implements hubapi.Router.
type Hub struct {
	store *Store
	log   *slog.Logger
	opts  Options

	mu       sync.Mutex
	sessions map[string]*session // registered sessions (after hello), by probe id
	conns    map[*session]bool   // every open connection, including those still waiting for hello
	closed   bool
	connWG   sync.WaitGroup // connection handlers still running

	enrollRate   *ipLimiter   // enrolment attempts per client
	enrollSlots  *slots       // enrolment handlers running
	connectFails *ipLimiter   // failed link authentications per client
	enrollLog    *logThrottle // refused enrolments, per client
	connectLog   *logThrottle // refused connections, per client

	stop     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// New builds the hub's probe side and starts its revocation watcher. Call Close to stop it.
func New(store *Store, logger *slog.Logger, opts Options) *Hub {
	opts.defaults()
	h := &Hub{
		store:    store,
		log:      logger,
		opts:     opts,
		sessions: map[string]*session{},
		conns:    map[*session]bool{},
		stop:     make(chan struct{}),

		enrollRate:   newIPLimiter(opts.EnrollRate, opts.EnrollBurst, maxLimiters),
		enrollSlots:  newSlots(opts.EnrollMaxConcurrent, opts.EnrollMaxPerClient),
		connectFails: newIPLimiter(opts.ConnectFailRate, opts.ConnectFailBurst, maxLimiters),
		enrollLog:    newLogThrottle(time.Minute, maxLimiters),
		connectLog:   newLogThrottle(time.Minute, maxLimiters),
	}
	h.wg.Add(1)
	go h.watch()
	return h
}

// Handler serves the probe listener: enrolment, the WebSocket link and /healthz.
//
// The listener has no server-wide ReadTimeout, because that would also cut hijacked WebSocket links. Instead every
// request gets a read deadline here, before anything else, and /v1/connect lifts it just before the upgrade. Without
// it, a request refused without reading its body would leave net/http draining that body with no deadline, so a client
// trickling a body could hold the connection and its goroutine for ever. Refusals also say Connection: close, so the
// drain is not attempted at all.
func (h *Hub) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+protocol.PathEnroll, h.handleEnroll)
	mux.HandleFunc("GET "+protocol.PathConnect, h.handleConnect)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength != 0 {
			// A health check has no use for a body; don't keep the connection to drain one.
			w.Header().Set("Connection", "close")
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok"))
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(h.opts.RequestReadTimeout)); err != nil {
			h.log.Error("request refused", "remote", r.RemoteAddr, "reason", "no_read_deadline", "err", err)
			refuse(w, "internal error", http.StatusInternalServerError)
			return
		}
		if _, pattern := mux.Handler(r); pattern == "" {
			// The mux's own 404, 405 or redirect: a refusal like any other.
			w.Header().Set("Connection", "close")
		}
		mux.ServeHTTP(w, r)
	})
}

// refuse writes an error response and closes the connection after it, so net/http does not try to drain a request
// body the handler never read.
func refuse(w http.ResponseWriter, msg string, status int) {
	w.Header().Set("Connection", "close")
	http.Error(w, msg, status)
}

// Close stops the watcher and closes every probe session. http.Server.Shutdown does not see hijacked WebSocket
// connections, so the server calls this as well.
func (h *Hub) Close() {
	h.stopOnce.Do(func() { close(h.stop) })
	h.mu.Lock()
	h.closed = true
	all := make([]*session, 0, len(h.conns))
	for s := range h.conns {
		all = append(all, s)
	}
	h.mu.Unlock()
	for _, s := range all {
		s.closeWith(statusGoingAway, "hub shutting down")
	}
	// Wait for the handlers too, so nothing writes to the store after this returns.
	h.connWG.Wait()
	h.wg.Wait()
}

// watch closes the sessions of probes revoked while connected (the admin command revokes in the database, possibly
// from another process) and saves last_seen for live probes.
func (h *Hub) watch() {
	defer h.wg.Done()
	t := time.NewTicker(h.opts.RevocationInterval)
	defer t.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-t.C:
			h.checkRevoked()
		}
	}
}

func (h *Hub) liveSessions() []*session {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]*session, 0, len(h.sessions))
	for _, s := range h.sessions {
		out = append(out, s)
	}
	return out
}

func (h *Hub) checkRevoked() {
	live := h.liveSessions()
	if len(live) == 0 {
		return
	}
	ids := make([]string, len(live))
	for i, s := range live {
		ids[i] = s.probe.ID
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	active, err := h.store.ActiveIDs(ctx, ids)
	if err != nil {
		h.log.Error("revocation check failed", "err", err)
		return
	}
	for _, s := range live {
		if !active[s.probe.ID] {
			h.log.Info("closing session of revoked probe", "probe", s.probe.Name, "probe_id", s.probe.ID)
			s.closeWith(statusRevoked, "probe revoked")
			continue
		}
		if err := h.store.SetLastSeen(ctx, s.probe.ID, s.lastSeen()); err != nil {
			h.log.Warn("saving last_seen failed", "probe", s.probe.Name, "err", err)
		}
	}
}

// logRefusal writes a refused enrolment or connection at WARN, at most once a minute per client, with the number of
// refusals left out since the last line. Refusals are what a flood produces, so unthrottled they would flood the log.
func (h *Hub) logRefusal(lt *logThrottle, msg, key string, r *http.Request, attrs ...any) {
	ok, suppressed := lt.admit(key, time.Now())
	if !ok {
		return
	}
	attrs = append([]any{"remote", r.RemoteAddr}, attrs...)
	if suppressed > 0 {
		attrs = append(attrs, "suppressed", suppressed)
	}
	h.log.Warn(msg, attrs...)
}
