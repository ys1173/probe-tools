package icmp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"syscall"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

// probeStagger spaces the queries of one hop a little, since routers often rate-limit the ICMP errors they send.
const probeStagger = 50 * time.Millisecond

// TracerouteResult is traceroute's answer.
type TracerouteResult struct {
	Target   string `json:"target"`
	Address  string `json:"address"`
	Mode     string `json:"mode"`
	Port     int    `json:"port,omitempty"`
	Hops     []Hop  `json:"hops"`
	Reached  bool   `json:"reached"`  // the destination itself answered
	Complete bool   `json:"complete"` // false when the time budget cut the trace short
	Note     string `json:"note,omitempty"`
}

// Hop is one TTL's worth of probes.
type Hop struct {
	TTL    int        `json:"ttl"`
	Probes []HopProbe `json:"probes"`
}

// HopProbe is one probe's answer: the address that replied and the round trip, or a timeout.
type HopProbe struct {
	Addr    string   `json:"addr,omitempty"`
	RTTMS   *float64 `json:"rtt_ms,omitempty"`
	Timeout bool     `json:"timeout,omitempty"`
	Note    string   `json:"note,omitempty"` // e.g. "destination unreachable / host unreachable", "connection refused"
}

// probeResult is a HopProbe plus what it means for the trace.
type probeResult struct {
	HopProbe
	final   bool // nothing past this hop is worth probing
	reached bool // the destination answered
}

func runTraceroute(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.TracerouteParams
	if err := check.Decode(raw, &p); err != nil {
		return nil, err
	}
	if p.Mode == "tcp" && !tcpTraceSupported {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "tcp traceroute is not supported on this system")
	}
	dst, perr := resolveTarget(ctx, env, p.Target, p.Family)
	if perr != nil {
		return nil, perr
	}
	s, err := openKinds(dst.Is6(), env.Capabilities, []sockKind{kindRaw})
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeUnavailable,
			"traceroute needs a raw ICMP socket to see the routers' replies: grant the probe the NET_RAW capability (%v)", errnoText(err))
	}
	t := newTracer(s, dst, p)
	defer t.close()
	res := t.run(ctx, checkDeadline(ctx, time.Now()))
	res.Target = p.Target
	return res, nil
}

// probeKey identifies a probe in the packet an ICMP error quotes: the echo identifier and sequence in icmp mode, the
// source and destination ports otherwise.
type probeKey struct{ a, b uint16 }

type tracer struct {
	s    *echoSock // raw: receives every ICMP message on the host; also sends the echoes in icmp mode
	v6   bool
	dst  netip.Addr
	p    protocol.TracerouteParams
	id   uint16
	mu   sync.Mutex
	wait map[probeKey]chan message
	done chan struct{}
}

func newTracer(s *echoSock, dst netip.Addr, p protocol.TracerouteParams) *tracer {
	var b [2]byte
	rand.Read(b[:])
	t := &tracer{s: s, v6: dst.Is6(), dst: dst, p: p, id: binary.BigEndian.Uint16(b[:]), wait: map[probeKey]chan message{},
		done: make(chan struct{})}
	go t.readLoop()
	return t
}

func (t *tracer) close() {
	t.s.Close()
	<-t.done
}

func (t *tracer) register(k probeKey) chan message {
	ch := make(chan message, 1)
	t.mu.Lock()
	t.wait[k] = ch
	t.mu.Unlock()
	return ch
}

func (t *tracer) registerCh(k probeKey, ch chan message) {
	t.mu.Lock()
	t.wait[k] = ch
	t.mu.Unlock()
}

func (t *tracer) unregister(k probeKey) {
	t.mu.Lock()
	delete(t.wait, k)
	t.mu.Unlock()
}

func (t *tracer) readLoop() {
	defer close(t.done)
	buf := make([]byte, 1500)
	for {
		n, _, from, err := t.s.read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		m, ok := parseMessage(t.v6, buf[:n], from)
		if !ok {
			continue
		}
		k, ok := keyFor(m, t.p.Mode, t.dst, t.id)
		if !ok {
			continue
		}
		t.mu.Lock()
		ch := t.wait[k]
		t.mu.Unlock()
		if ch != nil {
			select {
			case ch <- m:
			default: // the probe already has its answer
			}
		}
	}
}

// keyFor works out which of our probes a message answers, if any.
func keyFor(m message, mode string, dst netip.Addr, id uint16) (probeKey, bool) {
	if m.isEchoReply() {
		if mode == "icmp" && m.from == dst && m.id == id {
			return probeKey{m.id, m.seq}, true
		}
		return probeKey{}, false
	}
	q := m.quoted
	if !m.hasQ || q.dst != dst {
		return probeKey{}, false
	}
	switch mode {
	case "icmp":
		if q.echo && q.id == id {
			return probeKey{q.id, q.seq}, true
		}
	case "udp":
		if q.proto == protoUDP {
			return probeKey{q.srcPort, q.dstPort}, true
		}
	case "tcp":
		if q.proto == protoTCP {
			return probeKey{q.srcPort, q.dstPort}, true
		}
	}
	return probeKey{}, false
}

// classify turns an ICMP answer into a hop entry.
func classify(m message, dst netip.Addr, mode string, rtt time.Duration) probeResult {
	r := probeResult{HopProbe: HopProbe{Addr: m.from.String(), RTTMS: ptr(ms(rtt))}}
	fromDst := m.from == dst
	switch {
	case m.isEchoReply():
		r.final, r.reached = true, fromDst
	case m.isTimeExceeded():
	case isUnreach(m.v6, m.typ):
		// Unreachable ends the trace either way. From the destination itself it is still an answer from it; a port
		// unreachable is the expected answer in udp mode.
		r.final, r.reached = true, fromDst
		if !(mode == "udp" && fromDst && isPortUnreach(m.v6, m.typ, m.code)) {
			r.Note = describe(m.v6, m.typ, m.code)
		}
	default:
		r.Note = describe(m.v6, m.typ, m.code)
	}
	return r
}

func ptr(f float64) *float64 { return &f }

// hopFits reports whether one more hop (its queries, staggered, and the wait for the last) ends before deadline.
func hopFits(now, deadline time.Time, wait time.Duration, queries int) bool {
	cost := wait + time.Duration(queries-1)*probeStagger
	return !now.Add(cost).After(deadline)
}

func (t *tracer) run(ctx context.Context, deadline time.Time) TracerouteResult {
	p := t.p
	res := TracerouteResult{Address: t.dst.String(), Mode: p.Mode, Hops: []Hop{}}
	if p.Mode != "icmp" {
		res.Port = p.Port
	}
	wait := time.Duration(p.WaitMS) * time.Millisecond
	for ttl := 1; ttl <= p.MaxHops; ttl++ {
		if ctx.Err() != nil || !hopFits(time.Now(), deadline, wait, p.Queries) {
			res.Note = fmt.Sprintf("stopped after %d hops to fit the time budget", ttl-1)
			return res
		}
		if p.Mode == "icmp" {
			if err := t.setTTL(ttl); err != nil {
				res.Note = "could not set the TTL: " + errnoText(err)
				return res
			}
		}
		results := make([]probeResult, p.Queries)
		var wg sync.WaitGroup
		for q := 0; q < p.Queries; q++ {
			wg.Add(1)
			go func(q int) {
				defer wg.Done()
				if q > 0 {
					select {
					case <-time.After(time.Duration(q) * probeStagger):
					case <-ctx.Done():
					}
				}
				results[q] = t.probe(ctx, ttl, q, wait)
			}(q)
		}
		wg.Wait()
		hop := Hop{TTL: ttl}
		final := false
		for _, r := range results {
			hop.Probes = append(hop.Probes, r.HopProbe)
			final = final || r.final
			res.Reached = res.Reached || r.reached
		}
		res.Hops = append(res.Hops, hop)
		if ctx.Err() != nil {
			res.Note = "cancelled"
			return res
		}
		if final {
			break
		}
	}
	res.Complete = true
	return res
}

func (t *tracer) setTTL(ttl int) error {
	if t.v6 {
		return t.s.pc.IPv6PacketConn().SetHopLimit(ttl)
	}
	return t.s.pc.IPv4PacketConn().SetTTL(ttl)
}

func (t *tracer) probe(ctx context.Context, ttl, q int, wait time.Duration) probeResult {
	if ctx.Err() != nil {
		return probeResult{HopProbe: HopProbe{Timeout: true}}
	}
	switch t.p.Mode {
	case "udp":
		return t.probeUDP(ctx, ttl, wait)
	case "tcp":
		return t.probeTCP(ctx, ttl, wait)
	}
	return t.probeICMP(ctx, ttl, q, wait)
}

// awaitICMP waits for the ICMP answer to a probe sent at sent.
func (t *tracer) awaitICMP(ctx context.Context, ch chan message, sent time.Time, wait time.Duration) probeResult {
	timer := time.NewTimer(time.Until(sent.Add(wait)))
	defer timer.Stop()
	select {
	case m := <-ch:
		return classify(m, t.dst, t.p.Mode, time.Since(sent))
	case <-timer.C:
	case <-ctx.Done():
	}
	return probeResult{HopProbe: HopProbe{Timeout: true}}
}

func (t *tracer) probeICMP(ctx context.Context, ttl, q int, wait time.Duration) probeResult {
	seq := uint16(ttl*4 + q)
	ch := t.register(probeKey{t.id, seq})
	defer t.unregister(probeKey{t.id, seq})
	var typ xicmp.Type = ipv4.ICMPTypeEcho
	if t.v6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	m := xicmp.Message{Type: typ, Body: &xicmp.Echo{ID: int(t.id), Seq: int(seq), Data: make([]byte, 32)}}
	b, err := m.Marshal(nil)
	if err != nil {
		return sendFailure(err)
	}
	sent := time.Now()
	if err := t.s.writeTo(b, t.dst); err != nil {
		return sendFailure(err)
	}
	return t.awaitICMP(ctx, ch, sent, wait)
}

func (t *tracer) probeUDP(ctx context.Context, ttl int, wait time.Duration) probeResult {
	network := "udp4"
	if t.v6 {
		network = "udp6"
	}
	c, err := net.ListenUDP(network, nil)
	if err != nil {
		return sendFailure(err)
	}
	defer c.Close()
	if t.v6 {
		err = ipv6.NewConn(c).SetHopLimit(ttl)
	} else {
		err = ipv4.NewConn(c).SetTTL(ttl)
	}
	if err != nil {
		return sendFailure(err)
	}
	// Each probe has its own socket, so its source port tells the answers apart; the destination port stays fixed.
	k := probeKey{uint16(c.LocalAddr().(*net.UDPAddr).Port), uint16(t.p.Port)}
	ch := t.register(k)
	defer t.unregister(k)
	sent := time.Now()
	if _, err := c.WriteToUDP(make([]byte, 32), &net.UDPAddr{IP: t.dst.AsSlice(), Port: t.p.Port}); err != nil {
		return sendFailure(err)
	}
	return t.awaitICMP(ctx, ch, sent, wait)
}

type dialResult struct {
	conn net.Conn
	err  error
	at   time.Time
}

// probeTCP starts a connection with a limited TTL. A router on the way answers with time exceeded; the destination
// completes the handshake or refuses it, and either way has been reached.
func (t *tracer) probeTCP(ctx context.Context, ttl int, wait time.Duration) probeResult {
	network := "tcp4"
	if t.v6 {
		network = "tcp6"
	}
	ch := make(chan message, 1)
	var keyMu sync.Mutex
	var key *probeKey
	d := net.Dialer{Control: tcpControl(t.v6, ttl, func(port int) {
		k := probeKey{uint16(port), uint16(t.p.Port)}
		keyMu.Lock()
		key = &k
		keyMu.Unlock()
		t.registerCh(k, ch)
	})}
	dctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	sent := time.Now()
	dialed := make(chan dialResult, 1)
	go func() {
		c, err := d.DialContext(dctx, network, net.JoinHostPort(t.dst.String(), strconv.Itoa(t.p.Port)))
		at := time.Now()
		if c != nil {
			c.Close()
		}
		dialed <- dialResult{err: err, at: at}
	}()
	defer func() {
		cancel()
		<-dialed // the dial has returned, so the key will not be registered again
		keyMu.Lock()
		if key != nil {
			t.unregister(*key)
		}
		keyMu.Unlock()
	}()

	select {
	case m := <-ch:
		return classify(m, t.dst, t.p.Mode, time.Since(sent))
	case dr := <-dialed:
		dialed <- dr // put it back for the deferred wait
		rtt := dr.at.Sub(sent)
		if dr.err == nil {
			return probeResult{HopProbe: HopProbe{Addr: t.dst.String(), RTTMS: ptr(ms(rtt)), Note: "connected"}, final: true, reached: true}
		}
		// An ICMP error also fails the connect; give the matching message a moment to be read before deciding.
		grace := time.NewTimer(min(200*time.Millisecond, time.Until(sent.Add(wait))+time.Millisecond))
		defer grace.Stop()
		select {
		case m := <-ch:
			return classify(m, t.dst, t.p.Mode, rtt)
		case <-grace.C:
		}
		switch {
		case errors.Is(dr.err, syscall.ECONNREFUSED):
			return probeResult{HopProbe: HopProbe{Addr: t.dst.String(), RTTMS: ptr(ms(rtt)), Note: "connection refused"}, final: true, reached: true}
		case errors.Is(dr.err, syscall.ENETUNREACH):
			return probeResult{HopProbe: HopProbe{Timeout: true, Note: errnoText(dr.err)}, final: true}
		}
		r := probeResult{HopProbe: HopProbe{Timeout: true}}
		if !isTimeoutErr(dr.err) {
			r.Note = errnoText(dr.err)
		}
		return r
	case <-dctx.Done():
		return probeResult{HopProbe: HopProbe{Timeout: true}}
	}
}

func isTimeoutErr(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) || (errors.As(err, &ne) && ne.Timeout())
}

// sendFailure records a probe that could not be sent. No route to the destination ends the trace.
func sendFailure(err error) probeResult {
	r := probeResult{HopProbe: HopProbe{Timeout: true, Note: "send failed: " + errnoText(err)}}
	if errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH) {
		r.final = true
	}
	return r
}
