// Package pathtest is the probe side of the hub's path_test: the receiving probe opens a port and waits for the fixed
// path-test payload carrying the hub's nonce (listen_start, listen_collect), the sending probe connects and sends it
// (path_send). The payload is protocol.PathTestPayload, so the hub can choose only a short token, never the bytes sent. The receiver never sends
// anything back, so an open listener cannot be used to reflect or relay traffic.
package pathtest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"sync"
	"time"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
)

const (
	stateKey        = "pathtest"
	maxListeners    = 4
	maxArrivalBytes = 64 // how much of an arrival is read; the longest payload with "\r\n" is 61 bytes
	tcpReadTimeout  = 2 * time.Second
	maxTCPHandlers  = 16        // connections read at once; more are closed and only counted
	maxOtherCount   = 1_000_000 // other arrivals are counted up to this and then ignored
	firstBytesLimit = 64        // untrusted text kept from the first non-matching arrival
)

// Register adds listen_start, listen_collect and path_send to r.
func Register(r *check.Registry) {
	r.Register(protocol.CheckListenStart, listenStart)
	r.Register(protocol.CheckListenCollect, listenCollect)
	r.Register(protocol.CheckPathSend, pathSend)
}

// state holds the open listeners. It lives in Env.State because a listener outlives the job that opened it.
type state struct {
	mu        sync.Mutex
	listeners map[string]*listener
}

func getState(env *check.Env) *state {
	v, _ := env.State.LoadOrStore(stateKey, &state{listeners: map[string]*listener{}})
	return v.(*state)
}

func (s *state) remove(id string) {
	s.mu.Lock()
	delete(s.listeners, id)
	s.mu.Unlock()
}

// listener is one open port. Its lifetime is its own timer, not the listen_start job's context, which ends as soon as
// that job returns.
type listener struct {
	id       string
	protocol string
	port     int
	payload  []byte // the exact bytes an arrival must carry: the fixed prefix and the nonce

	tcp net.Listener
	udp net.PacketConn

	handlers chan struct{} // semaphore for TCP connection handlers
	arrived  chan struct{} // closed when the nonce arrives
	done     chan struct{} // closed when the listener closes
	timer    *time.Timer

	closeOnce sync.Once
	wg        sync.WaitGroup

	mu         sync.Mutex
	conns      map[net.Conn]struct{} // accepted connections still being read
	received   bool
	from       string
	other      int
	bytes      int
	firstBytes *protocol.Untrusted
}

func listenStart(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.ListenStartParams
	if err := check.Decode(raw, &p); err != nil {
		return nil, err
	}
	if env.ListenPortMin == 0 {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "listening is off on this probe (no listen_ports configured)")
	}
	if p.Port != 0 && (p.Port < env.ListenPortMin || p.Port > env.ListenPortMax) {
		return nil, protocol.Errorf(protocol.CodeDenied, "port %d is outside listen_ports %d-%d", p.Port, env.ListenPortMin, env.ListenPortMax)
	}

	st := getState(env)
	// Hold the lock while opening so two jobs cannot both pass the limit.
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.listeners) >= maxListeners {
		return nil, protocol.Errorf(protocol.CodeBusy, "this probe already has %d path_test listeners open", maxListeners)
	}

	l := &listener{
		id:       newID(),
		protocol: p.Protocol,
		payload:  []byte(protocol.PathTestPayload(p.Nonce)),
		handlers: make(chan struct{}, maxTCPHandlers),
		arrived:  make(chan struct{}),
		done:     make(chan struct{}),
		conns:    map[net.Conn]struct{}{},
	}
	if p.Port != 0 {
		if err := l.open(p.Port); err != nil {
			return nil, protocol.Errorf(protocol.CodeUnavailable, "port %d could not be opened on this probe: %v", p.Port, errText(err))
		}
	} else if err := l.openFree(env.ListenPortMin, env.ListenPortMax); err != nil {
		return nil, err
	}
	st.listeners[l.id] = l
	l.timer = time.AfterFunc(time.Duration(p.DurationMS)*time.Millisecond, func() {
		st.remove(l.id)
		l.close()
	})
	l.serve()
	return protocol.ListenStartResult{ListenID: l.id, Protocol: l.protocol, Port: l.port, Addresses: ownAddresses()}, nil
}

// open binds port on every address. "tcp" and "udp" with no host give a dual-stack socket where the host has IPv6.
func (l *listener) open(port int) error {
	addr := fmt.Sprintf(":%d", port)
	var err error
	if l.protocol == "tcp" {
		l.tcp, err = net.Listen("tcp", addr)
	} else {
		l.udp, err = net.ListenPacket("udp", addr)
	}
	if err == nil {
		l.port = port
	}
	return err
}

// openFree tries the ports of the range from a random starting point, so concurrent tests do not all race for the
// lowest port.
func (l *listener) openFree(min, max int) *protocol.Error {
	n := max - min + 1
	if n <= 0 {
		return protocol.Errorf(protocol.CodeUnavailable, "listen_ports %d-%d is empty", min, max)
	}
	start := 0
	if r, err := rand.Int(rand.Reader, big.NewInt(int64(n))); err == nil {
		start = int(r.Int64())
	}
	var lastErr error
	for i := 0; i < n; i++ {
		port := min + (start+i)%n
		if lastErr = l.open(port); lastErr == nil {
			return nil
		}
	}
	return protocol.Errorf(protocol.CodeUnavailable, "no port in listen_ports %d-%d could be opened on this probe: %v", min, max, errText(lastErr))
}

func (l *listener) serve() {
	l.wg.Add(1)
	if l.tcp != nil {
		go l.acceptLoop()
	} else {
		go l.udpLoop()
	}
}

func (l *listener) acceptLoop() {
	defer l.wg.Done()
	for {
		c, err := l.tcp.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// A transient accept error (e.g. out of file descriptors) should not end the listener early.
			time.Sleep(50 * time.Millisecond)
			continue
		}
		select {
		case l.handlers <- struct{}{}:
			l.wg.Add(1)
			go func() {
				defer l.wg.Done()
				defer func() { <-l.handlers }()
				l.handleTCP(c)
			}()
		default:
			// Too many connections at once: count it without reading.
			c.Close()
			l.record(nil, c.RemoteAddr())
		}
	}
}

func (l *listener) handleTCP(c net.Conn) {
	defer c.Close()
	l.mu.Lock()
	select {
	case <-l.done:
		l.mu.Unlock()
		return
	default:
	}
	l.conns[c] = struct{}{}
	l.mu.Unlock()
	c.SetReadDeadline(time.Now().Add(tcpReadTimeout))
	data := readArrival(c, maxArrivalBytes)
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
	l.record(data, c.RemoteAddr())
}

// readArrival reads up to max bytes, stopping early at a newline, EOF or the read deadline.
func readArrival(r io.Reader, max int) []byte {
	buf := make([]byte, max)
	n := 0
	for n < max {
		m, err := r.Read(buf[n:])
		n += m
		if bytes.IndexByte(buf[:n], '\n') >= 0 || err != nil {
			break
		}
	}
	return buf[:n]
}

func (l *listener) udpLoop() {
	defer l.wg.Done()
	buf := make([]byte, 2048)
	for {
		n, from, err := l.udp.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		if n > maxArrivalBytes {
			n = maxArrivalBytes
		}
		l.record(buf[:n], from)
	}
}

// matchPayload reports whether an arrival is exactly the path-test payload, allowing the line ending a TCP sender adds.
func matchPayload(data, payload []byte) bool {
	data = bytes.TrimRight(data, "\r\n")
	return len(data) == len(payload) && subtle.ConstantTimeCompare(data, payload) == 1
}

// record notes one arrival. Content that is not the payload is never logged; only its first bytes are kept, as untrusted
// text, for the first such arrival.
func (l *listener) record(data []byte, from net.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if matchPayload(data, l.payload) {
		// The sender repeats the payload (UDP goes three times); repeats are ours too, not other traffic.
		l.bytes += len(data)
		if !l.received {
			l.received = true
			l.from = addrString(from)
			close(l.arrived)
		}
		return
	}
	if l.other >= maxOtherCount {
		return
	}
	l.other++
	l.bytes += len(data)
	if l.firstBytes == nil && len(data) > 0 {
		u := protocol.UntrustedText(data, firstBytesLimit)
		l.firstBytes = &u
	}
}

func (l *listener) result() protocol.ListenCollectResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	return protocol.ListenCollectResult{Received: l.received, From: l.from, OtherArrivals: l.other, Bytes: l.bytes,
		FirstBytes: l.firstBytes}
}

// close stops the listener and waits for its handlers, so a result read afterwards is final. Safe to call twice (the
// expiry timer and listen_collect may both get here).
func (l *listener) close() {
	l.closeOnce.Do(func() {
		if l.timer != nil {
			l.timer.Stop()
		}
		if l.tcp != nil {
			l.tcp.Close()
		}
		if l.udp != nil {
			l.udp.Close()
		}
		// Cut short connections still being read, so closing never waits out their read deadline.
		l.mu.Lock()
		close(l.done)
		for c := range l.conns {
			c.SetReadDeadline(time.Now())
		}
		l.mu.Unlock()
	})
	l.wg.Wait()
}

func listenCollect(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.ListenCollectParams
	if err := check.Decode(raw, &p); err != nil {
		return nil, err
	}
	st := getState(env)
	st.mu.Lock()
	l, ok := st.listeners[p.ListenID]
	st.mu.Unlock()
	if !ok {
		return nil, protocol.Errorf(protocol.CodeNotFound, "no open listener %q (unknown, already collected or expired)", p.ListenID)
	}
	t := time.NewTimer(time.Duration(p.WaitMS) * time.Millisecond)
	select {
	case <-l.arrived:
	case <-l.done: // expired while we waited
	case <-t.C:
	case <-ctx.Done():
	}
	t.Stop()
	st.remove(l.id)
	l.close()
	return l.result(), nil
}

// ownAddresses lists the addresses another probe could send to: loopback is useless to it, and link-local addresses
// are refused by every probe's policy.
func ownAddresses() []string {
	out := []string{}
	for _, a := range policy.InterfaceAddrs() {
		if a.IsLoopback() || a.IsLinkLocalUnicast() || !a.IsValid() {
			continue
		}
		out = append(out, a.String())
	}
	return out
}

// addrString renders a source address with v4-mapped IPv6 shown as plain IPv4, since a dual-stack socket reports IPv4
// senders that way.
func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	if ap, err := netip.ParseAddrPort(a.String()); err == nil {
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String()
	}
	return a.String()
}

func newID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// errText strips the "listen tcp :N:" prefix Go puts on bind errors, leaving the reason.
func errText(err error) string {
	var oe *net.OpError
	if errors.As(err, &oe) && oe.Err != nil {
		return oe.Err.Error()
	}
	if err == nil {
		return "unknown error"
	}
	return err.Error()
}
