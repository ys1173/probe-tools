package icmp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"

	xicmp "golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmpError is an ICMP error that came back for one of our packets.
type icmpError struct {
	v6        bool
	from      netip.Addr
	typ, code int
	mtu       int
}

func (e icmpError) String() string {
	s := describe(e.v6, e.typ, e.code)
	if e.from.IsValid() {
		s += " from " + e.from.String()
	}
	return s
}

// echoEvent is a reply to, or an ICMP error about, one echo request of a session.
type echoEvent struct {
	seq   uint16
	at    time.Time
	ttl   int        // replies only
	err   *icmpError // nil for a reply
	bytes int
}

// echoSession sends echo requests to one address and reports the replies and errors that belong to them. On a raw
// socket, which sees every ICMP packet on the host, that means the reply comes from the target and carries our
// identifier and cookie; a datagram socket gets only its own replies (Linux rewrites the identifier to the socket's
// own), so the cookie and sequence are what match there.
type echoSession struct {
	s      *echoSock
	dst    netip.Addr
	id     uint16
	cookie [8]byte
	events chan echoEvent
}

func newSession(s *echoSock, dst netip.Addr) *echoSession {
	e := &echoSession{s: s, dst: dst, events: make(chan echoEvent, 256)}
	var b [10]byte
	rand.Read(b[:])
	e.id = binary.BigEndian.Uint16(b[0:2])
	copy(e.cookie[:], b[2:])
	if s.kind == kindDgram {
		// Without this, Linux drops ICMP errors for datagram ICMP sockets; failing to enable it costs only that detail.
		_ = enableRecvErr(s.conn, s.v6)
	}
	go e.readLoop()
	return e
}

// payload fills n bytes: the cookie first, then a fixed pattern.
func (e *echoSession) payload(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		if i < len(e.cookie) {
			p[i] = e.cookie[i]
		} else {
			p[i] = byte(i)
		}
	}
	return p
}

// cookieOK reports whether p starts with as much of our cookie as it has room for.
func (e *echoSession) cookieOK(p []byte) bool {
	n := min(len(p), len(e.cookie))
	return bytes.Equal(p[:n], e.cookie[:n])
}

func (e *echoSession) send(seq uint16, payloadLen int) error {
	var typ xicmp.Type = ipv4.ICMPTypeEcho
	if e.s.v6 {
		typ = ipv6.ICMPTypeEchoRequest
	}
	m := xicmp.Message{Type: typ, Body: &xicmp.Echo{ID: int(e.id), Seq: int(seq), Data: e.payload(payloadLen)}}
	b, err := m.Marshal(nil) // the kernel computes the ICMPv6 checksum, so no pseudo-header is needed
	if err != nil {
		return err
	}
	return e.s.writeTo(b, e.dst)
}

func (e *echoSession) emit(ev echoEvent) {
	select {
	case e.events <- ev:
	default: // nobody is keeping up; dropping is better than blocking the reader
	}
}

func (e *echoSession) readLoop() {
	buf := make([]byte, 10000)
	for {
		n, ttl, from, err := e.s.read(buf)
		now := time.Now()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// On a datagram socket an ICMP error surfaces as a failed read; the details wait on the error queue.
			if e.s.kind == kindDgram {
				e.drain()
			}
			continue
		}
		if ev, ok := e.match(buf[:n], ttl, from, now); ok {
			e.emit(ev)
		}
	}
}

// match decides whether a received message belongs to this session.
func (e *echoSession) match(b []byte, ttl int, from netip.Addr, now time.Time) (echoEvent, bool) {
	m, ok := parseMessage(e.s.v6, b, from)
	if !ok {
		return echoEvent{}, false
	}
	raw := e.s.kind == kindRaw
	if m.isEchoReply() {
		if m.from != e.dst || (raw && m.id != e.id) || !e.cookieOK(m.payload) {
			return echoEvent{}, false
		}
		return echoEvent{seq: m.seq, at: now, ttl: ttl, bytes: len(b)}, true
	}
	q := m.quoted
	if !m.hasQ || !q.echo || q.dst != e.dst || (raw && q.id != e.id) || !e.cookieOK(q.payload) {
		return echoEvent{}, false
	}
	return echoEvent{seq: q.seq, at: now, err: &icmpError{v6: e.s.v6, from: m.from, typ: m.typ, code: m.code, mtu: m.mtu}}, true
}

func (e *echoSession) drain() {
	now := time.Now()
	for _, q := range drainErrQueue(e.s.conn) {
		if q.local || len(q.payload) < 8 {
			continue // local errors (EMSGSIZE) were already returned by the send that caused them
		}
		ev := echoEvent{seq: binary.BigEndian.Uint16(q.payload[6:8]), at: now,
			err: &icmpError{v6: e.s.v6, from: q.from, typ: q.typ, code: q.code}}
		if isTooBig(e.s.v6, q.typ, q.code) {
			ev.err.mtu = int(q.info)
		}
		e.emit(ev)
	}
}

func (e *echoSession) Close() {
	e.s.Close()
}
