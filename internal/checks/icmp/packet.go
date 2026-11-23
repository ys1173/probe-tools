package icmp

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// ICMP types this package reads. Version 4 and 6 numbers differ, so every helper takes v6.
const (
	v4EchoReply    = 0
	v4DstUnreach   = 3
	v4EchoRequest  = 8
	v4TimeExceeded = 11
	v4ParamProblem = 12

	v6DstUnreach   = 1
	v6PacketTooBig = 2
	v6TimeExceeded = 3
	v6ParamProblem = 4
	v6EchoRequest  = 128
	v6EchoReply    = 129

	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// message is one received ICMP message, parsed only as far as matching needs.
type message struct {
	v6   bool
	from netip.Addr
	typ  int
	code int

	// Echo replies.
	id, seq uint16
	payload []byte

	// Errors: the next-hop MTU when the message carries one, and the start of the packet that caused it.
	mtu    int
	quoted quoted
	hasQ   bool
}

// quoted is the offending packet an ICMP error carries: its IP header and at least the first 8 bytes after it, which
// is enough for ports or the echo id and sequence.
type quoted struct {
	proto            int
	dst              netip.Addr
	srcPort, dstPort uint16 // UDP and TCP
	id, seq          uint16 // ICMP echo
	echo             bool
	payload          []byte // what the router quoted beyond the 8-byte transport header, often nothing
}

// parseMessage parses an ICMP message as the socket returned it: without an IP header (Go strips the IPv4 header on
// raw sockets, and IPv6 sockets never include it).
func parseMessage(v6 bool, b []byte, from netip.Addr) (message, bool) {
	if len(b) < 8 {
		return message{}, false
	}
	m := message{v6: v6, from: from.Unmap().WithZone(""), typ: int(b[0]), code: int(b[1])}
	switch {
	case m.isEchoReply():
		m.id = binary.BigEndian.Uint16(b[4:6])
		m.seq = binary.BigEndian.Uint16(b[6:8])
		m.payload = b[8:]
		return m, true
	case m.isError():
		if !v6 && m.typ == v4DstUnreach && m.code == 4 {
			m.mtu = int(binary.BigEndian.Uint16(b[6:8])) // RFC 1191 next-hop MTU
		}
		if v6 && m.typ == v6PacketTooBig {
			m.mtu = int(binary.BigEndian.Uint32(b[4:8]))
		}
		m.quoted, m.hasQ = parseQuoted(v6, b[8:])
		return m, true
	}
	return message{}, false
}

func (m message) isEchoReply() bool {
	return (!m.v6 && m.typ == v4EchoReply) || (m.v6 && m.typ == v6EchoReply)
}

func (m message) isError() bool {
	if m.v6 {
		return m.typ == v6DstUnreach || m.typ == v6PacketTooBig || m.typ == v6TimeExceeded || m.typ == v6ParamProblem
	}
	return m.typ == v4DstUnreach || m.typ == v4TimeExceeded || m.typ == v4ParamProblem
}

func (m message) isTimeExceeded() bool { return isTimeExceeded(m.v6, m.typ) }

func isTimeExceeded(v6 bool, typ int) bool {
	return (!v6 && typ == v4TimeExceeded) || (v6 && typ == v6TimeExceeded)
}

func isUnreach(v6 bool, typ int) bool {
	return (!v6 && typ == v4DstUnreach) || (v6 && typ == v6DstUnreach)
}

func isPortUnreach(v6 bool, typ, code int) bool {
	return isUnreach(v6, typ) && ((!v6 && code == 3) || (v6 && code == 4))
}

// isTooBig reports "fragmentation needed" (v4) or "packet too big" (v6).
func isTooBig(v6 bool, typ, code int) bool {
	return (!v6 && typ == v4DstUnreach && code == 4) || (v6 && typ == v6PacketTooBig)
}

func parseQuoted(v6 bool, b []byte) (quoted, bool) {
	var q quoted
	var rest []byte
	if v6 {
		// The quoted packet is ours, so it has no extension headers.
		if len(b) < 40 || b[0]>>4 != 6 {
			return q, false
		}
		q.proto = int(b[6])
		q.dst = netip.AddrFrom16([16]byte(b[24:40]))
		rest = b[40:]
	} else {
		if len(b) < 20 || b[0]>>4 != 4 {
			return q, false
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl {
			return q, false
		}
		q.proto = int(b[9])
		q.dst = netip.AddrFrom4([4]byte(b[16:20]))
		rest = b[ihl:]
	}
	if len(rest) < 8 {
		return q, false
	}
	switch q.proto {
	case protoUDP, protoTCP:
		q.srcPort = binary.BigEndian.Uint16(rest[0:2])
		q.dstPort = binary.BigEndian.Uint16(rest[2:4])
	case protoICMP, protoICMPv6:
		if (q.proto == protoICMP && rest[0] == v4EchoRequest) || (q.proto == protoICMPv6 && rest[0] == v6EchoRequest) {
			q.echo = true
			q.id = binary.BigEndian.Uint16(rest[4:6])
			q.seq = binary.BigEndian.Uint16(rest[6:8])
		}
	default:
		return q, false
	}
	q.payload = rest[8:]
	return q, true
}

// describe names an ICMP error the way people say it, e.g. "destination unreachable / host unreachable".
func describe(v6 bool, typ, code int) string {
	if v6 {
		switch typ {
		case v6DstUnreach:
			return "destination unreachable / " + pick(code, []string{"no route to destination", "administratively prohibited",
				"beyond scope of source address", "address unreachable", "port unreachable", "source address failed policy",
				"reject route to destination"})
		case v6PacketTooBig:
			return "packet too big"
		case v6TimeExceeded:
			return "time exceeded / " + pick(code, []string{"hop limit exceeded in transit", "fragment reassembly time exceeded"})
		case v6ParamProblem:
			return "parameter problem"
		}
		return fmt.Sprintf("icmpv6 type %d code %d", typ, code)
	}
	switch typ {
	case v4DstUnreach:
		return "destination unreachable / " + pick(code, []string{"network unreachable", "host unreachable", "protocol unreachable",
			"port unreachable", "fragmentation needed", "source route failed", "destination network unknown",
			"destination host unknown", "source host isolated", "network administratively prohibited",
			"host administratively prohibited", "network unreachable for TOS", "host unreachable for TOS",
			"communication administratively prohibited", "host precedence violation", "precedence cutoff in effect"})
	case v4TimeExceeded:
		return "time exceeded / " + pick(code, []string{"TTL exceeded in transit", "fragment reassembly time exceeded"})
	case v4ParamProblem:
		return "parameter problem"
	}
	return fmt.Sprintf("icmp type %d code %d", typ, code)
}

func pick(code int, names []string) string {
	if code >= 0 && code < len(names) {
		return names[code]
	}
	return fmt.Sprintf("code %d", code)
}
