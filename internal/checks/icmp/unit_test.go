package icmp

import (
	"context"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"probetools/internal/protocol"
)

var (
	src4 = netip.MustParseAddr("192.0.2.1")
	dst4 = netip.MustParseAddr("198.51.100.7")
	rtr4 = netip.MustParseAddr("10.0.0.1")
	src6 = netip.MustParseAddr("2001:db8::1")
	dst6 = netip.MustParseAddr("2001:db8::7")
	rtr6 = netip.MustParseAddr("2001:db8:ffff::1")
)

func ipv4Header(proto int, src, dst netip.Addr, options int) []byte {
	h := make([]byte, 20+options)
	h[0] = 0x40 | byte((20+options)/4)
	h[8] = 1
	h[9] = byte(proto)
	copy(h[12:16], src.AsSlice())
	copy(h[16:20], dst.AsSlice())
	return h
}

func ipv6Header(next int, src, dst netip.Addr) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	h[6] = byte(next)
	h[7] = 1
	copy(h[8:24], src.AsSlice())
	copy(h[24:40], dst.AsSlice())
	return h
}

func ports(src, dst uint16) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint16(b[0:], src)
	binary.BigEndian.PutUint16(b[2:], dst)
	return b
}

func echoHdr(typ byte, id, seq uint16, payload []byte) []byte {
	b := make([]byte, 8)
	b[0] = typ
	binary.BigEndian.PutUint16(b[4:], id)
	binary.BigEndian.PutUint16(b[6:], seq)
	return append(b, payload...)
}

func icmpErr(typ, code byte, rest uint32, quoted []byte) []byte {
	b := make([]byte, 8)
	b[0], b[1] = typ, code
	binary.BigEndian.PutUint32(b[4:], rest)
	return append(b, quoted...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestParseTimeExceededUDP(t *testing.T) {
	// The quoted IPv4 header has options, so the transport header starts after IHL*4 bytes.
	b := icmpErr(v4TimeExceeded, 0, 0, cat(ipv4Header(protoUDP, src4, dst4, 8), ports(40001, 33434)))
	m, ok := parseMessage(false, b, rtr4)
	if !ok || !m.isTimeExceeded() || !m.hasQ || m.quoted.proto != protoUDP || m.quoted.dst != dst4 ||
		m.quoted.srcPort != 40001 || m.quoted.dstPort != 33434 {
		t.Fatalf("parsed %+v", m)
	}
	k, ok := keyFor(m, "udp", dst4, 0)
	if !ok || k != (probeKey{40001, 33434}) {
		t.Fatalf("key %v %v", k, ok)
	}
	if _, ok := keyFor(m, "udp", netip.MustParseAddr("198.51.100.8"), 0); ok {
		t.Fatal("matched a probe to another destination")
	}
	if _, ok := keyFor(m, "tcp", dst4, 0); ok {
		t.Fatal("udp quote matched tcp mode")
	}
	r := classify(m, dst4, "udp", 1500*time.Microsecond)
	if r.final || r.reached || r.Addr != "10.0.0.1" || *r.RTTMS != 1.5 || r.Note != "" {
		t.Fatalf("classify %+v", r)
	}
}

func TestParseFragNeeded(t *testing.T) {
	b := icmpErr(v4DstUnreach, 4, 1400, cat(ipv4Header(protoICMP, src4, dst4, 0), echoHdr(v4EchoRequest, 7, 9, []byte("cookie12"))))
	m, ok := parseMessage(false, b, rtr4)
	if !ok || m.mtu != 1400 || !isTooBig(false, m.typ, m.code) || !m.quoted.echo || m.quoted.id != 7 || m.quoted.seq != 9 ||
		string(m.quoted.payload) != "cookie12" {
		t.Fatalf("parsed %+v", m)
	}
	if got := (icmpError{from: rtr4, typ: m.typ, code: m.code}).String(); got != "destination unreachable / fragmentation needed from 10.0.0.1" {
		t.Fatalf("describe: %q", got)
	}
}

func TestParseV6(t *testing.T) {
	q := cat(ipv6Header(protoICMPv6, src6, dst6), echoHdr(v6EchoRequest, 5, 42, nil))
	m, ok := parseMessage(true, icmpErr(v6TimeExceeded, 0, 0, q), rtr6)
	if !ok || !m.isTimeExceeded() {
		t.Fatalf("parsed %+v", m)
	}
	if k, ok := keyFor(m, "icmp", dst6, 5); !ok || k != (probeKey{5, 42}) {
		t.Fatalf("key %v %v", k, ok)
	}
	if _, ok := keyFor(m, "icmp", dst6, 6); ok {
		t.Fatal("matched another trace's identifier")
	}
	ptb, ok := parseMessage(true, icmpErr(v6PacketTooBig, 0, 1280, q), rtr6)
	if !ok || ptb.mtu != 1280 || !isTooBig(true, ptb.typ, ptb.code) {
		t.Fatalf("packet too big %+v", ptb)
	}
	pu, _ := parseMessage(true, icmpErr(v6DstUnreach, 4, 0, cat(ipv6Header(protoUDP, src6, dst6), ports(50000, 33434))), dst6)
	r := classify(pu, dst6, "udp", time.Millisecond)
	if !r.final || !r.reached || r.Note != "" {
		t.Fatalf("v6 port unreachable from destination: %+v", r)
	}
}

func TestParseEchoReplyAndJunk(t *testing.T) {
	m, ok := parseMessage(false, echoHdr(v4EchoReply, 3, 4, []byte("x")), dst4)
	if !ok || !m.isEchoReply() || m.id != 3 || m.seq != 4 {
		t.Fatalf("parsed %+v", m)
	}
	if k, ok := keyFor(m, "icmp", dst4, 3); !ok || k != (probeKey{3, 4}) {
		t.Fatal("echo reply not matched")
	}
	if _, ok := keyFor(m, "icmp", dst4, 9); ok {
		t.Fatal("echo reply with another id matched")
	}
	r := classify(m, dst4, "icmp", time.Millisecond)
	if !r.final || !r.reached {
		t.Fatalf("classify %+v", r)
	}
	for _, b := range [][]byte{nil, {1, 2, 3}, echoHdr(v4EchoRequest, 1, 1, nil), icmpErr(v4TimeExceeded, 0, 0, []byte{0x45, 0, 0})} {
		if m, ok := parseMessage(false, b, rtr4); ok && m.hasQ {
			t.Fatalf("junk %x parsed with a quote", b)
		}
	}
}

func TestClassifyUnreachable(t *testing.T) {
	q := cat(ipv4Header(protoTCP, src4, dst4, 0), ports(40000, 443))
	m, _ := parseMessage(false, icmpErr(v4DstUnreach, 1, 0, q), rtr4)
	r := classify(m, dst4, "tcp", time.Millisecond)
	if !r.final || r.reached || r.Note != "destination unreachable / host unreachable" {
		t.Fatalf("classify %+v", r)
	}
	m, _ = parseMessage(false, icmpErr(v4DstUnreach, 13, 0, q), dst4)
	r = classify(m, dst4, "tcp", time.Millisecond)
	if !r.final || !r.reached || !strings.Contains(r.Note, "administratively prohibited") {
		t.Fatalf("classify %+v", r)
	}
}

func TestDescribe(t *testing.T) {
	for _, c := range []struct {
		v6        bool
		typ, code int
		want      string
	}{
		{false, 3, 1, "destination unreachable / host unreachable"},
		{false, 11, 0, "time exceeded / TTL exceeded in transit"},
		{false, 3, 99, "destination unreachable / code 99"},
		{true, 1, 4, "destination unreachable / port unreachable"},
		{true, 3, 0, "time exceeded / hop limit exceeded in transit"},
		{true, 200, 1, "icmpv6 type 200 code 1"},
	} {
		if got := describe(c.v6, c.typ, c.code); got != c.want {
			t.Errorf("describe(%v,%d,%d) = %q", c.v6, c.typ, c.code, got)
		}
	}
}

func TestHopFits(t *testing.T) {
	now := time.Now()
	if !hopFits(now, now.Add(1100*time.Millisecond), time.Second, 3) {
		t.Fatal("hop of 1.1 s should fit 1.1 s")
	}
	if hopFits(now, now.Add(1099*time.Millisecond), time.Second, 3) {
		t.Fatal("hop of 1.1 s should not fit 1.099 s")
	}
	// 30 hops of 2 s cannot fit the 40 s budget: the trace must be cut short.
	d := checkDeadline(context.Background(), now)
	n := 0
	for at := now; hopFits(at, d, 2*time.Second, 3); at = at.Add(2*time.Second + 100*time.Millisecond) {
		n++
	}
	if n >= 30 || n < 15 {
		t.Fatalf("%d hops fit the budget", n)
	}
}

func TestCheckDeadline(t *testing.T) {
	now := time.Now()
	if d := checkDeadline(context.Background(), now); d.After(now.Add(40*time.Second)) || d.Before(now.Add(35*time.Second)) {
		t.Fatalf("no ctx deadline: %v", d.Sub(now))
	}
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(5*time.Second))
	defer cancel()
	if d := checkDeadline(ctx, now); d.After(now.Add(5 * time.Second)) {
		t.Fatalf("ctx deadline ignored: %v", d.Sub(now))
	}
}

// fakeMTU answers like a path whose MTU is mtu. hint makes it report the MTU in the too-big answer, silent makes it
// drop large packets without a word.
func fakeMTU(mtu int, hint, silent bool, calls *[]int) func(int) (sizeOutcome, int) {
	return func(size int) (sizeOutcome, int) {
		*calls = append(*calls, size)
		if size <= mtu {
			return sizeFits, 0
		}
		if silent {
			return sizeSilent, 0
		}
		if hint {
			return sizeTooBig, mtu
		}
		return sizeTooBig, 0
	}
}

func always() bool { return true }

func TestSearchMTU(t *testing.T) {
	var calls []int
	r := searchMTU(576, 9000, fakeMTU(1500, false, false, &calls), always)
	if r.mtu != 1500 || r.maxTested != 9000 || len(r.notes) != 0 || len(calls) > 16 {
		t.Fatalf("bisect: %+v after %v", r, calls)
	}

	calls = nil
	r = searchMTU(576, 9000, fakeMTU(1492, true, false, &calls), always)
	if r.mtu != 1492 || len(calls) != 3 { // min, max, then straight to the router's figure
		t.Fatalf("hint: %+v after %v", r, calls)
	}

	calls = nil
	r = searchMTU(576, 1500, fakeMTU(1500, false, false, &calls), always)
	if r.mtu != 1500 || len(calls) != 2 {
		t.Fatalf("max fits: %+v after %v", r, calls)
	}

	calls = nil
	r = searchMTU(576, 1500, fakeMTU(1400, false, true, &calls), always)
	if r.mtu != 1400 || len(r.notes) != 1 || !strings.Contains(r.notes[0], "black hole") {
		t.Fatalf("silent: %+v", r)
	}

	calls = nil
	r = searchMTU(576, 1500, fakeMTU(100, false, true, &calls), always)
	if r.mtu != 0 || len(calls) != 1 || r.notes[0] != "no reply even at minimum size: ICMP may be filtered" {
		t.Fatalf("filtered: %+v", r)
	}

	calls = nil
	budget := 3
	r = searchMTU(576, 9000, fakeMTU(1500, false, false, &calls), func() bool { budget--; return budget >= 0 })
	if len(calls) != 3 || r.mtu < 576 || len(r.notes) != 1 || !strings.Contains(r.notes[0], "stopped early") {
		t.Fatalf("budget: %+v after %v", r, calls)
	}
}

func TestIPOverhead(t *testing.T) {
	if ipOverhead(false) != 28 || ipOverhead(true) != 48 {
		t.Fatal("wrong header sizes")
	}
	// A 1500-byte IPv4 packet carries 1472 bytes of echo payload, the largest ping size the protocol allows.
	if 1500-ipOverhead(false) != 1472 {
		t.Fatal("payload for 1500")
	}
}

func TestStats(t *testing.T) {
	lo, avg, hi, sd := stats([]float64{1, 2, 3, 4})
	if lo != 1 || avg != 2.5 || hi != 4 || sd != 1.118 {
		t.Fatalf("stats %v %v %v %v", lo, avg, hi, sd)
	}
	if lo, avg, hi, sd := stats(nil); lo+avg+hi+sd != 0 {
		t.Fatal("empty stats")
	}
}

func TestSessionMatch(t *testing.T) {
	e := &echoSession{s: &echoSock{kind: kindRaw}, dst: dst4, id: 77}
	copy(e.cookie[:], "ABCDEFGH")
	now := time.Now()
	good := echoHdr(v4EchoReply, 77, 5, []byte("ABCDEFGHrest"))
	if ev, ok := e.match(good, 60, dst4, now); !ok || ev.seq != 5 || ev.ttl != 60 || ev.err != nil {
		t.Fatalf("good reply: %+v %v", ev, ok)
	}
	if _, ok := e.match(good, 60, rtr4, now); ok {
		t.Fatal("reply from another host matched")
	}
	if _, ok := e.match(echoHdr(v4EchoReply, 78, 5, []byte("ABCDEFGH")), 60, dst4, now); ok {
		t.Fatal("reply with another id matched on a raw socket")
	}
	if _, ok := e.match(echoHdr(v4EchoReply, 77, 5, []byte("XXXXXXXX")), 60, dst4, now); ok {
		t.Fatal("reply with another cookie matched")
	}
	// Datagram sockets: Linux rewrote the id, so it is not checked.
	e.s.kind = kindDgram
	if _, ok := e.match(echoHdr(v4EchoReply, 1234, 5, []byte("ABCDEFGH")), 60, dst4, now); !ok {
		t.Fatal("datagram reply with kernel id not matched")
	}
	e.s.kind = kindRaw
	unreach := icmpErr(v4DstUnreach, 1, 0, cat(ipv4Header(protoICMP, src4, dst4, 0), echoHdr(v4EchoRequest, 77, 6, nil)))
	ev, ok := e.match(unreach, 0, rtr4, now)
	if !ok || ev.seq != 6 || ev.err == nil || ev.err.String() != "destination unreachable / host unreachable from 10.0.0.1" {
		t.Fatalf("error: %+v %v", ev, ok)
	}
}

func TestOpenEchoRuledOut(t *testing.T) {
	_, err := openEcho(false, map[string]bool{"raw_icmp": false, "unpriv_icmp": false})
	if err == nil || err.Code != protocol.CodeUnavailable || !strings.Contains(err.Message, "NET_RAW") ||
		!strings.Contains(err.Message, "ping_group_range") {
		t.Fatalf("got %v", err)
	}
}
