package app

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

type udpResult struct {
	Target   string  `json:"target"`
	Address  string  `json:"address"`
	Port     int     `json:"port"`
	Template string  `json:"template"`
	Outcome  string  `json:"outcome"` // open | closed | open_or_filtered | unexpected_reply | error
	RTTMS    float64 `json:"rtt_ms,omitempty"`
	Attempts int     `json:"attempts"`
	Detail   string  `json:"detail,omitempty"`

	// dns_query
	Rcode         string `json:"rcode,omitempty"`
	AnswerCount   *int   `json:"answer_count,omitempty"`
	Authoritative *bool  `json:"authoritative,omitempty"`
	// ntp_request
	Version       *int                `json:"version,omitempty"`
	Stratum       *int                `json:"stratum,omitempty"`
	LeapIndicator *int                `json:"leap_indicator,omitempty"`
	ReferenceID   *protocol.Untrusted `json:"reference_id,omitempty"` // ASCII from the server at stratum 0 and 1
	KissCode      *protocol.Untrusted `json:"kiss_code,omitempty"`    // stratum 0: the server refused to give the time
	OffsetMS      *float64            `json:"offset_ms,omitempty"`
	DelayMS       *float64            `json:"delay_ms,omitempty"`
	// snmp_v3_discovery
	EngineID    string `json:"engine_id,omitempty"` // hex
	EngineBoots *int64 `json:"engine_boots,omitempty"`
	EngineTime  *int64 `json:"engine_time,omitempty"`
	PDUType     string `json:"pdu_type,omitempty"`
}

// udpTemplate builds a fresh request for each attempt and recognises a reply to any request it built, so a late reply
// to the first attempt still counts.
type udpTemplate interface {
	request(now time.Time) ([]byte, error)
	// parse fills res from reply and returns when the matching request was sent; ok is false when the reply does not
	// answer any request this template built.
	parse(reply []byte, received time.Time, res *udpResult) (sent time.Time, ok bool)
}

func udpProbe(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.UDPProbeParams
	if e := check.Decode(raw, &p); e != nil {
		return nil, e
	}
	addr, e := resolveTarget(ctx, env, p.Target, p.Family)
	if e != nil {
		return nil, e
	}
	res := &udpResult{Target: p.Target, Address: addr.String(), Port: p.Port, Template: p.Template}
	var tmpl udpTemplate
	switch p.Template {
	case protocol.TemplateDNSQuery:
		tmpl = &dnsTemplate{sent: map[uint16]time.Time{}}
	case protocol.TemplateNTPRequest:
		tmpl = &ntpTemplate{sent: map[uint64]time.Time{}}
	case protocol.TemplateSNMPv3Discovery:
		tmpl = &snmpTemplate{sent: map[int64]time.Time{}}
	}

	conn, err := dialChecked(ctx, &net.Dialer{}, "udp", addr, p.Port)
	if err != nil {
		res.Outcome, res.Detail = "error", err.Error()
		return res, nil
	}
	defer conn.Close()
	stop := watch(ctx, conn)
	defer stop()

	buf := make([]byte, 4096)
	gotOther := false
	for attempt := 0; attempt <= *p.Retries && ctx.Err() == nil; attempt++ {
		pkt, err := tmpl.request(time.Now())
		if err != nil {
			return nil, protocol.Errorf(protocol.CodeInternal, "building the request: %v", err)
		}
		res.Attempts++
		if _, err := conn.Write(pkt); err != nil {
			if errors.Is(err, syscall.ECONNREFUSED) {
				res.Outcome = "closed"
				return res, nil
			}
			res.Outcome, res.Detail = "error", err.Error()
			return res, nil
		}
		deadline := within(ctx, millis(p.TimeoutMS))
		for {
			_ = conn.SetReadDeadline(deadline)
			n, err := conn.Read(buf)
			received := time.Now()
			if err != nil {
				if errors.Is(err, syscall.ECONNREFUSED) {
					// An ICMP port unreachable came back: the host is there and nothing listens on the port.
					res.Outcome = "closed"
					return res, nil
				}
				if isTimeout(err) {
					break
				}
				res.Outcome, res.Detail = "error", err.Error()
				return res, nil
			}
			if sent, ok := tmpl.parse(buf[:n], received, res); ok {
				res.Outcome = "open"
				res.RTTMS = msOf(received.Sub(sent))
				return res, nil
			}
			gotOther = true
		}
	}
	if gotOther {
		res.Outcome = "unexpected_reply"
		res.Detail = "datagrams came back but none was a valid reply to the request"
	} else {
		// Silence is never "closed": a firewall that drops the request looks the same as a service that ignores it.
		res.Outcome = "open_or_filtered"
	}
	return res, nil
}

// --- dns_query: a query for the root NS set, matched on its random ID.

type dnsTemplate struct{ sent map[uint16]time.Time }

func (t *dnsTemplate) request(now time.Time) ([]byte, error) {
	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeNS)
	m.Id = dns.Id()
	t.sent[m.Id] = now
	return m.Pack()
}

func (t *dnsTemplate) parse(reply []byte, _ time.Time, res *udpResult) (time.Time, bool) {
	r := new(dns.Msg)
	if err := r.Unpack(reply); err != nil || !r.Response {
		return time.Time{}, false
	}
	sent, ok := t.sent[r.Id]
	if !ok {
		return time.Time{}, false
	}
	res.Rcode = dns.RcodeToString[r.Rcode]
	n := len(r.Answer)
	res.AnswerCount = &n
	auth := r.Authoritative
	res.Authoritative = &auth
	return sent, true
}

// --- ntp_request: an NTPv4 client packet; the reply must echo our transmit timestamp as its origin timestamp.

const ntpEpochOffset = 2208988800 // seconds from 1900-01-01 to 1970-01-01

type ntpTemplate struct{ sent map[uint64]time.Time }

func (t *ntpTemplate) request(now time.Time) ([]byte, error) {
	b := make([]byte, 48)
	b[0] = 0<<6 | 4<<3 | 3 // leap 0, version 4, mode 3 (client)
	ts := toNTP(now)
	binary.BigEndian.PutUint64(b[40:48], ts)
	t.sent[ts] = now
	return b, nil
}

func (t *ntpTemplate) parse(b []byte, received time.Time, res *udpResult) (time.Time, bool) {
	if len(b) < 48 || b[0]&7 != 4 { // mode 4: server
		return time.Time{}, false
	}
	t1, ok := t.sent[binary.BigEndian.Uint64(b[24:32])]
	if !ok {
		return time.Time{}, false
	}
	version := int(b[0]>>3) & 7
	leap := int(b[0] >> 6)
	stratum := int(b[1])
	res.Version, res.LeapIndicator, res.Stratum = &version, &leap, &stratum
	refID := b[12:16]
	if stratum <= 1 {
		// At stratum 0 and 1 the reference id is four ASCII characters chosen by the server.
		text := protocol.UntrustedString(strings.TrimRight(string(refID), "\x00"), 16)
		res.ReferenceID = &text
		if stratum == 0 {
			res.KissCode = &text
			return t1, true // a kiss-o'-death carries no usable time
		}
	} else {
		text := protocol.UntrustedString(net.IP(refID).String(), 16)
		res.ReferenceID = &text
	}
	t2 := fromNTP(binary.BigEndian.Uint64(b[32:40]))
	t3 := fromNTP(binary.BigEndian.Uint64(b[40:48]))
	offset := msOf((t2.Sub(t1) + t3.Sub(received)) / 2)
	delay := msOf(received.Sub(t1) - t3.Sub(t2))
	res.OffsetMS, res.DelayMS = &offset, &delay
	return t1, true
}

func toNTP(t time.Time) uint64 {
	secs := uint64(t.Unix()+ntpEpochOffset) & 0xffffffff
	frac := (uint64(t.Nanosecond()) << 32) / 1e9
	return secs<<32 | frac
}

func fromNTP(v uint64) time.Time {
	secs := int64(v >> 32)
	if secs < 0x80000000 {
		secs += 1 << 32 // era 1 starts in 2036; a value this small cannot be in the 1900s
	}
	nanos := int64((v & 0xffffffff) * 1e9 >> 32)
	return time.Unix(secs-ntpEpochOffset, nanos)
}

// --- snmp_v3_discovery: an SNMPv3 GetRequest with noAuthNoPriv, the reportable flag, an empty engine ID and an empty
// user. An agent answers with a Report PDU carrying its engine ID, boots and time (RFC 3414 section 4). No community,
// user or key is sent.

type snmpTemplate struct{ sent map[int64]time.Time }

func randInt31() (int64, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<31-1))
	if err != nil {
		return 0, err
	}
	return n.Int64() + 1, nil
}

func (t *snmpTemplate) request(now time.Time) ([]byte, error) {
	msgID, err := randInt31()
	if err != nil {
		return nil, err
	}
	reqID, err := randInt31()
	if err != nil {
		return nil, err
	}
	t.sent[msgID] = now
	return snmpDiscoveryRequest(msgID, reqID), nil
}

func snmpDiscoveryRequest(msgID, reqID int64) []byte {
	usm := berSeq(berOctets(nil), berInt(0), berInt(0), berOctets(nil), berOctets(nil), berOctets(nil))
	pdu := berTLV(0xa0, concat(berInt(reqID), berInt(0), berInt(0), berSeq())) // GetRequest, no variable bindings
	scoped := berSeq(berOctets(nil), berOctets(nil), pdu)
	global := berSeq(berInt(msgID), berInt(65507), berOctets([]byte{0x04}), berInt(3)) // reportable; USM
	return berSeq(berInt(3), global, berOctets(usm), scoped)
}

func (t *snmpTemplate) parse(b []byte, _ time.Time, res *udpResult) (time.Time, bool) {
	d, err := parseSNMPDiscovery(b)
	if err != nil {
		return time.Time{}, false
	}
	sent, ok := t.sent[d.msgID]
	if !ok {
		return time.Time{}, false
	}
	res.EngineID = hex.EncodeToString(d.engineID)
	res.EngineBoots, res.EngineTime = &d.boots, &d.time
	res.PDUType = d.pduType
	return sent, true
}

type snmpDiscovery struct {
	msgID       int64
	engineID    []byte
	boots, time int64
	pduType     string
}

var errBER = errors.New("malformed BER")

func parseSNMPDiscovery(b []byte) (*snmpDiscovery, error) {
	tag, msg, _, err := berNext(b)
	if err != nil || tag != 0x30 {
		return nil, errBER
	}
	version, msg, err := berNextInt(msg)
	if err != nil || version != 3 {
		return nil, errBER
	}
	tag, global, msg, err := berNext(msg)
	if err != nil || tag != 0x30 {
		return nil, errBER
	}
	d := &snmpDiscovery{}
	if d.msgID, _, err = berNextInt(global); err != nil {
		return nil, err
	}
	tag, secParams, msg, err := berNext(msg)
	if err != nil || tag != 0x04 {
		return nil, errBER
	}
	tag, usm, _, err := berNext(secParams)
	if err != nil || tag != 0x30 {
		return nil, errBER
	}
	tag, engineID, usm, err := berNext(usm)
	if err != nil || tag != 0x04 || len(engineID) > 64 {
		return nil, errBER
	}
	d.engineID = engineID
	if d.boots, usm, err = berNextInt(usm); err != nil {
		return nil, err
	}
	if d.time, _, err = berNextInt(usm); err != nil {
		return nil, err
	}
	// The scoped PDU is plaintext for noAuthNoPriv; its PDU tag says whether the agent sent a Report.
	if tag, scoped, _, err := berNext(msg); err == nil && tag == 0x30 {
		if _, _, scoped, err = berNext(scoped); err == nil { // contextEngineID
			if _, _, scoped, err = berNext(scoped); err == nil { // contextName
				if tag, _, _, err = berNext(scoped); err == nil {
					d.pduType = map[byte]string{0xa2: "response", 0xa8: "report"}[tag]
					if d.pduType == "" {
						d.pduType = "other"
					}
				}
			}
		}
	}
	return d, nil
}

// berNext splits the first TLV off b. Only single-byte tags and definite lengths of up to four bytes are accepted, and
// every length is checked against what remains.
func berNext(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 || b[0]&0x1f == 0x1f {
		return 0, nil, nil, errBER
	}
	tag = b[0]
	l := int(b[1])
	i := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return 0, nil, nil, errBER
		}
		l = 0
		for ; n > 0; n-- {
			l = l<<8 | int(b[i])
			i++
		}
	}
	if l < 0 || l > len(b)-i {
		return 0, nil, nil, errBER
	}
	return tag, b[i : i+l], b[i+l:], nil
}

func berNextInt(b []byte) (int64, []byte, error) {
	tag, c, rest, err := berNext(b)
	if err != nil || tag != 0x02 || len(c) == 0 || len(c) > 8 {
		return 0, nil, errBER
	}
	v := int64(int8(c[0])) // sign-extend the first byte
	for _, x := range c[1:] {
		v = v<<8 | int64(x)
	}
	return v, rest, nil
}

func berTLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	n := len(content)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func berInt(v int64) []byte {
	var c []byte
	for {
		c = append([]byte{byte(v)}, c...)
		next := v >> 8
		// Stop once the remaining bits are pure sign extension of the byte just written.
		if (next == 0 && c[0]&0x80 == 0) || (next == -1 && c[0]&0x80 != 0) {
			break
		}
		v = next
	}
	return berTLV(0x02, c)
}

func berOctets(b []byte) []byte     { return berTLV(0x04, b) }
func berSeq(parts ...[]byte) []byte { return berTLV(0x30, concat(parts...)) }

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
