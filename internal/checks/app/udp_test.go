package app

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"

	"probetools/internal/protocol"
)

// udpServer answers each datagram with reply(req); a nil reply sends nothing.
func udpServer(t *testing.T, ip netip.Addr, reply func([]byte) []byte) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if out := reply(append([]byte(nil), buf[:n]...)); out != nil {
				pc.WriteTo(out, from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func TestUDPDNSQuery(t *testing.T) {
	ip := hostIP(t)
	port := udpServer(t, ip, func(b []byte) []byte {
		q := new(dns.Msg)
		if q.Unpack(b) != nil || len(q.Question) != 1 || q.Question[0].Name != "." || q.Question[0].Qtype != dns.TypeNS {
			return nil
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Answer = append(r.Answer, &dns.NS{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60}, Ns: "a.root-servers.net."})
		out, _ := r.Pack()
		return out
	})
	m := mustRun(t, udpProbe, testEnv(t, nil), protocol.UDPProbeParams{Target: ip.String(), Port: port, Template: "dns_query"})
	if m["outcome"] != "open" || m["rcode"] != "NOERROR" || m["answer_count"] != float64(1) || m["attempts"] != float64(1) {
		t.Fatalf("result: %v", m)
	}
}

func TestUDPWrongIDIsNotAValidReply(t *testing.T) {
	ip := hostIP(t)
	port := udpServer(t, ip, func(b []byte) []byte {
		q := new(dns.Msg)
		if q.Unpack(b) != nil {
			return nil
		}
		r := new(dns.Msg)
		r.SetReply(q)
		r.Id = q.Id + 1
		out, _ := r.Pack()
		return out
	})
	m := mustRun(t, udpProbe, testEnv(t, nil), protocol.UDPProbeParams{Target: ip.String(), Port: port, Template: "dns_query", TimeoutMS: 300})
	if m["outcome"] != "unexpected_reply" {
		t.Fatalf("result: %v", m)
	}
}

func TestUDPSilenceIsOpenOrFiltered(t *testing.T) {
	ip := hostIP(t)
	port := udpServer(t, ip, func([]byte) []byte { return nil })
	m := mustRun(t, udpProbe, testEnv(t, nil), protocol.UDPProbeParams{Target: ip.String(), Port: port, Template: "ntp_request", TimeoutMS: 300, Retries: new(1)})
	if m["outcome"] != "open_or_filtered" || m["attempts"] != float64(2) {
		t.Fatalf("result: %v", m)
	}
}

// retries is documented to default to 1; leaving it out must give two sends, and an explicit 0 one.
func TestUDPRetriesDefault(t *testing.T) {
	ip := hostIP(t)
	port := udpServer(t, ip, func([]byte) []byte { return nil })
	m := mustRun(t, udpProbe, testEnv(t, nil), map[string]any{"target": ip.String(), "port": port, "template": "dns_query", "timeout_ms": 200})
	if m["attempts"] != float64(2) {
		t.Fatalf("default: %v", m)
	}
	m = mustRun(t, udpProbe, testEnv(t, nil), map[string]any{"target": ip.String(), "port": port, "template": "dns_query", "timeout_ms": 200, "retries": 0})
	if m["attempts"] != float64(1) {
		t.Fatalf("explicit 0: %v", m)
	}
}

func TestUDPRefusedIsClosed(t *testing.T) {
	ip := hostIP(t)
	m := mustRun(t, udpProbe, testEnv(t, nil), protocol.UDPProbeParams{Target: ip.String(), Port: freePort(t, ip, "udp"), Template: "dns_query", TimeoutMS: 2000})
	if m["outcome"] != "closed" {
		t.Fatalf("result: %v", m)
	}
}

func TestUDPDenied(t *testing.T) {
	_, perr := runCheck(t, udpProbe, testEnv(t, nil), protocol.UDPProbeParams{Target: "169.254.169.254", Template: "ntp_request"})
	wantCode(t, perr, protocol.CodeDenied)
}

func ntpReply(req []byte, stratum byte, refID []byte, skew time.Duration) []byte {
	if len(req) < 48 {
		return nil
	}
	b := make([]byte, 48)
	b[0] = 0<<6 | 4<<3 | 4
	b[1] = stratum
	copy(b[12:16], refID)
	copy(b[24:32], req[40:48]) // origin = the client's transmit timestamp
	now := time.Now().Add(skew)
	binary.BigEndian.PutUint64(b[32:40], toNTP(now))
	binary.BigEndian.PutUint64(b[40:48], toNTP(now))
	return b
}

func TestUDPNTP(t *testing.T) {
	ip := hostIP(t)
	port := udpServer(t, ip, func(b []byte) []byte { return ntpReply(b, 2, []byte{192, 0, 2, 7}, 5*time.Second) })
	m := mustRun(t, udpProbe, testEnv(t, nil), protocol.UDPProbeParams{Target: ip.String(), Port: port, Template: "ntp_request"})
	if m["outcome"] != "open" || m["stratum"] != float64(2) || untrustedText(t, m["reference_id"]) != "192.0.2.7" {
		t.Fatalf("result: %v", m)
	}
	if off, _ := m["offset_ms"].(float64); off < 4900 || off > 5100 {
		t.Fatalf("offset %v, want about 5000", m["offset_ms"])
	}

	port = udpServer(t, ip, func(b []byte) []byte { return ntpReply(b, 1, []byte("G\x1bS\x00"), 0) })
	m = mustRun(t, udpProbe, testEnv(t, nil), protocol.UDPProbeParams{Target: ip.String(), Port: port, Template: "ntp_request"})
	if ref := untrustedText(t, m["reference_id"]); ref != `G\u001bS` {
		t.Fatalf("reference id %q", ref)
	}

	// A reply whose origin timestamp is not ours is not an answer to our request.
	port = udpServer(t, ip, func(b []byte) []byte {
		r := ntpReply(b, 2, nil, 0)
		r[25] ^= 0xff
		return r
	})
	m = mustRun(t, udpProbe, testEnv(t, nil), protocol.UDPProbeParams{Target: ip.String(), Port: port, Template: "ntp_request", TimeoutMS: 300})
	if m["outcome"] != "unexpected_reply" {
		t.Fatalf("spoofed origin: %v", m)
	}
}

func TestNTPTime(t *testing.T) {
	now := time.Date(2040, 3, 1, 12, 0, 0, 500_000_000, time.UTC) // after the 2036 era rollover
	if got := fromNTP(toNTP(now)); got.Sub(now).Abs() > time.Microsecond {
		t.Fatalf("round trip %v -> %v", now, got)
	}
}

// The request matches the RFC 3414 engine discovery message byte for byte (version 3; msgID; max size 65507; flags
// reportable, noAuthNoPriv; USM; empty engine ID, boots, time, user, auth and privacy parameters; an empty GetRequest),
// written out and checked field by field, for msgID 0x4a69 and request-id 0x37f0.
func TestSNMPDiscoveryEncoding(t *testing.T) {
	want, _ := hex.DecodeString("303a020103300f02024a69020300ffe3040104020103041030" +
		"0e0400020100020100040004000400301204000400a00c020237f00201000201003000")
	if got := snmpDiscoveryRequest(0x4a69, 0x37f0); !bytes.Equal(got, want) {
		t.Fatalf("encoding\n got % x\nwant % x", got, want)
	}
	for _, v := range []int64{0, 1, 127, 128, 255, 256, 65507, -1, -128, -129, 1<<31 - 1} {
		_, c, _, err := berNext(berInt(v))
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := berNextInt(berTLV(0x02, c))
		if err != nil || got != v {
			t.Fatalf("int %d round trip: %d %v", v, got, err)
		}
	}
}

func snmpReport(msgID int64, engineID []byte, boots, etime int64) []byte {
	usm := berSeq(berOctets(engineID), berInt(boots), berInt(etime), berOctets(nil), berOctets(nil), berOctets(nil))
	// usmStatsUnknownEngineIDs.0 = Counter32 1
	oid := []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x04, 0x00}
	vb := berSeq(berSeq(oid, berTLV(0x41, []byte{1})))
	pdu := berTLV(0xa8, concat(berInt(7), berInt(0), berInt(0), vb))
	scoped := berSeq(berOctets(engineID), berOctets(nil), pdu)
	global := berSeq(berInt(msgID), berInt(65507), berOctets([]byte{0x00}), berInt(3))
	return berSeq(berInt(3), global, berOctets(usm), scoped)
}

func TestUDPSNMPv3Discovery(t *testing.T) {
	ip := hostIP(t)
	engine, _ := hex.DecodeString("80001f888059dc486145a26314")
	port := udpServer(t, ip, func(b []byte) []byte {
		d, err := parseRequestMsgID(b)
		if err != nil {
			return nil
		}
		return snmpReport(d, engine, 12, 345678)
	})
	m := mustRun(t, udpProbe, testEnv(t, nil), protocol.UDPProbeParams{Target: ip.String(), Port: port, Template: "snmp_v3_discovery"})
	if m["outcome"] != "open" || m["engine_id"] != hex.EncodeToString(engine) || m["engine_boots"] != float64(12) ||
		m["engine_time"] != float64(345678) || m["pdu_type"] != "report" {
		t.Fatalf("result: %v", m)
	}
}

// parseRequestMsgID reads the msgID from a request, as an agent would.
func parseRequestMsgID(b []byte) (int64, error) {
	_, msg, _, err := berNext(b)
	if err != nil {
		return 0, err
	}
	_, msg, err = berNextInt(msg)
	if err != nil {
		return 0, err
	}
	_, global, _, err := berNext(msg)
	if err != nil {
		return 0, err
	}
	id, _, err := berNextInt(global)
	return id, err
}

func TestSNMPParserRejectsDamage(t *testing.T) {
	good := snmpReport(99, []byte{1, 2, 3}, 1, 2)
	if _, err := parseSNMPDiscovery(good); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(good); i++ {
		parseSNMPDiscovery(good[:i]) // must not panic
		bad := append([]byte(nil), good...)
		for _, v := range []byte{0x00, 0x7f, 0x80, 0x84, 0xff} {
			bad[i] = v
			parseSNMPDiscovery(bad)
		}
	}
	if _, err := parseSNMPDiscovery([]byte{0x30, 0x84, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("a length past the end must be refused")
	}
}
