package app

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

// systemResolvers lists the probe's own resolvers as host:port. They are the operator's configuration, not targets, so
// they are not checked against the policy (inside Docker the resolver is 127.0.0.11, which the policy always refuses).
// Tests replace it so they never leave the test host.
var systemResolvers = func() ([]string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, s := range cfg.Servers {
		out = append(out, net.JoinHostPort(s, cfg.Port))
	}
	return out, nil
}

const (
	maxDNSRecords = 100 // per section; a bigger answer is cut, and the result says so
	maxNameLen    = 300 // presentation form of a name, escapes included
	dnsUDPSize    = 1232
	maxResolvers  = 3
)

type dnsRecord struct {
	// Name is the record's owner name. The server chooses it (a CNAME chain or an authority record can name anything),
	// and a label can hold any text, so it is untrusted.
	Name protocol.Untrusted `json:"name"`
	Type string             `json:"type"`
	TTL  uint32             `json:"ttl"`
	// Data is a plain string for A and AAAA, which can only be addresses, and a protocol.Untrusted for everything else:
	// names (CNAME, NS, PTR), records that contain names (MX, SRV, SOA, written as in a zone file) and free text (TXT,
	// CAA and any other type).
	Data any `json:"data"`
}

type dnsResult struct {
	Name              string      `json:"name"`
	Type              string      `json:"type"`
	Server            string      `json:"server"`
	Transport         string      `json:"transport"`
	Outcome           string      `json:"outcome"` // ok (a reply came, whatever its rcode) | timeout | refused | unreachable | error
	Detail            string      `json:"detail,omitempty"`
	Rcode             string      `json:"rcode,omitempty"`
	Authoritative     bool        `json:"authoritative"`
	Truncated         bool        `json:"truncated"`
	RetriedTCP        bool        `json:"retried_tcp,omitempty"` // the UDP reply was truncated and the query was repeated over TCP
	AuthenticatedData bool        `json:"authenticated_data"`
	RTTMS             float64     `json:"rtt_ms"`
	Answers           []dnsRecord `json:"answers"`
	Authority         []dnsRecord `json:"authority,omitempty"`
	RecordsCut        bool        `json:"records_cut,omitempty"`
}

func dnsLookup(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.DNSLookupParams
	if e := check.Decode(raw, &p); e != nil {
		return nil, e
	}
	qname, qtype, e := dnsQuestion(p.Name, p.Type)
	if e != nil {
		return nil, e
	}
	servers, viaPolicy, e := dnsServers(ctx, env, p.Server)
	if e != nil {
		return nil, e
	}

	m := new(dns.Msg)
	m.SetQuestion(qname, qtype)
	m.RecursionDesired = true
	// Setting AD in the query asks a validating resolver to report whether it validated the answer (RFC 6840 5.7).
	m.AuthenticatedData = true
	m.SetEdns0(dnsUDPSize, false)

	res := &dnsResult{Name: qname, Type: dns.TypeToString[qtype], Answers: []dnsRecord{}}
	timeout := millis(p.TimeoutMS)
	for _, server := range servers {
		res.Server = server
		r, rtt, transport, retried, err := dnsExchange(ctx, env, viaPolicy, server, m, p.TCP, timeout)
		res.Transport = transport
		if err != nil {
			if isDenied(err) || isCode(err, protocol.CodeBusy) {
				return nil, err.(*protocol.Error)
			}
			res.Outcome = dialOutcome(err)
			res.Detail = err.Error()
			if ctx.Err() != nil {
				break
			}
			continue // only the probe's own resolvers give more than one server to try
		}
		res.Outcome, res.Detail = "ok", ""
		res.RetriedTCP = retried
		res.Rcode = dns.RcodeToString[r.Rcode]
		if res.Rcode == "" {
			res.Rcode = strconv.Itoa(r.Rcode)
		}
		res.Authoritative = r.Authoritative
		res.Truncated = r.Truncated
		res.AuthenticatedData = r.AuthenticatedData
		res.RTTMS = msOf(rtt)
		var cut1, cut2 bool
		res.Answers, cut1 = dnsRecords(r.Answer)
		res.Authority, cut2 = dnsRecords(r.Ns)
		res.RecordsCut = cut1 || cut2
		break
	}
	return res, nil
}

// dnsQuestion turns the requested name and type into a query. An IP address with no type (or type PTR) becomes a PTR
// query for its reverse name.
func dnsQuestion(name, typ string) (string, uint16, *protocol.Error) {
	if a, err := netip.ParseAddr(strings.Trim(name, "[]")); err == nil && (typ == "" || typ == "PTR") {
		rev, err := dns.ReverseAddr(a.String())
		if err != nil {
			return "", 0, protocol.Errorf(protocol.CodeInvalidParams, "cannot build a reverse name for %s", a)
		}
		return rev, dns.TypePTR, nil
	}
	if typ == "" {
		typ = "A"
	}
	qtype, ok := dns.StringToType[typ]
	if !ok {
		return "", 0, protocol.Errorf(protocol.CodeInvalidParams, "type %q is not supported", typ)
	}
	fq := dns.Fqdn(name)
	if _, ok := dns.IsDomainName(fq); !ok {
		return "", 0, protocol.Errorf(protocol.CodeInvalidParams, "%q is not a valid DNS name", name)
	}
	return fq, qtype, nil
}

// dnsServers returns the servers to ask, and whether they are targets that must be reached through the policy.
func dnsServers(ctx context.Context, env *check.Env, server string) ([]string, bool, *protocol.Error) {
	server = strings.TrimSpace(server)
	if server == "" {
		list, err := systemResolvers()
		if err != nil || len(list) == 0 {
			return nil, false, protocol.Errorf(protocol.CodeUnavailable, "this probe has no resolvers configured in /etc/resolv.conf")
		}
		if len(list) > maxResolvers {
			list = list[:maxResolvers]
		}
		return list, false, nil
	}
	ap, err := netip.ParseAddrPort(server)
	if err != nil {
		a, err2 := netip.ParseAddr(strings.Trim(server, "[]"))
		if err2 != nil {
			return nil, false, protocol.Errorf(protocol.CodeInvalidParams, "server must be an IP address or ip:port, not a name")
		}
		ap = netip.AddrPortFrom(a, 53)
	}
	if ap.Port() == 0 {
		return nil, false, protocol.Errorf(protocol.CodeInvalidParams, "server port must be 1 to 65535")
	}
	ap = netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
	if d := env.Policy.Allowed("", ap.Addr()); d != nil {
		return nil, false, d
	}
	// An explicit server is a target like any other, so it counts against its rate limit. The probe's own resolvers
	// above are its configuration and are not charged.
	if b := env.Policy.Charge(ctx, ap.Addr()); b != nil {
		return nil, false, b
	}
	return []string{ap.String()}, true, nil
}

// dnsExchange sends m to server, repeating the query over TCP when the UDP reply is truncated. If the TCP retry fails,
// the truncated UDP reply is still returned: it is an answer, and the result says it was truncated.
func dnsExchange(ctx context.Context, env *check.Env, viaPolicy bool, server string, m *dns.Msg, useTCP bool, timeout time.Duration) (*dns.Msg, time.Duration, string, bool, error) {
	transport := "udp"
	if useTCP {
		transport = "tcp"
	}
	r, rtt, err := dnsExchangeOnce(ctx, env, viaPolicy, transport, server, m, timeout)
	if err != nil || !r.Truncated || transport == "tcp" {
		return r, rtt, transport, false, err
	}
	r2, rtt2, err2 := dnsExchangeOnce(ctx, env, viaPolicy, "tcp", server, m, timeout)
	if err2 != nil {
		return r, rtt, "udp", false, nil
	}
	return r2, rtt2, "tcp", true, nil
}

func dnsExchangeOnce(ctx context.Context, env *check.Env, viaPolicy bool, network, server string, m *dns.Msg, timeout time.Duration) (*dns.Msg, time.Duration, error) {
	qctx, cancel := context.WithDeadline(ctx, within(ctx, timeout))
	defer cancel()
	var conn net.Conn
	var err error
	if viaPolicy {
		conn, err = env.Policy.DialContext(qctx, &net.Dialer{}, network, server)
	} else {
		conn, err = (&net.Dialer{}).DialContext(qctx, network, server)
	}
	if err != nil {
		return nil, 0, err
	}
	defer conn.Close()
	stop := watch(qctx, conn)
	defer stop()
	c := &dns.Client{Net: network, Timeout: timeout, UDPSize: dnsUDPSize}
	r, rtt, err := c.ExchangeWithConnContext(qctx, m, &dns.Conn{Conn: conn, UDPSize: dnsUDPSize})
	if err != nil {
		return nil, 0, err
	}
	return r, rtt, nil
}

// dnsRecords converts a section to records, cutting it at maxDNSRecords.
func dnsRecords(rrs []dns.RR) ([]dnsRecord, bool) {
	cut := false
	if len(rrs) > maxDNSRecords {
		rrs, cut = rrs[:maxDNSRecords], true
	}
	out := make([]dnsRecord, 0, len(rrs))
	for _, rr := range rrs {
		h := rr.Header()
		typ := dns.TypeToString[h.Rrtype]
		if typ == "" {
			typ = dns.Type(h.Rrtype).String()
		}
		rec := dnsRecord{Name: untrustedName(h.Name), Type: typ, TTL: h.Ttl}
		switch v := rr.(type) {
		case *dns.A:
			rec.Data = v.A.String()
		case *dns.AAAA:
			rec.Data = v.AAAA.String()
		case *dns.CNAME:
			rec.Data = untrustedName(v.Target)
		case *dns.NS:
			rec.Data = untrustedName(v.Ns)
		case *dns.PTR:
			rec.Data = untrustedName(v.Ptr)
		case *dns.MX:
			rec.Data = protocol.UntrustedString(fmt.Sprintf("%d %s", v.Preference, capPlain(v.Mx, maxNameLen)), protocol.MaxRecordBytes)
		case *dns.SRV:
			rec.Data = protocol.UntrustedString(fmt.Sprintf("%d %d %d %s", v.Priority, v.Weight, v.Port, capPlain(v.Target, maxNameLen)),
				protocol.MaxRecordBytes)
		case *dns.SOA:
			rec.Data = protocol.UntrustedString(fmt.Sprintf("%s %s %d %d %d %d %d", capPlain(v.Ns, maxNameLen), capPlain(v.Mbox, maxNameLen),
				v.Serial, v.Refresh, v.Retry, v.Expire, v.Minttl), protocol.MaxRecordBytes)
		case *dns.TXT:
			// Long TXT values (SPF, DKIM) are split into strings that consumers join without a separator.
			rec.Data = protocol.UntrustedString(strings.Join(v.Txt, ""), protocol.MaxRecordBytes)
		case *dns.CAA:
			rec.Data = protocol.UntrustedString(fmt.Sprintf("%d %s %q", v.Flag, v.Tag, v.Value), protocol.MaxRecordBytes)
		default:
			rec.Data = protocol.UntrustedString(strings.TrimSpace(strings.TrimPrefix(rr.String(), h.String())), protocol.MaxRecordBytes)
		}
		out = append(out, rec)
	}
	return out, cut
}

// untrustedName wraps a name from a DNS answer. Names are in presentation form, so unusual bytes are already escaped,
// but a label can still spell out text meant for whoever reads the result.
func untrustedName(name string) protocol.Untrusted {
	return protocol.UntrustedString(name, maxNameLen)
}
