package protocol

import (
	"net/url"
	"strings"
)

// Check names. Public checks are offered to agents by the hub. Internal checks exist only for the hub's path_test.
const (
	CheckProbeInfo   = "probe_info"
	CheckPing        = "ping"
	CheckTraceroute  = "traceroute"
	CheckPathMTU     = "path_mtu"
	CheckDNSLookup   = "dns_lookup"
	CheckTCPConnect  = "tcp_connect"
	CheckTCPTemplate = "tcp_template"
	CheckUDPProbe    = "udp_probe"
	CheckTLSCheck    = "tls_check"
	CheckHTTPCheck   = "http_check"
	CheckDiagnose    = "diagnose"

	CheckListenStart   = "listen_start"   // internal: path_test's receiving side opens a port
	CheckListenCollect = "listen_collect" // internal: path_test's receiving side reports what arrived
	CheckPathSend      = "path_send"      // internal: path_test's sending side connects and sends the fixed payload with the nonce
)

// Time budgets. A caller such as an agent platform may give a tool call 60 s; the hub answers well within that.
const (
	HubCallBudgetMS   = 50_000 // the most a hub tool call may take in all
	MaxCheckBudgetMS  = 40_000 // the most one job may take on a probe
	HubSlackMS        = 2_000  // the hub waits this much past a job's deadline for its result
	DefaultTimeoutMS  = 3_000
	MaxConnectTimeout = 10_000
)

// ProbeInfoParams takes nothing.
type ProbeInfoParams struct{}

func (p *ProbeInfoParams) Normalize() *Error { return nil }

// PingParams for an ICMP echo test.
type PingParams struct {
	Target     string `json:"target" jsonschema:"host name or IP address to ping"`
	Count      int    `json:"count,omitempty" jsonschema:"echo requests to send, 1 to 10, default 4"`
	IntervalMS int    `json:"interval_ms,omitempty" jsonschema:"time between requests in ms, at least 200, default 500"`
	TimeoutMS  int    `json:"timeout_ms,omitempty" jsonschema:"time to wait for each reply in ms, 100 to 5000, default 1000"`
	Size       int    `json:"size,omitempty" jsonschema:"payload bytes, 0 to 1472, default 56"`
	Family     string `json:"family,omitempty" jsonschema:"4 or 6 to force an IP version; empty uses the first address"`
}

func (p *PingParams) Normalize() *Error {
	if err := needTarget(p.Target); err != nil {
		return err
	}
	p.Count = clampDefault(p.Count, 1, 10, 4)
	p.IntervalMS = clampDefault(p.IntervalMS, 200, 5000, 500)
	p.TimeoutMS = clampDefault(p.TimeoutMS, 100, 5000, 1000)
	if p.Size < 0 || p.Size > 1472 {
		return Errorf(CodeInvalidParams, "size must be 0 to 1472")
	}
	if p.Size == 0 {
		p.Size = 56
	}
	return checkFamily(p.Family)
}

// TracerouteParams for a hop-by-hop path trace.
type TracerouteParams struct {
	Target  string `json:"target" jsonschema:"host name or IP address to trace to"`
	Mode    string `json:"mode,omitempty" jsonschema:"icmp, udp or tcp, default icmp"`
	Port    int    `json:"port,omitempty" jsonschema:"destination port for udp (default 33434) or tcp (default 443)"`
	MaxHops int    `json:"max_hops,omitempty" jsonschema:"1 to 30, default 20"`
	Queries int    `json:"queries,omitempty" jsonschema:"probes per hop, 1 to 3, default 2"`
	WaitMS  int    `json:"wait_ms,omitempty" jsonschema:"time to wait for each probe in ms, 200 to 2000, default 1000"`
	Family  string `json:"family,omitempty" jsonschema:"4 or 6 to force an IP version"`
}

func (p *TracerouteParams) Normalize() *Error {
	if err := needTarget(p.Target); err != nil {
		return err
	}
	switch p.Mode {
	case "":
		p.Mode = "icmp"
	case "icmp", "udp", "tcp":
	default:
		return Errorf(CodeInvalidParams, "mode must be icmp, udp or tcp")
	}
	if p.Port == 0 {
		if p.Mode == "udp" {
			p.Port = 33434
		} else if p.Mode == "tcp" {
			p.Port = 443
		}
	}
	if err := checkPort(p.Port, p.Mode == "icmp"); err != nil {
		return err
	}
	p.MaxHops = clampDefault(p.MaxHops, 1, 30, 20)
	p.Queries = clampDefault(p.Queries, 1, 3, 2)
	p.WaitMS = clampDefault(p.WaitMS, 200, 2000, 1000)
	return checkFamily(p.Family)
}

// PathMTUParams for finding the largest packet that passes unfragmented.
type PathMTUParams struct {
	Target  string `json:"target" jsonschema:"host name or IP address"`
	MaxSize int    `json:"max_size,omitempty" jsonschema:"largest packet size to try in bytes, 576 to 9000, default 1500"`
	Family  string `json:"family,omitempty" jsonschema:"4 or 6 to force an IP version"`
}

func (p *PathMTUParams) Normalize() *Error {
	if err := needTarget(p.Target); err != nil {
		return err
	}
	p.MaxSize = clampDefault(p.MaxSize, 576, 9000, 1500)
	return checkFamily(p.Family)
}

// DNSLookupParams for one DNS query.
type DNSLookupParams struct {
	Name      string `json:"name" jsonschema:"the name to look up, or an IP address for a PTR lookup"`
	Type      string `json:"type,omitempty" jsonschema:"A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV or CAA, default A (PTR when name is an IP address)"`
	Server    string `json:"server,omitempty" jsonschema:"DNS server as ip or ip:port; empty uses the probe's own resolvers"`
	TCP       bool   `json:"tcp,omitempty" jsonschema:"query over TCP instead of UDP"`
	TimeoutMS int    `json:"timeout_ms,omitempty" jsonschema:"500 to 10000, default 3000"`
}

var dnsTypes = map[string]bool{"A": true, "AAAA": true, "CNAME": true, "MX": true, "TXT": true, "NS": true, "SOA": true, "PTR": true, "SRV": true, "CAA": true}

func (p *DNSLookupParams) Normalize() *Error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 253 {
		return Errorf(CodeInvalidParams, "name is required and at most 253 characters")
	}
	p.Type = strings.ToUpper(strings.TrimSpace(p.Type))
	if p.Type != "" && !dnsTypes[p.Type] {
		return Errorf(CodeInvalidParams, "type %q is not supported", p.Type)
	}
	p.TimeoutMS = clampDefault(p.TimeoutMS, 500, 10000, DefaultTimeoutMS)
	return nil
}

// TCPConnectParams for testing whether TCP ports accept connections.
type TCPConnectParams struct {
	Target          string `json:"target" jsonschema:"host name or IP address"`
	Ports           []int  `json:"ports" jsonschema:"1 to 10 ports to try"`
	TimeoutMS       int    `json:"timeout_ms,omitempty" jsonschema:"per port, 200 to 10000, default 3000"`
	TLS             bool   `json:"tls,omitempty" jsonschema:"complete a TLS handshake after connecting"`
	ServerName      string `json:"server_name,omitempty" jsonschema:"TLS server name (SNI); default the target when it is a name"`
	ReadBanner      bool   `json:"read_banner,omitempty" jsonschema:"read what the service sends first, for up to 2 s"`
	SourceInterface string `json:"source_interface,omitempty" jsonschema:"connect from this interface of the probe, e.g. eth1"`
	Family          string `json:"family,omitempty" jsonschema:"4 or 6 to force an IP version"`
}

func (p *TCPConnectParams) Normalize() *Error {
	if err := needTarget(p.Target); err != nil {
		return err
	}
	if len(p.Ports) == 0 || len(p.Ports) > 10 {
		return Errorf(CodeInvalidParams, "ports must list 1 to 10 ports")
	}
	for _, port := range p.Ports {
		if err := checkPort(port, false); err != nil {
			return err
		}
	}
	p.TimeoutMS = clampDefault(p.TimeoutMS, 200, MaxConnectTimeout, DefaultTimeoutMS)
	if len(p.SourceInterface) > 64 {
		return Errorf(CodeInvalidParams, "source_interface is too long")
	}
	return checkFamily(p.Family)
}

// TCP templates: fixed, harmless requests that make a service identify itself. Nothing an agent types is sent.
const (
	TemplateHTTPHead      = "http_head"      // HEAD request; host_header and path are the only inputs, both validated
	TemplateRedisPing     = "redis_ping"     // PING\r\n
	TemplateSMTPEHLO      = "smtp_ehlo"      // read greeting, EHLO probe.invalid, QUIT
	TemplateSSHBanner     = "ssh_banner"     // read the SSH version line
	TemplateMySQLGreeting = "mysql_greeting" // read the handshake packet's server version
	TemplatePostgresSSL   = "postgres_ssl"   // send SSLRequest, report whether the server offers TLS
	TemplateFTPBanner     = "ftp_banner"     // read the greeting, send QUIT
)

var tcpTemplates = map[string]int{TemplateHTTPHead: 80, TemplateRedisPing: 6379, TemplateSMTPEHLO: 25, TemplateSSHBanner: 22,
	TemplateMySQLGreeting: 3306, TemplatePostgresSSL: 5432, TemplateFTPBanner: 21}

// TCPTemplateParams for one templated exchange.
type TCPTemplateParams struct {
	Target     string `json:"target" jsonschema:"host name or IP address"`
	Template   string `json:"template" jsonschema:"http_head, redis_ping, smtp_ehlo, ssh_banner, mysql_greeting, postgres_ssl or ftp_banner"`
	Port       int    `json:"port,omitempty" jsonschema:"default is the template's usual port"`
	TLS        bool   `json:"tls,omitempty" jsonschema:"wrap the exchange in TLS (e.g. http_head to 443)"`
	ServerName string `json:"server_name,omitempty" jsonschema:"TLS server name (SNI)"`
	HostHeader string `json:"host_header,omitempty" jsonschema:"http_head only: Host header, default the target"`
	Path       string `json:"path,omitempty" jsonschema:"http_head only: request path, default /"`
	TimeoutMS  int    `json:"timeout_ms,omitempty" jsonschema:"200 to 10000, default 5000"`
	Family     string `json:"family,omitempty" jsonschema:"4 or 6 to force an IP version"`
}

func (p *TCPTemplateParams) Normalize() *Error {
	if err := needTarget(p.Target); err != nil {
		return err
	}
	port, ok := tcpTemplates[p.Template]
	if !ok {
		return Errorf(CodeInvalidParams, "template %q is not one of the TCP templates", p.Template)
	}
	if p.Port == 0 {
		p.Port = port
	}
	if err := checkPort(p.Port, false); err != nil {
		return err
	}
	// Path gets its default only for http_head: the hub normalises, encodes and sends the parameters, and the probe
	// normalises them again, so a default given to every template would make the second pass refuse all the others.
	if p.Template == TemplateHTTPHead {
		if !printableASCII(p.HostHeader, 253) {
			return Errorf(CodeInvalidParams, "host_header must be printable ASCII without spaces, at most 253 characters")
		}
		if p.Path == "" {
			p.Path = "/"
		}
		if !strings.HasPrefix(p.Path, "/") || !printableASCII(p.Path, 512) {
			return Errorf(CodeInvalidParams, "path must start with / and be printable ASCII without spaces, at most 512 characters")
		}
	} else if p.HostHeader != "" || p.Path != "" {
		return Errorf(CodeInvalidParams, "host_header and path apply to http_head only")
	}
	p.TimeoutMS = clampDefault(p.TimeoutMS, 200, MaxConnectTimeout, 5000)
	return checkFamily(p.Family)
}

// UDP templates. Each is a well-formed request that needs no credentials and changes nothing on the target.
const (
	TemplateDNSQuery        = "dns_query"         // standard query for the root NS
	TemplateNTPRequest      = "ntp_request"       // NTPv4 client request; reports stratum and clock offset
	TemplateSNMPv3Discovery = "snmp_v3_discovery" // SNMPv3 engine discovery: no community or credentials sent
)

var udpTemplates = map[string]int{TemplateDNSQuery: 53, TemplateNTPRequest: 123, TemplateSNMPv3Discovery: 161}

// UDPProbeParams for one templated UDP exchange. A UDP result is "open" (a reply came), "closed" (ICMP port unreachable)
// or "open_or_filtered" (silence), never simply closed on silence.
type UDPProbeParams struct {
	Target    string `json:"target" jsonschema:"host name or IP address"`
	Template  string `json:"template" jsonschema:"dns_query, ntp_request or snmp_v3_discovery"`
	Port      int    `json:"port,omitempty" jsonschema:"default is the template's usual port"`
	TimeoutMS int    `json:"timeout_ms,omitempty" jsonschema:"200 to 10000, default 3000"`
	Retries   *int   `json:"retries,omitempty" jsonschema:"extra sends after silence, 0 to 2, default 1"`
	Family    string `json:"family,omitempty" jsonschema:"4 or 6 to force an IP version"`
}

func (p *UDPProbeParams) Normalize() *Error {
	if err := needTarget(p.Target); err != nil {
		return err
	}
	port, ok := udpTemplates[p.Template]
	if !ok {
		return Errorf(CodeInvalidParams, "template %q is not one of the UDP templates", p.Template)
	}
	if p.Port == 0 {
		p.Port = port
	}
	if err := checkPort(p.Port, false); err != nil {
		return err
	}
	p.TimeoutMS = clampDefault(p.TimeoutMS, 200, MaxConnectTimeout, DefaultTimeoutMS)
	if p.Retries == nil {
		one := 1
		p.Retries = &one
	}
	if *p.Retries < 0 || *p.Retries > 2 {
		return Errorf(CodeInvalidParams, "retries must be 0 to 2")
	}
	return checkFamily(p.Family)
}

// TLSCheckParams for inspecting a TLS endpoint. The check never fails on a bad certificate; it reports why it is bad.
type TLSCheckParams struct {
	Target     string `json:"target" jsonschema:"host name or IP address"`
	Port       int    `json:"port,omitempty" jsonschema:"default 443"`
	ServerName string `json:"server_name,omitempty" jsonschema:"TLS server name (SNI) and the name to verify; default the target when it is a name"`
	TimeoutMS  int    `json:"timeout_ms,omitempty" jsonschema:"200 to 10000, default 5000"`
	Family     string `json:"family,omitempty" jsonschema:"4 or 6 to force an IP version"`
}

func (p *TLSCheckParams) Normalize() *Error {
	if err := needTarget(p.Target); err != nil {
		return err
	}
	if p.Port == 0 {
		p.Port = 443
	}
	if err := checkPort(p.Port, false); err != nil {
		return err
	}
	p.TimeoutMS = clampDefault(p.TimeoutMS, 200, MaxConnectTimeout, 5000)
	return checkFamily(p.Family)
}

const maxURLLen = 2048

// HTTPCheckParams for one HTTP request. No request body, no custom headers, no proxy. The response body is never
// returned: only its size, a SHA-256 and whether expect_text was found in the first 1 MiB.
type HTTPCheckParams struct {
	URL          string `json:"url" jsonschema:"http or https URL"`
	Method       string `json:"method,omitempty" jsonschema:"GET or HEAD, default GET"`
	MaxRedirects *int   `json:"max_redirects,omitempty" jsonschema:"0 to 5, default 3; every hop is checked against the probe's target policy"`
	TimeoutMS    int    `json:"timeout_ms,omitempty" jsonschema:"whole request including redirects, 500 to 15000, default 10000"`
	ExpectStatus int    `json:"expect_status,omitempty" jsonschema:"report whether the final status equals this"`
	ExpectText   string `json:"expect_text,omitempty" jsonschema:"report whether the body contains this text, at most 200 characters"`
	VerifyTLS    *bool  `json:"verify_tls,omitempty" jsonschema:"default true; false still reports the certificate problem but continues"`
}

func (p *HTTPCheckParams) Normalize() *Error {
	if len(p.URL) > maxURLLen {
		return Errorf(CodeInvalidParams, "url is longer than %d characters", maxURLLen)
	}
	u, err := url.Parse(strings.TrimSpace(p.URL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return Errorf(CodeInvalidParams, "url must be an http or https URL with a host and no user info")
	}
	// The limit applies to the re-encoded form too: escaping can lengthen a URL, and the probe normalises what the hub
	// already normalised, so a URL accepted here must still be accepted the second time.
	p.URL = u.String()
	if len(p.URL) > maxURLLen {
		return Errorf(CodeInvalidParams, "url is longer than %d characters once encoded", maxURLLen)
	}
	switch strings.ToUpper(p.Method) {
	case "", "GET":
		p.Method = "GET"
	case "HEAD":
		p.Method = "HEAD"
	default:
		return Errorf(CodeInvalidParams, "method must be GET or HEAD")
	}
	if p.MaxRedirects == nil {
		three := 3
		p.MaxRedirects = &three
	}
	if *p.MaxRedirects < 0 || *p.MaxRedirects > 5 {
		return Errorf(CodeInvalidParams, "max_redirects must be 0 to 5")
	}
	p.TimeoutMS = clampDefault(p.TimeoutMS, 500, 15000, 10000)
	if len(p.ExpectText) > 200 {
		return Errorf(CodeInvalidParams, "expect_text is longer than 200 characters")
	}
	if p.ExpectStatus != 0 && (p.ExpectStatus < 100 || p.ExpectStatus > 599) {
		return Errorf(CodeInvalidParams, "expect_status must be 100 to 599")
	}
	if p.VerifyTLS == nil {
		t := true
		p.VerifyTLS = &t
	}
	return nil
}

// DiagnoseParams for a layered check of one target: DNS, then ping, then TCP, then TLS, then HTTP, each only where it
// applies. The result names the first layer that failed.
type DiagnoseParams struct {
	Target string `json:"target" jsonschema:"host name, IP address, or http/https URL"`
	Port   int    `json:"port,omitempty" jsonschema:"TCP port to test; default from the URL, otherwise none (TCP, TLS and HTTP are skipped)"`
	Family string `json:"family,omitempty" jsonschema:"4 or 6 to force an IP version"`
}

func (p *DiagnoseParams) Normalize() *Error {
	if strings.TrimSpace(p.Target) == "" || len(p.Target) > 2048 {
		return Errorf(CodeInvalidParams, "target is required and at most 2048 characters")
	}
	if p.Port != 0 {
		if err := checkPort(p.Port, false); err != nil {
			return err
		}
	}
	return checkFamily(p.Family)
}

// Path test payload. The hub chooses the nonce, so it is held to a short URL-safe alphabet and wrapped in a fixed
// prefix: path_send can then only ever put "probe-path-test " and a token on the wire, never text the hub composed.
const (
	PathTestPrefix = "probe-path-test "
	minNonceLen    = 22 // 128 bits of base64url
	maxNonceLen    = 43 // 256 bits of base64url
)

// PathTestPayload is exactly what path_send sends and what the listener accepts: the prefix and the nonce. Over TCP the
// sender adds "\n" and the listener ignores a trailing "\r\n"; a UDP datagram carries the payload alone.
func PathTestPayload(nonce string) string { return PathTestPrefix + nonce }

func validNonce(s string) bool {
	if len(s) < minNonceLen || len(s) > maxNonceLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ListenStartParams opens a port on the receiving probe of a path_test. Only the hub sends it.
type ListenStartParams struct {
	Protocol   string `json:"protocol"`              // tcp or udp
	Port       int    `json:"port,omitempty"`        // 0 picks a free port in the probe's listen range
	Nonce      string `json:"nonce"`                 // 22 to 43 of [A-Za-z0-9_-]; arrives as PathTestPayload(nonce)
	DurationMS int    `json:"duration_ms,omitempty"` // how long to stay open, 1000 to 40000, default 20000
}

func (p *ListenStartParams) Normalize() *Error {
	if p.Protocol != "tcp" && p.Protocol != "udp" {
		return Errorf(CodeInvalidParams, "protocol must be tcp or udp")
	}
	if p.Port != 0 {
		if err := checkPort(p.Port, false); err != nil {
			return err
		}
	}
	if !validNonce(p.Nonce) {
		return Errorf(CodeInvalidParams, "nonce must be %d to %d characters of A-Z, a-z, 0-9, _ and -", minNonceLen, maxNonceLen)
	}
	p.DurationMS = clampDefault(p.DurationMS, 1000, MaxCheckBudgetMS, 20000)
	return nil
}

// ListenStartResult says where the receiving probe is listening.
type ListenStartResult struct {
	ListenID  string   `json:"listen_id"`
	Protocol  string   `json:"protocol"`
	Port      int      `json:"port"`
	Addresses []string `json:"addresses"`
}

// ListenCollectParams asks the receiving probe what arrived, waiting up to WaitMS for a first arrival. The listener is
// closed after collecting.
type ListenCollectParams struct {
	ListenID string `json:"listen_id"`
	WaitMS   int    `json:"wait_ms,omitempty"` // 0 to 10000, default 3000
}

func (p *ListenCollectParams) Normalize() *Error {
	if p.ListenID == "" {
		return Errorf(CodeInvalidParams, "listen_id is required")
	}
	p.WaitMS = clampDefault(p.WaitMS, 0, 10000, 3000)
	return nil
}

// ListenCollectResult reports arrivals. Received is true only when the path-test payload with the hub's nonce arrived;
// other traffic on the port is counted but never taken as the test's arrival.
type ListenCollectResult struct {
	Received      bool       `json:"received"`       // the nonce arrived
	From          string     `json:"from,omitempty"` // source address and port of the arrival carrying the nonce, as this probe saw it
	OtherArrivals int        `json:"other_arrivals"` // connections or datagrams without the nonce
	Bytes         int        `json:"bytes"`
	FirstBytes    *Untrusted `json:"first_bytes,omitempty"` // only when an arrival did not carry the nonce
}

// PathSendParams has the sending probe connect to the receiver and send the fixed path-test payload carrying the nonce.
// Only the hub sends it.
type PathSendParams struct {
	Address   string `json:"address"` // receiving probe's address as this probe should reach it, IP or name
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`             // tcp or udp
	Nonce     string `json:"nonce"`                // 22 to 43 of [A-Za-z0-9_-]; sent as PathTestPayload(nonce)
	TimeoutMS int    `json:"timeout_ms,omitempty"` // 200 to 10000, default 5000
}

func (p *PathSendParams) Normalize() *Error {
	if err := needTarget(p.Address); err != nil {
		return err
	}
	if err := checkPort(p.Port, false); err != nil {
		return err
	}
	if p.Protocol != "tcp" && p.Protocol != "udp" {
		return Errorf(CodeInvalidParams, "protocol must be tcp or udp")
	}
	if !validNonce(p.Nonce) {
		return Errorf(CodeInvalidParams, "nonce must be %d to %d characters of A-Z, a-z, 0-9, _ and -", minNonceLen, maxNonceLen)
	}
	p.TimeoutMS = clampDefault(p.TimeoutMS, 200, MaxConnectTimeout, 5000)
	return nil
}

// PathSendResult is the sending side's view. Outcome is "connected", "refused", "timeout", "unreachable", "sent" (UDP,
// which cannot know more), or "error".
type PathSendResult struct {
	Outcome   string `json:"outcome"`
	LocalAddr string `json:"local_addr,omitempty"`
	RemoteIP  string `json:"remote_ip,omitempty"`
	Detail    string `json:"detail,omitempty"`
	ConnectMS int64  `json:"connect_ms,omitempty"`
}

// PublicChecks are the checks the hub offers as tools, in the order it lists them.
var PublicChecks = []string{CheckDiagnose, CheckPing, CheckTraceroute, CheckPathMTU, CheckDNSLookup, CheckTCPConnect,
	CheckTCPTemplate, CheckUDPProbe, CheckTLSCheck, CheckHTTPCheck, CheckProbeInfo}

func needTarget(t string) *Error {
	t = strings.TrimSpace(t)
	if t == "" || len(t) > 253 || strings.ContainsAny(t, " /\\@?#") {
		return Errorf(CodeInvalidParams, "target must be a host name or IP address, at most 253 characters")
	}
	return nil
}

func checkPort(port int, zeroOK bool) *Error {
	if (port == 0 && zeroOK) || (port >= 1 && port <= 65535) {
		return nil
	}
	return Errorf(CodeInvalidParams, "port must be 1 to 65535")
}

func checkFamily(f string) *Error {
	if f == "" || f == "4" || f == "6" {
		return nil
	}
	return Errorf(CodeInvalidParams, "family must be 4, 6 or empty")
}

func clampDefault(v, lo, hi, def int) int {
	if v == 0 {
		return def
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func printableASCII(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}
