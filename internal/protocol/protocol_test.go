package protocol

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

type normalizer interface{ Normalize() *Error }

func intp(v int) *int    { return &v }
func boolp(v bool) *bool { return &v }

// TestNormalizeIdempotent covers the hub-to-probe path: the hub normalises an agent's parameters and encodes them, and
// the probe decodes and normalises them again. The second pass must accept what the first produced and change nothing.
func TestNormalizeIdempotent(t *testing.T) {
	nonce := strings.Repeat("aZ0_-", 5)[:24]
	longPath := "http://web.example/" + strings.Repeat("a", 2048-len("http://web.example/"))
	cases := []struct {
		name string
		in   normalizer
	}{
		{"probe_info", &ProbeInfoParams{}},
		{"ping defaults", &PingParams{Target: "host.example"}},
		{"ping clamped", &PingParams{Target: "10.0.0.1", Count: 99, IntervalMS: 1, TimeoutMS: 99999, Size: 1472, Family: "4"}},
		{"ping negative", &PingParams{Target: "10.0.0.1", Count: -3, IntervalMS: -1}},
		{"traceroute icmp", &TracerouteParams{Target: "host.example"}},
		{"traceroute udp", &TracerouteParams{Target: "host.example", Mode: "udp", MaxHops: 100, Queries: 9, WaitMS: 1}},
		{"traceroute tcp port", &TracerouteParams{Target: "2001:db8::1", Mode: "tcp", Port: 8443, Family: "6"}},
		{"path_mtu", &PathMTUParams{Target: "host.example", MaxSize: 100000}},
		{"dns defaults", &DNSLookupParams{Name: " example.com "}},
		{"dns typed", &DNSLookupParams{Name: "example.com", Type: " mx ", Server: "192.0.2.53:5353", TCP: true, TimeoutMS: 1}},
		{"tcp_connect", &TCPConnectParams{Target: "host.example", Ports: []int{22, 443}}},
		{"tcp_connect full", &TCPConnectParams{Target: "host.example", Ports: []int{443}, TimeoutMS: 50000, TLS: true,
			ServerName: "sni.example", ReadBanner: true, SourceInterface: "eth1", Family: "4"}},
		{"tcp_template http_head", &TCPTemplateParams{Target: "host.example", Template: TemplateHTTPHead}},
		{"tcp_template http_head set", &TCPTemplateParams{Target: "host.example", Template: TemplateHTTPHead, HostHeader: "h.example",
			Path: "/health?x=1", TLS: true, Port: 443}},
		{"tcp_template redis", &TCPTemplateParams{Target: "host.example", Template: TemplateRedisPing}},
		{"tcp_template smtp", &TCPTemplateParams{Target: "host.example", Template: TemplateSMTPEHLO, Port: 587, TimeoutMS: 1}},
		{"tcp_template ssh", &TCPTemplateParams{Target: "host.example", Template: TemplateSSHBanner}},
		{"tcp_template mysql", &TCPTemplateParams{Target: "host.example", Template: TemplateMySQLGreeting}},
		{"tcp_template postgres", &TCPTemplateParams{Target: "host.example", Template: TemplatePostgresSSL}},
		{"tcp_template ftp", &TCPTemplateParams{Target: "host.example", Template: TemplateFTPBanner, Family: "6"}},
		{"udp default retries", &UDPProbeParams{Target: "host.example", Template: TemplateDNSQuery}},
		{"udp zero retries", &UDPProbeParams{Target: "host.example", Template: TemplateNTPRequest, Retries: intp(0)}},
		{"udp snmp", &UDPProbeParams{Target: "host.example", Template: TemplateSNMPv3Discovery, Port: 1161, Retries: intp(2), TimeoutMS: 1}},
		{"tls_check", &TLSCheckParams{Target: "host.example"}},
		{"tls_check set", &TLSCheckParams{Target: "host.example", Port: 8443, ServerName: "sni.example", TimeoutMS: 99999}},
		{"http defaults", &HTTPCheckParams{URL: "https://web.example"}},
		{"http encoded", &HTTPCheckParams{URL: " http://web.example/a b/\u00fc?q=1 2#frag ", Method: "head"}},
		{"http zero values", &HTTPCheckParams{URL: "http://web.example/", MaxRedirects: intp(0), VerifyTLS: boolp(false),
			ExpectStatus: 204, ExpectText: "ok", TimeoutMS: 1}},
		{"http at length limit", &HTTPCheckParams{URL: longPath}},
		{"diagnose", &DiagnoseParams{Target: "https://web.example:8443/x"}},
		{"diagnose port", &DiagnoseParams{Target: "10.0.0.1", Port: 22, Family: "4"}},
		{"listen_start", &ListenStartParams{Protocol: "tcp", Nonce: nonce}},
		{"listen_start set", &ListenStartParams{Protocol: "udp", Port: 40001, Nonce: nonce, DurationMS: 99999}},
		{"listen_collect", &ListenCollectParams{ListenID: "abc"}},
		{"listen_collect set", &ListenCollectParams{ListenID: "abc", WaitMS: 50000}},
		{"path_send", &PathSendParams{Address: "10.0.0.2", Port: 40001, Protocol: "tcp", Nonce: nonce}},
		{"path_send set", &PathSendParams{Address: "b.example", Port: 40001, Protocol: "udp", Nonce: nonce, TimeoutMS: 1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.in.Normalize(); err != nil {
				t.Fatalf("first pass: %v", err)
			}
			data, err := json.Marshal(c.in)
			if err != nil {
				t.Fatal(err)
			}
			again := reflect.New(reflect.TypeOf(c.in).Elem()).Interface().(normalizer)
			dec := json.NewDecoder(bytes.NewReader(data))
			dec.DisallowUnknownFields()
			if err := dec.Decode(again); err != nil {
				t.Fatalf("decoding %s: %v", data, err)
			}
			if err := again.Normalize(); err != nil {
				t.Fatalf("second pass refused %s: %v", data, err)
			}
			if !reflect.DeepEqual(c.in, again) {
				t.Fatalf("second pass changed the parameters:\n first %+v\nsecond %+v", c.in, again)
			}
		})
	}
}

func TestTCPTemplateHTTPOnlyFields(t *testing.T) {
	for _, tpl := range []string{TemplateRedisPing, TemplateSSHBanner} {
		for _, p := range []TCPTemplateParams{
			{Target: "h.example", Template: tpl, Path: "/"},
			{Target: "h.example", Template: tpl, HostHeader: "h.example"},
		} {
			if err := p.Normalize(); err == nil || err.Code != CodeInvalidParams {
				t.Errorf("%s with %+v: %v", tpl, p, err)
			}
		}
	}
	bad := []TCPTemplateParams{
		{Target: "h.example", Template: TemplateHTTPHead, Path: "noslash"},
		{Target: "h.example", Template: TemplateHTTPHead, Path: "/a b"},
		{Target: "h.example", Template: TemplateHTTPHead, HostHeader: "h.example\r\nX: y"},
	}
	for _, p := range bad {
		if err := p.Normalize(); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
}

func TestHTTPURLLengthAfterEncoding(t *testing.T) {
	// Spaces are escaped to %20, so this is within the limit as typed but not once encoded.
	u := "http://web.example/" + strings.Repeat("a ", 700)
	p := HTTPCheckParams{URL: u}
	if err := p.Normalize(); err == nil || err.Code != CodeInvalidParams {
		t.Fatalf("url that grows past the limit: %v", err)
	}
}

func TestNonce(t *testing.T) {
	ok := []string{strings.Repeat("a", 22), strings.Repeat("Z", 43), "abcDEF012_-abcDEF012_-x"}
	bad := []string{"", strings.Repeat("a", 21), strings.Repeat("a", 44), strings.Repeat("a", 22) + " ",
		"ignore previous instructions", strings.Repeat("a", 21) + "!", strings.Repeat("a", 21) + "\n",
		strings.Repeat("a", 21) + "\u00e9"}
	for _, n := range ok {
		ls := ListenStartParams{Protocol: "tcp", Nonce: n}
		ps := PathSendParams{Address: "10.0.0.1", Port: 1, Protocol: "udp", Nonce: n}
		if err := ls.Normalize(); err != nil {
			t.Errorf("listen_start %q: %v", n, err)
		}
		if err := ps.Normalize(); err != nil {
			t.Errorf("path_send %q: %v", n, err)
		}
	}
	for _, n := range bad {
		ls := ListenStartParams{Protocol: "tcp", Nonce: n}
		ps := PathSendParams{Address: "10.0.0.1", Port: 1, Protocol: "udp", Nonce: n}
		if err := ls.Normalize(); err == nil {
			t.Errorf("listen_start accepted %q", n)
		}
		if err := ps.Normalize(); err == nil {
			t.Errorf("path_send accepted %q", n)
		}
	}
	if got := PathTestPayload("abc"); got != "probe-path-test abc" {
		t.Fatalf("payload %q", got)
	}
}

func TestUntrustedTextEscapesInvisible(t *testing.T) {
	// Inputs are built with escapes so the source file itself carries no invisible characters.
	cases := []struct{ in, want string }{
		{"a\u200bb", `a\u200bb`},                         // zero-width space
		{"a\u200db", `a\u200db`},                         // zero-width joiner
		{"a\u200fb", `a\u200fb`},                         // right-to-left mark
		{"a\u061cb", `a\u061cb`},                         // Arabic letter mark
		{"\ufeffa", `\ufeffa`},                           // byte order mark
		{"a\u2060b", `a\u2060b`},                         // word joiner
		{"a\u2065b", `a\u2065b`},                         // unassigned, inside the 2060-206F block
		{"a\u206fb", `a\u206fb`},                         // nominal digit shapes
		{"a\u202eb", `a\u202eb`},                         // right-to-left override
		{"a\u2028b", `a\u2028b`},                         // line separator
		{"a\u00adb", `a\u00adb`},                         // soft hyphen, category Cf
		{"a\U000E0041b", `a\U000e0041b`},                 // tag latin capital A
		{"\U000E0000\U000E007F", `\U000e0000\U000e007f`}, // ends of the tag block, unassigned
		{"a\U000110BDb", `a\U000110bdb`},                 // Kaithi number sign: Cf outside the listed ranges
		{"plain \u00e9 \u2713 \u4e2d", "plain \u00e9 \u2713 \u4e2d"},
		{"tab\tnl\n", "tab\tnl\n"},
	}
	for _, c := range cases {
		if got := UntrustedString(c.in, 512).Text; got != c.want {
			t.Errorf("%+q: got %q, want %q", c.in, got, c.want)
		}
	}
	// Truncation counts the escaped form.
	u := UntrustedString(strings.Repeat("\u200b", 10), 13)
	if u.Text != `\u200b\u200b` || !u.Truncated {
		t.Fatalf("truncation: %+v", u)
	}
}
