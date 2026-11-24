package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"probetools/internal/hubapi"
	"probetools/internal/protocol"
)

const (
	fullToken = "full-token-0123456789abcdefghij"
	sydToken  = "syd-token-0123456789abcdefghijk"
	noneToken = "none-token-0123456789abcdefghij"
	opsToken  = "ops-token-0123456789abcdefghijk"
	netSydTok = "netsyd-token-0123456789abcdefghi"
)

type fakeCall struct {
	probe, check string
	params       json.RawMessage
	deadline     time.Duration
}

// fakeRouter answers jobs from a function, or echoes the check name for online probes.
type fakeRouter struct {
	mu     sync.Mutex
	probes []hubapi.ProbeStatus
	run    func(ctx context.Context, probe, check string, params json.RawMessage) protocol.ProbeResult
	calls  []fakeCall
}

func (f *fakeRouter) Run(ctx context.Context, probe, check string, params json.RawMessage, deadline time.Duration) protocol.ProbeResult {
	f.mu.Lock()
	f.calls = append(f.calls, fakeCall{probe, check, params, deadline})
	run := f.run
	f.mu.Unlock()
	p, ok := f.Probe(probe)
	if !ok {
		return protocol.ProbeResult{Probe: probe, Error: protocol.Errorf(protocol.CodeProbeUnknown, "unknown")}
	}
	if !p.Online {
		return protocol.ProbeResult{Probe: probe, Site: p.Site, Error: protocol.Errorf(protocol.CodeProbeOffline, "offline")}
	}
	if run != nil {
		r := run(ctx, probe, check, params)
		r.Probe, r.Site = probe, p.Site
		return r
	}
	return okResult(map[string]string{"check": check})
}

func (f *fakeRouter) Probes() []hubapi.ProbeStatus { return slices.Clone(f.probes) }

func (f *fakeRouter) Probe(name string) (hubapi.ProbeStatus, bool) {
	for _, p := range f.probes {
		if p.Name == name {
			return p, true
		}
	}
	return hubapi.ProbeStatus{}, false
}

func (f *fakeRouter) callsTo(check string) []fakeCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeCall
	for _, c := range f.calls {
		if c.check == check {
			out = append(out, c)
		}
	}
	return out
}

func okResult(v any) protocol.ProbeResult {
	b, _ := json.Marshal(v)
	return protocol.ProbeResult{OK: true, Result: json.RawMessage(b), StartedAt: time.Now()}
}

func errResult(code string) protocol.ProbeResult {
	return protocol.ProbeResult{Error: protocol.Errorf(code, "fake %s", code), StartedAt: time.Now()}
}

func newFakeRouter() *fakeRouter {
	return &fakeRouter{probes: []hubapi.ProbeStatus{
		{Name: "lon-1", Site: "lon", Online: false, Addresses: []string{"10.3.0.1"}},
		{Name: "mel-1", Site: "mel", Online: true, Addresses: []string{"10.2.0.1"}},
		{Name: "syd-1", Site: "syd", Online: true, Addresses: []string{"10.1.0.1/24"}, Version: "1.0", ListenPorts: "40000-40100",
			Checks: []string{"ping", "device_show", "device_commands", "probe_info"}, Capabilities: map[string]bool{"raw_icmp": true, "ssh": true},
			Policy: protocol.PolicySummary{Mode: "closed", AllowCIDRs: []string{"10.0.0.0/8"}}, LastSeen: time.Now(),
			SSH: &protocol.SSHSummary{Profiles: []protocol.SSHProfileSummary{
				{Name: "core", CIDRs: []string{"10.1.0.0/16"}, Platform: "ios", Jump: "bastion-1"}}}},
		{Name: "syd-2", Site: "syd", Online: true, Addresses: []string{"10.1.0.2/24", "192.0.2.2"}},
	}}
}

var testClients = []hubapi.Client{
	{Name: "full", TokenEnv: "FULL_TOKEN", Probes: []string{"*"}, Tools: []string{"*"}},
	{Name: "syd-agent", TokenEnv: "SYD_TOKEN", Probes: []string{"syd-*"}, Tools: []string{"list_probes", "ping", "path_test"}},
	{Name: "no-tools", TokenEnv: "NONE_TOKEN", Probes: []string{"*"}},
	{Name: "net-ops", TokenEnv: "OPS_TOKEN", Probes: []string{"*"}, Tools: []string{"*", "device_show", "device_commands"}},
	{Name: "net-syd", TokenEnv: "NETSYD_TOKEN", Probes: []string{"syd-*"}, Tools: []string{"list_probes", "device_show"}},
}

func testEnv(k string) (string, bool) {
	switch k {
	case "FULL_TOKEN":
		return fullToken, true
	case "SYD_TOKEN":
		return sydToken, true
	case "NONE_TOKEN":
		return noneToken, true
	case "OPS_TOKEN":
		return opsToken, true
	case "NETSYD_TOKEN":
		return netSydTok, true
	}
	return "", false
}

type testHub struct {
	*hub
	router *fakeRouter
	url    string
	logs   *syncBuffer
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startHub(t *testing.T, budget time.Duration) *testHub {
	t.Helper()
	router := newFakeRouter()
	logs := &syncBuffer{}
	h, err := newHub(router, testClients, slog.New(slog.NewJSONHandler(logs, nil)), testEnv, budget)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &testHub{hub: h, router: router, url: srv.URL, logs: logs}
}

type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func dial(url, token string) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	return client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:             url,
		HTTPClient:           &http.Client{Transport: bearer{token}},
		DisableStandaloneSSE: true,
		MaxRetries:           -1,
	}, nil)
}

func (th *testHub) session(t *testing.T, token string) *mcp.ClientSession {
	t.Helper()
	cs, err := dial(th.url, token)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, tool string, args any) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", tool, err)
	}
	return res
}

func text(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text
		}
	}
	return ""
}

// decode reads a successful call's structured content, and checks the text content carries the same JSON.
func decode(t *testing.T, res *mcp.CallToolResult, v any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("tool error: %s", text(res))
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatal(err)
	}
	var fromText, fromStruct any
	if err := json.Unmarshal([]byte(text(res)), &fromText); err != nil {
		t.Fatalf("text content is not JSON: %v", err)
	}
	_ = json.Unmarshal(b, &fromStruct)
	tb, _ := json.Marshal(fromText)
	sb, _ := json.Marshal(fromStruct)
	if !bytes.Equal(tb, sb) {
		t.Fatalf("text content differs from structured content:\n%s\n%s", tb, sb)
	}
}

func wantToolError(t *testing.T, res *mcp.CallToolResult, prefix string) {
	t.Helper()
	if !res.IsError {
		t.Fatalf("want tool error %q, got success: %s", prefix, text(res))
	}
	if !strings.HasPrefix(text(res), prefix) {
		t.Fatalf("want tool error starting %q, got %q", prefix, text(res))
	}
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

// Each client sees only the tools it may call.
func TestToolsListPerClient(t *testing.T) {
	th := startHub(t, time.Second)
	if got := toolNames(t, th.session(t, sydToken)); !slices.Equal(got, []string{"list_probes", "path_test", "ping"}) {
		t.Errorf("syd-agent tools = %v", got)
	}
	if got := toolNames(t, th.session(t, noneToken)); len(got) != 0 {
		t.Errorf("no-tools client tools = %v", got)
	}
	if got := toolNames(t, th.session(t, netSydTok)); !slices.Equal(got, []string{"device_show", "list_probes"}) {
		t.Errorf("net-syd tools = %v", got)
	}
}

// tools: ["*"] never includes the device tools; naming them is the only way to get them.
func TestDeviceToolsNeedNaming(t *testing.T) {
	th := startHub(t, time.Second)
	star := toolNames(t, th.session(t, fullToken))
	for _, name := range protocol.DeviceChecks {
		if slices.Contains(star, name) {
			t.Errorf("tools [*] lists %s", name)
		}
	}
	if len(star) != len(protocol.PublicChecks)-len(protocol.DeviceChecks)+2 {
		t.Errorf("tools [*] = %v", star)
	}
	// "*" plus both names: every tool.
	ops := toolNames(t, th.session(t, opsToken))
	for _, name := range protocol.DeviceChecks {
		if !slices.Contains(ops, name) {
			t.Errorf("net-ops does not list %s", name)
		}
	}
	if len(ops) != len(protocol.PublicChecks)+2 {
		t.Errorf("net-ops tools = %v", ops)
	}
	// Naming one gives that one only.
	if got := toolNames(t, th.session(t, netSydTok)); slices.Contains(got, "device_commands") {
		t.Errorf("net-syd lists device_commands: %v", got)
	}

	// The call-time check does not depend on registration.
	var full, netSyd *clientState
	for _, c := range th.clients {
		switch c.Name {
		case "full":
			full = c
		case "net-syd":
			netSyd = c
		}
	}
	in := &deviceShowInput{Probe: "syd-1", DeviceShowParams: protocol.DeviceShowParams{Device: "10.1.1.1", Command: "show version"}}
	if _, err := th.runCheck(context.Background(), full, "device_show", in); err == nil || !strings.HasPrefix(err.Error(), "forbidden") {
		t.Errorf("device_show for a [*] client: %v", err)
	}
	cin := &deviceCommandsInput{probeSelection: probeSelection{[]string{"syd-1"}}}
	if _, err := th.runCheck(context.Background(), netSyd, "device_commands", cin); err == nil || !strings.HasPrefix(err.Error(), "forbidden") {
		t.Errorf("device_commands for a client that was not granted it: %v", err)
	}
	if n := len(th.router.callsTo("device_show")) + len(th.router.callsTo("device_commands")); n != 0 {
		t.Errorf("%d device jobs ran for refused calls", n)
	}
	// A call over the wire for a tool the client lacks is a protocol error.
	if _, err := th.session(t, fullToken).CallTool(context.Background(), &mcp.CallToolParams{Name: "device_show",
		Arguments: map[string]any{"probe": "syd-1", "device": "10.1.1.1", "command": "show version"}}); err == nil {
		t.Error("[*] client called device_show")
	}
	// Both tool names are valid in a client's configuration.
	for _, tl := range protocol.DeviceChecks {
		if _, err := New(newFakeRouter(), []hubapi.Client{{Name: "a", TokenEnv: "A", Tools: []string{tl}}}, nil,
			func(string) (string, bool) { return strings.Repeat("a", 24), true }); err != nil {
			t.Errorf("tool %s refused in config: %v", tl, err)
		}
	}
}

func TestToolsList(t *testing.T) {
	th := startHub(t, time.Second)
	cs := th.session(t, opsToken) // "*" plus the device tools by name: every tool
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{"list_probes"}, protocol.PublicChecks...)
	want = append(want, "path_test")
	var got []string
	schemas := map[string]struct {
		Type       string         `json:"type"`
		Properties map[string]any `json:"properties"`
		Required   []string       `json:"required"`
	}{}
	for _, tool := range res.Tools {
		got = append(got, tool.Name)
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s: readOnlyHint is not set", tool.Name)
		}
		if tool.Annotations == nil || tool.Annotations.OpenWorldHint == nil || !*tool.Annotations.OpenWorldHint {
			t.Errorf("%s: openWorldHint is not set", tool.Name)
		}
		if tool.Description == "" {
			t.Errorf("%s: no description", tool.Name)
		}
		b, _ := json.Marshal(tool.InputSchema)
		s := schemas[tool.Name]
		if err := json.Unmarshal(b, &s); err != nil {
			t.Fatal(err)
		}
		schemas[tool.Name] = s
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("tools = %v, want %v", got, want)
	}

	cases := []struct {
		tool     string
		props    []string
		required []string
	}{
		{"ping", []string{"probes", "target", "count", "interval_ms", "timeout_ms", "size", "family"}, []string{"probes", "target"}},
		{"tcp_connect", []string{"probes", "target", "ports", "tls", "read_banner"}, []string{"probes", "target", "ports"}},
		{"tcp_template", []string{"probes", "target", "template", "host_header"}, []string{"probes", "target", "template"}},
		{"http_check", []string{"probes", "url", "max_redirects", "verify_tls"}, []string{"probes", "url"}},
		{"dns_lookup", []string{"probes", "name", "type", "server"}, []string{"probes", "name"}},
		{"probe_info", []string{"probes"}, []string{"probes"}},
		{"list_probes", []string{"site"}, nil},
		{"device_show", []string{"probe", "device", "command", "timeout_ms"}, []string{"probe", "device", "command"}},
		{"device_commands", []string{"probes", "platform"}, []string{"probes"}},
		{"path_test", []string{"from", "to", "protocol", "port", "to_address", "timeout_ms"}, []string{"from", "to"}},
	}
	for _, c := range cases {
		s := schemas[c.tool]
		if s.Type != "object" {
			t.Errorf("%s: schema type %q", c.tool, s.Type)
		}
		for _, p := range c.props {
			if _, ok := s.Properties[p]; !ok {
				t.Errorf("%s: schema has no property %q (has %v)", c.tool, p, keys(s.Properties))
			}
		}
		for p := range s.Properties {
			if strings.HasSuffix(p, "Params") || p == "probeSelection" {
				t.Errorf("%s: schema is not flat: property %q", c.tool, p)
			}
		}
		req := slices.Clone(s.Required)
		slices.Sort(req)
		wantReq := slices.Clone(c.required)
		slices.Sort(wantReq)
		if !slices.Equal(req, wantReq) {
			t.Errorf("%s: required = %v, want %v", c.tool, s.Required, c.required)
		}
	}
	if d := schemas["ping"].Properties["target"].(map[string]any)["description"]; d != "host name or IP address to ping" {
		t.Errorf("ping target description = %v", d)
	}
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func TestAuth(t *testing.T) {
	th := startHub(t, time.Second)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	for name, header := range map[string]string{
		"missing":      "",
		"wrong":        "Bearer " + strings.Repeat("x", 32),
		"not bearer":   "Basic " + fullToken,
		"empty bearer": "Bearer ",
	} {
		req, _ := http.NewRequest("POST", th.url, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, resp.StatusCode)
		}
		if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%s: WWW-Authenticate = %q", name, resp.Header.Get("WWW-Authenticate"))
		}
	}
	if _, err := dial(th.url, "wrong-token-0123456789abcdefgh"); err == nil {
		t.Error("connect with a wrong token succeeded")
	}
	cs := th.session(t, fullToken)
	var out checkOutput
	decode(t, call(t, cs, "probe_info", map[string]any{"probes": []string{"syd-1"}}), &out)
	if len(out.Results) != 1 || !out.Results[0].OK {
		t.Fatalf("probe_info results = %+v", out.Results)
	}
	if strings.Contains(th.logs.String(), fullToken) || strings.Contains(th.logs.String(), sydToken) {
		t.Error("a token appears in the log")
	}
}

func TestConfigErrors(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	long := strings.Repeat("a", 24)
	cases := []struct {
		name    string
		clients []hubapi.Client
		env     map[string]string
		want    string
	}{
		{"missing env", []hubapi.Client{{Name: "a", TokenEnv: "A"}}, map[string]string{}, "not set"},
		{"empty env", []hubapi.Client{{Name: "a", TokenEnv: "A"}}, map[string]string{"A": ""}, "not set"},
		{"short token", []hubapi.Client{{Name: "a", TokenEnv: "A"}}, map[string]string{"A": "short"}, "shorter than 24"},
		{"duplicate token", []hubapi.Client{{Name: "a", TokenEnv: "A"}, {Name: "b", TokenEnv: "B"}},
			map[string]string{"A": long, "B": long}, "same token"},
		{"duplicate name", []hubapi.Client{{Name: "a", TokenEnv: "A"}, {Name: "a", TokenEnv: "B"}},
			map[string]string{"A": long, "B": long + "b"}, "used twice"},
		{"empty name", []hubapi.Client{{Name: " ", TokenEnv: "A"}}, map[string]string{"A": long}, "no name"},
		{"no token_env", []hubapi.Client{{Name: "a"}}, map[string]string{}, "no token_env"},
		{"bad glob", []hubapi.Client{{Name: "a", TokenEnv: "A", Probes: []string{"syd-["}}}, map[string]string{"A": long}, "not a valid"},
		{"unknown tool", []hubapi.Client{{Name: "a", TokenEnv: "A", Tools: []string{"shell"}}}, map[string]string{"A": long}, "does not exist"},
	}
	for _, c := range cases {
		_, err := New(newFakeRouter(), c.clients, nil, env(c.env))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want it to mention %q", c.name, err, c.want)
		}
	}
	if h, err := New(newFakeRouter(), []hubapi.Client{{Name: "short", TokenEnv: "A"}}, nil, env(map[string]string{"A": "x"})); h != nil || err == nil {
		t.Errorf("refused config returned handler %v, err %v", h, err)
	}
	if _, err := New(newFakeRouter(), []hubapi.Client{{Name: "a", TokenEnv: "A"}}, nil, env(map[string]string{"A": long})); err != nil {
		t.Errorf("valid config refused: %v", err)
	}
	if _, err := New(newFakeRouter(), nil, nil, env(nil)); err != nil {
		t.Errorf("no clients refused: %v", err)
	}
}

func TestScope(t *testing.T) {
	th := startHub(t, time.Second)
	cs := th.session(t, sydToken)

	// A tool the client may not use is not registered for it, so calling it is a protocol error, not a tool result.
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "tcp_connect",
		Arguments: map[string]any{"probes": []string{"syd-1"}, "target": "x", "ports": []int{443}}}); err == nil ||
		!strings.Contains(err.Error(), "tcp_connect") {
		t.Errorf("calling an unlisted tool: err = %v", err)
	}
	// The handlers check as well.
	var syd *clientState
	for _, c := range th.clients {
		if c.Name == "syd-agent" {
			syd = c
		}
	}
	in := &tcpConnectInput{probeSelection{[]string{"syd-1"}}, protocol.TCPConnectParams{Target: "x", Ports: []int{443}}}
	if _, err := th.runCheck(context.Background(), syd, "tcp_connect", in); err == nil || !strings.HasPrefix(err.Error(), "forbidden") {
		t.Errorf("runCheck without the tool: %v", err)
	}

	results := func(args map[string]any) []protocol.ProbeResult {
		t.Helper()
		var out checkOutput
		decode(t, call(t, cs, "ping", args), &out)
		if out.Tool != "ping" {
			t.Fatalf("tool = %q", out.Tool)
		}
		return out.Results
	}
	summary := func(rs []protocol.ProbeResult) []string {
		var s []string
		for _, r := range rs {
			s = append(s, r.Probe+"="+outcome(r))
		}
		return s
	}

	rs := results(map[string]any{"probes": []string{"mel-1", "syd-1", "nope"}, "target": "10.0.0.1"})
	got := summary(rs)
	if want := []string{"mel-1=probe_unknown", "nope=probe_unknown", "syd-1=ok"}; !slices.Equal(got, want) {
		t.Errorf("explicit names: %v, want %v", got, want)
	}
	// A probe outside the scope must look exactly like one that does not exist.
	if a, b := strings.ReplaceAll(rs[0].Error.Message, "mel-1", "X"), strings.ReplaceAll(rs[1].Error.Message, "nope", "X"); a != b ||
		rs[0].Site != "" || rs[1].Site != "" {
		t.Errorf("out of scope and unknown differ: %+v vs %+v", rs[0], rs[1])
	}
	got = summary(results(map[string]any{"probes": []string{"*"}, "target": "10.0.0.1"}))
	if want := []string{"syd-1=ok", "syd-2=ok"}; !slices.Equal(got, want) {
		t.Errorf("*: %v, want %v", got, want)
	}
	got = summary(results(map[string]any{"probes": []string{"*-1"}, "target": "10.0.0.1"}))
	if want := []string{"syd-1=ok"}; !slices.Equal(got, want) {
		t.Errorf("glob *-1: %v, want %v (must not reach mel-1 or lon-1)", got, want)
	}
	wantToolError(t, call(t, cs, "ping", map[string]any{"probes": []string{"site:mel"}, "target": "10.0.0.1"}), "invalid_params: no probe")

	full := th.session(t, fullToken)
	var out checkOutput
	decode(t, call(t, full, "ping", map[string]any{"probes": []string{"site:syd"}, "target": "10.0.0.1"}), &out)
	if got := summary(out.Results); !slices.Equal(got, []string{"syd-1=ok", "syd-2=ok"}) {
		t.Errorf("site:syd: %v", got)
	}

	var lp listProbesOutput
	decode(t, call(t, cs, "list_probes", map[string]any{}), &lp)
	var names []string
	for _, p := range lp.Probes {
		names = append(names, p.Name)
	}
	if !slices.Equal(names, []string{"syd-1", "syd-2"}) {
		t.Errorf("list_probes for syd-agent = %v", names)
	}
	if lp.Probes[0].ListenPorts != "40000-40100" || lp.Probes[0].Policy.Mode != "closed" || lp.Probes[0].LastSeen == nil {
		t.Errorf("list_probes entry = %+v", lp.Probes[0])
	}
	// A site outside the scope looks like a site that does not exist.
	outside := text(call(t, cs, "list_probes", map[string]any{"site": "mel"}))
	if nowhere := text(call(t, cs, "list_probes", map[string]any{"site": "nowhere"})); outside != nowhere {
		t.Errorf("list_probes site=mel %s, site=nowhere %s", outside, nowhere)
	}
	decode(t, call(t, full, "list_probes", map[string]any{"site": "mel"}), &lp)
	if len(lp.Probes) != 1 || lp.Probes[0].Name != "mel-1" {
		t.Errorf("list_probes site=mel = %+v", lp.Probes)
	}
	decode(t, call(t, full, "list_probes", map[string]any{"site": "nowhere"}), &lp)
	if lp.Probes == nil || len(lp.Probes) != 0 {
		t.Errorf("list_probes site=nowhere = %+v", lp.Probes)
	}
}

func TestFanOut(t *testing.T) {
	th := startHub(t, 5*time.Second)
	cs := th.session(t, fullToken)
	var out checkOutput
	decode(t, call(t, cs, "ping", map[string]any{"probes": []string{"syd-2", "mel-1", "syd-1", "lon-1", "syd-*"}, "target": "example.com"}), &out)
	var got []string
	for _, r := range out.Results {
		got = append(got, r.Probe+"@"+r.Site+"="+outcome(r))
	}
	want := []string{"lon-1@lon=probe_offline", "mel-1@mel=ok", "syd-1@syd=ok", "syd-2@syd=ok"}
	if !slices.Equal(got, want) {
		t.Fatalf("results = %v, want %v", got, want)
	}
	calls := th.router.callsTo("ping")
	if len(calls) != 4 {
		t.Fatalf("router saw %d ping jobs, want 4", len(calls))
	}
	var sent protocol.PingParams
	if err := json.Unmarshal(calls[0].params, &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Target != "example.com" || sent.Count != 4 || sent.IntervalMS != 500 || sent.TimeoutMS != 1000 || sent.Size != 56 {
		t.Errorf("params not normalised: %+v", sent)
	}
	if string(calls[0].params) == "" || strings.Contains(string(calls[0].params), "probes") {
		t.Errorf("params sent to the probe include the selectors: %s", calls[0].params)
	}
	if calls[0].deadline != 4*time.Second {
		t.Errorf("ping deadline = %v, want 4s", calls[0].deadline)
	}

	// The audit line.
	var line map[string]any
	for _, l := range strings.Split(strings.TrimSpace(th.logs.String()), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(l), &m) == nil && m["event"] == "tool_call" && m["tool"] == "ping" {
			line = m
		}
	}
	if line == nil {
		t.Fatalf("no audit line in %s", th.logs.String())
	}
	if line["client"] != "full" || line["target"] != "example.com" || line["msg"] != "tool_call" {
		t.Errorf("audit line = %v", line)
	}
	if oc, _ := line["outcomes"].(map[string]any); oc["lon-1"] != "probe_offline" || oc["syd-1"] != "ok" {
		t.Errorf("audit outcomes = %v", line["outcomes"])
	}
	if _, ok := line["duration_ms"]; !ok {
		t.Error("audit line has no duration_ms")
	}
	if strings.Contains(th.logs.String(), `"check":"ping"`) {
		t.Error("the audit log contains a probe result")
	}
}

func TestTooManyProbes(t *testing.T) {
	th := startHub(t, time.Second)
	for i := range 21 {
		th.router.probes = append(th.router.probes, hubapi.ProbeStatus{Name: "bulk-" + string(rune('a'+i)), Site: "bulk", Online: true})
	}
	cs := th.session(t, fullToken)
	wantToolError(t, call(t, cs, "probe_info", map[string]any{"probes": []string{"site:bulk"}}), "invalid_params: the selection matches 21")
	if n := len(th.router.callsTo("probe_info")); n != 0 {
		t.Errorf("%d jobs ran", n)
	}
}

func TestInvalidParams(t *testing.T) {
	th := startHub(t, time.Second)
	cs := th.session(t, fullToken)
	wantToolError(t, call(t, cs, "ping", map[string]any{"probes": []string{"syd-1"}, "target": "a b"}), "invalid_params: target")
	wantToolError(t, call(t, cs, "ping", map[string]any{"probes": []string{"syd-1"}, "target": "x", "size": 9000}), "invalid_params: size")
	wantToolError(t, call(t, cs, "http_check", map[string]any{"probes": []string{"syd-1"}, "url": "ftp://x"}), "invalid_params")
	wantToolError(t, call(t, cs, "ping", map[string]any{"probes": []string{"syd-["}, "target": "x"}), "invalid_params")
	// Rejected by the input schema before the handler runs, and still audited.
	res := call(t, cs, "ping", map[string]any{"target": "x"})
	if !res.IsError {
		t.Fatalf("missing probes accepted: %s", text(res))
	}
	if n := len(th.router.callsTo("ping")); n != 0 {
		t.Errorf("%d jobs ran for invalid calls", n)
	}
	if !strings.Contains(th.logs.String(), `"error":"validating`) {
		t.Errorf("schema rejection not audited: %s", th.logs.String())
	}
}

func TestCallBudget(t *testing.T) {
	th := startHub(t, 300*time.Millisecond)
	release := make(chan struct{})
	defer close(release)
	// A router that ignores its context entirely: the hub must still answer on time.
	th.router.run = func(ctx context.Context, probe, check string, _ json.RawMessage) protocol.ProbeResult {
		if probe == "syd-1" {
			return okResult("fast")
		}
		<-release
		return okResult("late")
	}
	cs := th.session(t, fullToken)
	start := time.Now()
	var out checkOutput
	decode(t, call(t, cs, "diagnose", map[string]any{"probes": []string{"syd-1", "syd-2"}, "target": "example.com"}), &out)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("call took %v with a 300ms budget", d)
	}
	if len(out.Results) != 2 || !out.Results[0].OK || outcome(out.Results[1]) != protocol.CodeTimeout || out.Results[1].Site != "syd" {
		t.Errorf("results = %+v", out.Results)
	}
	if calls := th.router.callsTo("diagnose"); len(calls) != 2 || calls[0].deadline != time.Duration(protocol.MaxCheckBudgetMS)*time.Millisecond {
		t.Errorf("diagnose deadline = %+v", calls)
	}
}

func TestBusy(t *testing.T) {
	th := startHub(t, 10*time.Second)
	release := make(chan struct{})
	var started sync.WaitGroup
	started.Add(maxConcurrentCalls)
	th.router.run = func(ctx context.Context, probe, check string, _ json.RawMessage) protocol.ProbeResult {
		started.Done()
		<-release
		return okResult("done")
	}
	cs := th.session(t, fullToken)
	var wg sync.WaitGroup
	for range maxConcurrentCalls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "probe_info", Arguments: map[string]any{"probes": []string{"syd-1"}}})
			if err != nil || res.IsError {
				t.Errorf("blocked call failed: %v %v", err, res)
			}
		}()
	}
	started.Wait()
	wantToolError(t, call(t, cs, "probe_info", map[string]any{"probes": []string{"syd-1"}}), "busy")
	// Another client is not affected.
	other := th.session(t, sydToken)
	if res := call(t, other, "list_probes", map[string]any{}); res.IsError {
		t.Errorf("other client refused: %s", text(res))
	}
	close(release)
	wg.Wait()
	if res := call(t, cs, "list_probes", map[string]any{}); res.IsError {
		t.Errorf("call after release refused: %s", text(res))
	}
}

func TestDeadlineFor(t *testing.T) {
	maxD := time.Duration(protocol.MaxCheckBudgetMS) * time.Millisecond
	cases := []struct {
		params any
		want   time.Duration
	}{
		{protocol.PingParams{Count: 10, IntervalMS: 5000, TimeoutMS: 5000}, maxD},
		{protocol.TracerouteParams{MaxHops: 30, Queries: 3, WaitMS: 2000}, maxD},
		{protocol.TracerouteParams{MaxHops: 5, Queries: 1, WaitMS: 1000}, 7 * time.Second},
		{protocol.DNSLookupParams{TimeoutMS: 3000}, 5 * time.Second},
		{protocol.TCPConnectParams{Ports: []int{1, 2}, TimeoutMS: 3000, TLS: true}, 14 * time.Second},
		{protocol.UDPProbeParams{TimeoutMS: 3000, Retries: new(2)}, 11 * time.Second},
		{protocol.HTTPCheckParams{TimeoutMS: 15000}, 17 * time.Second},
		{protocol.PathMTUParams{}, maxD},
		{protocol.ProbeInfoParams{}, 5 * time.Second},
	}
	for _, c := range cases {
		if got := deadlineFor(c.params); got != c.want {
			t.Errorf("deadlineFor(%T %+v) = %v, want %v", c.params, c.params, got, c.want)
		}
	}
}

func TestLogTarget(t *testing.T) {
	if got := logTarget("https://example.com/a?token=secret#x"); got != "https://example.com/a" {
		t.Errorf("logTarget = %q", got)
	}
	if got := logTarget("example.com"); got != "example.com" {
		t.Errorf("logTarget = %q", got)
	}
}

// deviceShowRouter answers device_show like a probe would, and records nothing the test does not check.
func deviceShowReply(outcome string) func(ctx context.Context, probe, check string, params json.RawMessage) protocol.ProbeResult {
	return func(ctx context.Context, probe, check string, params json.RawMessage) protocol.ProbeResult {
		return okResult(map[string]any{"outcome": outcome, "command": "show version",
			"output": protocol.Untrusted{Text: "SECRET-DEVICE-OUTPUT hostname r1", Untrusted: true}, "output_bytes": 32})
	}
}

func TestDeviceShowRunsOnOneProbe(t *testing.T) {
	th := startHub(t, 5*time.Second)
	th.router.run = deviceShowReply("ok")
	cs := th.session(t, opsToken)

	var out checkOutput
	decode(t, call(t, cs, "device_show", map[string]any{"probe": " syd-1 ", "device": "10.1.1.1", "command": "  show   interfaces\tGi1/0/1 "}), &out)
	if out.Tool != "device_show" || len(out.Results) != 1 || out.Results[0].Probe != "syd-1" || out.Results[0].Site != "syd" || !out.Results[0].OK {
		t.Fatalf("output = %+v", out)
	}
	calls := th.router.callsTo("device_show")
	if len(calls) != 1 || calls[0].probe != "syd-1" {
		t.Fatalf("calls = %+v", calls)
	}
	var sent map[string]any
	if err := json.Unmarshal(calls[0].params, &sent); err != nil {
		t.Fatal(err)
	}
	if sent["device"] != "10.1.1.1" || sent["command"] != "show interfaces Gi1/0/1" || sent["timeout_ms"] != float64(20000) {
		t.Errorf("params not normalised: %s", calls[0].params)
	}
	if _, ok := sent["probe"]; ok {
		t.Errorf("the probe selector went to the probe: %s", calls[0].params)
	}
	if calls[0].deadline != 23*time.Second {
		t.Errorf("deadline = %v, want default 20 s + 3 s", calls[0].deadline)
	}

	// An explicit timeout: timeout_ms + 3 s, and never more than a job may take.
	decode(t, call(t, cs, "device_show", map[string]any{"probe": "mel-1", "device": "10.2.1.1", "command": "show version", "timeout_ms": 5000}), &out)
	if c := th.router.callsTo("device_show"); len(c) != 2 || c[1].probe != "mel-1" || c[1].deadline != 8*time.Second {
		t.Errorf("calls = %+v", c)
	}
	decode(t, call(t, cs, "device_show", map[string]any{"probe": "mel-1", "device": "10.2.1.1", "command": "show version", "timeout_ms": 99999}), &out)
	if c := th.router.callsTo("device_show"); c[2].deadline != 38*time.Second || c[2].deadline > time.Duration(protocol.MaxCheckBudgetMS)*time.Millisecond {
		t.Errorf("deadline for the largest timeout = %v", c[2].deadline)
	}
	if got := deadlineFor(protocol.DeviceShowParams{TimeoutMS: 39000}); got != time.Duration(protocol.MaxCheckBudgetMS)*time.Millisecond {
		t.Errorf("deadlineFor is not capped: %v", got)
	}

	// An offline probe, a probe out of scope and a probe that does not exist each give one result.
	for probe, want := range map[string]string{"lon-1": "probe_offline", "nope": "probe_unknown"} {
		decode(t, call(t, cs, "device_show", map[string]any{"probe": probe, "device": "10.3.1.1", "command": "show version"}), &out)
		if len(out.Results) != 1 || out.Results[0].Probe != probe || outcome(out.Results[0]) != want {
			t.Errorf("%s: %+v", probe, out.Results)
		}
	}
	ns := th.session(t, netSydTok)
	decode(t, call(t, ns, "device_show", map[string]any{"probe": "mel-1", "device": "10.2.1.1", "command": "show version"}), &out)
	if len(out.Results) != 1 || outcome(out.Results[0]) != "probe_unknown" || out.Results[0].Site != "" {
		t.Errorf("out-of-scope probe: %+v", out.Results)
	}
	if n := len(th.router.callsTo("device_show")); n != 4 {
		t.Errorf("%d device_show jobs ran, want 4 (an offline probe is still asked; unknown and out-of-scope ones are not)", n)
	}
}

func TestDeviceShowRejectsSelectors(t *testing.T) {
	th := startHub(t, time.Second)
	cs := th.session(t, opsToken)
	for _, probe := range []string{"*", "syd-*", "site:syd", "syd-?", "syd-[12]", "syd-1,syd-2", "syd-1 syd-2", "", "  ", `syd\-1`, strings.Repeat("a", 64)} {
		res := call(t, cs, "device_show", map[string]any{"probe": probe, "device": "10.1.1.1", "command": "show version"})
		if !res.IsError {
			t.Errorf("probe %q accepted: %s", probe, text(res))
		} else if probe != "" && strings.TrimSpace(probe) != "" && !strings.HasPrefix(text(res), "invalid_params: probe must be exactly one probe") {
			t.Errorf("probe %q: %s", probe, text(res))
		}
	}
	// A list of probes is not the schema; neither is a missing field.
	for name, args := range map[string]map[string]any{
		"probes list": {"probes": []string{"syd-1"}, "device": "10.1.1.1", "command": "show version"},
		"no probe":    {"device": "10.1.1.1", "command": "show version"},
		"no device":   {"probe": "syd-1", "command": "show version"},
		"no command":  {"probe": "syd-1", "device": "10.1.1.1"},
		"probe array": {"probe": []string{"syd-1"}, "device": "10.1.1.1", "command": "show version"},
	} {
		if res := call(t, cs, "device_show", args); !res.IsError {
			t.Errorf("%s accepted: %s", name, text(res))
		}
	}
	for name, args := range map[string]map[string]any{
		"command with pipe": {"probe": "syd-1", "device": "10.1.1.1", "command": "show version | include x"},
		"non-ascii":         {"probe": "syd-1", "device": "10.1.1.1", "command": "show vérsion"},
		"device with space": {"probe": "syd-1", "device": "10.1.1.1 x", "command": "show version"},
		"empty command":     {"probe": "syd-1", "device": "10.1.1.1", "command": "   "},
	} {
		res := call(t, cs, "device_show", args)
		if name == "command with pipe" {
			continue // the floor is the probe's to enforce; the hub only normalises
		}
		if !res.IsError || !strings.HasPrefix(text(res), "invalid_params") {
			t.Errorf("%s: %s", name, text(res))
		}
	}
	if n := len(th.router.callsTo("device_show")); n != 1 {
		t.Errorf("%d jobs ran; only the pipe command (the probe's floor refuses it) should have", n)
	}
}

func TestDeviceCommandsFansOut(t *testing.T) {
	th := startHub(t, 5*time.Second)
	cs := th.session(t, opsToken)
	var out checkOutput
	decode(t, call(t, cs, "device_commands", map[string]any{"probes": []string{"site:syd", "mel-1"}, "platform": " IOS "}), &out)
	if out.Tool != "device_commands" || len(out.Results) != 3 {
		t.Fatalf("output = %+v", out)
	}
	calls := th.router.callsTo("device_commands")
	if len(calls) != 3 {
		t.Fatalf("calls = %+v", calls)
	}
	if string(calls[0].params) != `{"platform":"ios"}` {
		t.Errorf("params = %s", calls[0].params)
	}
	wantToolError(t, call(t, cs, "device_commands", map[string]any{"probes": []string{"syd-1"}, "platform": "vyos"}), "invalid_params: platform")
	wantToolError(t, call(t, cs, "device_commands", map[string]any{"platform": "ios"}), "validating")
}

func TestDeviceShowAudit(t *testing.T) {
	th := startHub(t, 5*time.Second)
	cs := th.session(t, opsToken)
	audit := func() map[string]any {
		t.Helper()
		var line map[string]any
		for _, l := range strings.Split(strings.TrimSpace(th.logs.String()), "\n") {
			var m map[string]any
			if json.Unmarshal([]byte(l), &m) == nil && m["event"] == "tool_call" && m["tool"] == "device_show" {
				line = m
			}
		}
		if line == nil {
			t.Fatalf("no audit line in %s", th.logs.String())
		}
		return line
	}

	th.router.run = deviceShowReply("auth_failed")
	var out checkOutput
	decode(t, call(t, cs, "device_show", map[string]any{"probe": "syd-1", "device": "10.1.1.1", "command": "show ip route"}), &out)
	line := audit()
	if line["client"] != "net-ops" || line["target"] != "10.1.1.1" || line["command"] != "show ip route" {
		t.Errorf("audit line = %v", line)
	}
	if p, _ := line["probes"].([]any); len(p) != 1 || p[0] != "syd-1" {
		t.Errorf("audit probes = %v", line["probes"])
	}
	if oc, _ := line["outcomes"].(map[string]any); oc["syd-1"] != "auth_failed" {
		t.Errorf("audit outcomes = %v, want the result's outcome", line["outcomes"])
	}
	if _, ok := line["duration_ms"]; !ok {
		t.Error("audit line has no duration_ms")
	}
	if strings.Contains(th.logs.String(), "SECRET-DEVICE-OUTPUT") || strings.Contains(th.logs.String(), `"output"`) {
		t.Errorf("device output reached the log: %s", th.logs.String())
	}

	th.router.run = deviceShowReply("ok")
	decode(t, call(t, cs, "device_show", map[string]any{"probe": "syd-1", "device": "10.1.1.1", "command": "show version"}), &out)
	if oc, _ := audit()["outcomes"].(map[string]any); oc["syd-1"] != "ok" {
		t.Errorf("outcome = %v", oc)
	}
	// A probe-side error is logged as its code; an outcome that is not a short word is not logged as written.
	th.router.run = func(context.Context, string, string, json.RawMessage) protocol.ProbeResult {
		return errResult(protocol.CodeNotAllowed)
	}
	decode(t, call(t, cs, "device_show", map[string]any{"probe": "syd-1", "device": "10.1.1.1", "command": "show running-config"}), &out)
	if oc, _ := audit()["outcomes"].(map[string]any); oc["syd-1"] != "command_not_allowed" {
		t.Errorf("outcome = %v", oc)
	}
	th.router.run = deviceShowReply("ok\nforged log line")
	decode(t, call(t, cs, "device_show", map[string]any{"probe": "syd-1", "device": "10.1.1.1", "command": "show version"}), &out)
	if oc, _ := audit()["outcomes"].(map[string]any); oc["syd-1"] != "invalid" {
		t.Errorf("outcome = %v", oc)
	}
	// Other tools do not log a command.
	decode(t, call(t, cs, "ping", map[string]any{"probes": []string{"syd-1"}, "target": "10.1.1.1"}), &out)
	if strings.Count(th.logs.String(), `"command"`) != 4 {
		t.Errorf("command logged by other tools: %s", th.logs.String())
	}
}

func TestListProbesShowsSSH(t *testing.T) {
	th := startHub(t, time.Second)
	// Clients with and without the device tools alternate, so hiding a field for one must not hide it for the next.
	for _, c := range []struct {
		token string
		want  bool
	}{{fullToken, false}, {opsToken, true}, {sydToken, false}, {netSydTok, true}} {
		var lp listProbesOutput // fresh each time: decoding into a used slice keeps fields the new JSON omits
		decode(t, call(t, th.session(t, c.token), "list_probes", map[string]any{}), &lp)
		var syd1 *probeView
		for i := range lp.Probes {
			if lp.Probes[i].Name == "syd-1" {
				syd1 = &lp.Probes[i]
			}
		}
		if syd1 == nil {
			t.Fatalf("%s: syd-1 not listed", c.token)
		}
		if c.want {
			if syd1.SSH == nil || len(syd1.SSH.Profiles) != 1 {
				t.Errorf("%s: ssh = %+v", c.token, syd1.SSH)
			} else if p := syd1.SSH.Profiles[0]; p.Name != "core" || p.Platform != "ios" || p.Jump != "bastion-1" || p.CIDRs[0] != "10.1.0.0/16" {
				t.Errorf("%s: profile = %+v", c.token, p)
			}
		} else if syd1.SSH != nil {
			t.Errorf("%s: ssh shown to a client without the device tools: %+v", c.token, syd1.SSH)
		}
		// The ssh capability and the device checks are hidden the same way; the rest stays.
		wantChecks := []string{"ping", "device_show", "device_commands", "probe_info"}
		wantCaps := map[string]bool{"raw_icmp": true, "ssh": true}
		if !c.want {
			wantChecks = []string{"ping", "probe_info"}
			wantCaps = map[string]bool{"raw_icmp": true}
		}
		if !slices.Equal(syd1.Checks, wantChecks) || !maps.Equal(syd1.Capabilities, wantCaps) {
			t.Errorf("%s: checks %v, capabilities %v; want %v, %v", c.token, syd1.Checks, syd1.Capabilities,
				wantChecks, wantCaps)
		}
		for _, p := range lp.Probes {
			if p.Name != "syd-1" && p.SSH != nil {
				t.Errorf("%s: %s has ssh %+v", c.token, p.Name, p.SSH)
			}
		}
	}
}
