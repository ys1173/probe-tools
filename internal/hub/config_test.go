package hub

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const sampleConfig = `
data_dir: /data
probe_listener:
  address: ":8443"
  tls_cert_file: /certs/tls.crt
  tls_key_file: /certs/tls.key
  insecure_plaintext: false
  public_url: wss://hub.example.com:8443
mcp:
  address: ":8080"
  path: /mcp
  tls_cert_file: ""
  tls_key_file: ""
clients:
  - name: agents
    token_env: HUB_TOKEN_AGENTS
    probes: ["*"]
    tools: ["*"]
log_level: info
`

func TestParseConfigSample(t *testing.T) {
	cfg, err := ParseConfig([]byte(sampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/data" || cfg.ProbeListener.PublicURL != "wss://hub.example.com:8443" || cfg.MCP.Path != "/mcp" ||
		len(cfg.Clients) != 1 || cfg.Clients[0].TokenEnv != "HUB_TOKEN_AGENTS" || cfg.Clients[0].Probes[0] != "*" {
		t.Fatalf("%+v", cfg)
	}
}

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := ParseConfig([]byte("probe_listener:\n  insecure_plaintext: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DataDir != "/data" || cfg.ProbeListener.Address != ":8443" || cfg.MCP.Address != ":8080" || cfg.MCP.Path != "/mcp" || cfg.LogLevel != "info" {
		t.Fatalf("%+v", cfg)
	}
}

func TestParseConfigErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key":        "probe_listener:\n  insecure_plaintext: true\nbogus: 1\n",
		"unknown nested key": "probe_listener:\n  insecure_plaintext: true\n  tls: x\n",
		"tls missing":        "probe_listener:\n  address: \":8443\"\n",
		"tls and plaintext":  "probe_listener:\n  insecure_plaintext: true\n  tls_cert_file: a\n  tls_key_file: b\n",
		"mcp half tls":       "probe_listener:\n  insecure_plaintext: true\nmcp:\n  tls_cert_file: a\n",
		"mcp path":           "probe_listener:\n  insecure_plaintext: true\nmcp:\n  path: mcp\n",
		"same address":       "probe_listener:\n  insecure_plaintext: true\n  address: \":9000\"\nmcp:\n  address: \":9000\"\n",
		"log level":          "probe_listener:\n  insecure_plaintext: true\nlog_level: loud\n",
		"public url creds":   "probe_listener:\n  insecure_plaintext: true\n  public_url: wss://u:p@hub:8443\n",
		"public url scheme":  "probe_listener:\n  insecure_plaintext: true\n  public_url: ftp://hub\n",
		"public url https":   "probe_listener:\n  insecure_plaintext: true\n  public_url: https://hub\n",
		"public url query":   "probe_listener:\n  insecure_plaintext: true\n  public_url: wss://hub?x=1\n",
		"client without env": "probe_listener:\n  insecure_plaintext: true\nclients:\n  - name: a\n",
		"duplicate client":   "probe_listener:\n  insecure_plaintext: true\nclients:\n  - {name: a, token_env: X}\n  - {name: a, token_env: Y}\n",
		"unknown client key": "probe_listener:\n  insecure_plaintext: true\nclients:\n  - {name: a, token_env: X, token: secret}\n",
		"two documents":      "probe_listener:\n  insecure_plaintext: true\n---\nlog_level: info\n",
	}
	for name, y := range cases {
		if _, err := ParseConfig([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestResolveConfigPath(t *testing.T) {
	env := func(m map[string]string) func(string) (string, bool) {
		return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
	}
	if got := ResolveConfigPath("a.yaml", env(map[string]string{"HUB_CONFIG": "b.yaml"})); got != "a.yaml" {
		t.Fatal(got)
	}
	if got := ResolveConfigPath("", env(map[string]string{"HUB_CONFIG": "b.yaml"})); got != "b.yaml" {
		t.Fatal(got)
	}
	if got := ResolveConfigPath("", env(nil)); got != DefaultConfigPath {
		t.Fatal(got)
	}
}

func runCLI(t *testing.T, env map[string]string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	c := &CLI{Stdout: &out, Stderr: &errb, LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}
	code := c.Run(context.Background(), args)
	return code, out.String(), errb.String()
}

func TestCLIAdminCommands(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hub.yaml")
	os.WriteFile(cfgPath, []byte("data_dir: "+filepath.Join(dir, "data")+"\nprobe_listener:\n  insecure_plaintext: true\n  public_url: wss://hub.example.com:8443\nclients:\n  - {name: a, token_env: HUB_TOKEN_A}\n"), 0o600)
	env := map[string]string{"HUB_CONFIG": cfgPath}

	code, out, errOut := runCLI(t, env, "token", "create", "--name", "syd-1", "--site", "sydney", "--ttl", "2h")
	if code != 0 {
		t.Fatalf("create: %d %s", code, errOut)
	}
	tokRE := regexp.MustCompile(`(?m)^  ([A-Za-z0-9_-]{43})$`)
	m := tokRE.FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "PROBE_ENROLL_TOKEN='"+m[1]+"'") || !strings.Contains(out, "wss://hub.example.com:8443") || !strings.Contains(out, "Expires") {
		t.Fatalf("create output:\n%s", out)
	}
	token := m[1]

	if code, _, _ := runCLI(t, env, "token", "create", "--name", "Bad_Name", "--site", "s"); code == 0 {
		t.Fatal("bad name accepted")
	}

	code, out, _ = runCLI(t, env, "token", "list", "--config", cfgPath)
	if code != 0 || !strings.Contains(out, "syd-1") || !strings.Contains(out, "valid") || strings.Contains(out, token) {
		t.Fatalf("list %d:\n%s", code, out)
	}
	id := strings.Fields(strings.Split(out, "\n")[1])[0]

	// Enrol through the store, as the hub would.
	st, err := OpenStore(filepath.Join(dir, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if _, err := st.Enroll(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runCLI(t, env, "token", "create", "--name", "syd-1", "--site", "sydney"); code == 0 || !strings.Contains(errOut, "--replace") {
		t.Fatalf("clash: %d %s", code, errOut)
	}
	if code, _, _ := runCLI(t, env, "token", "create", "--name", "syd-1", "--site", "sydney", "--replace"); code != 0 {
		t.Fatal("replace refused")
	}

	code, out, _ = runCLI(t, env, "probes", "list")
	if code != 0 || !strings.Contains(out, "syd-1") || !strings.Contains(out, "sydney") {
		t.Fatalf("probes list:\n%s", out)
	}
	// Flags after the positional argument work too.
	if code, out, errOut := runCLI(t, nil, "probes", "revoke", "syd-1", "--config", cfgPath); code != 0 || !strings.Contains(out, "revoked") {
		t.Fatalf("revoke: %d %s %s", code, out, errOut)
	}
	if code, _, _ := runCLI(t, env, "probes", "revoke", "syd-1"); code != 1 {
		t.Fatal("second revoke succeeded")
	}
	if code, _, _ := runCLI(t, env, "token", "revoke", id); code != 0 {
		t.Fatal("token revoke failed")
	}
	if code, _, _ := runCLI(t, env, "token", "revoke", "nope"); code != 1 {
		t.Fatal("revoking unknown token succeeded")
	}

	code, out, _ = runCLI(t, env, "check-config")
	if code != 0 || !strings.Contains(out, "ok") || !strings.Contains(out, "HUB_TOKEN_A") {
		t.Fatalf("check-config %d:\n%s", code, out)
	}
	if code, out, _ := runCLI(t, nil, "version"); code != 0 || strings.TrimSpace(out) != Version {
		t.Fatal("version")
	}
	if code, _, _ := runCLI(t, nil, "frobnicate"); code != 2 {
		t.Fatal("unknown command accepted")
	}
	if code, _, _ := runCLI(t, nil, "check-config", "--config", filepath.Join(dir, "missing.yaml")); code != 1 {
		t.Fatal("missing config accepted")
	}
}
