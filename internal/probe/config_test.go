package probe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validYAML = `
hub_url: wss://hub.example.com:8443
enroll_token_env: MY_TOKEN
state_dir: /tmp/probe-state
targets:
  mode: closed
  allow_cidrs: [10.0.0.0/8]
  allow_hosts: ["*.corp.example"]
listen_ports: "40000-40100"
limits:
  max_concurrent: 2
  per_target_per_minute: 10
log_level: debug
`

func noEnv(string) string { return "" }

func TestParseConfigValid(t *testing.T) {
	cfg, err := ParseConfig([]byte(validYAML), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HubURL != "wss://hub.example.com:8443" || cfg.EnrollTokenEnv != "MY_TOKEN" || cfg.StateDir != "/tmp/probe-state" {
		t.Fatalf("unexpected config %+v", cfg)
	}
	if cfg.ListenPortMin != 40000 || cfg.ListenPortMax != 40100 {
		t.Fatalf("listen ports %d-%d", cfg.ListenPortMin, cfg.ListenPortMax)
	}
	if cfg.Limits.MaxConcurrent != 2 || cfg.Limits.PerTargetPerMinute != 10 || cfg.LogLevel != "debug" {
		t.Fatalf("unexpected limits %+v", cfg)
	}
}

func TestParseConfigDefaultsAndEnv(t *testing.T) {
	env := map[string]string{"PROBE_HUB_URL": "wss://other.example.com", "PROBE_STATE_DIR": "/srv/probe", "PROBE_LOG_LEVEL": "warn"}
	cfg, err := ParseConfig([]byte("targets: {mode: open}\n"), func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HubURL != "wss://other.example.com" || cfg.StateDir != "/srv/probe" || cfg.LogLevel != "warn" {
		t.Fatalf("env overrides not applied: %+v", cfg)
	}
	if cfg.EnrollTokenEnv != DefaultEnrollTokenEnv || cfg.Limits.MaxConcurrent != DefaultMaxConcurrent ||
		cfg.Limits.PerTargetPerMinute != DefaultPerTargetPerMin {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
	if cfg.ListenPortMin != 0 || cfg.ListenPortMax != 0 {
		t.Fatal("empty listen_ports should disable listening")
	}
}

func TestParseConfigErrors(t *testing.T) {
	base := "hub_url: wss://hub.example.com\ntargets: {mode: open}\n"
	cases := []struct {
		name, yaml, want string
	}{
		{"empty file", "", "hub_url is required"},
		{"no mode", "hub_url: wss://hub.example.com\n", "targets.mode is required"},
		{"unknown key", base + "hub_ulr: x\n", "field hub_ulr not found"},
		{"unknown nested key", "hub_url: wss://hub.example.com\ntargets: {mode: open, allow: []}\n", "field allow not found"},
		{"ws without opt-in", "hub_url: ws://hub.example.com\ntargets: {mode: open}\n", "insecure_plaintext"},
		{"http scheme", "hub_url: https://hub.example.com\ntargets: {mode: open}\n", "must start with wss://"},
		{"user info", "hub_url: wss://u:p@hub.example.com\ntargets: {mode: open}\n", "user name or password"},
		{"no host", "hub_url: wss://\ntargets: {mode: open}\n", "no host"},
		{"bad hub port", "hub_url: wss://hub.example.com:99999\ntargets: {mode: open}\n", "1 to 65535"},
		{"range min over max", base + "listen_ports: 40100-40000\n", "starts above where it ends"},
		{"port zero", base + "listen_ports: 0-10\n", "outside 1 to 65535"},
		{"port too big", base + "listen_ports: \"70000\"\n", "outside 1 to 65535"},
		{"port not a number", base + "listen_ports: abc\n", "not a port number"},
		{"half range", base + "listen_ports: 40000-\n", "not a port number"},
		{"negative concurrency", base + "limits: {max_concurrent: -1}\n", "max_concurrent must be"},
		{"huge concurrency", base + "limits: {max_concurrent: 1000}\n", "max_concurrent must be"},
		{"huge rate", base + "limits: {per_target_per_minute: 100000}\n", "per_target_per_minute must be"},
		{"log level", base + "log_level: verbose\n", "log_level"},
		{"bad mode", "hub_url: wss://hub.example.com\ntargets: {mode: wide}\n", "must be open or closed"},
		{"closed without allow", "hub_url: wss://hub.example.com\ntargets: {mode: closed}\n", "nothing could be probed"},
		{"bad cidr", "hub_url: wss://hub.example.com\ntargets: {mode: open, deny_cidrs: [10.0.0.0/99]}\n", "deny_cidrs"},
		{"missing ca file", base + "ca_file: /nonexistent/ca.pem\n", "ca_file"},
		{"not yaml", "hub_url: [\n", "parsing config"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseConfig([]byte(c.yaml), noEnv)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestParseConfigReportsAllProblems(t *testing.T) {
	_, err := ParseConfig([]byte("targets: {mode: open}\nlisten_ports: 9-1\nlog_level: loud\n"), noEnv)
	if err == nil {
		t.Fatal("want error")
	}
	for _, want := range []string{"hub_url", "listen_ports", "log_level"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestParseConfigPlaintextOptIn(t *testing.T) {
	if _, err := ParseConfig([]byte("hub_url: ws://hub.example.com\ninsecure_plaintext: true\ntargets: {mode: open}\n"), noEnv); err != nil {
		t.Fatal(err)
	}
}

func TestParseConfigCAFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.pem")
	os.WriteFile(empty, []byte("not a certificate\n"), 0o600)
	base := "hub_url: wss://hub.example.com\ntargets: {mode: open}\n"
	if _, err := ParseConfig([]byte(base+"ca_file: "+empty+"\n"), noEnv); err == nil || !strings.Contains(err.Error(), "no PEM certificates") {
		t.Fatalf("want no-certificates error, got %v", err)
	}
	good := filepath.Join(dir, "ca.pem")
	os.WriteFile(good, selfSignedPEM(t), 0o600)
	cfg, err := ParseConfig([]byte(base+"ca_file: "+good+"\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newHubClient(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestConfigPath(t *testing.T) {
	t.Setenv("PROBE_CONFIG", "")
	if ConfigPath("") != DefaultConfigPath {
		t.Fatal("default path")
	}
	t.Setenv("PROBE_CONFIG", "/env/probe.yaml")
	if ConfigPath("") != "/env/probe.yaml" || ConfigPath("/flag.yaml") != "/flag.yaml" {
		t.Fatal("flag must win over env, env over default")
	}
}

func TestParsePortRange(t *testing.T) {
	for in, want := range map[string][2]int{"": {0, 0}, "8080": {8080, 8080}, " 1 - 65535 ": {1, 65535}} {
		lo, hi, err := ParsePortRange(in)
		if err != nil || lo != want[0] || hi != want[1] {
			t.Errorf("%q: got %d-%d %v", in, lo, hi, err)
		}
	}
}

func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
