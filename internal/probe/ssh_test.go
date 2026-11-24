package probe

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
	"probetools/internal/sshcfg"
)

func TestParseConfigSSH(t *testing.T) {
	base := "hub_url: wss://hub.example.com\ntargets: {mode: open, deny_hosts: [\"*.Payments.example.\", core-db1]}\n"
	cfg, err := ParseConfig([]byte(base), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SSH.Enabled || cfg.SSH.MaxOutputBytes != 262144 || cfg.SSH.ConnectTimeoutMS != 10000 {
		t.Fatalf("ssh defaults: %+v", cfg.SSH)
	}
	pol, err := policy.New(cfg.Targets)
	if err != nil {
		t.Fatal(err)
	}
	if got := pol.Summary().DenyHosts; strings.Join(got, ",") != "*.payments.example,core-db1" {
		t.Fatalf("deny_hosts %v", got)
	}

	cfg, err = ParseConfig([]byte(base+"ssh:\n  enabled: true\n  max_output_bytes: 65536\n  connect_timeout_ms: 5000\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SSH.Enabled || cfg.SSH.MaxOutputBytes != 65536 || cfg.SSH.ConnectTimeoutMS != 5000 {
		t.Fatalf("ssh: %+v", cfg.SSH)
	}

	for yaml, want := range map[string]string{
		"ssh: {enabled: true, max_output_bytes: 100}\n":       "ssh.max_output_bytes",
		"ssh: {enabled: true, max_output_bytes: 8388608}\n":   "ssh.max_output_bytes",
		"ssh: {enabled: true, connect_timeout_ms: 50}\n":      "ssh.connect_timeout_ms",
		"ssh: {enabled: true, password: hunter2}\n":           "password",
		"targets: {mode: open, deny_hosts: [\"bad host\"]}\n": "deny_hosts",
	} {
		in := base + yaml
		if strings.HasPrefix(yaml, "targets:") {
			in = "hub_url: wss://hub.example.com\n" + yaml
		}
		if _, err := ParseConfig([]byte(in), noEnv); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want an error about %s, got %v", yaml, want, err)
		}
	}
}

func TestHelloReportsSSHProfiles(t *testing.T) {
	cfg, err := ParseConfig([]byte("hub_url: wss://hub.example.com\ntargets: {mode: open}\nssh: {enabled: true}\nstate_dir: "+t.TempDir()+"\n"), noEnv)
	if err != nil {
		t.Fatal(err)
	}
	pol, _ := policy.New(cfg.Targets)
	reg := check.NewRegistry()
	reg.Register(protocol.CheckDeviceShow, nil)
	reg.Register(protocol.CheckDeviceCommands, nil)
	store := sshcfg.New(cfg.StateDir)

	h := buildHello(cfg, reg, map[string]bool{"raw_icmp": true}, pol, store)
	if !h.Capabilities["ssh"] || !h.Capabilities["raw_icmp"] || h.SSH == nil || len(h.SSH.Profiles) != 0 {
		t.Fatalf("empty store: caps %v ssh %+v", h.Capabilities, h.SSH)
	}
	if strings.Join(h.Checks, ",") != "device_commands,device_show" {
		t.Fatalf("checks %v", h.Checks)
	}
	// A profile added while the probe runs is in the next hello, without the user name.
	if err := store.AddProfile(sshcfg.Profile{Name: "core", CIDRs: []string{"10.1.0.0/16"}, Platform: "nxos", Username: "svc-probe",
		Auth: sshcfg.AuthPassword}, sshcfg.Secret{Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	h = buildHello(cfg, reg, nil, pol, store)
	if len(h.SSH.Profiles) != 1 || h.SSH.Profiles[0].Name != "core" || h.SSH.Profiles[0].CIDRs[0] != "10.1.0.0/16" {
		t.Fatalf("profiles %+v", h.SSH.Profiles)
	}
	if b := fmt.Sprintf("%+v", h); strings.Contains(b, "svc-probe") || strings.Contains(b, "pw}") {
		t.Fatalf("hello carries credentials: %s", b)
	}

	// Disabled: no capability, no summary.
	h = buildHello(cfg, check.NewRegistry(), map[string]bool{}, pol, nil)
	if h.SSH != nil || h.Capabilities["ssh"] {
		t.Fatalf("disabled: %+v", h)
	}
}

func TestBoundHelloSSHAndDenyHosts(t *testing.T) {
	var profiles []protocol.SSHProfileSummary
	for i := range 70 {
		var cidrs []string
		for j := range 20 {
			cidrs = append(cidrs, fmt.Sprintf("10.%d.%d.0/24", i, j))
		}
		profiles = append(profiles, protocol.SSHProfileSummary{Name: fmt.Sprintf("p%d", i), CIDRs: cidrs, Platform: "ios"})
	}
	profiles = append([]protocol.SSHProfileSummary{
		{Name: "Bad Name", CIDRs: []string{"10.0.0.0/8"}, Platform: "ios"},
		{Name: "odd", CIDRs: []string{"10.0.0.0/8"}, Platform: "windows"},
		{Name: "j", CIDRs: []string{"10.0.0.0/8", "nonsense"}, Platform: "junos", Jump: "Bastion!"},
	}, profiles...)
	h := boundHello(protocol.Hello{SSH: &protocol.SSHSummary{Profiles: profiles},
		Policy: protocol.PolicySummary{Mode: "open", DenyHosts: []string{"*.corp.example", "café.example"}}})
	if len(h.SSH.Profiles) != 64 || h.SSH.Profiles[0].Name != "p0" || len(h.SSH.Profiles[0].CIDRs) != 16 {
		t.Fatalf("ssh profiles: %d, first %+v", len(h.SSH.Profiles), h.SSH.Profiles[0])
	}
	if strings.Join(h.Policy.DenyHosts, ",") != "*.corp.example" {
		t.Fatalf("deny_hosts %v", h.Policy.DenyHosts)
	}
}

func TestLogTargetDevice(t *testing.T) {
	if got := logTarget(protocol.CheckDeviceShow, []byte(`{"device":"Core-SW1.example.","command":"show version"}`)); got != "core-sw1.example" {
		t.Fatalf("log target %q", got)
	}
}

func TestParseConfigAuthFailureCooldown(t *testing.T) {
	base := "hub_url: wss://hub.example.com\ntargets: {mode: open}\n"
	for yaml, want := range map[string]time.Duration{
		"":                                     10 * time.Minute,
		"ssh: {enabled: true}\n":               10 * time.Minute,
		"ssh: {auth_failure_cooldown_s: 0}\n":  0,
		"ssh: {auth_failure_cooldown_s: 90}\n": 90 * time.Second,
		"ssh: {auth_failure_cooldown_s: 86400}\n": 24 * time.Hour,
	} {
		cfg, err := ParseConfig([]byte(base+yaml), noEnv)
		if err != nil {
			t.Fatalf("%q: %v", yaml, err)
		}
		if got := cfg.SSH.AuthFailureCooldown(); got != want {
			t.Errorf("%q: %v, want %v", yaml, got, want)
		}
	}
	for _, bad := range []string{"ssh: {auth_failure_cooldown_s: -1}\n", "ssh: {auth_failure_cooldown_s: 86401}\n"} {
		if _, err := ParseConfig([]byte(base+bad), noEnv); err == nil || !strings.Contains(err.Error(), "auth_failure_cooldown_s") {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

// On a build whose SSH store has no protections, ssh.enabled is refused, naming the system; with SSH off nothing changes.
func TestSSHEnabledRefusedWithoutStoreProtections(t *testing.T) {
	saved := sshPlatformError
	t.Cleanup(func() { sshPlatformError = saved })
	sshPlatformError = func() error { return sshcfg.PlatformErrorFor(false, "windows") }
	base := "hub_url: wss://hub.example.com\ntargets: {mode: open}\n"
	_, err := ParseConfig([]byte(base+"ssh: {enabled: true}\n"), noEnv)
	if err == nil || !strings.Contains(err.Error(), "ssh.enabled") || !strings.Contains(err.Error(), "not supported on windows") {
		t.Fatalf("%v", err)
	}
	if _, err := ParseConfig([]byte(base+"ssh: {enabled: false}\n"), noEnv); err != nil {
		t.Fatal(err)
	}
}
