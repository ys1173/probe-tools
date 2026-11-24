package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"probetools/internal/policy"
	"probetools/internal/sshcfg"
)

type fakeTerm struct {
	stdin    string
	terminal bool
	secrets  []string // answers to readSecret, in order
	lines    []string // answers to readLine, in order
}

type result struct {
	code           int
	stdout, stderr string
}

func runCLI(t *testing.T, ft fakeTerm, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	c := &cli{stdin: bufio.NewReader(strings.NewReader(ft.stdin)), stdout: &out, stderr: &errb,
		isTerminal: func() bool { return ft.terminal }}
	c.readSecret = func(string) ([]byte, error) {
		if len(ft.secrets) == 0 {
			return nil, errors.New("no more secrets")
		}
		s := ft.secrets[0]
		ft.secrets = ft.secrets[1:]
		return []byte(s), nil
	}
	c.readLine = func(string) (string, error) {
		if len(ft.lines) == 0 {
			return "", errors.New("no more lines")
		}
		s := ft.lines[0]
		ft.lines = ft.lines[1:]
		return s, nil
	}
	code := c.run(args)
	return result{code, out.String(), errb.String()}
}

// testConfig writes a probe configuration with its own state directory.
func testConfig(t *testing.T) (cfgPath, stateDir string) {
	t.Helper()
	dir := t.TempDir()
	stateDir = filepath.Join(dir, "state")
	if err := os.Mkdir(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "probe.yaml")
	cfg := "hub_url: wss://hub.example.com\nstate_dir: " + stateDir + "\ntargets: {mode: open}\n"
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, stateDir
}

func profileArgs(cfg string, extra ...string) []string {
	return append([]string{"profile", "add", "--config", cfg, "--name", "core", "--cidr", "10.1.0.0/16", "--cidr", "10.2.0.0/16",
		"--platform", "ios", "--username", "netops"}, extra...)
}

func TestPasswordRefusedWithoutTerminal(t *testing.T) {
	cfg, state := testConfig(t)
	r := runCLI(t, fakeTerm{stdin: "pw-from-pipe\n"}, profileArgs(cfg, "--auth", "password")...)
	if r.code != 1 || !strings.Contains(r.stderr, "not a terminal") || !strings.Contains(r.stderr, "--password-stdin") {
		t.Fatalf("got %+v", r)
	}
	if _, err := os.Stat(filepath.Join(state, "ssh", "profiles.json")); !os.IsNotExist(err) {
		t.Fatalf("profiles.json written: %v", err)
	}
}

func TestPasswordStdin(t *testing.T) {
	cfg, state := testConfig(t)
	const pw = "s3cr3t-Passw0rd"
	r := runCLI(t, fakeTerm{stdin: pw + "\r\n"}, profileArgs(cfg, "--auth", "password", "--password-stdin")...)
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	cred, err := sshcfg.New(state).Credentials(sshcfg.KindProfile, "core", sshcfg.AuthPassword)
	if err != nil || cred.Password != pw {
		t.Fatalf("stored password wrong: %v", err)
	}
	list := runCLI(t, fakeTerm{}, "profile", "list", "--config", cfg)
	if list.code != 0 || !strings.Contains(list.stdout, "core") || !strings.Contains(list.stdout, "10.1.0.0/16,10.2.0.0/16") ||
		!strings.Contains(list.stdout, "netops") {
		t.Fatalf("list: %+v", list)
	}
	for _, s := range []string{r.stdout, r.stderr, list.stdout, list.stderr} {
		if strings.Contains(s, pw) {
			t.Fatalf("password printed: %q", s)
		}
	}
	// A second profile with the same name is refused before any secret is read.
	again := runCLI(t, fakeTerm{}, profileArgs(cfg, "--auth", "password", "--password-stdin")...)
	if again.code != 1 || !strings.Contains(again.stderr, "already exists") {
		t.Fatalf("duplicate: %+v", again)
	}
}

func TestTerminalPasswordMustMatch(t *testing.T) {
	cfg, state := testConfig(t)
	r := runCLI(t, fakeTerm{terminal: true, secrets: []string{"one", "two"}}, profileArgs(cfg, "--auth", "password")...)
	if r.code != 1 || !strings.Contains(r.stderr, "differ") {
		t.Fatalf("got %+v", r)
	}
	r = runCLI(t, fakeTerm{terminal: true, secrets: []string{"same", "same"}}, profileArgs(cfg, "--auth", "password")...)
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	if cred, err := sshcfg.New(state).Credentials(sshcfg.KindProfile, "core", sshcfg.AuthPassword); err != nil || cred.Password != "same" {
		t.Fatalf("credentials: %v", err)
	}
}

func TestCatchAllRefused(t *testing.T) {
	cfg, _ := testConfig(t)
	r := runCLI(t, fakeTerm{stdin: "pw\n"}, "profile", "add", "--config", cfg, "--name", "all", "--cidr", "0.0.0.0/0",
		"--platform", "ios", "--username", "u", "--auth", "password", "--password-stdin")
	if r.code != 1 || !strings.Contains(r.stderr, "catch-all") {
		t.Fatalf("got %+v", r)
	}
	r = runCLI(t, fakeTerm{stdin: "pw\n"}, "profile", "add", "--config", cfg, "--name", "bad", "--cidr", "10.0.0.0/8",
		"--platform", "windows", "--username", "u", "--auth", "password", "--password-stdin")
	if r.code != 1 || !strings.Contains(r.stderr, "platform") {
		t.Fatalf("got %+v", r)
	}
}

func TestEncryptedKeyFile(t *testing.T) {
	cfg, state := testConfig(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("open sesame"))
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	// Wrong passphrase: refused, nothing stored.
	r := runCLI(t, fakeTerm{terminal: true, secrets: []string{"nope"}}, profileArgs(cfg, "--auth", "key", "--key-file", keyFile)...)
	if r.code != 1 {
		t.Fatalf("wrong passphrase: %+v", r)
	}
	r = runCLI(t, fakeTerm{terminal: true, secrets: []string{"open sesame"}}, profileArgs(cfg, "--auth", "key", "--key-file", keyFile)...)
	if r.code != 0 {
		t.Fatalf("got %+v", r)
	}
	cred, err := sshcfg.New(state).Credentials(sshcfg.KindProfile, "core", sshcfg.AuthKey)
	if err != nil || cred.Signer == nil {
		t.Fatalf("credentials: %v", err)
	}
	fi, err := os.Stat(filepath.Join(state, "ssh", "keys", "profile-core"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	if strings.Contains(r.stdout+r.stderr, "open sesame") {
		t.Fatal("passphrase printed")
	}
	// Key auth without a key file is a usage error.
	if r := runCLI(t, fakeTerm{}, "profile", "add", "--config", cfg, "--name", "k2", "--cidr", "10.9.0.0/16", "--platform", "junos",
		"--username", "u", "--auth", "key"); r.code != 2 {
		t.Fatalf("no key file: %+v", r)
	}
}

func TestHostkeyAddListForget(t *testing.T) {
	cfg, _ := testConfig(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sg, _ := ssh.NewSignerFromKey(priv)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sg.PublicKey())))
	fp := ssh.FingerprintSHA256(sg.PublicKey())

	// Flags may come after the positionals.
	r := runCLI(t, fakeTerm{}, "hostkey", "add", "10.0.0.1:2222", line, "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, fp) {
		t.Fatalf("add: %+v", r)
	}
	r = runCLI(t, fakeTerm{}, "hostkey", "add", "10.0.0.1", "10.0.0.1 "+line, "--config", cfg)
	if r.code != 0 {
		t.Fatalf("add known_hosts line: %+v", r)
	}
	// A device by name is refused without a fingerprint to connect with: device keys are kept by address.
	if r := runCLI(t, fakeTerm{}, "hostkey", "add", "sw1.example.net", line, "--config", cfg); r.code != 1 {
		t.Fatalf("name: %+v", r)
	}
	list := runCLI(t, fakeTerm{}, "hostkey", "list", "--config", cfg)
	if list.code != 0 || !strings.Contains(list.stdout, "[10.0.0.1]:2222") || !strings.Contains(list.stdout, fp) ||
		!strings.Contains(list.stdout, "direct") {
		t.Fatalf("list: %+v", list)
	}
	r = runCLI(t, fakeTerm{}, "hostkey", "forget", "10.0.0.1:2222", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "forgot 1") {
		t.Fatalf("forget: %+v", r)
	}
	r = runCLI(t, fakeTerm{}, "hostkey", "forget", "--config", cfg, "10.0.0.1:2222")
	if r.code != 1 || !strings.Contains(r.stderr, "no key recorded") {
		t.Fatalf("forget again: %+v", r)
	}
	if r := runCLI(t, fakeTerm{}, "hostkey", "forget", "10.0.0.1", "--jump", "nojump", "--config", cfg); r.code != 1 {
		t.Fatalf("forget via unknown jump: %+v", r)
	}
	if r := runCLI(t, fakeTerm{}, "hostkey", "forget", "10.0.0.1", "--config", cfg); r.code != 0 {
		t.Fatalf("forget port 22: %+v", r)
	}
}

func TestProfileRemoveFlagsAfterName(t *testing.T) {
	cfg, state := testConfig(t)
	if r := runCLI(t, fakeTerm{stdin: "pw\n"}, profileArgs(cfg, "--auth", "password", "--password-stdin")...); r.code != 0 {
		t.Fatalf("add: %+v", r)
	}
	r := runCLI(t, fakeTerm{}, "profile", "remove", "core", "--config", cfg)
	if r.code != 0 {
		t.Fatalf("remove: %+v", r)
	}
	if c, err := sshcfg.New(state).Load(); err != nil || len(c.Profiles) != 0 {
		t.Fatalf("after remove: %v %v", c, err)
	}
	if r := runCLI(t, fakeTerm{}, "profile", "remove", "--config", cfg); r.code != 2 {
		t.Fatalf("remove without a name: %+v", r)
	}
	if r := runCLI(t, fakeTerm{}, "profile", "frobnicate"); r.code != 2 {
		t.Fatalf("unknown action: %+v", r)
	}
}

// hostIP is this host's first non-loopback IPv4 address; the policy refuses loopback.
func hostIP(t *testing.T) netip.Addr {
	t.Helper()
	raw, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range raw {
		pre, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		if ip := pre.Addr(); ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return ip
		}
	}
	t.Skip("no non-loopback IPv4 address to run a test server on")
	return netip.Addr{}
}

// keyServer accepts SSH connections far enough to show its host key.
func keyServer(t *testing.T, ip netip.Addr) (port int, key ssh.PublicKey) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	sg, _ := ssh.NewSignerFromKey(priv)
	conf := &ssh.ServerConfig{NoClientAuth: true}
	conf.AddHostKey(sg)
	ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				ssh.NewServerConn(c, conf)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, sg.PublicKey()
}

func TestJumpAddConfirmsHostKey(t *testing.T) {
	ip := hostIP(t)
	policyHook = func(p *policy.Policy) { p.SelfAddrs = nil }
	t.Cleanup(func() { policyHook = nil })
	port, key := keyServer(t, ip)
	fp := ssh.FingerprintSHA256(key)
	cfg, state := testConfig(t)
	args := []string{"jump", "add", "--config", cfg, "--name", "bastion", "--address", ip.String(), "--port", strconv.Itoa(port),
		"--username", "jumper", "--auth", "password", "--password-stdin"}

	// Not a terminal and no --accept-host-key: refused after showing the key.
	r := runCLI(t, fakeTerm{stdin: "pw\n"}, args...)
	if r.code != 1 || !strings.Contains(r.stdout, fp) || !strings.Contains(r.stderr, "--accept-host-key") {
		t.Fatalf("unconfirmed: %+v", r)
	}
	// The wrong fingerprint: refused.
	r = runCLI(t, fakeTerm{stdin: "pw\n"}, append(args, "--accept-host-key", "SHA256:wrong")...)
	if r.code != 1 {
		t.Fatalf("wrong fingerprint: %+v", r)
	}
	st := sshcfg.New(state)
	if c, _ := st.Load(); len(c.Jumps) != 0 {
		t.Fatal("jump added without confirmation")
	}
	// The right fingerprint: added, key recorded.
	r = runCLI(t, fakeTerm{stdin: "pw\n"}, append(args, "--accept-host-key", fp)...)
	if r.code != 0 {
		t.Fatalf("confirmed: %+v", r)
	}
	keys, err := st.LookupHostKeys("", sshcfg.HostPort(ip.String(), port))
	if err != nil || len(keys) != 1 || ssh.FingerprintSHA256(keys[0]) != fp {
		t.Fatalf("recorded keys %v %v", keys, err)
	}
	// Interactive confirmation.
	cfg2, _ := testConfig(t)
	args[3] = cfg2
	r = runCLI(t, fakeTerm{terminal: true, lines: []string{"y"}, secrets: []string{"pw", "pw"}}, args[:len(args)-1]...)
	if r.code != 0 {
		t.Fatalf("interactive: %+v", r)
	}

	// hostkey add by fingerprint connects and compares.
	cfg3, state3 := testConfig(t)
	r = runCLI(t, fakeTerm{}, "hostkey", "add", netip.AddrPortFrom(ip, uint16(port)).String(), fp, "--config", cfg3)
	if r.code != 0 {
		t.Fatalf("hostkey add by fingerprint: %+v", r)
	}
	if keys, _ := sshcfg.New(state3).LookupHostKeys("", sshcfg.HostPort(ip.String(), port)); len(keys) != 1 {
		t.Fatal("key not recorded")
	}
	r = runCLI(t, fakeTerm{}, "hostkey", "add", netip.AddrPortFrom(ip, uint16(port)).String(), "SHA256:other", "--config", cfg3)
	if r.code != 1 || !strings.Contains(r.stderr, "not SHA256:other") {
		t.Fatalf("mismatched fingerprint: %+v", r)
	}
}

func TestSSHTestRefusesBeforeConnecting(t *testing.T) {
	cfg, _ := testConfig(t)
	// No profile covers the device: refused, exit 1.
	r := runCLI(t, fakeTerm{}, "test", "--config", cfg, "--device", "192.0.2.10", "--command", "show version")
	if r.code != 1 || !strings.Contains(r.stdout, "refused: unavailable") {
		t.Fatalf("got %+v", r)
	}
	if !strings.Contains(r.stderr, "ssh.enabled is false") {
		t.Fatalf("no note about ssh.enabled: %+v", r)
	}
	if r := runCLI(t, fakeTerm{}, "test", "--config", cfg, "--device", "192.0.2.10"); r.code != 2 {
		t.Fatalf("missing command: %+v", r)
	}
}

func TestPasswordStdinRefusedOnTerminal(t *testing.T) {
	cfg, state := testConfig(t)
	r := runCLI(t, fakeTerm{terminal: true, stdin: "typed-with-echo\n"}, profileArgs(cfg, "--auth", "password", "--password-stdin")...)
	if r.code != 2 || !strings.Contains(r.stderr, "stdin is a terminal") {
		t.Fatalf("got %+v", r)
	}
	if _, err := os.Stat(filepath.Join(state, "ssh", "profiles.json")); !os.IsNotExist(err) {
		t.Fatalf("profiles.json written: %v", err)
	}
	r = runCLI(t, fakeTerm{terminal: true, stdin: "pw\n"}, "jump", "add", "--config", cfg, "--name", "j", "--address", "192.0.2.1",
		"--username", "u", "--auth", "password", "--password-stdin")
	if r.code != 2 || !strings.Contains(r.stderr, "stdin is a terminal") {
		t.Fatalf("jump add: %+v", r)
	}
}

func TestTrustOnFirstUseFlagAndProfileSet(t *testing.T) {
	cfg, state := testConfig(t)
	r := runCLI(t, fakeTerm{stdin: "pw\n"}, profileArgs(cfg, "--auth", "password", "--password-stdin")...)
	if r.code != 0 || !strings.Contains(r.stdout, "hostkey learn") || strings.Contains(r.stderr, "warning") {
		t.Fatalf("strict add: %+v", r)
	}
	r = runCLI(t, fakeTerm{stdin: "pw\n"}, "profile", "add", "--config", cfg, "--name", "tofu", "--cidr", "10.3.0.0/16",
		"--platform", "ios", "--username", "u", "--auth", "password", "--password-stdin", "--trust-on-first-use")
	if r.code != 0 || !strings.Contains(r.stderr, "warning: profile tofu") || strings.Count(r.stderr, "\n") != 1 {
		t.Fatalf("tofu add: %+v", r)
	}
	st := sshcfg.New(state)
	c, _ := st.Load()
	if p, _ := c.Profile("tofu"); p == nil || !p.TrustOnFirstUse {
		t.Fatalf("not stored: %+v", p)
	}
	b, _ := os.ReadFile(filepath.Join(state, "ssh", "profiles.json"))
	if !strings.Contains(string(b), `"trust_on_first_use": true`) {
		t.Fatalf("profiles.json: %s", b)
	}
	list := runCLI(t, fakeTerm{}, "profile", "list", "--config", cfg)
	if !strings.Contains(list.stdout, "FIRST-USE") || !strings.Contains(list.stdout, "trust (opted in)") || !strings.Contains(list.stdout, "refuse") {
		t.Fatalf("list: %+v", list)
	}

	r = runCLI(t, fakeTerm{}, "profile", "set", "core", "--legacy", "--trust-on-first-use", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "legacy_algorithms yes, trust_on_first_use yes") || !strings.Contains(r.stderr, "warning") {
		t.Fatalf("set: %+v", r)
	}
	r = runCLI(t, fakeTerm{}, "profile", "set", "core", "--no-legacy", "--no-trust-on-first-use", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "legacy_algorithms no, trust_on_first_use no") {
		t.Fatalf("unset: %+v", r)
	}
	c, _ = st.Load()
	if c.Profiles[0].Name != "core" || c.Profiles[0].Legacy || c.Profiles[0].TrustOnFirstUse {
		t.Fatalf("after set: %+v", c.Profiles)
	}
	// The secret is kept.
	if cred, err := st.Credentials(sshcfg.KindProfile, "core", sshcfg.AuthPassword); err != nil || cred.Password != "pw" {
		t.Fatalf("secret after set: %v", err)
	}
	for _, bad := range [][]string{{"core"}, {"core", "--legacy", "--no-legacy"}, {"core", "--trust-on-first-use", "--no-trust-on-first-use"}} {
		if r := runCLI(t, fakeTerm{}, append([]string{"profile", "set", "--config", cfg}, bad...)...); r.code != 2 {
			t.Fatalf("set %v: %+v", bad, r)
		}
	}
	if r := runCLI(t, fakeTerm{}, "profile", "set", "nosuch", "--legacy", "--config", cfg); r.code != 1 {
		t.Fatalf("set unknown: %+v", r)
	}
}

func TestHostkeyLearn(t *testing.T) {
	ip := hostIP(t)
	policyHook = func(p *policy.Policy) { p.SelfAddrs = nil }
	t.Cleanup(func() { policyHook = nil })
	port, key := keyServer(t, ip)
	fp := ssh.FingerprintSHA256(key)
	cfg, state := testConfig(t)
	// A strict password profile on the server's port.
	r := runCLI(t, fakeTerm{stdin: "pw\n"}, "profile", "add", "--config", cfg, "--name", "lab", "--cidr", ip.String(),
		"--platform", "ios", "--username", "u", "--auth", "password", "--password-stdin", "--port", strconv.Itoa(port))
	if r.code != 0 {
		t.Fatalf("add: %+v", r)
	}
	st := sshcfg.New(state)
	hp := sshcfg.HostPort(ip.String(), port)

	// No terminal and no --yes: refused before connecting.
	r = runCLI(t, fakeTerm{}, "hostkey", "learn", ip.String(), "--config", cfg)
	if r.code != 2 || !strings.Contains(r.stderr, "--yes") {
		t.Fatalf("no terminal: %+v", r)
	}
	// At a terminal, answered no: shown, not recorded.
	r = runCLI(t, fakeTerm{terminal: true, lines: []string{"n"}}, "hostkey", "learn", ip.String(), "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stdout, fp) || !strings.Contains(r.stdout, "profile lab") {
		t.Fatalf("declined: %+v", r)
	}
	if keys, _ := st.LookupHostKeys("", hp); len(keys) != 0 {
		t.Fatal("recorded without confirmation")
	}
	// --yes: the profile's port is used without being given, and what is recorded is printed.
	r = runCLI(t, fakeTerm{}, "hostkey", "learn", ip.String(), "--yes", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "recorded ssh-ed25519 "+fp+" for "+hp) {
		t.Fatalf("--yes: %+v", r)
	}
	if keys, _ := st.LookupHostKeys("", hp); len(keys) != 1 || ssh.FingerprintSHA256(keys[0]) != fp {
		t.Fatalf("recorded %v", keys)
	}
	r = runCLI(t, fakeTerm{}, "hostkey", "learn", ip.String(), "--yes", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "already recorded") {
		t.Fatalf("again: %+v", r)
	}
	// Interactive yes, given with an explicit port.
	cfg2, state2 := testConfig(t)
	r = runCLI(t, fakeTerm{terminal: true, lines: []string{"y"}}, "hostkey", "learn", netip.AddrPortFrom(ip, uint16(port)).String(), "--config", cfg2)
	if r.code != 0 {
		t.Fatalf("interactive: %+v", r)
	}
	if keys, _ := sshcfg.New(state2).LookupHostKeys("", hp); len(keys) != 1 {
		t.Fatal("not recorded")
	}
	// A zone and an address the policy refuses each fail; the others are still handled.
	r = runCLI(t, fakeTerm{}, "hostkey", "learn", "fd00::1%eth0", "127.0.0.1", netip.AddrPortFrom(ip, uint16(port)).String(), "--yes", "--config", cfg2)
	if r.code != 1 || !strings.Contains(r.stderr, "zone") || !strings.Contains(r.stderr, "2 of 3 host keys not recorded") {
		t.Fatalf("mixed: %+v", r)
	}
}

func TestRootRefusedInProbeUsersStore(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (scripts/go runs tests as root)")
	}
	cfg, state := testConfig(t)
	if err := os.Chown(state, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	r := runCLI(t, fakeTerm{terminal: true, secrets: []string{"pw", "pw"}}, profileArgs(cfg, "--auth", "password")...)
	if r.code != 1 || !strings.Contains(r.stderr, "sudo -u") {
		t.Fatalf("got %+v", r)
	}
	if _, err := os.Lstat(filepath.Join(state, "ssh")); !os.IsNotExist(err) {
		t.Fatalf("ssh/ created: %v", err)
	}
}

func TestCheckConfigCommandsFileWhenSSHOff(t *testing.T) {
	cfg, _ := testConfig(t)
	dir := filepath.Dir(cfg)
	bad := filepath.Join(dir, "commands-bad.yaml")
	good := filepath.Join(dir, "commands-good.yaml")
	os.WriteFile(bad, []byte("platforms:\n  ios:\n    allow: ['^show (unclosed$']\n"), 0o600)
	os.WriteFile(good, []byte("platforms:\n  ios:\n    allow: ['^show e2e-local$']\n"), 0o600)
	base, _ := os.ReadFile(cfg)
	for file, wantCode := range map[string]int{bad: 1, good: 0} {
		os.WriteFile(cfg, append(append([]byte(nil), base...), []byte("ssh: {commands_file: "+file+"}\n")...), 0o600)
		var out, errb bytes.Buffer
		code := realMain([]string{"check-config", "--config", cfg}, &out, &errb)
		if code != wantCode || !strings.Contains(out.String(), "not used") {
			t.Errorf("%s: code %d\n%s%s", filepath.Base(file), code, out.String(), errb.String())
		}
	}
}

type nameResolver map[string][]netip.Addr

func (r nameResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

// In closed mode a device the policy allows only by name (allow_hosts) is learnt by that name and recorded under its
// address, which is what device_show looks up.
func TestHostkeyLearnByAllowedName(t *testing.T) {
	ip := hostIP(t)
	policyHook = func(p *policy.Policy) {
		p.SelfAddrs = nil
		p.Resolver = nameResolver{"sw1.example.net": {ip}}
	}
	t.Cleanup(func() { policyHook = nil })
	port, key := keyServer(t, ip)
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	os.Mkdir(state, 0o700)
	cfg := filepath.Join(dir, "probe.yaml")
	os.WriteFile(cfg, []byte("hub_url: wss://hub.example.com\nstate_dir: "+state+"\ntargets: {mode: closed, allow_hosts: [sw1.example.net]}\n"), 0o600)
	r := runCLI(t, fakeTerm{}, "hostkey", "learn", ip.String()+":"+strconv.Itoa(port), "--yes", "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stderr, "denied") {
		t.Fatalf("by address, not allowed: %+v", r)
	}
	r = runCLI(t, fakeTerm{}, "hostkey", "learn", "sw1.example.net:"+strconv.Itoa(port), "--yes", "--config", cfg)
	if r.code != 0 {
		t.Fatalf("by name: %+v", r)
	}
	keys, _ := sshcfg.New(state).LookupHostKeys("", sshcfg.HostPort(ip.String(), port))
	if len(keys) != 1 || ssh.FingerprintSHA256(keys[0]) != ssh.FingerprintSHA256(key) {
		t.Fatalf("recorded %v", keys)
	}
}

// On a build whose SSH store has no protections, every probe ssh command is refused before it reads or asks anything.
func TestSSHCommandsRefusedWithoutStoreProtections(t *testing.T) {
	saved := sshPlatformError
	t.Cleanup(func() { sshPlatformError = saved })
	sshPlatformError = func() error { return sshcfg.PlatformErrorFor(false, "windows") }
	cfg, stateDir := testConfig(t)
	for _, args := range [][]string{
		profileArgs(cfg, "--auth", "password", "--password-stdin"),
		{"profile", "list", "--config", cfg},
		{"jump", "list", "--config", cfg},
		{"hostkey", "list", "--config", cfg},
		{"test", "--config", cfg, "10.1.0.1", "show version"},
		{"profile"},
	} {
		r := runCLI(t, fakeTerm{stdin: "pw\n"}, args...)
		if r.code != 1 || !strings.Contains(r.stderr, "not supported on windows") {
			t.Fatalf("%v: %+v", args, r)
		}
	}
	if _, err := os.Stat(filepath.Join(stateDir, "ssh")); !os.IsNotExist(err) {
		t.Fatalf("the store was created: %v", err)
	}
	if r := runCLI(t, fakeTerm{}, "help"); r.code != 0 {
		t.Fatalf("help: %+v", r)
	}
}

// probe ssh profile, jump and hostkey without an action name their own actions.
func TestSubcommandNeedsAction(t *testing.T) {
	for sub, want := range map[string]string{
		"profile": "(add, set, move, list or remove)",
		"jump":    "(add, set, list or remove)",
		"hostkey": "(list, add, learn or forget)",
	} {
		r := runCLI(t, fakeTerm{}, sub)
		if r.code != 2 || !strings.Contains(r.stderr, "probe ssh "+sub+" needs an action "+want) {
			t.Fatalf("%s: %+v", sub, r)
		}
	}
}

// addPasswordProfile adds a password profile reading pw from stdin.
func addPasswordProfile(t *testing.T, cfg, name, cidr, pw string) {
	t.Helper()
	r := runCLI(t, fakeTerm{stdin: pw + "\n"}, "profile", "add", "--config", cfg, "--name", name, "--cidr", cidr,
		"--platform", "ios", "--username", "u", "--auth", "password", "--password-stdin")
	if r.code != 0 {
		t.Fatalf("add %s: %+v", name, r)
	}
}

func writeKeyFile(t *testing.T, passphrase string) (path string, pub ssh.PublicKey) {
	t.Helper()
	pubK, priv, _ := ed25519.GenerateKey(rand.Reader)
	var blk *pem.Block
	var err error
	if passphrase == "" {
		blk, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		blk, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pubK)
	if err != nil {
		t.Fatal(err)
	}
	return path, sp
}

func profileNames(t *testing.T, st *sshcfg.Store) []string {
	t.Helper()
	c, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, p := range c.Profiles {
		names = append(names, p.Name)
	}
	return names
}

func TestProfileSetRotatesPassword(t *testing.T) {
	cfg, state := testConfig(t)
	st := sshcfg.New(state)
	addPasswordProfile(t, cfg, "first", "10.1.0.0/16", "old-pw-1")
	addPasswordProfile(t, cfg, "second", "10.2.0.0/16", "old-pw-2")
	addPasswordProfile(t, cfg, "third", "10.3.0.0/16", "old-pw-3")
	before, err := st.Credentials(sshcfg.KindProfile, "second", sshcfg.AuthPassword)
	if err != nil {
		t.Fatal(err)
	}

	// On a terminal: asked twice, no echo; the secret changes, the place and the other settings stay.
	const newPW = "brand-new-pw"
	r := runCLI(t, fakeTerm{terminal: true, secrets: []string{newPW, newPW}}, "profile", "set", "second", "--password", "--legacy", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "password updated; takes effect on the next command; any cool-down for this profile ends") {
		t.Fatalf("rotate: %+v", r)
	}
	after, err := st.Credentials(sshcfg.KindProfile, "second", sshcfg.AuthPassword)
	if err != nil || after.Password != newPW || after.Password == before.Password {
		t.Fatalf("password not rotated: %v", err)
	}
	// The cool-down mark is an HMAC of this very secret, so a different secret is a different mark (see devssh.secretMark).
	if got := profileNames(t, st); strings.Join(got, ",") != "first,second,third" {
		t.Fatalf("order changed: %v", got)
	}
	c, _ := st.Load()
	if p, _ := c.Profile("second"); !p.Legacy || strings.Join(p.CIDRs, ",") != "10.2.0.0/16" || p.Username != "u" {
		t.Fatalf("settings changed: %+v", p)
	}
	// The neighbours' secrets are untouched.
	for name, pw := range map[string]string{"first": "old-pw-1", "third": "old-pw-3"} {
		if cred, err := st.Credentials(sshcfg.KindProfile, name, sshcfg.AuthPassword); err != nil || cred.Password != pw {
			t.Fatalf("%s secret: %v", name, err)
		}
	}
	for _, out := range []string{r.stdout, r.stderr} {
		if strings.Contains(out, newPW) || strings.Contains(out, "old-pw") {
			t.Fatalf("password printed: %q", out)
		}
	}

	// From stdin, with --password-stdin; and the same password again says it ends nothing.
	r = runCLI(t, fakeTerm{stdin: "piped-pw\n"}, "profile", "set", "second", "--password", "--password-stdin", "--config", cfg)
	if r.code != 0 {
		t.Fatalf("stdin: %+v", r)
	}
	if cred, _ := st.Credentials(sshcfg.KindProfile, "second", sshcfg.AuthPassword); cred.Password != "piped-pw" {
		t.Fatal("stdin password not stored")
	}
	r = runCLI(t, fakeTerm{stdin: "piped-pw\n"}, "profile", "set", "second", "--password", "--password-stdin", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "password unchanged") || strings.Contains(r.stdout, "piped-pw") {
		t.Fatalf("same password: %+v", r)
	}

	// Refused without a terminal and without --password-stdin; mismatched entries; a terminal with --password-stdin.
	r = runCLI(t, fakeTerm{stdin: "x\n"}, "profile", "set", "second", "--password", "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stderr, "not a terminal") || !strings.Contains(r.stderr, "--password-stdin") {
		t.Fatalf("no terminal: %+v", r)
	}
	r = runCLI(t, fakeTerm{terminal: true, secrets: []string{"a", "b"}}, "profile", "set", "second", "--password", "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stderr, "differ") {
		t.Fatalf("mismatch: %+v", r)
	}
	r = runCLI(t, fakeTerm{terminal: true, stdin: "x\n"}, "profile", "set", "second", "--password", "--password-stdin", "--config", cfg)
	if r.code != 2 || !strings.Contains(r.stderr, "stdin is a terminal") {
		t.Fatalf("stdin on terminal: %+v", r)
	}
	if cred, _ := st.Credentials(sshcfg.KindProfile, "second", sshcfg.AuthPassword); cred.Password != "piped-pw" {
		t.Fatal("a refused rotation changed the password")
	}
}

func TestProfileSetRotatesKey(t *testing.T) {
	cfg, state := testConfig(t)
	st := sshcfg.New(state)
	oldFile, oldPub := writeKeyFile(t, "")
	r := runCLI(t, fakeTerm{}, "profile", "add", "--config", cfg, "--name", "k", "--cidr", "10.5.0.0/16", "--platform", "junos",
		"--username", "u", "--auth", "key", "--key-file", oldFile)
	if r.code != 0 {
		t.Fatalf("add: %+v", r)
	}
	addPasswordProfile(t, cfg, "after", "10.6.0.0/16", "pw")
	cred, _ := st.Credentials(sshcfg.KindProfile, "k", sshcfg.AuthKey)
	if string(cred.Signer.PublicKey().Marshal()) != string(oldPub.Marshal()) {
		t.Fatal("old key not stored")
	}

	// A new, encrypted key: passphrase asked for, key replaced, order kept.
	newFile, newPub := writeKeyFile(t, "open sesame")
	r = runCLI(t, fakeTerm{terminal: true, secrets: []string{"open sesame"}}, "profile", "set", "k", "--key-file", newFile, "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "key updated; takes effect on the next command; any cool-down for this profile ends") {
		t.Fatalf("rotate: %+v", r)
	}
	cred, err := st.Credentials(sshcfg.KindProfile, "k", sshcfg.AuthKey)
	if err != nil || string(cred.Signer.PublicKey().Marshal()) != string(newPub.Marshal()) {
		t.Fatalf("key not replaced: %v", err)
	}
	if got := strings.Join(profileNames(t, st), ","); got != "k,after" {
		t.Fatalf("order: %s", got)
	}
	if strings.Contains(r.stdout+r.stderr, "open sesame") {
		t.Fatal("passphrase printed")
	}
	fi, err := os.Stat(filepath.Join(state, "ssh", "keys", "profile-k"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}

	// Back to an unencrypted key: the old passphrase is dropped.
	plainFile, plainPub := writeKeyFile(t, "")
	if r = runCLI(t, fakeTerm{}, "profile", "set", "k", "--key-file", plainFile, "--config", cfg); r.code != 0 {
		t.Fatalf("plain key: %+v", r)
	}
	cred, err = st.Credentials(sshcfg.KindProfile, "k", sshcfg.AuthKey)
	if err != nil || string(cred.Signer.PublicKey().Marshal()) != string(plainPub.Marshal()) {
		t.Fatalf("plain key: %v", err)
	}

	// A wrong passphrase, a missing file and a non-key leave the stored key alone.
	for _, tc := range []struct {
		ft   fakeTerm
		file string
	}{
		{fakeTerm{terminal: true, secrets: []string{"wrong"}}, newFile},
		{fakeTerm{}, filepath.Join(t.TempDir(), "missing")},
		{fakeTerm{}, cfg},
	} {
		if r := runCLI(t, tc.ft, "profile", "set", "k", "--key-file", tc.file, "--config", cfg); r.code != 1 {
			t.Fatalf("%s: %+v", tc.file, r)
		}
	}
	cred, err = st.Credentials(sshcfg.KindProfile, "k", sshcfg.AuthKey)
	if err != nil || string(cred.Signer.PublicKey().Marshal()) != string(plainPub.Marshal()) {
		t.Fatalf("key changed by a refused rotation: %v", err)
	}
}

func TestProfileSetWrongAuthTypeRefused(t *testing.T) {
	cfg, state := testConfig(t)
	st := sshcfg.New(state)
	addPasswordProfile(t, cfg, "pwprof", "10.1.0.0/16", "the-pw")
	keyFile, _ := writeKeyFile(t, "")
	if r := runCLI(t, fakeTerm{}, "profile", "add", "--config", cfg, "--name", "keyprof", "--cidr", "10.2.0.0/16", "--platform", "eos",
		"--username", "u", "--auth", "key", "--key-file", keyFile); r.code != 0 {
		t.Fatalf("add: %+v", r)
	}
	// --key-file on a password profile, --password on a key profile: refused, with the way out, before any prompt.
	r := runCLI(t, fakeTerm{terminal: true}, "profile", "set", "pwprof", "--key-file", keyFile, "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stderr, "logs in with a password") || !strings.Contains(r.stderr, "remove it and add it again") {
		t.Fatalf("key on password profile: %+v", r)
	}
	r = runCLI(t, fakeTerm{terminal: true}, "profile", "set", "keyprof", "--password", "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stderr, "logs in with a key") || !strings.Contains(r.stderr, "remove it and add it again") {
		t.Fatalf("password on key profile: %+v", r)
	}
	// Combined flags and flags without a secret to read.
	for _, bad := range [][]string{
		{"pwprof", "--password", "--key-file", keyFile},
		{"pwprof", "--password-stdin"},
		{"nosuch", "--password"},
	} {
		r := runCLI(t, fakeTerm{terminal: true}, append([]string{"profile", "set", "--config", cfg}, bad...)...)
		if r.code == 0 {
			t.Fatalf("%v accepted: %+v", bad, r)
		}
	}
	if cred, _ := st.Credentials(sshcfg.KindProfile, "pwprof", sshcfg.AuthPassword); cred.Password != "the-pw" {
		t.Fatal("password changed by a refused command")
	}
	// The store itself refuses a secret of the wrong kind too.
	if _, err := st.SetProfileOptions("pwprof", sshcfg.ProfileOptions{Secret: &sshcfg.Secret{Key: []byte("x")}}); err == nil {
		t.Fatal("store accepted a key for a password profile")
	}
	if _, err := st.SetProfileOptions("keyprof", sshcfg.ProfileOptions{Secret: &sshcfg.Secret{Password: "x"}}); err == nil {
		t.Fatal("store accepted a password for a key profile")
	}
}

func TestProfileSetCombinesFlags(t *testing.T) {
	cfg, state := testConfig(t)
	st := sshcfg.New(state)
	addPasswordProfile(t, cfg, "a", "10.1.0.0/16", "pw-a")
	r := runCLI(t, fakeTerm{stdin: "pw-new\n"}, "profile", "set", "a", "--legacy", "--trust-on-first-use", "--password", "--password-stdin", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "legacy_algorithms yes, trust_on_first_use yes") || !strings.Contains(r.stdout, "password updated") ||
		!strings.Contains(r.stderr, "warning") {
		t.Fatalf("combined: %+v", r)
	}
	c, _ := st.Load()
	if p, _ := c.Profile("a"); !p.Legacy || !p.TrustOnFirstUse {
		t.Fatalf("options: %+v", p)
	}
	if cred, _ := st.Credentials(sshcfg.KindProfile, "a", sshcfg.AuthPassword); cred.Password != "pw-new" {
		t.Fatal("password not rotated")
	}
}

func TestJumpSet(t *testing.T) {
	cfg, state := testConfig(t)
	st := sshcfg.New(state)
	// Jump hosts are added without the network by writing through the store (jump add reads the host key live).
	keyFile, _ := writeKeyFile(t, "")
	key, _ := os.ReadFile(keyFile)
	if err := st.AddJump(sshcfg.Jump{Name: "pwj", Address: "192.0.2.1", Port: 22, Username: "j", Auth: sshcfg.AuthPassword}, sshcfg.Secret{Password: "jump-old"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddJump(sshcfg.Jump{Name: "keyj", Address: "192.0.2.2", Port: 22, Username: "j", Auth: sshcfg.AuthKey}, sshcfg.Secret{Key: key}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddJump(sshcfg.Jump{Name: "other", Address: "192.0.2.3", Port: 22, Username: "j", Auth: sshcfg.AuthPassword}, sshcfg.Secret{Password: "other-pw"}); err != nil {
		t.Fatal(err)
	}

	r := runCLI(t, fakeTerm{terminal: true, secrets: []string{"jump-new", "jump-new"}}, "jump", "set", "pwj", "--password", "--legacy", "--config", cfg)
	if r.code != 0 || !strings.Contains(r.stdout, "password updated; takes effect on the next command; any cool-down for this jump host ends") ||
		!strings.Contains(r.stdout, "legacy_algorithms yes") {
		t.Fatalf("password: %+v", r)
	}
	if cred, err := st.Credentials(sshcfg.KindJump, "pwj", sshcfg.AuthPassword); err != nil || cred.Password != "jump-new" {
		t.Fatalf("jump password: %v", err)
	}
	if strings.Contains(r.stdout+r.stderr, "jump-new") || strings.Contains(r.stdout+r.stderr, "jump-old") {
		t.Fatal("secret printed")
	}
	if cred, _ := st.Credentials(sshcfg.KindJump, "other", sshcfg.AuthPassword); cred.Password != "other-pw" {
		t.Fatal("another jump host's secret changed")
	}
	c, _ := st.Load()
	if names := []string{c.Jumps[0].Name, c.Jumps[1].Name, c.Jumps[2].Name}; strings.Join(names, ",") != "pwj,keyj,other" || !c.Jumps[0].Legacy {
		t.Fatalf("jumps: %+v", c.Jumps)
	}

	// Key rotation, and --no-legacy alone.
	newFile, newPub := writeKeyFile(t, "")
	if r = runCLI(t, fakeTerm{}, "jump", "set", "keyj", "--key-file", newFile, "--config", cfg); r.code != 0 || !strings.Contains(r.stdout, "key updated") {
		t.Fatalf("key: %+v", r)
	}
	if cred, err := st.Credentials(sshcfg.KindJump, "keyj", sshcfg.AuthKey); err != nil || string(cred.Signer.PublicKey().Marshal()) != string(newPub.Marshal()) {
		t.Fatalf("jump key: %v", err)
	}
	if r = runCLI(t, fakeTerm{}, "jump", "set", "pwj", "--no-legacy", "--config", cfg); r.code != 0 || !strings.Contains(r.stdout, "legacy_algorithms no") {
		t.Fatalf("no-legacy: %+v", r)
	}
	if cred, _ := st.Credentials(sshcfg.KindJump, "pwj", sshcfg.AuthPassword); cred.Password != "jump-new" {
		t.Fatal("secret lost by an options-only set")
	}

	// Refusals.
	r = runCLI(t, fakeTerm{terminal: true}, "jump", "set", "pwj", "--key-file", newFile, "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stderr, "logs in with a password") {
		t.Fatalf("key on password jump: %+v", r)
	}
	r = runCLI(t, fakeTerm{terminal: true}, "jump", "set", "keyj", "--password", "--config", cfg)
	if r.code != 1 || !strings.Contains(r.stderr, "logs in with a key") {
		t.Fatalf("password on key jump: %+v", r)
	}
	if r = runCLI(t, fakeTerm{}, "jump", "set", "pwj", "--config", cfg); r.code != 2 {
		t.Fatalf("nothing to set: %+v", r)
	}
	if r = runCLI(t, fakeTerm{}, "jump", "set", "pwj", "--legacy", "--no-legacy", "--config", cfg); r.code != 2 {
		t.Fatalf("both: %+v", r)
	}
	if r = runCLI(t, fakeTerm{}, "jump", "set", "nosuch", "--legacy", "--config", cfg); r.code != 1 || !strings.Contains(r.stderr, "no jump host") {
		t.Fatalf("unknown: %+v", r)
	}
	if r = runCLI(t, fakeTerm{stdin: "x\n"}, "jump", "set", "pwj", "--password", "--config", cfg); r.code != 1 || !strings.Contains(r.stderr, "not a terminal") {
		t.Fatalf("no terminal: %+v", r)
	}
}

func TestProfileMove(t *testing.T) {
	cfg, state := testConfig(t)
	st := sshcfg.New(state)
	for i, n := range []string{"a", "b", "c", "d"} {
		addPasswordProfile(t, cfg, n, "10."+strconv.Itoa(i+1)+".0.0/16", "pw-"+n)
	}
	order := func() string { return strings.Join(profileNames(t, st), ",") }

	r := runCLI(t, fakeTerm{}, "profile", "move", "d", "--before", "b", "--config", cfg)
	if r.code != 0 || order() != "a,d,b,c" || !strings.Contains(r.stdout, "moved profile d before b (now #2 of 4)") ||
		!strings.Contains(r.stdout, "order: a, d, b, c") {
		t.Fatalf("before: %+v %s", r, order())
	}
	r = runCLI(t, fakeTerm{}, "profile", "move", "a", "--last", "--config", cfg)
	if r.code != 0 || order() != "d,b,c,a" || !strings.Contains(r.stdout, "now #4 of 4") {
		t.Fatalf("last: %+v %s", r, order())
	}
	// Flags may come before the name.
	if r = runCLI(t, fakeTerm{}, "profile", "move", "--config", cfg, "--before", "d", "a"); r.code != 0 || order() != "a,d,b,c" {
		t.Fatalf("flags first: %+v %s", r, order())
	}
	// Already in place: nothing written.
	r = runCLI(t, fakeTerm{}, "profile", "move", "c", "--last", "--config", cfg)
	if r.code != 0 || order() != "a,d,b,c" || !strings.Contains(r.stdout, "already in place") {
		t.Fatalf("no-op last: %+v", r)
	}
	r = runCLI(t, fakeTerm{}, "profile", "move", "d", "--before", "b", "--config", cfg)
	if r.code != 0 || order() != "a,d,b,c" || !strings.Contains(r.stdout, "already in place") {
		t.Fatalf("no-op before: %+v", r)
	}
	// The secrets and settings go with the profile.
	if cred, err := st.Credentials(sshcfg.KindProfile, "d", sshcfg.AuthPassword); err != nil || cred.Password != "pw-d" {
		t.Fatalf("secret: %v", err)
	}

	for _, tc := range []struct {
		args []string
		code int
		msg  string
	}{
		{[]string{"nosuch", "--last"}, 1, `no profile "nosuch"`},
		{[]string{"a", "--before", "nosuch"}, 1, `no profile "nosuch" to move "a" before`},
		{[]string{"a", "--before", "a"}, 1, "before itself"},
		{[]string{"a"}, 2, "needs --before OTHER or --last"},
		{[]string{"a", "--before", "b", "--last"}, 2, "not both"},
	} {
		r := runCLI(t, fakeTerm{}, append([]string{"profile", "move", "--config", cfg}, tc.args...)...)
		if r.code != tc.code || !strings.Contains(r.stderr, tc.msg) {
			t.Fatalf("%v: %+v", tc.args, r)
		}
	}
	if order() != "a,d,b,c" {
		t.Fatalf("a refused move changed the order: %s", order())
	}
}

func TestProfileListNumbersRows(t *testing.T) {
	cfg, _ := testConfig(t)
	addPasswordProfile(t, cfg, "one", "10.1.0.0/16", "pw")
	addPasswordProfile(t, cfg, "two", "10.2.0.0/16", "pw")
	r := runCLI(t, fakeTerm{}, "profile", "list", "--config", cfg)
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	if r.code != 0 || len(lines) < 4 {
		t.Fatalf("list: %+v", r)
	}
	f := func(i int) []string { return strings.Fields(lines[i]) }
	if f(0)[0] != "#" || f(0)[1] != "NAME" || f(1)[0] != "1" || f(1)[1] != "one" || f(2)[0] != "2" || f(2)[1] != "two" {
		t.Fatalf("list rows are not numbered:\n%s", r.stdout)
	}
	if r := runCLI(t, fakeTerm{}, "profile", "move", "two", "--before", "one", "--config", cfg); r.code != 0 {
		t.Fatal(r)
	}
	r = runCLI(t, fakeTerm{}, "profile", "list", "--config", cfg)
	lines = strings.Split(strings.TrimSpace(r.stdout), "\n")
	if f(1)[1] != "two" || f(2)[1] != "one" {
		t.Fatalf("order after move:\n%s", r.stdout)
	}
}

func TestHelpListsRotationAndMove(t *testing.T) {
	r := runCLI(t, fakeTerm{}, "help")
	if r.code != 0 {
		t.Fatalf("help: %+v", r)
	}
	for _, want := range []string{
		"probe ssh profile set NAME", "[--password | --key-file PATH] [--password-stdin]",
		"probe ssh profile move NAME --before OTHER | --last",
		"probe ssh jump set NAME [--legacy | --no-legacy] [--password | --key-file PATH] [--password-stdin]",
		"cool-down after failed logins ends",
	} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("help does not mention %q:\n%s", want, r.stdout)
		}
	}
	for sub, want := range map[string][]string{"profile": {"set", "move"}, "jump": {"set"}} {
		r := runCLI(t, fakeTerm{}, sub)
		for _, a := range want {
			if r.code != 2 || !strings.Contains(r.stderr, a) {
				t.Errorf("%s needs-an-action message lacks %q: %+v", sub, a, r)
			}
		}
	}
	// No flags: the set commands name every flag they accept.
	cfg, _ := testConfig(t)
	addPasswordProfile(t, cfg, "a", "10.1.0.0/16", "pw")
	r = runCLI(t, fakeTerm{}, "profile", "set", "a", "--config", cfg)
	if r.code != 2 || !strings.Contains(r.stderr, "--password") || !strings.Contains(r.stderr, "--key-file") {
		t.Fatalf("profile set usage: %+v", r)
	}
}

// TestTrustFlagsRefusedOnKeyProfile: key profiles always record a device key on first use, so the trust flags would
// change nothing; they are refused rather than accepted silently.
func TestTrustFlagsRefusedOnKeyProfile(t *testing.T) {
	cfg, _ := testConfig(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	if r := runCLI(t, fakeTerm{terminal: true}, profileArgs(cfg, "--auth", "key", "--key-file", keyFile)...); r.code != 0 {
		t.Fatalf("add key profile: %+v", r)
	}
	for _, flag := range []string{"--trust-on-first-use", "--no-trust-on-first-use"} {
		r := runCLI(t, fakeTerm{}, "profile", "set", "core", flag, "--config", cfg)
		if r.code != 1 || !strings.Contains(r.stderr, "apply to password profiles") {
			t.Fatalf("%s on a key profile: %+v", flag, r)
		}
	}
}
