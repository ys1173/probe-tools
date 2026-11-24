package devssh

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"probetools/internal/policy"
	"probetools/internal/protocol"
	"probetools/internal/sshcfg"
)

// knownHostsFiles returns the store's known_hosts files and their contents.
func knownHostsFiles(t *testing.T, s *sshcfg.Store) map[string]string {
	t.Helper()
	out := map[string]string{}
	m, _ := filepath.Glob(filepath.Join(s.Dir(), "known_hosts*"))
	for _, p := range m {
		b, _ := os.ReadFile(p)
		out[filepath.Base(p)] = string(b)
	}
	return out
}

// A device with an IPv6 zone is refused at every layer: the parameters, the policy, and Show called directly.
func TestZonedDeviceRefused(t *testing.T) {
	f := newFixture(t, open(), nil)
	srv := newServer(t, f.ip, serverOpts{kind: "exec", password: testPassword})
	f.addProfile(sshcfg.Profile{Port: srv.port, CIDRs: []string{f.ip.String(), "fd00:1::/64"}}, sshcfg.Secret{})
	pinned := edSigner(t).PublicKey()
	if err := f.store.AddHostKey("", sshcfg.HostPort(f.ip.String(), srv.port), pinned); err != nil {
		t.Fatal(err)
	}
	before := knownHostsFiles(t, f.store)
	_, other := slashFreeKey(t)
	inject := "fd00:1::5%z\tssh-ed25519\t" + other + "\n" + f.ip.String() + "\tssh-ed25519\t" + other + "\tx"
	for _, device := range []string{"fd00:1::5%x", "::ffff:" + f.ip.String() + "%x", f.ip.String() + "%x", inject} {
		_, perr := f.show(device, "show version", 5000)
		wantCode(t, perr, protocol.CodeInvalidParams)
		// Show itself, without the parameters' own check, is refused by the policy.
		_, perr = f.rt.Show(policy.WithJob(context.Background()), f.env.Policy,
			protocol.DeviceShowParams{Device: device, Command: "show version", TimeoutMS: 5000})
		wantCode(t, perr, protocol.CodeInvalidParams)
	}
	if srv.conns.Load() != 0 || srv.attempts.Load() != 0 {
		t.Fatalf("a zoned device reached the server: %d connections", srv.conns.Load())
	}
	if after := knownHostsFiles(t, f.store); len(after) != len(before) || after["known_hosts"] != before["known_hosts"] {
		t.Fatalf("known_hosts changed: %q", after)
	}
	// The pinned key still holds for the plain address.
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "host_key_changed")
}

func slashFreeKey(t *testing.T) (ssh.Signer, string) {
	for {
		s := edSigner(t)
		f := strings.Fields(string(ssh.MarshalAuthorizedKey(s.PublicKey())))
		if !strings.Contains(f[1], "/") {
			return s, f[1]
		}
	}
}

// Every spelling of one address takes the same session slot.
func TestBusyKeyIsCanonical(t *testing.T) {
	f := newFixture(t, open(), nil)
	srv := newServer(t, f.ip, serverOpts{kind: "exec", password: testPassword})
	f.addProfile(sshcfg.Profile{Port: srv.port}, sshcfg.Secret{})
	if !f.rt.lock(f.ip) {
		t.Fatal("lock")
	}
	for _, device := range []string{f.ip.String(), "::ffff:" + f.ip.String()} {
		_, perr := f.show(device, "show version", 5000)
		wantCode(t, perr, protocol.CodeBusy)
	}
	f.rt.unlock(f.ip)
	if srv.conns.Load() != 0 {
		t.Fatal("connected while busy")
	}
	wantOutcome(t, f.mustShow("::ffff:"+f.ip.String(), "show version"), "ok")
	f.rt.mu.Lock()
	n := len(f.rt.busy)
	f.rt.mu.Unlock()
	if n != 0 {
		t.Fatal("slot not released")
	}
}

// A password profile never logs in to a device whose key is not recorded; the operator records it first.
func TestPasswordProfileUnknownKey(t *testing.T) {
	f := newFixture(t, open(), nil)
	key := edSigner(t)
	srv := newServer(t, f.ip, serverOpts{kind: "exec", password: testPassword, both: true, hostKey: key})
	f.addStrictProfile(sshcfg.Profile{Port: srv.port}, sshcfg.Secret{})
	res := f.mustShow(f.ip.String(), "show version")
	wantOutcome(t, res, "host_key_unknown")
	if res.HostKey != ssh.FingerprintSHA256(key.PublicKey()) || res.HostKeyFirstUse {
		t.Fatalf("host key %q first use %v", res.HostKey, res.HostKeyFirstUse)
	}
	hp := sshcfg.HostPort(f.ip.String(), srv.port)
	if !strings.HasSuffix(res.Detail, "probe ssh hostkey learn "+f.ip.String()) || !strings.Contains(res.Detail, hp+" presented") ||
		!strings.Contains(res.Detail, "nothing was sent") {
		t.Fatalf("detail %q", res.Detail)
	}
	if srv.attempts.Load() != 0 || len(srv.seen()) != 0 {
		t.Fatal("the password or a command was sent to an unknown host")
	}
	if keys, _ := f.store.LookupHostKeys("", hp); len(keys) != 0 {
		t.Fatal("the unknown key was recorded")
	}
	// What `probe ssh hostkey learn` does: read the key without logging in, then record it.
	k, addr, err := f.rt.FetchHostKey(context.Background(), f.env.Policy, f.ip.String(), srv.port, "", false)
	if err != nil || srv.attempts.Load() != 0 {
		t.Fatalf("fetch: %v", err)
	}
	if err := f.store.AddHostKey("", sshcfg.HostPort(addr.String(), srv.port), k); err != nil {
		t.Fatal(err)
	}
	res = f.mustShow(f.ip.String(), "show version")
	wantOutcome(t, res, "ok")
	if res.HostKeyFirstUse || srv.attempts.Load() != 1 {
		t.Fatalf("after learning: first use %v attempts %d", res.HostKeyFirstUse, srv.attempts.Load())
	}
}

func TestTrustOnFirstUseOptIn(t *testing.T) {
	f := newFixture(t, open(), nil)
	srv := newServer(t, f.ip, serverOpts{kind: "exec", password: testPassword})
	f.addStrictProfile(sshcfg.Profile{Port: srv.port, TrustOnFirstUse: true}, sshcfg.Secret{})
	res := f.mustShow(f.ip.String(), "show version")
	wantOutcome(t, res, "ok")
	if !res.HostKeyFirstUse {
		t.Fatal("first use not reported")
	}
	if keys, _ := f.store.LookupHostKeys("", sshcfg.HostPort(f.ip.String(), srv.port)); len(keys) != 1 {
		t.Fatal("key not recorded")
	}
}

// After auth_failed, the profile is not tried again within the cool-down, unless its secret changes.
func TestAuthFailureCooldown(t *testing.T) {
	f := newFixture(t, open(), nil)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f.rt.now = func() time.Time { return now }
	f.rt.cfg.AuthFailureCooldown = 10 * time.Minute
	srv := newServer(t, f.ip, serverOpts{kind: "exec", password: "the-real-one"})
	f.addProfile(sshcfg.Profile{Port: srv.port}, sshcfg.Secret{})

	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
	if srv.conns.Load() != 1 || srv.attempts.Load() != 1 {
		t.Fatalf("first: %d connections, %d attempts", srv.conns.Load(), srv.attempts.Load())
	}
	now = now.Add(9 * time.Minute)
	res := f.mustShow(f.ip.String(), "show version")
	wantOutcome(t, res, "auth_failed")
	if srv.conns.Load() != 1 || srv.attempts.Load() != 1 {
		t.Fatalf("within the cool-down: %d connections, %d attempts", srv.conns.Load(), srv.attempts.Load())
	}
	if !strings.Contains(res.Detail, "profile lab") || !strings.Contains(res.Detail, "2026-01-02T03:14:05Z") ||
		!strings.Contains(res.Detail, "no connection was made") || res.Profile != "lab" || res.Address != f.ip.String() {
		t.Fatalf("cool-down result %+v", res)
	}
	// The same address on another port waits too: it is the same device and the same account.
	other := newServer(t, f.ip, serverOpts{kind: "exec", password: "the-real-one"})
	if err := f.store.RemoveProfile("lab"); err != nil {
		t.Fatal(err)
	}
	// Re-adding it with the same (wrong) secret keeps the wait.
	f.addProfile(sshcfg.Profile{Port: other.port}, sshcfg.Secret{})
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
	if other.conns.Load() != 0 {
		t.Fatal("same secret, still cooling down, but connected")
	}
	// Changing the secret ends it.
	if err := f.store.RemoveProfile("lab"); err != nil {
		t.Fatal(err)
	}
	f.addProfile(sshcfg.Profile{Port: other.port}, sshcfg.Secret{Password: "the-real-one"})
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "ok")

	// And it ends by itself after the cool-down.
	if err := f.store.RemoveProfile("lab"); err != nil {
		t.Fatal(err)
	}
	f.addProfile(sshcfg.Profile{Port: srv.port}, sshcfg.Secret{Password: "wrong-again"})
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
	n := srv.conns.Load()
	now = now.Add(10*time.Minute + time.Second)
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
	if srv.conns.Load() != n+1 {
		t.Fatal("not tried again after the cool-down")
	}

	// Off when 0.
	f.rt.cfg.AuthFailureCooldown = 0
	n = srv.conns.Load()
	f.mustShow(f.ip.String(), "show version")
	f.mustShow(f.ip.String(), "show version")
	if srv.conns.Load() != n+2 {
		t.Fatal("cool-down applied while off")
	}
}

// A jump host whose login failed waits too, and the device is not contacted.
func TestAuthFailureCooldownJump(t *testing.T) {
	ip := hostIP(t)
	f := newFixture(t, open(), map[string][]netip.Addr{"bastion.example.net": {ip}})
	f.rt.cfg.AuthFailureCooldown = time.Minute
	dev := newServer(t, f.ip, serverOpts{kind: "exec", password: testPassword})
	jumpKey := edSigner(t)
	jump := newServer(t, f.ip, serverOpts{kind: "jump", user: "hop-user", password: "jump-pw", hostKey: jumpKey})
	if err := f.store.AddJump(sshcfg.Jump{Name: "bastion", Address: "bastion.example.net", Port: jump.port, Username: "hop-user",
		Auth: sshcfg.AuthPassword}, sshcfg.Secret{Password: "not-the-jump-pw"}); err != nil {
		t.Fatal(err)
	}
	if err := f.store.AddHostKey("", sshcfg.HostPort("bastion.example.net", jump.port), jumpKey.PublicKey()); err != nil {
		t.Fatal(err)
	}
	f.addProfile(sshcfg.Profile{Port: dev.port, Jump: "bastion"}, sshcfg.Secret{})
	res := f.mustShow(ip.String(), "show version")
	wantOutcome(t, res, "auth_failed")
	if !strings.HasPrefix(res.Detail, "jump host bastion: ") || jump.attempts.Load() != 1 {
		t.Fatalf("jump login: %q, %d attempts", res.Detail, jump.attempts.Load())
	}
	res = f.mustShow(ip.String(), "show version")
	wantOutcome(t, res, "auth_failed")
	if !strings.HasPrefix(res.Detail, "jump host bastion: ") || jump.conns.Load() != 1 || dev.conns.Load() != 0 {
		t.Fatalf("cooling jump: %q, jump conns %d, device conns %d", res.Detail, jump.conns.Load(), dev.conns.Load())
	}
}
