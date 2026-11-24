package devssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"probetools/internal/sshcfg"
)

// The cool-down tests run their SSH servers on the host's one non-loopback address. Other addresses in a profile's
// range are synthetic: a failed login there is recorded with failedLogin, as run would after the password was sent.

var sentFailure = &passwordSentError{errors.New("ssh: handshake failed: ssh: unable to authenticate")}

func (f *fixture) failAt(addr string) {
	f.t.Helper()
	f.rt.failedLogin(target{addr: netip.MustParseAddr(addr), kind: sshcfg.KindProfile, name: "lab",
		auth: sshcfg.AuthPassword}, sentFailure)
}

func (f *fixture) cooling(addr string) (string, bool) {
	return f.rt.coolingDown(target{addr: netip.MustParseAddr(addr), kind: sshcfg.KindProfile, name: "lab",
		auth: sshcfg.AuthPassword})
}

// The reviewer's case: a host squatting on one address in a key profile's range accepts the first-use key and
// refuses the login. Nothing was sent that costs an account anything, so no cool-down starts, and the profile's other
// devices are not blocked.
func TestCooldownSquatterDoesNotBlockProfile(t *testing.T) {
	f := newFixture(t, open(), nil)
	f.rt.cfg.AuthFailureCooldown = 10 * time.Minute
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	squat := newServer(t, f.ip, serverOpts{kind: "exec", password: "x", pubkey: edSigner(t).PublicKey()})
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	f.addStrictProfile(sshcfg.Profile{Auth: sshcfg.AuthKey, CIDRs: []string{f.ip.String(), "10.99.0.0/24"}, Port: squat.port},
		sshcfg.Secret{Key: pem.EncodeToMemory(blk)})
	res := f.mustShow(f.ip.String(), "show version")
	wantOutcome(t, res, "auth_failed")
	if !res.HostKeyFirstUse || squat.attempts.Load() != 0 {
		t.Fatalf("first use %v, passwords %d", res.HostKeyFirstUse, squat.attempts.Load())
	}
	// Tried again, at that address too: a refused key costs no account a failure.
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
	if squat.conns.Load() != 2 {
		t.Fatalf("a refused key started a cool-down: %d connections", squat.conns.Load())
	}
	if len(f.rt.cool) != 0 {
		t.Fatalf("cool-downs after key failures: %v", f.rt.cool)
	}
}

// A password failure at one address cools that address down only; the profile's other devices are still tried.
func TestCooldownPerAddress(t *testing.T) {
	f := newFixture(t, open(), nil)
	f.rt.cfg.AuthFailureCooldown = 10 * time.Minute
	srv := newServer(t, f.ip, serverOpts{kind: "exec", password: testPassword})
	f.addProfile(sshcfg.Profile{Port: srv.port, CIDRs: []string{f.ip.String(), "10.99.0.0/24"}}, sshcfg.Secret{})

	// A squatter at 10.99.0.7 took the password and refused it.
	f.failAt("10.99.0.7")
	detail, cooling := f.cooling("10.99.0.7")
	if !cooling || !strings.HasPrefix(detail, "profile lab: a login to 10.99.0.7 ") ||
		!strings.Contains(detail, "not tried again until ") ||
		!strings.Contains(detail, "other devices of the profile are still tried") {
		t.Fatalf("squatted address: %v %q", cooling, detail)
	}
	// device_show to it answers at once.
	res := f.mustShow("10.99.0.7", "show version")
	wantOutcome(t, res, "auth_failed")
	if res.Detail != detail {
		t.Fatalf("detail %q", res.Detail)
	}
	// The real device under the same profile is still reached.
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "ok")
	if srv.conns.Load() != 1 {
		t.Fatalf("%d connections", srv.conns.Load())
	}

	// And the other way round: a real failure at this address leaves 10.99.0.8 alone.
	if err := f.store.RemoveProfile("lab"); err != nil {
		t.Fatal(err)
	}
	f.addProfile(sshcfg.Profile{Port: srv.port, CIDRs: []string{f.ip.String(), "10.99.0.0/24"}}, sshcfg.Secret{Password: "wrong"})
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
	if _, cooling := f.cooling(f.ip.String()); !cooling {
		t.Fatal("the failed address is not cooling down")
	}
	if _, cooling := f.cooling("10.99.0.8"); cooling {
		t.Fatal("one failed address cooled another down")
	}
}

// Password failures at three different addresses, within the cool-down and with the same secret, are the pattern of
// an account being locked out: then the profile is not tried at any address.
func TestCooldownProfileWideTrip(t *testing.T) {
	f := newFixture(t, open(), nil)
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	f.rt.now = func() time.Time { return now }
	f.rt.cfg.AuthFailureCooldown = 10 * time.Minute
	srv := newServer(t, f.ip, serverOpts{kind: "exec", password: testPassword})
	f.addProfile(sshcfg.Profile{Port: srv.port, CIDRs: []string{f.ip.String(), "10.99.0.0/24"}}, sshcfg.Secret{})

	f.failAt("10.99.0.1")
	f.failAt("10.99.0.1") // the same address twice is one address
	now = now.Add(time.Minute)
	f.failAt("10.99.0.2")
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "ok")
	if srv.conns.Load() != 1 {
		t.Fatal("two addresses blocked the profile")
	}
	// A failure that has ended no longer counts.
	now = now.Add(9*time.Minute + time.Second) // 10.99.0.1's ended, 10.99.0.2's has not
	f.failAt("10.99.0.3")
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "ok")
	// A third address within the window trips the profile.
	f.failAt("10.99.0.4")
	res := f.mustShow(f.ip.String(), "show version")
	wantOutcome(t, res, "auth_failed")
	if srv.conns.Load() != 2 {
		t.Fatalf("tripped profile connected: %d", srv.conns.Load())
	}
	if !strings.HasPrefix(res.Detail, "profile lab: logins with these credentials failed at 3 different addresses (10.99.0.2, 10.99.0.3, 10.99.0.4)") ||
		!strings.Contains(res.Detail, "not tried again until 2026-01-02T03:24:06Z at any address") ||
		!strings.Contains(res.Detail, "no connection was made") {
		t.Fatalf("detail %q", res.Detail)
	}
	if _, cooling := f.cooling("10.99.0.200"); !cooling {
		t.Fatal("an address that never failed is not covered by the trip")
	}
	// Changing the secret ends the trip and the per-address waits.
	if err := f.store.RemoveProfile("lab"); err != nil {
		t.Fatal(err)
	}
	f.addProfile(sshcfg.Profile{Port: srv.port, CIDRs: []string{f.ip.String(), "10.99.0.0/24"}}, sshcfg.Secret{Password: "new-one"})
	for _, a := range []string{"10.99.0.200", "10.99.0.4"} {
		if _, cooling := f.cooling(a); cooling {
			t.Fatalf("%s still cooling after the secret changed", a)
		}
	}
	// With the same secret again, the trip ends by itself after the cool-down.
	if err := f.store.RemoveProfile("lab"); err != nil {
		t.Fatal(err)
	}
	f.addProfile(sshcfg.Profile{Port: srv.port, CIDRs: []string{f.ip.String(), "10.99.0.0/24"}}, sshcfg.Secret{})
	now = now.Add(11 * time.Minute) // every earlier wait has ended
	for _, a := range []string{"10.99.0.11", "10.99.0.12", "10.99.0.13"} {
		f.failAt(a)
	}
	if _, cooling := f.cooling("10.99.0.200"); !cooling {
		t.Fatal("not tripped again")
	}
	now = now.Add(10 * time.Minute)
	wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "ok")
}

// A login that sent no password starts no cool-down: a refused key, a question that is not the password, a server
// that offers no password method.
func TestCooldownOnlyAfterPasswordSent(t *testing.T) {
	t.Run("odd prompt", func(t *testing.T) {
		f := newFixture(t, open(), nil)
		f.rt.cfg.AuthFailureCooldown = 10 * time.Minute
		srv := newServer(t, f.ip, serverOpts{kind: "exec", password: testPassword, both: true, prompt: "Passcode: "})
		f.addProfile(sshcfg.Profile{Port: srv.port}, sshcfg.Secret{})
		for range 2 {
			wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
		}
		if srv.conns.Load() != 2 || srv.attempts.Load() != 0 {
			t.Fatalf("%d connections, %d passwords", srv.conns.Load(), srv.attempts.Load())
		}
	})
	t.Run("no password method", func(t *testing.T) {
		f := newFixture(t, open(), nil)
		f.rt.cfg.AuthFailureCooldown = 10 * time.Minute
		srv := newServer(t, f.ip, serverOpts{kind: "exec", pubkey: edSigner(t).PublicKey()})
		f.addProfile(sshcfg.Profile{Port: srv.port}, sshcfg.Secret{})
		for range 2 {
			wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
		}
		if srv.conns.Load() != 2 {
			t.Fatalf("%d connections", srv.conns.Load())
		}
	})
	t.Run("password refused", func(t *testing.T) {
		f := newFixture(t, open(), nil)
		f.rt.cfg.AuthFailureCooldown = 10 * time.Minute
		srv := newServer(t, f.ip, serverOpts{kind: "exec", password: "the-real-one", kbdOnly: true})
		f.addProfile(sshcfg.Profile{Port: srv.port}, sshcfg.Secret{})
		for range 2 {
			wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
		}
		if srv.conns.Load() != 1 || srv.attempts.Load() != 1 {
			t.Fatalf("%d connections, %d passwords", srv.conns.Load(), srv.attempts.Load())
		}
	})
}

// A jump host is one host: a password refused there cools it down for every profile that uses it, at every device;
// a refused key starts nothing; and a device's failure behind the jump cools the device's address, not the jump.
func TestCooldownJumpScope(t *testing.T) {
	setup := func(t *testing.T, jumpAuth string, jumpSecret sshcfg.Secret, jumpOpts serverOpts, devPassword string) (*fixture, *devServer, *devServer) {
		ip := hostIP(t)
		f := newFixture(t, open(), map[string][]netip.Addr{"bastion.example.net": {ip}})
		f.rt.cfg.AuthFailureCooldown = 10 * time.Minute
		dev := newServer(t, f.ip, serverOpts{kind: "exec", password: devPassword})
		jumpKey := edSigner(t)
		jumpOpts.kind, jumpOpts.user, jumpOpts.hostKey = "jump", "hop-user", jumpKey
		jump := newServer(t, f.ip, jumpOpts)
		if err := f.store.AddJump(sshcfg.Jump{Name: "bastion", Address: "bastion.example.net", Port: jump.port,
			Username: "hop-user", Auth: jumpAuth}, jumpSecret); err != nil {
			t.Fatal(err)
		}
		if err := f.store.AddHostKey("", sshcfg.HostPort("bastion.example.net", jump.port), jumpKey.PublicKey()); err != nil {
			t.Fatal(err)
		}
		f.addProfile(sshcfg.Profile{Port: dev.port, Jump: "bastion"}, sshcfg.Secret{})
		f.addProfile(sshcfg.Profile{Name: "other", Port: dev.port, Jump: "bastion", CIDRs: []string{"10.99.0.0/24"}}, sshcfg.Secret{})
		return f, dev, jump
	}
	t.Run("password refused at the jump", func(t *testing.T) {
		f, dev, jump := setup(t, sshcfg.AuthPassword, sshcfg.Secret{Password: "not-the-jump-pw"},
			serverOpts{password: "jump-pw"}, testPassword)
		wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
		// Another profile, another device, the same jump: it waits, and the jump is not contacted.
		res := f.mustShow("10.99.0.7", "show version")
		wantOutcome(t, res, "auth_failed")
		if !strings.HasPrefix(res.Detail, "jump host bastion: a login to it with these credentials failed") ||
			jump.conns.Load() != 1 || dev.conns.Load() != 0 {
			t.Fatalf("detail %q, jump conns %d, device conns %d", res.Detail, jump.conns.Load(), dev.conns.Load())
		}
		// The profiles themselves are not cooling down.
		if _, cooling := f.cooling(f.ip.String()); cooling {
			t.Fatal("a jump failure cooled the profile down")
		}
	})
	t.Run("key refused at the jump", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		blk, _ := ssh.MarshalPrivateKey(priv, "")
		f, _, jump := setup(t, sshcfg.AuthKey, sshcfg.Secret{Key: pem.EncodeToMemory(blk)},
			serverOpts{pubkey: edSigner(t).PublicKey()}, testPassword)
		for range 2 {
			wantOutcome(t, f.mustShow(f.ip.String(), "show version"), "auth_failed")
		}
		if jump.conns.Load() != 2 {
			t.Fatalf("a refused jump key started a cool-down: %d connections", jump.conns.Load())
		}
	})
	t.Run("password refused at the device behind the jump", func(t *testing.T) {
		f, dev, _ := setup(t, sshcfg.AuthPassword, sshcfg.Secret{Password: "jump-pw"},
			serverOpts{password: "jump-pw"}, "the-real-one")
		res := f.mustShow(f.ip.String(), "show version")
		wantOutcome(t, res, "auth_failed")
		if dev.attempts.Load() != 1 {
			t.Fatalf("device passwords %d", dev.attempts.Load())
		}
		res = f.mustShow(f.ip.String(), "show version")
		wantOutcome(t, res, "auth_failed")
		if !strings.HasPrefix(res.Detail, "profile lab: a login to "+f.ip.String()+" ") || dev.conns.Load() != 1 {
			t.Fatalf("detail %q, device conns %d", res.Detail, dev.conns.Load())
		}
		// The jump itself is not cooling down, so the other profile's devices are still tried through it.
		c, err := f.store.Load()
		if err != nil {
			t.Fatal(err)
		}
		j, _ := c.Jump("bastion")
		if d, cooling := f.rt.coolingDown(target{addr: netip.MustParseAddr("10.99.0.7"), kind: sshcfg.KindProfile,
			name: "other", auth: sshcfg.AuthPassword, jump: j}); cooling {
			t.Fatalf("a device failure cooled the jump down: %q", d)
		}
	})
}
