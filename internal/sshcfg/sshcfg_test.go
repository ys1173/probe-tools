package sshcfg

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"
)

func profile(name string, cidrs ...string) Profile {
	return Profile{Name: name, CIDRs: cidrs, Platform: "ios", Username: "netops", Auth: AuthPassword}
}

func TestCIDRsAndCatchAll(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/0", "10.0.0.0/7", "::/0", "2001::/15", "::ffff:0:0/96", "nonsense", "10.0.0.1%eth0"} {
		if _, err := ParseCIDR(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	for in, want := range map[string]string{"10.1.2.3/8": "10.0.0.0/8", "192.0.2.7": "192.0.2.7/32", "2001:db8::/16": "2001::/16",
		"::ffff:10.0.0.0/104": "10.0.0.0/8"} {
		got, err := ParseCIDR(in)
		if err != nil || got.String() != want {
			t.Errorf("%s: got %v %v, want %s", in, got, err, want)
		}
	}
	s := New(t.TempDir())
	if err := s.AddProfile(profile("all", "0.0.0.0/0"), Secret{Password: "pw"}); err == nil || !strings.Contains(err.Error(), "catch-all") {
		t.Fatalf("catch-all profile: %v", err)
	}
}

func TestMatchFirstInFileOrder(t *testing.T) {
	s := New(t.TempDir())
	if err := s.AddProfile(profile("core", "10.1.0.0/16"), Secret{Password: "a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProfile(profile("wide", "10.0.0.0/8"), Secret{Password: "b"}); err != nil {
		t.Fatal(err)
	}
	c, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := c.Match(netip.MustParseAddr("10.1.2.3")); !ok || p.Name != "core" {
		t.Fatalf("10.1.2.3 -> %v", p)
	}
	if p, ok := c.Match(netip.MustParseAddr("::ffff:10.9.0.1")); !ok || p.Name != "wide" {
		t.Fatalf("mapped 10.9.0.1 -> %v", p)
	}
	if _, ok := c.Match(netip.MustParseAddr("192.0.2.1")); ok {
		t.Fatal("192.0.2.1 matched")
	}
	sum := c.Summaries()
	if len(sum) != 2 || sum[0].Name != "core" || sum[0].CIDRs[0] != "10.1.0.0/16" {
		t.Fatalf("summaries %+v", sum)
	}
	cred, err := s.Credentials(KindProfile, "wide", AuthPassword)
	if err != nil || cred.Password != "b" {
		t.Fatalf("credentials: %v", err)
	}
	if err := s.RemoveProfile("core"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Credentials(KindProfile, "core", AuthPassword); err == nil {
		t.Fatal("secret survived removal")
	}
}

func TestJumpReferencesAndValidation(t *testing.T) {
	s := New(t.TempDir())
	p := profile("behind", "10.2.0.0/16")
	p.Jump = "bastion"
	if err := s.AddProfile(p, Secret{Password: "x"}); err == nil {
		t.Fatal("profile with a missing jump accepted")
	}
	if err := s.AddJump(Jump{Name: "bastion", Address: "bastion.example.net", Username: "u", Auth: AuthPassword}, Secret{Password: "j"}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddProfile(p, Secret{Password: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveJump("bastion"); err == nil {
		t.Fatal("removed a jump in use")
	}
	for _, bad := range []Profile{
		{Name: "Bad", CIDRs: []string{"10.0.0.0/8"}, Platform: "ios", Username: "u", Auth: AuthPassword},
		{Name: "p", CIDRs: []string{"10.0.0.0/8"}, Platform: "windows", Username: "u", Auth: AuthPassword},
		{Name: "p", CIDRs: []string{"10.0.0.0/8"}, Platform: "ios", Username: "a b", Auth: AuthPassword},
		{Name: "p", CIDRs: []string{"10.0.0.0/8"}, Platform: "ios", Username: "u", Auth: "token"},
		{Name: "p", CIDRs: nil, Platform: "ios", Username: "u", Auth: AuthPassword},
	} {
		if err := s.AddProfile(bad, Secret{Password: "x"}); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}

func TestPermissions(t *testing.T) {
	state := t.TempDir()
	s := New(state)
	key := testKey(t)
	if err := s.AddProfile(Profile{Name: "k", CIDRs: []string{"10.0.0.0/8"}, Platform: "junos", Username: "u", Auth: AuthKey},
		Secret{Key: key}); err != nil {
		t.Fatal(err)
	}
	if err := s.AddHostKey("", HostPort("10.0.0.1", 22), mustSigner(t, key).PublicKey()); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"", "keys"} {
		fi, err := os.Lstat(filepath.Join(state, "ssh", rel))
		if err != nil || fi.Mode().Perm() != 0o700 || !fi.IsDir() {
			t.Errorf("dir %q mode %v %v", rel, fi.Mode(), err)
		}
	}
	for _, rel := range []string{"profiles.json", "secrets.json", "keys/profile-k", "known_hosts", ".lock"} {
		fi, err := os.Lstat(filepath.Join(state, "ssh", rel))
		if err != nil || fi.Mode().Perm() != 0o600 || !fi.Mode().IsRegular() {
			t.Errorf("%s mode %v %v", rel, fi.Mode(), err)
		}
	}
	// No temporary file is left behind.
	ents, _ := os.ReadDir(filepath.Join(state, "ssh"))
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("left behind: %s", e.Name())
		}
	}
}

// victim stands in for a file root must never touch (/etc/shadow, /etc/sudoers): it returns its path and a check that
// it is unchanged.
func victim(t *testing.T) (string, func()) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "victim")
	if err := os.WriteFile(p, []byte("root:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(p)
	return p, func() {
		t.Helper()
		b, err := os.ReadFile(p)
		after, _ := os.Stat(p)
		if err != nil || string(b) != "root:secret\n" || after.Mode() != before.Mode() || !sameOwner(before, after) {
			t.Fatalf("the victim file changed: %q %v", b, err)
		}
	}
}

// asOtherUser makes the state directory belong to another user while this process counts as root: for real when the
// tests run as root (scripts/go), otherwise by pretending to be root.
func asOtherUser(t *testing.T, state string) {
	t.Helper()
	if os.Geteuid() == 0 {
		if err := os.Chown(state, 1000, 1000); err != nil {
			t.Fatal(err)
		}
		return
	}
	geteuid = func() int { return 0 }
	t.Cleanup(func() { geteuid = os.Geteuid })
}

func TestRootRefusesAnotherUsersStateDir(t *testing.T) {
	state := t.TempDir()
	// The probe user's doing: the store exists and its lock is a link to a root-owned file.
	if err := os.Mkdir(filepath.Join(state, "ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	v, unchanged := victim(t)
	if err := os.Symlink(v, filepath.Join(state, "ssh", ".lock")); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		os.Chown(filepath.Join(state, "ssh"), 1000, 1000)
		os.Lchown(filepath.Join(state, "ssh", ".lock"), 1000, 1000)
	}
	asOtherUser(t, state)
	s := New(state)
	err := s.AddProfile(profile("core", "10.1.0.0/16"), Secret{Password: "pw"})
	if err == nil || !strings.Contains(err.Error(), "sudo -u") || !strings.Contains(err.Error(), "root") {
		t.Fatalf("root in another user's state directory: %v", err)
	}
	unchanged()
	for name, err := range map[string]error{"Check": s.Check(), "Load": loadErr(s), "AddHostKey": s.AddHostKey("", "10.0.0.1",
		mustSigner(t, testKey(t)).PublicKey())} {
		if err == nil || !strings.Contains(err.Error(), "sudo -u") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := s.Credentials(KindProfile, "core", AuthPassword); err == nil {
		t.Error("credentials read")
	}
	unchanged()
}

func loadErr(s *Store) error { _, err := s.Load(); return err }

func TestSymlinksRefused(t *testing.T) {
	setup := func(t *testing.T) (*Store, string) {
		state := t.TempDir()
		s := New(state)
		if err := s.AddProfile(Profile{Name: "k", CIDRs: []string{"10.0.0.0/8"}, Platform: "ios", Username: "u", Auth: AuthKey},
			Secret{Key: testKey(t)}); err != nil {
			t.Fatal(err)
		}
		return s, filepath.Join(state, "ssh")
	}
	t.Run("lock", func(t *testing.T) {
		s, dir := setup(t)
		v, unchanged := victim(t)
		os.Remove(filepath.Join(dir, ".lock"))
		if err := os.Symlink(v, filepath.Join(dir, ".lock")); err != nil {
			t.Fatal(err)
		}
		if err := s.AddProfile(profile("p", "10.9.0.0/16"), Secret{Password: "pw"}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("lock link: %v", err)
		}
		unchanged()
	})
	t.Run("ssh dir", func(t *testing.T) {
		state := t.TempDir()
		elsewhere := t.TempDir()
		if err := os.Symlink(elsewhere, filepath.Join(state, "ssh")); err != nil {
			t.Fatal(err)
		}
		s := New(state)
		if err := s.AddProfile(profile("p", "10.9.0.0/16"), Secret{Password: "pw"}); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("ssh link: %v", err)
		}
		if _, err := s.Load(); err == nil {
			t.Fatal("a linked ssh directory read as a store")
		}
		if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
			t.Fatalf("written through the link: %v", ents)
		}
	})
	t.Run("keys dir", func(t *testing.T) {
		s, dir := setup(t)
		elsewhere := t.TempDir()
		os.RemoveAll(filepath.Join(dir, "keys"))
		if err := os.Symlink(elsewhere, filepath.Join(dir, "keys")); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Credentials(KindProfile, "k", AuthKey); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("keys link read: %v", err)
		}
		if err := s.AddProfile(Profile{Name: "k2", CIDRs: []string{"10.9.0.0/16"}, Platform: "ios", Username: "u", Auth: AuthKey},
			Secret{Key: testKey(t)}); err == nil {
			t.Fatal("key written through a linked keys directory")
		}
		if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
			t.Fatalf("written through the link: %v", ents)
		}
	})
	t.Run("key file", func(t *testing.T) {
		s, dir := setup(t)
		v, unchanged := victim(t)
		kp := filepath.Join(dir, "keys", "profile-k")
		os.Remove(kp)
		if err := os.Symlink(v, kp); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Credentials(KindProfile, "k", AuthKey); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("key link: %v", err)
		}
		// Removing the profile removes the link, not its target.
		if err := s.RemoveProfile("k"); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Lstat(kp); !os.IsNotExist(err) {
			t.Fatalf("link kept: %v", err)
		}
		unchanged()
	})
	t.Run("profiles and known_hosts", func(t *testing.T) {
		s, dir := setup(t)
		v, unchanged := victim(t)
		for _, name := range []string{"profiles.json", "known_hosts"} {
			os.Remove(filepath.Join(dir, name))
			if err := os.Symlink(v, filepath.Join(dir, name)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("profiles link: %v", err)
		}
		if _, err := s.LookupHostKeys("", "10.0.0.1"); err == nil || !strings.Contains(err.Error(), "symbolic link") {
			t.Fatalf("known_hosts link: %v", err)
		}
		if err := s.AddHostKey("", "10.0.0.1", mustSigner(t, testKey(t)).PublicKey()); err == nil {
			t.Fatal("host key added through a link")
		}
		unchanged()
	})
	t.Run("temp name", func(t *testing.T) {
		s, dir := setup(t)
		v, unchanged := victim(t)
		tempName = func(name string) string { return "." + name + "-planted.tmp" }
		t.Cleanup(func() { tempName = defaultTempName })
		if err := os.Symlink(v, filepath.Join(dir, ".profiles.json-planted.tmp")); err != nil {
			t.Fatal(err)
		}
		if err := s.AddProfile(profile("p", "10.9.0.0/16"), Secret{Password: "pw"}); err == nil {
			t.Fatal("wrote through a planted temporary name")
		}
		unchanged()
		if c, err := s.Load(); err != nil || len(c.Profiles) != 1 {
			t.Fatalf("store after the refused write: %v %v", c, err)
		}
	})
}

func TestOwnerAndModeChecked(t *testing.T) {
	state := t.TempDir()
	s := New(state)
	if err := s.AddProfile(profile("p", "10.0.0.0/8"), Secret{Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(state, "ssh")
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "chmod 700") {
		t.Fatalf("open ssh directory: %v", err)
	}
	os.Chmod(dir, 0o700)
	for _, name := range []string{"profiles.json", "secrets.json"} {
		p := filepath.Join(dir, name)
		os.Chmod(p, 0o640)
		err := loadErr(s)
		if name == "secrets.json" {
			_, err = s.Credentials(KindProfile, "p", AuthPassword)
		}
		if err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("%s 0640: %v", name, err)
		}
		os.Chmod(p, 0o600)
	}
	if os.Geteuid() != 0 {
		return // changing a file's owner needs root
	}
	if err := os.Chown(filepath.Join(dir, "profiles.json"), 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "uid 1000") {
		t.Fatalf("profiles.json owned by another user: %v", err)
	}
	os.Chown(filepath.Join(dir, "profiles.json"), 0, 0)
	if err := os.Chown(dir, 1000, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); err == nil || !strings.Contains(err.Error(), "uid 1000") {
		t.Fatalf("ssh directory owned by another user: %v", err)
	}
}

func TestHostPortInjectionRefused(t *testing.T) {
	s := New(t.TempDir())
	key := mustSigner(t, testKey(t)).PublicKey()
	if err := s.AddHostKey("", HostPort("10.0.0.1", 22), key); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(s.Dir(), "known_hosts"))
	other := strings.Fields(string(ssh.MarshalAuthorizedKey(mustSigner(t, testKey(t)).PublicKey())))[1]
	for _, hp := range []string{
		"fd00:1::5%z",
		"[fd00:1::5%z]:2222",
		"fd00:1::5%z\tssh-ed25519\t" + other + "\n10.0.0.2\tssh-ed25519\t" + other + "\tx",
		"10.0.0.2 ssh-ed25519 " + other,
		"10.0.0.2,10.0.0.3",
		"10.0.0.*",
		"!10.0.0.2",
		"|1|abc|def",
		"@revoked",
		"[10.0.0.2]:22",
		"[10.0.0.2]:0",
		"10.0.0.2:2222",
		"",
		"host\x00name",
		"10.0.0.2\r",
	} {
		if err := s.AddHostKey("", hp, key); err == nil {
			t.Errorf("recorded %q", hp)
		}
		if _, err := ParseHostPort(hp); err == nil && strings.Contains(hp, "%") {
			t.Errorf("ParseHostPort accepted %q", hp)
		}
	}
	after, _ := os.ReadFile(filepath.Join(s.Dir(), "known_hosts"))
	if string(before) != string(after) {
		t.Fatalf("known_hosts changed:\n%s", after)
	}
	for _, ok := range []string{"10.0.0.9", "[10.0.0.9]:2222", "2001:db8::9", "[2001:db8::9]:830", "sw1.example.net", "[jump_1.example]:2200"} {
		if err := CheckHostPort(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
}

func TestSecretsFileMustBePrivate(t *testing.T) {
	s := New(t.TempDir())
	if err := s.AddProfile(profile("p", "10.0.0.0/8"), Secret{Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(s.Dir(), "secrets.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Credentials(KindProfile, "p", AuthPassword); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-readable secrets used: %v", err)
	}
}

func TestEncryptedKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("open sesame"))
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(blk)
	if _, err := CheckKey(key, ""); err != ErrPassphraseNeeded {
		t.Fatalf("want ErrPassphraseNeeded, got %v", err)
	}
	if _, err := CheckKey(key, "wrong"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	s := New(t.TempDir())
	if err := s.AddProfile(Profile{Name: "k", CIDRs: []string{"10.0.0.0/8"}, Platform: "eos", Username: "u", Auth: AuthKey},
		Secret{Key: key, Passphrase: "open sesame"}); err != nil {
		t.Fatal(err)
	}
	cred, err := s.Credentials(KindProfile, "k", AuthKey)
	if err != nil || cred.Signer == nil {
		t.Fatalf("credentials: %v", err)
	}
}

func TestHostKeys(t *testing.T) {
	s := New(t.TempDir())
	k1 := mustSigner(t, testKey(t)).PublicKey()
	k2 := mustSigner(t, testKey(t)).PublicKey()
	hp, err := ParseHostPort("10.0.0.1:2222")
	if err != nil || hp != "[10.0.0.1]:2222" {
		t.Fatalf("hostport %q %v", hp, err)
	}
	if hp2, _ := ParseHostPort("2001:db8::1"); hp2 != "2001:db8::1" {
		t.Fatalf("v6 hostport %q", hp2)
	}
	if err := s.AddHostKey("", hp, k1); err != nil {
		t.Fatal(err)
	}
	if err := s.AddHostKey("", hp, k1); err != nil {
		t.Fatal("re-adding the same key:", err)
	}
	if err := s.AddHostKey("", hp, k2); err == nil {
		t.Fatal("a different key of the same type was added")
	}
	if err := s.AddHostKey("site-b", hp, k2); err != nil {
		t.Fatal("same address behind a jump:", err)
	}
	keys, _ := s.LookupHostKeys("", hp)
	if len(keys) != 1 || ssh.FingerprintSHA256(keys[0]) != ssh.FingerprintSHA256(k1) {
		t.Fatalf("direct keys %v", keys)
	}
	keys, _ = s.LookupHostKeys("site-b", hp)
	if len(keys) != 1 || ssh.FingerprintSHA256(keys[0]) != ssh.FingerprintSHA256(k2) {
		t.Fatalf("via-jump keys %v", keys)
	}
	list, err := s.ListHostKeys()
	if err != nil || len(list) != 2 || list[1].Jump != "site-b" {
		t.Fatalf("list %+v %v", list, err)
	}
	if n, err := s.ForgetHostKey("", hp); err != nil || n != 1 {
		t.Fatalf("forget: %d %v", n, err)
	}
	if keys, _ := s.LookupHostKeys("", hp); len(keys) != 0 {
		t.Fatal("key survived forget")
	}
}

func testKey(t *testing.T) []byte {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(blk)
}

func mustSigner(t *testing.T, key []byte) ssh.Signer {
	t.Helper()
	s, err := ssh.ParsePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConcurrentHostKeyRecordsAllKept(t *testing.T) {
	s := New(t.TempDir())
	// Several stores on one directory, as the probe and a `probe ssh` command would have.
	stores := []*Store{s, New(filepath.Dir(s.Dir())), New(filepath.Dir(s.Dir()))}
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := mustSigner(t, testKey(t)).PublicKey()
			errs <- stores[i%len(stores)].AddHostKey("", HostPort(fmt.Sprintf("10.0.0.%d", i+1), 22), key)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	list, err := s.ListHostKeys()
	if err != nil || len(list) != n {
		t.Fatalf("%d keys recorded, want %d (%v)", len(list), n, err)
	}
}

func sameOwner(a, b os.FileInfo) bool {
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	return !ok1 || !ok2 || (sa.Uid == sb.Uid && sa.Gid == sb.Gid)
}

// SSH device commands are refused on a build without the store's protections, naming the system; this build has them.
func TestPlatformError(t *testing.T) {
	if err := PlatformErrorFor(true, "linux"); err != nil {
		t.Fatal(err)
	}
	err := PlatformErrorFor(false, "windows")
	if err == nil || !strings.Contains(err.Error(), "not supported on windows") {
		t.Fatalf("%v", err)
	}
	if err := PlatformError(); (err == nil) != storeProtected {
		t.Fatalf("this build (protected %v): %v", storeProtected, err)
	}
}

func TestMoveProfileAndSetOptions(t *testing.T) {
	s := New(t.TempDir())
	for i, n := range []string{"a", "b", "c"} {
		if err := s.AddProfile(Profile{Name: n, CIDRs: []string{"10." + strconv.Itoa(i+1) + ".0.0/16"}, Platform: "eos", Username: "u", Auth: AuthPassword},
			Secret{Password: "pw-" + n}); err != nil {
			t.Fatal(err)
		}
	}
	order := func() string {
		c, err := s.Load()
		if err != nil {
			t.Fatal(err)
		}
		var n []string
		for _, p := range c.Profiles {
			n = append(n, p.Name)
		}
		return strings.Join(n, ",")
	}
	if pos, changed, err := s.MoveProfile("c", "a"); err != nil || !changed || pos != 1 || order() != "c,a,b" {
		t.Fatalf("move c before a: %d %v %v %s", pos, changed, err, order())
	}
	if pos, changed, err := s.MoveProfile("c", ""); err != nil || !changed || pos != 3 || order() != "a,b,c" {
		t.Fatalf("move c last: %d %v %v %s", pos, changed, err, order())
	}
	if _, changed, err := s.MoveProfile("c", ""); err != nil || changed {
		t.Fatalf("no-op: %v %v", changed, err)
	}
	if _, _, err := s.MoveProfile("a", "a"); err == nil || !strings.Contains(err.Error(), "itself") {
		t.Fatalf("before itself: %v", err)
	}
	if _, _, err := s.MoveProfile("x", ""); err == nil {
		t.Fatal("unknown name accepted")
	}
	if _, _, err := s.MoveProfile("a", "x"); err == nil {
		t.Fatal("unknown target accepted")
	}
	if order() != "a,b,c" {
		t.Fatalf("refused moves changed the order: %s", order())
	}
	// Matching follows the new order.
	if _, _, err := s.MoveProfile("b", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetProfileOptions("b", ProfileOptions{Secret: &Secret{Password: "pw-b2"}}); err != nil {
		t.Fatal(err)
	}
	if cred, err := s.Credentials(KindProfile, "b", AuthPassword); err != nil || cred.Password != "pw-b2" {
		t.Fatalf("rotated: %v", err)
	}
	if got, _ := s.Load(); got.Profiles[0].Name != "b" || len(got.Profiles) != 3 {
		t.Fatalf("rotation moved the profile: %+v", got.Profiles)
	}
	// An empty password, or a key for a password profile, writes nothing.
	for _, sec := range []Secret{{}, {Key: []byte("k")}, {Password: "x", Key: []byte("k")}} {
		if _, err := s.SetProfileOptions("b", ProfileOptions{Secret: &sec}); err == nil {
			t.Fatalf("accepted %v", sec)
		}
	}
	if cred, _ := s.Credentials(KindProfile, "b", AuthPassword); cred.Password != "pw-b2" {
		t.Fatal("password changed by a refused rotation")
	}
	if _, err := s.SetJumpOptions("nosuch", JumpOptions{}); err == nil {
		t.Fatal("unknown jump accepted")
	}
}
