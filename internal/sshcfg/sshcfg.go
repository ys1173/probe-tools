// Package sshcfg is the probe's local SSH store: the profiles that say which credentials and platform to use for which
// device addresses, the jump hosts, their secrets, private keys and the known host keys. It lives under
// <state_dir>/ssh/ and is written only by the local `probe ssh ...` commands (and, for host keys first seen, by the
// probe itself). Nothing in it ever leaves the probe except the profile summaries (names, CIDRs, platform, jump).
//
// Layout, all owned by the probe's user, directory 0700 and files 0600:
//
//	ssh/profiles.json               profiles and jump hosts, in order; no secrets
//	ssh/secrets.json                passwords and key passphrases, keyed "profile/<name>" or "jump/<name>"
//	ssh/keys/profile-<name>         a profile's private key (copied in by `probe ssh profile add --auth key`)
//	ssh/keys/jump-<name>            a jump host's private key
//	ssh/known_hosts                 host keys of devices reached directly, and of the jump hosts themselves
//	ssh/known_hosts.via-<jump>      host keys of devices reached through jump host <jump>
//
// known_hosts files are in OpenSSH format with one host per line, written as knownhosts.Normalize gives it: "addr" for
// port 22, "[addr]:port" otherwise. Devices behind a jump get a file per jump, so the same private address reached
// through two jumps (two sites reusing a range) is two hosts.
//
// Every write is atomic (temporary file, then rename). The probe reads the store for every job, so a change applies to
// the next command without a restart.
//
// The store is used only by the user that owns it. ssh/ and keys/ must be real directories owned by that user with no
// access for others, and every file a regular file owned by it, mode 0600; symbolic links are refused, never
// followed. A process running as root refuses a state directory that belongs to another user (the systemd install's
// "probe"): run `probe ssh ...` as that user (sudo -u probe probe ssh ...). These protections need a unix system; on
// any other build PlatformError refuses the store.
package sshcfg

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"

	"probetools/internal/protocol"
)

// Authentication methods.
const (
	AuthPassword = "password"
	AuthKey      = "key"
)

const (
	DefaultPort = 22
	// MaxProfiles and MaxProfileCIDRs match what the hub accepts in a hello, so every profile can be reported.
	MaxProfiles     = 64
	MaxProfileCIDRs = 16
	MaxJumps        = 64
	maxUsername     = 64
	maxAddress      = 253
	maxKeyFileBytes = 64 << 10

	// Catch-all ranges are refused: a profile must name the networks it is for.
	minPrefixV4 = 8
	minPrefixV6 = 16

	dirName       = "ssh"
	profilesFile  = "profiles.json"
	secretsFile   = "secrets.json"
	keysDir       = "keys"
	knownHosts    = "known_hosts"
	knownViaPrefx = "known_hosts.via-"
	lockFile      = ".lock"
)

var nameRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

// ValidName reports whether s is a valid profile or jump name.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// Kind says whether a secret or key belongs to a profile or a jump host.
type Kind string

const (
	KindProfile Kind = "profile"
	KindJump    Kind = "jump"
)

// Profile is one set of device credentials and the device ranges it covers.
type Profile struct {
	Name     string   `json:"name"`
	CIDRs    []string `json:"cidrs"`
	Platform string   `json:"platform"`
	Username string   `json:"username"`
	Auth     string   `json:"auth"`
	Port     int      `json:"port"`
	Jump     string   `json:"jump,omitempty"`
	// Legacy adds the old algorithms x/crypto still implements but leaves out by default (SHA-1 key exchanges, CBC
	// ciphers, ssh-rsa with SHA-1 signatures, hmac-sha1-96), for devices that offer nothing newer.
	Legacy bool `json:"legacy_algorithms,omitempty"`
	// TrustOnFirstUse lets a password profile record an unknown device key and log in. Without it a password is sent
	// only to a device whose key is already recorded (`probe ssh hostkey learn`); a key profile always trusts on first
	// use, since a public-key signature gives a rogue server nothing it can reuse.
	TrustOnFirstUse bool `json:"trust_on_first_use,omitempty"`

	prefixes []netip.Prefix
}

// Jump is a jump host: an SSH server the probe logs in to and asks to open a TCP connection (direct-tcpip) to the
// device's address.
type Jump struct {
	Name     string `json:"name"`
	Address  string `json:"address"` // IP literal, or a name the probe resolves through its target policy
	Port     int    `json:"port"`
	Username string `json:"username"`
	Auth     string `json:"auth"`
	Legacy   bool   `json:"legacy_algorithms,omitempty"`
}

// Config is profiles.json.
type Config struct {
	Profiles []Profile `json:"profiles"`
	Jumps    []Jump    `json:"jumps"`
}

// Validate checks every profile and jump, fills defaults and compiles the CIDRs. It refuses duplicate names, catch-all
// ranges and profiles that name a jump host that does not exist.
func (c *Config) Validate() error {
	var errs []error
	if len(c.Profiles) > MaxProfiles {
		errs = append(errs, fmt.Errorf("more than %d profiles", MaxProfiles))
	}
	if len(c.Jumps) > MaxJumps {
		errs = append(errs, fmt.Errorf("more than %d jump hosts", MaxJumps))
	}
	jumps := map[string]bool{}
	for i := range c.Jumps {
		j := &c.Jumps[i]
		if err := j.validate(); err != nil {
			errs = append(errs, fmt.Errorf("jump %q: %w", j.Name, err))
			continue
		}
		if jumps[j.Name] {
			errs = append(errs, fmt.Errorf("jump %q is listed twice", j.Name))
		}
		jumps[j.Name] = true
	}
	seen := map[string]bool{}
	for i := range c.Profiles {
		p := &c.Profiles[i]
		if err := p.validate(); err != nil {
			errs = append(errs, fmt.Errorf("profile %q: %w", p.Name, err))
			continue
		}
		if seen[p.Name] {
			errs = append(errs, fmt.Errorf("profile %q is listed twice", p.Name))
		}
		seen[p.Name] = true
		if p.Jump != "" && !jumps[p.Jump] {
			errs = append(errs, fmt.Errorf("profile %q uses jump host %q, which does not exist", p.Name, p.Jump))
		}
	}
	return errors.Join(errs...)
}

func (p *Profile) validate() error {
	if !ValidName(p.Name) {
		return errors.New("name must be 1 to 32 of a-z, 0-9 and -")
	}
	if len(p.CIDRs) == 0 || len(p.CIDRs) > MaxProfileCIDRs {
		return fmt.Errorf("needs 1 to %d CIDRs", MaxProfileCIDRs)
	}
	p.prefixes = p.prefixes[:0]
	for i, s := range p.CIDRs {
		pre, err := ParseCIDR(s)
		if err != nil {
			return err
		}
		p.CIDRs[i] = pre.String()
		p.prefixes = append(p.prefixes, pre)
	}
	if !slices.Contains(protocol.Platforms, p.Platform) {
		return fmt.Errorf("platform %q must be one of %s", p.Platform, strings.Join(protocol.Platforms, ", "))
	}
	if err := validUsername(p.Username); err != nil {
		return err
	}
	if p.Auth != AuthPassword && p.Auth != AuthKey {
		return errors.New("auth must be password or key")
	}
	if p.Port == 0 {
		p.Port = DefaultPort
	}
	if p.Port < 1 || p.Port > 65535 {
		return errors.New("port must be 1 to 65535")
	}
	if p.Jump != "" && !ValidName(p.Jump) {
		return errors.New("jump must be a jump host name")
	}
	return nil
}

func (j *Jump) validate() error {
	if !ValidName(j.Name) {
		return errors.New("name must be 1 to 32 of a-z, 0-9 and -")
	}
	if err := ValidAddress(j.Address); err != nil {
		return err
	}
	if err := validUsername(j.Username); err != nil {
		return err
	}
	if j.Auth != AuthPassword && j.Auth != AuthKey {
		return errors.New("auth must be password or key")
	}
	if j.Port == 0 {
		j.Port = DefaultPort
	}
	if j.Port < 1 || j.Port > 65535 {
		return errors.New("port must be 1 to 65535")
	}
	return nil
}

// ValidAddress accepts an IP literal or a DNS name.
func ValidAddress(a string) error {
	if a == "" || len(a) > maxAddress {
		return errors.New("address must be an IP address or host name")
	}
	if ip, err := netip.ParseAddr(a); err == nil {
		if ip.Zone() != "" {
			return errors.New("address must not have a zone")
		}
		return nil
	}
	for i := 0; i < len(a); i++ {
		c := a[i]
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '-' || c == '_') {
			return errors.New("address must be an IP address or host name")
		}
	}
	return nil
}

func validUsername(u string) error {
	if u == "" || len(u) > maxUsername {
		return fmt.Errorf("username is required and at most %d characters", maxUsername)
	}
	for i := 0; i < len(u); i++ {
		if c := u[i]; c <= 0x20 || c >= 0x7f {
			return errors.New("username must be printable ASCII without spaces")
		}
	}
	return nil
}

// ParseCIDR parses a CIDR or a bare address (a /32 or /128). IPv4-mapped IPv6 prefixes are written as IPv4. It refuses
// prefixes shorter than /8 (IPv4) or /16 (IPv6): a profile must not cover everything.
func ParseCIDR(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	var pre netip.Prefix
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q is not an address or CIDR", s)
		}
		a = a.Unmap()
		pre = netip.PrefixFrom(a, a.BitLen())
	} else {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a CIDR", s)
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("%q is not a usable CIDR", s)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		pre = p.Masked()
	}
	if pre.Addr().Is4() && pre.Bits() < minPrefixV4 {
		return netip.Prefix{}, fmt.Errorf("%s is wider than /%d; a profile may not cover a catch-all range", pre, minPrefixV4)
	}
	if pre.Addr().Is6() && pre.Bits() < minPrefixV6 {
		return netip.Prefix{}, fmt.Errorf("%s is wider than /%d; a profile may not cover a catch-all range", pre, minPrefixV6)
	}
	return pre, nil
}

// Covers reports whether addr is in one of the profile's ranges. Validate must have run.
func (p *Profile) Covers(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, pre := range p.prefixes {
		if pre.Contains(addr) {
			return true
		}
	}
	return false
}

// Match returns the first profile, in file order, whose ranges contain addr. It matches the device's resolved
// address only, never a name, so DNS cannot steer a profile's credentials to another host.
func (c *Config) Match(addr netip.Addr) (*Profile, bool) {
	for i := range c.Profiles {
		if c.Profiles[i].Covers(addr) {
			return &c.Profiles[i], true
		}
	}
	return nil, false
}

// Profile returns the profile called name.
func (c *Config) Profile(name string) (*Profile, bool) {
	for i := range c.Profiles {
		if c.Profiles[i].Name == name {
			return &c.Profiles[i], true
		}
	}
	return nil, false
}

// Jump returns the jump host called name.
func (c *Config) Jump(name string) (*Jump, bool) {
	for i := range c.Jumps {
		if c.Jumps[i].Name == name {
			return &c.Jumps[i], true
		}
	}
	return nil, false
}

// Summaries describes the profiles without user names or secrets.
func (c *Config) Summaries() []protocol.SSHProfileSummary {
	out := make([]protocol.SSHProfileSummary, 0, len(c.Profiles))
	for _, p := range c.Profiles {
		out = append(out, protocol.SSHProfileSummary{Name: p.Name, CIDRs: slices.Clone(p.CIDRs), Platform: p.Platform, Jump: p.Jump})
	}
	return out
}

// Store is the SSH store under one state directory.
type Store struct {
	stateDir string
	dir      string
}

// New returns the store under stateDir. Nothing is created until something is written.
func New(stateDir string) *Store {
	return &Store{stateDir: stateDir, dir: filepath.Join(stateDir, dirName)}
}

// Dir is <state_dir>/ssh.
func (s *Store) Dir() string { return s.dir }

// Check opens the store as every operation does, so a command can refuse (root in another user's state directory, a
// symbolic link, wrong owner or mode) before it asks for anything. A store that does not exist yet passes.
func (s *Store) Check() error {
	d, err := s.openDir(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	d.close()
	return nil
}

// Load reads and validates profiles.json. A missing file is an empty store.
func (s *Store) Load() (*Config, error) {
	data, err := s.readFile(profilesFile)
	if errors.Is(err, fs.ErrNotExist) {
		return &Config{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading SSH profiles: %w", err)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s is damaged: %v", filepath.Join(s.dir, profilesFile), err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(s.dir, profilesFile), err)
	}
	return &c, nil
}

// Save validates c and writes profiles.json.
func (s *Store) Save(c *Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Profiles == nil {
		c.Profiles = []Profile{}
	}
	if c.Jumps == nil {
		c.Jumps = []Jump{}
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(profilesFile, append(data, '\n'))
}

// Secret is what `probe ssh ... add` collects: a password, or a private key and its passphrase (empty when the key is
// not encrypted).
type Secret struct {
	Password   string
	Key        []byte
	Passphrase string
}

// String and LogValue keep secrets out of output even if a Secret is printed or logged whole by mistake.
func (Secret) String() string           { return "[secret]" }
func (Secret) LogValue() slog.Value     { return slog.StringValue("[secret]") }
func (c Credential) String() string     { return "[credential]" }
func (Credential) LogValue() slog.Value { return slog.StringValue("[credential]") }

// Credential is what a connection uses: a password, or a signer from the stored key.
type Credential struct {
	Password string
	Signer   ssh.Signer
}

// CheckKey parses a private key, with its passphrase when it is encrypted. It returns ErrPassphraseNeeded for an
// encrypted key without one.
func CheckKey(key []byte, passphrase string) (ssh.Signer, error) {
	if len(key) == 0 || len(key) > maxKeyFileBytes {
		return nil, errors.New("the key file is empty or too large")
	}
	if passphrase != "" {
		sg, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("the key does not open with that passphrase or is not a private key: %v", err)
		}
		return sg, nil
	}
	sg, err := ssh.ParsePrivateKey(key)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		return nil, ErrPassphraseNeeded
	}
	if err != nil {
		return nil, fmt.Errorf("not a private key OpenSSH can read: %v", err)
	}
	return sg, nil
}

// ErrPassphraseNeeded means the key is encrypted.
var ErrPassphraseNeeded = errors.New("the key is encrypted and needs its passphrase")

// AddProfile adds p (at the end, so it matches after the existing ones) with its secret. The secret is written first,
// so a profile is never visible without it.
func (s *Store) AddProfile(p Profile, sec Secret) error {
	return s.locked(func() error { return s.addProfile(p, sec) })
}

func (s *Store) addProfile(p Profile, sec Secret) error {
	c, err := s.Load()
	if err != nil {
		return err
	}
	if _, ok := c.Profile(p.Name); ok {
		return fmt.Errorf("profile %q already exists; remove it first", p.Name)
	}
	c.Profiles = append(c.Profiles, p)
	if err := c.Validate(); err != nil {
		return err
	}
	if err := s.putSecret(KindProfile, p.Name, p.Auth, sec); err != nil {
		return err
	}
	return s.Save(c)
}

// ProfileOptions are the settings `probe ssh profile set` changes; nil leaves a setting as it is.
type ProfileOptions struct {
	Legacy          *bool
	TrustOnFirstUse *bool
	// Secret replaces the profile's password (auth password) or private key and passphrase (auth key). Its kind must
	// match the profile's auth: changing the auth type takes removing and adding the profile.
	Secret *Secret
}

// JumpOptions are the settings `probe ssh jump set` changes; nil leaves a setting as it is.
type JumpOptions struct {
	Legacy *bool
	// Secret replaces the jump host's password or private key and passphrase; its kind must match the jump host's auth.
	Secret *Secret
}

// checkSecretKind refuses a replacement secret of the wrong kind for auth (a password for a key login, or a key for a
// password login), without saying anything about the secret.
func checkSecretKind(kind Kind, name, auth string, sec Secret) error {
	switch auth {
	case AuthPassword:
		if len(sec.Key) > 0 || sec.Password == "" {
			return fmt.Errorf("%s %q logs in with a password; give it a new password, not a key (to change the auth type, remove it and add it again)", kind, name)
		}
	case AuthKey:
		if sec.Password != "" || len(sec.Key) == 0 {
			return fmt.Errorf("%s %q logs in with a key; give it a new key file, not a password (to change the auth type, remove it and add it again)", kind, name)
		}
	}
	return nil
}

// SetProfileOptions changes a profile's options and, when o.Secret is set, its secret, in place: it keeps its place in
// the order. Everything is checked before anything is written.
func (s *Store) SetProfileOptions(name string, o ProfileOptions) (Profile, error) {
	var out Profile
	err := s.locked(func() error {
		c, err := s.Load()
		if err != nil {
			return err
		}
		p, ok := c.Profile(name)
		if !ok {
			return fmt.Errorf("no profile %q", name)
		}
		if o.Secret != nil {
			if err := checkSecretKind(KindProfile, name, p.Auth, *o.Secret); err != nil {
				return err
			}
			if p.Auth == AuthKey {
				if _, err := CheckKey(o.Secret.Key, o.Secret.Passphrase); err != nil {
					return err
				}
			}
		}
		if o.Legacy != nil {
			p.Legacy = *o.Legacy
		}
		if o.TrustOnFirstUse != nil {
			p.TrustOnFirstUse = *o.TrustOnFirstUse
		}
		if err := c.Validate(); err != nil {
			return err
		}
		out = *p
		if o.Secret != nil {
			if err := s.putSecret(KindProfile, name, p.Auth, *o.Secret); err != nil {
				return err
			}
		}
		return s.Save(c)
	})
	return out, err
}

// MoveProfile moves a profile to just before the profile named before, or to the end when before is empty, so the order
// in which the first matching profile wins can be fixed without removing and adding it again. position is the profile's
// 1-based place afterwards; changed is false when it was already there (nothing is written then).
func (s *Store) MoveProfile(name, before string) (position int, changed bool, err error) {
	err = s.locked(func() error {
		c, err := s.Load()
		if err != nil {
			return err
		}
		i := slices.IndexFunc(c.Profiles, func(p Profile) bool { return p.Name == name })
		if i < 0 {
			return fmt.Errorf("no profile %q", name)
		}
		if before == name {
			return fmt.Errorf("cannot move profile %q before itself", name)
		}
		moving := c.Profiles[i]
		rest := slices.Delete(slices.Clone(c.Profiles), i, i+1)
		at := len(rest)
		if before != "" {
			at = slices.IndexFunc(rest, func(p Profile) bool { return p.Name == before })
			if at < 0 {
				return fmt.Errorf("no profile %q to move %q before", before, name)
			}
		}
		position = at + 1
		if at == i {
			return nil
		}
		c.Profiles = slices.Insert(rest, at, moving)
		changed = true
		return s.Save(c)
	})
	return position, changed, err
}

// RemoveProfile removes the profile and its secret and key.
func (s *Store) RemoveProfile(name string) error {
	return s.locked(func() error { return s.removeProfile(name) })
}

func (s *Store) removeProfile(name string) error {
	c, err := s.Load()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(c.Profiles, func(p Profile) bool { return p.Name == name })
	if i < 0 {
		return fmt.Errorf("no profile %q", name)
	}
	c.Profiles = slices.Delete(c.Profiles, i, i+1)
	if err := s.Save(c); err != nil {
		return err
	}
	return s.dropSecret(KindProfile, name)
}

// AddJump adds j with its secret. The caller records the jump's host key (AddHostKey) once the operator confirmed it.
func (s *Store) AddJump(j Jump, sec Secret) error {
	return s.locked(func() error { return s.addJump(j, sec) })
}

func (s *Store) addJump(j Jump, sec Secret) error {
	c, err := s.Load()
	if err != nil {
		return err
	}
	if _, ok := c.Jump(j.Name); ok {
		return fmt.Errorf("jump host %q already exists; remove it first", j.Name)
	}
	c.Jumps = append(c.Jumps, j)
	if err := c.Validate(); err != nil {
		return err
	}
	if err := s.putSecret(KindJump, j.Name, j.Auth, sec); err != nil {
		return err
	}
	return s.Save(c)
}

// SetJumpOptions changes a jump host's options and, when o.Secret is set, its secret, in place. Everything is checked
// before anything is written.
func (s *Store) SetJumpOptions(name string, o JumpOptions) (Jump, error) {
	var out Jump
	err := s.locked(func() error {
		c, err := s.Load()
		if err != nil {
			return err
		}
		j, ok := c.Jump(name)
		if !ok {
			return fmt.Errorf("no jump host %q", name)
		}
		if o.Secret != nil {
			if err := checkSecretKind(KindJump, name, j.Auth, *o.Secret); err != nil {
				return err
			}
			if j.Auth == AuthKey {
				if _, err := CheckKey(o.Secret.Key, o.Secret.Passphrase); err != nil {
					return err
				}
			}
		}
		if o.Legacy != nil {
			j.Legacy = *o.Legacy
		}
		if err := c.Validate(); err != nil {
			return err
		}
		out = *j
		if o.Secret != nil {
			if err := s.putSecret(KindJump, name, j.Auth, *o.Secret); err != nil {
				return err
			}
		}
		return s.Save(c)
	})
	return out, err
}

// RemoveJump removes a jump host that no profile uses.
func (s *Store) RemoveJump(name string) error {
	return s.locked(func() error { return s.removeJump(name) })
}

func (s *Store) removeJump(name string) error {
	c, err := s.Load()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(c.Jumps, func(j Jump) bool { return j.Name == name })
	if i < 0 {
		return fmt.Errorf("no jump host %q", name)
	}
	for _, p := range c.Profiles {
		if p.Jump == name {
			return fmt.Errorf("profile %q uses jump host %q; remove the profile first", p.Name, name)
		}
	}
	c.Jumps = slices.Delete(c.Jumps, i, i+1)
	if err := s.Save(c); err != nil {
		return err
	}
	if err := s.dropSecret(KindJump, name); err != nil {
		return err
	}
	// Host keys learnt through this jump belong to it; a new jump of the same name starts afresh.
	return s.removeFile(s.knownHostsName(name))
}

func secretKey(kind Kind, name string) string { return string(kind) + "/" + name }

// keyRel is a private key's name relative to the store.
func keyRel(kind Kind, name string) string { return keysDir + "/" + string(kind) + "-" + name }

func (s *Store) putSecret(kind Kind, name, auth string, sec Secret) error {
	secrets, err := s.loadSecrets()
	if err != nil {
		return err
	}
	switch auth {
	case AuthPassword:
		if sec.Password == "" {
			return errors.New("the password is empty")
		}
		secrets[secretKey(kind, name)] = sec.Password
	case AuthKey:
		if _, err := CheckKey(sec.Key, sec.Passphrase); err != nil {
			return err
		}
		if err := s.writeFile(keyRel(kind, name), sec.Key); err != nil {
			return err
		}
		if sec.Passphrase != "" {
			secrets[secretKey(kind, name)] = sec.Passphrase
		} else {
			delete(secrets, secretKey(kind, name))
		}
	}
	return s.saveSecrets(secrets)
}

func (s *Store) dropSecret(kind Kind, name string) error {
	secrets, err := s.loadSecrets()
	if err != nil {
		return err
	}
	if _, ok := secrets[secretKey(kind, name)]; ok {
		delete(secrets, secretKey(kind, name))
		if err := s.saveSecrets(secrets); err != nil {
			return err
		}
	}
	return s.removeFile(keyRel(kind, name))
}

func (s *Store) loadSecrets() (map[string]string, error) {
	path := filepath.Join(s.dir, secretsFile)
	data, err := s.readFile(secretsFile)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading SSH secrets: %w", err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s is damaged", path) // never echo the parser's view of a secrets file
	}
	return m, nil
}

func (s *Store) saveSecrets(m map[string]string) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return s.writeFile(secretsFile, append(data, '\n'))
}

// Credentials returns what a profile or jump host logs in with.
func (s *Store) Credentials(kind Kind, name, auth string) (Credential, error) {
	secrets, err := s.loadSecrets()
	if err != nil {
		return Credential{}, err
	}
	secret := secrets[secretKey(kind, name)]
	switch auth {
	case AuthPassword:
		if secret == "" {
			return Credential{}, fmt.Errorf("no password stored for %s %q", kind, name)
		}
		return Credential{Password: secret}, nil
	case AuthKey:
		key, err := s.readFile(keyRel(kind, name))
		if errors.Is(err, fs.ErrNotExist) {
			return Credential{}, fmt.Errorf("no key stored for %s %q", kind, name)
		}
		if err != nil {
			return Credential{}, err
		}
		sg, err := CheckKey(key, secret)
		if err != nil {
			return Credential{}, fmt.Errorf("the key stored for %s %q cannot be used: %v", kind, name, err)
		}
		return Credential{Signer: sg}, nil
	}
	return Credential{}, fmt.Errorf("%s %q has unknown auth %q", kind, name, auth)
}

// maxStoreFile bounds any file read from the store.
const maxStoreFile = 16 << 20

// geteuid is replaced in tests.
var geteuid = os.Geteuid

// tempName names the temporary file a write starts with; replaced in tests.
var tempName = defaultTempName

func defaultTempName(name string) string {
	var b [8]byte
	rand.Read(b[:])
	return "." + name + "-" + hex.EncodeToString(b[:]) + ".tmp"
}

// checkOwner refuses a store directory or file that another user owns.
func checkOwner(path string, uid int) error {
	if euid := geteuid(); uid != euid {
		return fmt.Errorf("%s belongs to %s, not to the user this runs as (%s); run probe ssh as the user that owns the store (e.g. sudo -u %s probe ssh ...)",
			path, userName(uid), userName(euid), userOrUID(uid))
	}
	return nil
}

// foreignOwnerError is the refusal for root working in a state directory another user owns. The probe's user could
// otherwise plant links there that root would follow.
func foreignOwnerError(stateDir string, uid int) error {
	return fmt.Errorf("the state directory %s belongs to %s, and this runs as root; run it as that user instead, e.g. sudo -u %s probe ssh ...",
		stateDir, userName(uid), userOrUID(uid))
}

func userName(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		return fmt.Sprintf("user %s (uid %d)", u.Username, uid)
	}
	return fmt.Sprintf("uid %d", uid)
}

func userOrUID(uid int) string {
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		return u.Username
	}
	return "#" + strconv.Itoa(uid)
}

// splitRel splits a store-relative name into its directory ("" or keysDir) and file name.
func splitRel(rel string) (sub, name string) {
	if d, f, ok := strings.Cut(rel, "/"); ok {
		return d, f
	}
	return "", rel
}

// openFor opens the directory holding rel.
func (s *Store) openFor(rel string, create bool) (*storeDir, string, error) {
	sub, name := splitRel(rel)
	d, err := s.openDir(create)
	if err != nil {
		return nil, "", err
	}
	if sub == "" {
		return d, name, nil
	}
	defer d.close()
	k, err := d.sub(sub, create)
	if err != nil {
		return nil, "", err
	}
	return k, name, nil
}

// readFile reads rel (relative to the store). A missing file or directory is fs.ErrNotExist.
func (s *Store) readFile(rel string) ([]byte, error) {
	d, name, err := s.openFor(rel, false)
	if err != nil {
		return nil, err
	}
	defer d.close()
	return d.read(name)
}

// writeFile writes rel (relative to the store) atomically with mode 0600, creating the directories it needs.
func (s *Store) writeFile(rel string, data []byte) error {
	d, name, err := s.openFor(rel, true)
	if err != nil {
		return err
	}
	defer d.close()
	return d.write(name, data)
}

// removeFile removes rel; a missing file is not an error.
func (s *Store) removeFile(rel string) error {
	d, name, err := s.openFor(rel, false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer d.close()
	if err := d.remove(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// writeMu serialises read-modify-write updates within this process (every Store on any state directory: there is
// normally one), and the lock file serialises them across processes: the running probe records host keys on first
// use while an operator runs `probe ssh ...`, and neither may lose the other's change.
var writeMu sync.Mutex

// locked runs f holding the store's write lock.
func (s *Store) locked(f func() error) error {
	writeMu.Lock()
	defer writeMu.Unlock()
	d, err := s.openDir(true)
	if err != nil {
		return err
	}
	defer d.close()
	unlock, err := d.lock()
	if err != nil {
		return err
	}
	defer unlock()
	return f()
}

// PlatformError is nil when this build can keep the store safe, and otherwise says why SSH device commands are refused
// here: the store's protections (no-follow opens relative to a checked directory, owner and mode checks, a file lock)
// exist only on unix systems.
func PlatformError() error { return PlatformErrorFor(storeProtected, runtime.GOOS) }

// PlatformErrorFor is PlatformError for a build that has (protected) or lacks the store's protections, on goos. It
// does not depend on the build, so every outcome can be tested on any system.
func PlatformErrorFor(protected bool, goos string) error {
	if protected {
		return nil
	}
	return fmt.Errorf("SSH device commands are not supported on %s: the SSH store's protections (no symbolic links "+
		"followed, owner and mode checks, a file lock) exist only on unix systems; run the probe on Linux", goos)
}
