// Package devssh is the device_show and device_commands checks: one allowed, read-only command on a network device over
// SSH, with credentials and platform taken from the probe's local profiles (internal/sshcfg) by the device's resolved
// address, through the probe's target policy, optionally through a jump host.
package devssh

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
	"probetools/internal/sshcfg"
)

// Commands is the command catalog (*devcmd.Catalog).
type Commands interface {
	Check(platform, command string) *protocol.Error
	List(platform string) []protocol.PlatformCommands
}

// Defaults and bounds for Config.
const (
	DefaultMaxOutputBytes = 256 << 10
	MinMaxOutputBytes     = 4 << 10
	MaxMaxOutputBytes     = 4 << 20
	DefaultConnectTimeout = 10 * time.Second

	// maxResultJSON keeps a result under the probe's 900 KiB result limit with room for the envelope. Output is
	// returned as untrusted text, which JSON encoding can make several times longer, so the text is cut to fit.
	maxResultJSON = 850 << 10
)

// Config is what the checks need from the probe.
type Config struct {
	Store          *sshcfg.Store
	Commands       Commands
	MaxOutputBytes int           // raw output bytes read from the device; 0 means DefaultMaxOutputBytes
	ConnectTimeout time.Duration // per TCP connection; 0 means DefaultConnectTimeout
	Logger         *slog.Logger  // one line per device_show; nil uses slog.Default()
	// AuthFailureCooldown is how long a login whose password was sent and that failed is not tried again: a
	// profile's at that device address, a jump host's at that jump host, and a profile's at every address once its
	// password failed at ProfileTripAddresses different addresses within this window. device_show answers auth_failed
	// at once, without connecting. 0 turns it off. Changing the profile's or jump host's secret ends it.
	AuthFailureCooldown time.Duration
}

// DefaultAuthFailureCooldown is the probe's default ssh.auth_failure_cooldown_s.
const DefaultAuthFailureCooldown = 10 * time.Minute

// ProfileTripAddresses is how many different device addresses a profile's password must fail at, within the
// cool-down, before the profile is not tried at any address: the pattern of an AAA account being locked out, rather
// than one device (or one host squatting on an address in the profile's range) that does not take the password.
const ProfileTripAddresses = 3

// Runtime runs device commands. It holds the one-session-per-device lock and the login cool-downs, so one Runtime
// serves the whole probe.
type Runtime struct {
	cfg  Config
	mu   sync.Mutex
	busy map[netip.Addr]bool

	coolMu  sync.Mutex
	cool    map[credKey]cooldown
	markKey [32]byte         // HMAC key for secret marks, random per process
	now     func() time.Time // replaced in tests
}

// credKey names one cool-down: a profile's credentials at one device address, a profile's credentials at every
// address (addr is the zero Addr: the profile-wide trip), or a jump host's credentials (addr is the zero Addr: a jump
// is one host).
type credKey struct {
	kind sshcfg.Kind
	name string
	addr netip.Addr
}

// cooldown is a failed login: when, until when it is not tried again, and a mark of the secret it failed with, so a
// changed secret ends it. A profile-wide trip also lists the addresses whose failures started it.
type cooldown struct {
	at, until time.Time
	mark      [32]byte
	addrs     string // the addresses, comma-separated
	n         int    // how many
}

// New returns a Runtime for cfg.
func New(cfg Config) *Runtime {
	if cfg.MaxOutputBytes == 0 {
		cfg.MaxOutputBytes = DefaultMaxOutputBytes
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	rt := &Runtime{cfg: cfg, busy: map[netip.Addr]bool{}, cool: map[credKey]cooldown{}, now: time.Now}
	rand.Read(rt.markKey[:])
	return rt
}

// Register adds device_show and device_commands to r.
func Register(r *check.Registry, cfg Config) *Runtime {
	rt := New(cfg)
	r.Register(protocol.CheckDeviceShow, rt.deviceShow)
	r.Register(protocol.CheckDeviceCommands, rt.deviceCommands)
	return rt
}

func (rt *Runtime) deviceCommands(_ context.Context, _ *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.DeviceCommandsParams
	if e := check.Decode(raw, &p); e != nil {
		return nil, e
	}
	c, err := rt.cfg.Store.Load()
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "this probe's SSH profiles cannot be read: %v", err)
	}
	res := protocol.DeviceCommandsResult{Platforms: rt.cfg.Commands.List(p.Platform), Profiles: c.Summaries()}
	if res.Platforms == nil {
		res.Platforms = []protocol.PlatformCommands{}
	}
	return res, nil
}

func (rt *Runtime) deviceShow(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.DeviceShowParams
	if e := check.Decode(raw, &p); e != nil {
		return nil, e
	}
	res, perr := rt.Show(ctx, env.Policy, p)
	if perr != nil {
		return nil, perr
	}
	return res, nil
}

// lock takes the device's single session slot; false when a session to it is already open.
func (rt *Runtime) lock(a netip.Addr) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.busy[a] {
		return false
	}
	rt.busy[a] = true
	return true
}

func (rt *Runtime) unlock(a netip.Addr) {
	rt.mu.Lock()
	delete(rt.busy, a)
	rt.mu.Unlock()
}

// Show runs one normalised device_show request. It is the check's body, and what `probe ssh test` runs. Every
// request is logged once, refusals included, with the device's address, profile, platform, command and outcome (an
// error code for a refusal) and never a user name, secret or output.
func (rt *Runtime) Show(ctx context.Context, pol *policy.Policy, p protocol.DeviceShowParams) (*protocol.DeviceShowResult, *protocol.Error) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.TimeoutMS)*time.Millisecond)
	defer cancel()
	var lg logLine
	res, perr := rt.show(ctx, pol, p, &lg)
	outcome := ""
	if perr != nil {
		outcome = perr.Code
	} else {
		outcome = res.Outcome
		res.DurationMS = time.Since(started).Milliseconds()
	}
	device := lg.address
	if device == "" {
		device = p.Device
	}
	rt.cfg.Logger.Info("device_show", "device", device, "profile", lg.profile, "jump", lg.jump, "platform", lg.platform,
		"command", p.Command, "outcome", outcome, "duration_ms", time.Since(started).Milliseconds())
	return res, perr
}

type logLine struct{ address, profile, jump, platform string }

func (rt *Runtime) show(ctx context.Context, pol *policy.Policy, p protocol.DeviceShowParams, lg *logLine) (*protocol.DeviceShowResult, *protocol.Error) {
	store, err := rt.cfg.Store.Load()
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "this probe's SSH profiles cannot be read: %v", err)
	}
	// The policy resolves the name, applies deny_cidrs, deny_hosts and the always-refused ranges, and charges the
	// rate limit. Only the address it returns is used from here on: the profile is chosen by it and the connection
	// goes to it, so neither DNS nor the jump host can move the session elsewhere.
	addrs, perr := pol.Resolve(ctx, p.Device, "")
	if perr != nil {
		return nil, perr
	}
	// The busy lock, the profile match and the known_hosts entry are all keyed on this one canonical address: no zone,
	// IPv4 unmapped (the policy refuses a zone and returns addresses this way; this keeps it so).
	addr := addrs[0].Unmap().WithZone("")
	lg.address = addr.String()
	prof, ok := store.Match(addr)
	if !ok {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "no SSH profile covers %s", addr)
	}
	lg.profile, lg.platform, lg.jump = prof.Name, prof.Platform, prof.Jump
	drv, ok := drivers[prof.Platform]
	if !ok {
		return nil, protocol.Errorf(protocol.CodeInternal, "no driver for platform %s", prof.Platform)
	}
	// The command is checked before any connection is made.
	if perr := rt.cfg.Commands.Check(prof.Platform, p.Command); perr != nil {
		return nil, perr
	}
	if !shellSafe(p.Command) {
		return nil, protocol.Errorf(protocol.CodeNotAllowed,
			"the command has characters this probe never sends to a device; use letters, digits, spaces and . _ : / , = @ + -")
	}
	t := target{addr: addr, port: prof.Port, legacy: prof.Legacy, kind: sshcfg.KindProfile, name: prof.Name,
		user: loginName(prof.Username, drv.userSuffix), auth: prof.Auth,
		tofu: prof.Auth == sshcfg.AuthKey || prof.TrustOnFirstUse, learnAs: p.Device}
	res := &protocol.DeviceShowResult{Device: p.Device, Address: addr.String(), Platform: prof.Platform, Profile: prof.Name,
		Jump: prof.Jump, Command: p.Command}
	if prof.Jump != "" {
		if t.jump, ok = store.Jump(prof.Jump); !ok {
			return nil, protocol.Errorf(protocol.CodeUnavailable, "profile %s uses jump host %s, which does not exist", prof.Name, prof.Jump)
		}
	}
	// A login whose password was sent and refused recently is not tried again with the same secret: each attempt
	// would cost the account another failure at the AAA, and enough of them lock it. The wait is kept per device
	// address (and per jump host), so one host that refuses the profile's credentials does not block the others.
	if detail, cooling := rt.coolingDown(t); cooling {
		res.Outcome, res.Detail = "auth_failed", detail
		return res, nil
	}
	if t.jump != nil {
		// The jump host is a target like any other: resolved, checked and charged by the policy. A refusal (denied,
		// unresolved, rate limit) is answered like one for the device.
		jaddrs, perr := pol.Resolve(ctx, t.jump.Address, "")
		if perr != nil {
			return nil, protocol.Errorf(perr.Code, "jump host %s: %s", t.jump.Name, perr.Message)
		}
		t.jumpAddr = jaddrs[0]
	}
	if !rt.lock(addr) {
		return nil, protocol.Errorf(protocol.CodeBusy, "a session to %s is already open; try again when it finishes", addr)
	}
	defer rt.unlock(addr)

	rt.run(ctx, t, drv, p.Command, res)
	return res, nil
}

// secretMark is an HMAC (under a key random to this process) of the secret a profile or jump host logs in with, so a
// cool-down can tell that the operator changed it without keeping the secret. ok is false when there is none.
func (rt *Runtime) secretMark(kind sshcfg.Kind, name, auth string) (mark [32]byte, ok bool) {
	cred, err := rt.cfg.Store.Credentials(kind, name, auth)
	if err != nil {
		return mark, false
	}
	h := hmac.New(sha256.New, rt.markKey[:])
	h.Write([]byte(string(kind) + "/" + name + "/" + auth + "/"))
	if cred.Signer != nil {
		h.Write(cred.Signer.PublicKey().Marshal())
	} else {
		h.Write([]byte(cred.Password))
	}
	copy(mark[:], h.Sum(nil))
	return mark, true
}

// coolingDown reports whether a login t would make is cooling down with the secret it would use now, and if so the
// detail to answer with: its jump host's, its profile's at every address, or its profile's at this device address.
func (rt *Runtime) coolingDown(t target) (string, bool) {
	if rt.cfg.AuthFailureCooldown <= 0 {
		return "", false
	}
	const fix = "; no connection was made. Fix the credentials on the probe; changing them ends the wait"
	if t.jump != nil {
		if c, ok := rt.activeCooldown(credKey{sshcfg.KindJump, t.jump.Name, netip.Addr{}}, t.jump.Auth); ok {
			return fmt.Sprintf("jump host %s: a login to it with these credentials failed at %s after the password was sent, so it is not tried again until %s (ssh.auth_failure_cooldown_s)%s",
				t.jump.Name, stamp(c.at), stamp(c.until), fix), true
		}
	}
	if c, ok := rt.activeCooldown(credKey{t.kind, t.name, netip.Addr{}}, t.auth); ok {
		return fmt.Sprintf("profile %s: logins with these credentials failed at %d different addresses (%s) within ssh.auth_failure_cooldown_s after the password was sent, the pattern of an account being locked out, so the profile is not tried again until %s at any address%s",
			t.name, c.n, c.addrs, stamp(c.until), fix), true
	}
	if c, ok := rt.activeCooldown(credKey{t.kind, t.name, t.addr}, t.auth); ok {
		return fmt.Sprintf("profile %s: a login to %s with these credentials failed at %s after the password was sent, so they are not tried again until %s at this address (ssh.auth_failure_cooldown_s); other devices of the profile are still tried%s",
			t.name, t.addr, stamp(c.at), stamp(c.until), fix), true
	}
	return "", false
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// activeCooldown returns k's cool-down when it is still running with the secret the credentials have now (auth is how
// they log in). An ended one, or one whose secret changed, is removed.
func (rt *Runtime) activeCooldown(k credKey, auth string) (cooldown, bool) {
	rt.coolMu.Lock()
	c, ok := rt.cool[k]
	rt.coolMu.Unlock()
	if !ok {
		return cooldown{}, false
	}
	mark, _ := rt.secretMark(k.kind, k.name, auth)
	if !rt.now().Before(c.until) || mark != c.mark {
		rt.coolMu.Lock()
		if cur, ok := rt.cool[k]; ok && cur == c {
			delete(rt.cool, k)
		}
		rt.coolMu.Unlock()
		return cooldown{}, false
	}
	return c, true
}

// failedLogin starts a cool-down after a failed login in which the password was sent (a key login, or one that
// stopped at a question that is not the password, sent nothing and starts none). A failure at the jump stage cools
// the jump host down; one at the device cools the profile down at that address, and the profile at every address
// once its password failed, within the cool-down and with the same secret, at ProfileTripAddresses addresses.
func (rt *Runtime) failedLogin(t target, err error) {
	if rt.cfg.AuthFailureCooldown <= 0 {
		return
	}
	var sent *passwordSentError
	if !errors.As(err, &sent) {
		return
	}
	k := credKey{t.kind, t.name, t.addr}
	auth := t.auth
	var se *stageError
	if errors.As(err, &se) && se.stage != "" && t.jump != nil {
		k, auth = credKey{sshcfg.KindJump, t.jump.Name, netip.Addr{}}, t.jump.Auth
	}
	mark, ok := rt.secretMark(k.kind, k.name, auth)
	if !ok {
		return
	}
	now := rt.now()
	until := now.Add(rt.cfg.AuthFailureCooldown)
	rt.coolMu.Lock()
	defer rt.coolMu.Unlock()
	for ck, c := range rt.cool {
		if !now.Before(c.until) {
			delete(rt.cool, ck)
		}
	}
	rt.cool[k] = cooldown{at: now, until: until, mark: mark}
	if k.kind != sshcfg.KindProfile {
		return
	}
	var failed []netip.Addr
	for ck, c := range rt.cool {
		if ck.kind == k.kind && ck.name == k.name && ck.addr.IsValid() && c.mark == mark {
			failed = append(failed, ck.addr)
		}
	}
	if len(failed) < ProfileTripAddresses {
		return
	}
	slices.SortFunc(failed, func(a, b netip.Addr) int { return a.Compare(b) })
	list := make([]string, len(failed))
	for i, a := range failed {
		list[i] = a.String()
	}
	rt.cool[credKey{k.kind, k.name, netip.Addr{}}] = cooldown{at: now, until: until, mark: mark,
		addrs: strings.Join(list, ", "), n: len(list)}
}

// run connects, runs the command and fills res. Every failure past this point is an outcome, not an error.
func (rt *Runtime) run(ctx context.Context, t target, drv driver, command string, res *protocol.DeviceShowResult) {
	conn, err := rt.connect(ctx, t)
	if conn != nil {
		res.HostKey = conn.hostKey
		res.HostKeyFirstUse = conn.firstUse
	}
	if err != nil {
		res.Outcome, res.Detail = classify(ctx, err)
		if res.Outcome == "auth_failed" {
			rt.failedLogin(t, err)
		}
		return
	}
	defer conn.close()

	limit := rt.cfg.MaxOutputBytes
	var out runOutput
	if drv.shell {
		out = runShell(ctx, conn.client, drv, command, limit)
	} else {
		out = runExec(ctx, conn.client, drv, command, limit)
	}
	text := drv.stripPager(clean(out.raw))
	res.ExitStatus = out.exit
	res.OutputBytes = len(text)
	res.Truncated = out.truncated
	switch {
	case out.err != nil:
		res.Outcome, res.Detail = classify(ctx, out.err)
	case drv.commandError(text) != "":
		// The device's own message is in the output; it is not repeated in the detail, which is not untrusted text.
		res.Outcome, res.Detail = "command_error", "the device rejected the command (its message is in the output)"
	default:
		res.Outcome = "ok"
	}
	if len(text) > 0 || res.Outcome == "ok" {
		fitOutput(res, text, limit)
	}
}

// loginName adds the platform's console options to the user name (RouterOS), unless the operator already gave some.
func loginName(user, suffix string) string {
	if suffix == "" {
		return user
	}
	for i := 0; i < len(user); i++ {
		if user[i] == '+' {
			return user
		}
	}
	return user + suffix
}

// fitOutput puts text in res.Output as untrusted text, cut so the encoded result stays under maxResultJSON.
func fitOutput(res *protocol.DeviceShowResult, text []byte, limit int) {
	max := limit
	for range 8 {
		u := protocol.UntrustedText(text, max)
		res.Output = &u
		b, err := json.Marshal(res)
		if err != nil || len(b) <= maxResultJSON {
			break
		}
		// Shrink in proportion to the overshoot, with a margin, and try again.
		max = int(float64(max) * float64(maxResultJSON) / float64(len(b)) * 0.9)
	}
	if res.Output.Truncated {
		res.Truncated = true
	}
}

// Error classification for outcomes.
var (
	errAuthOnce     = errors.New("login refused; the password is sent only once and not retried")
	errAuthReprompt = errors.New("the device asked for the password again after it was refused; a login is never retried")
	errOddPrompt    = errors.New("the device asked for something other than the password during login; it was not answered")
	errDisclaimer   = errors.New("the device shows a login disclaimer that must be accepted; device_show does not accept it")
	errNoPrompt     = errors.New("no CLI prompt was recognised before timeout_ms; the device's prompt may not be the platform's usual one")
)

type hostKeyChangedError struct {
	host      string
	presented string
	known     string
}

func (e *hostKeyChangedError) Error() string {
	return fmt.Sprintf("%s presented host key %s, but %s is recorded; if the change is expected, run `probe ssh hostkey forget` on the probe",
		e.host, e.presented, e.known)
}

// hostKeyUnknownError is a device whose key is not recorded, met by a profile that does not trust on first use.
type hostKeyUnknownError struct {
	host      string // known_hosts spelling: "addr" or "[addr]:port"
	presented string
	learnAs   string // the device as requested; `hostkey learn` takes the port and jump host from the profile
	profile   string
}

func (e *hostKeyUnknownError) Error() string {
	return fmt.Sprintf("%s presented host key %s, which is not recorded; profile %s logs in with a password, which is never sent to a host whose key is not recorded, so nothing was sent and nothing recorded. Check the fingerprint, then record it on the probe: probe ssh hostkey learn %s",
		e.host, e.presented, e.profile, e.learnAs)
}

// jumpKeyUnknownError is a jump host whose key is not recorded. A jump host is never trusted on first use.
type jumpKeyUnknownError struct{ learnAs string }

func (e *jumpKeyUnknownError) Error() string {
	return "the jump host's key is not recorded, so it is not used; check its fingerprint, then record it on the probe: probe ssh hostkey learn " +
		e.learnAs
}

// stageError says which hop failed, so the detail can name the jump host.
type stageError struct {
	stage string // "jump" or ""
	err   error
}

func (e *stageError) Error() string {
	if e.stage == "" {
		return e.err.Error()
	}
	return e.stage + ": " + e.err.Error()
}
func (e *stageError) Unwrap() error { return e.err }
