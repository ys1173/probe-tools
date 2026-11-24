package devssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"

	"probetools/internal/policy"
	"probetools/internal/protocol"
	"probetools/internal/sshcfg"
)

// target is one SSH login: a device (or, for FetchHostKey, any host) at addr:port, optionally through a jump host.
type target struct {
	addr     netip.Addr
	port     int
	jump     *sshcfg.Jump
	jumpAddr netip.Addr // the jump's address, resolved and checked by the policy
	legacy   bool
	kind     sshcfg.Kind
	name     string // profile or jump name, for its credentials
	user     string
	auth     string
	// tofu records an unknown host key and logs in; otherwise an unknown key is refused before any credential is
	// sent (host_key_unknown). A key profile, or a password profile with trust_on_first_use, sets it.
	tofu bool
	// captureOnly stops after the host key is seen (FetchHostKey); no credentials are used.
	captureOnly bool
	// learnAs is how the operator names this host to `probe ssh hostkey learn`: the device as requested (the covering
	// profile supplies the port and jump host), or a jump host's configured address.
	learnAs string
}

type session struct {
	client   *ssh.Client
	jump     *ssh.Client
	hostKey  string
	firstUse bool
	key      ssh.PublicKey
	stop     func() bool
}

func (s *session) close() {
	if s.client != nil {
		s.client.Close()
	}
	if s.jump != nil {
		s.jump.Close()
	}
	if s.stop != nil {
		s.stop()
	}
}

// errCaptured ends a handshake once the host key has been seen.
var errCaptured = errors.New("host key captured")

// algorithms are x/crypto's algorithms without the ones it marks insecure, unless legacy is on; then the insecure
// key exchanges (diffie-hellman-group1-sha1, group14-sha1, group-exchange-sha1), CBC ciphers (aes128-cbc, 3des-cbc),
// hmac-sha1-96 and ssh-rsa host keys with SHA-1 signatures are added after them. RC4 ciphers are never offered.
// x/crypto's own defaults already include group14-sha1 and ssh-rsa, so the lists are always set explicitly.
func algorithms(legacy bool) ssh.Algorithms {
	a := ssh.SupportedAlgorithms()
	if legacy {
		in := ssh.InsecureAlgorithms()
		a.KeyExchanges = append(a.KeyExchanges, in.KeyExchanges...)
		for _, c := range in.Ciphers {
			if !strings.HasPrefix(c, "arcfour") {
				a.Ciphers = append(a.Ciphers, c)
			}
		}
		a.MACs = append(a.MACs, in.MACs...)
		a.HostKeys = append(a.HostKeys, in.HostKeys...)
	}
	return a
}

// hostKeyAlgos pins the host key algorithms to the types already recorded for a host, so a key of another type the
// host also has is not mistaken for a changed key.
func hostKeyAlgos(known []ssh.PublicKey, legacy bool) []string {
	all := algorithms(legacy).HostKeys
	if len(known) == 0 {
		return all
	}
	var out []string
	for _, k := range known {
		cands := []string{k.Type()}
		if k.Type() == ssh.KeyAlgoRSA {
			cands = []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
		}
		for _, c := range cands {
			if slices.Contains(all, c) && !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
	}
	if len(out) == 0 {
		return all
	}
	return out
}

// passwordPrompt is the only keyboard-interactive question answered: "Password:", "netops's password:", "Password for
// netops:" and the like. A passcode, a one-time code or any other question is not.
var passwordPrompt = regexp.MustCompile(`(?i)^\s*(\S+'s\s+)?password(\s+for\s+\S+)?\s*:\s*$`)

// onceAuth hands out the password at most once per login, across password and keyboard-interactive, so a wrong
// password costs the account one failure, never two.
type onceAuth struct {
	pw    string
	mu    sync.Mutex
	used  bool
	cause error // why the password may not be sent at all (a question that is not the password)
}

// take returns the password the first time; later it returns again, or the reason it was withheld.
func (o *onceAuth) take(again error) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.used {
		if o.cause != nil {
			return "", o.cause
		}
		return "", again
	}
	o.used = true
	return o.pw, nil
}

// sent reports whether the password went to the host in this login, by password or keyboard-interactive.
func (o *onceAuth) sent() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.used && o.cause == nil
}

// withhold stops the password from being sent in this login, by any method.
func (o *onceAuth) withhold(cause error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.used {
		o.used, o.cause = true, cause
	}
}

// password is the password method. x/crypto moves on to it after keyboard-interactive fails; by then the password has
// been sent and refused, so nothing is sent again.
func (o *onceAuth) password() (string, error) { return o.take(errAuthOnce) }

func (o *onceAuth) challenge(_, _ string, questions []string, echos []bool) ([]string, error) {
	if len(questions) == 0 {
		return nil, nil
	}
	// Only a single, hidden password prompt is answered; anything else (a passcode, a one-time code, a second
	// factor, a question shown in clear) is not ours to answer, and the password is not offered by another method
	// either.
	if len(questions) > 1 || (len(echos) > 0 && echos[0]) || !passwordPrompt.MatchString(questions[0]) {
		o.withhold(errOddPrompt)
		return nil, errOddPrompt
	}
	pw, err := o.take(errAuthReprompt)
	if err != nil {
		return nil, err
	}
	return []string{pw}, nil
}

// authMethods returns t's login methods, and for a password login the onceAuth that hands the password out (nil for
// a key).
func (rt *Runtime) authMethods(t target) ([]ssh.AuthMethod, *onceAuth, error) {
	cred, err := rt.cfg.Store.Credentials(t.kind, t.name, t.auth)
	if err != nil {
		return nil, nil, err
	}
	if cred.Signer != nil {
		return []ssh.AuthMethod{ssh.PublicKeys(cred.Signer)}, nil, nil
	}
	o := &onceAuth{pw: cred.Password}
	// Keyboard-interactive first: if it fails, x/crypto moves on to the password method, which asks onceAuth before
	// sending anything and so sends nothing. The other order would start a keyboard-interactive exchange after a
	// failed password.
	return []ssh.AuthMethod{ssh.KeyboardInteractive(o.challenge), ssh.PasswordCallback(o.password)}, o, nil
}

// passwordSentError marks a failed login in which the password was sent: only such a failure costs the account a
// failure at the host's AAA, so only such a failure starts a cool-down. Its text is the wrapped error's.
type passwordSentError struct{ err error }

func (e *passwordSentError) Error() string { return e.err.Error() }
func (e *passwordSentError) Unwrap() error { return e.err }

// connect opens an SSH client to t, through its jump host if it has one. The returned session is non-nil when a host
// key was seen, even on error, so the caller can report the key.
func (rt *Runtime) connect(ctx context.Context, t target) (*session, error) {
	s := &session{}
	var raw net.Conn
	var err error
	if t.jump != nil {
		jc, err := rt.connectJump(ctx, t.jump, t.jumpAddr)
		if err != nil {
			return nil, &stageError{stage: "jump host " + t.jump.Name, err: err}
		}
		s.jump = jc
		s.stop = context.AfterFunc(ctx, func() { jc.Close() })
		// The jump is asked for the address the probe resolved and checked, never a name.
		raw, err = jc.DialContext(ctx, "tcp", netip.AddrPortFrom(t.addr, uint16(t.port)).String())
		if err != nil {
			s.close()
			return nil, &stageError{stage: "jump host " + t.jump.Name, err: err}
		}
	} else {
		d := &net.Dialer{Timeout: rt.cfg.ConnectTimeout}
		// The address was resolved and checked by the policy already; dialling it directly (not through
		// Policy.DialContext) keeps the connection on exactly that address.
		raw, err = d.DialContext(ctx, "tcp", netip.AddrPortFrom(t.addr, uint16(t.port)).String())
		if err != nil {
			return nil, err
		}
		s.stop = context.AfterFunc(ctx, func() { raw.Close() })
	}
	jumpName := ""
	if t.jump != nil {
		jumpName = t.jump.Name
	}
	hostport := sshcfg.HostPort(t.addr.String(), t.port)
	client, err := rt.handshake(ctx, raw, hostport, jumpName, t, s)
	if err != nil {
		raw.Close()
		s.close()
		return s, err
	}
	s.client = client
	return s, nil
}

// connectJump logs in to a jump host at addr, which the caller resolved and checked through the policy. Its host key
// must already be recorded (it is confirmed when the jump is added).
func (rt *Runtime) connectJump(ctx context.Context, j *sshcfg.Jump, addr netip.Addr) (*ssh.Client, error) {
	d := &net.Dialer{Timeout: rt.cfg.ConnectTimeout}
	raw, err := d.DialContext(ctx, "tcp", netip.AddrPortFrom(addr, uint16(j.Port)).String())
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	t := target{addr: addr, port: j.Port, legacy: j.Legacy, kind: sshcfg.KindJump, name: j.Name, user: j.Username, auth: j.Auth,
		learnAs: j.Address}
	c, err := rt.handshake(ctx, raw, sshcfg.HostPort(strings.ToLower(j.Address), j.Port), "", t, &session{})
	if err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// handshake runs the SSH handshake and login on raw. hostport and jump say where the host key is recorded.
func (rt *Runtime) handshake(ctx context.Context, raw net.Conn, hostport, jump string, t target, s *session) (*ssh.Client, error) {
	known, err := rt.cfg.Store.LookupHostKeys(jump, hostport)
	if err != nil {
		return nil, localErr{err}
	}
	algos := algorithms(t.legacy)
	cfg := &ssh.ClientConfig{
		Config:            ssh.Config{KeyExchanges: algos.KeyExchanges, Ciphers: algos.Ciphers, MACs: algos.MACs},
		User:              t.user,
		HostKeyAlgorithms: hostKeyAlgos(known, t.legacy),
		ClientVersion:     "SSH-2.0-probe",
	}
	cfg.HostKeyCallback = func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		s.hostKey, s.key = fp, key
		if t.captureOnly {
			return errCaptured
		}
		for _, k := range known {
			if k.Type() == key.Type() && string(k.Marshal()) == string(key.Marshal()) {
				return nil
			}
		}
		if len(known) > 0 {
			return &hostKeyChangedError{host: hostport, presented: fp, known: ssh.FingerprintSHA256(known[0])}
		}
		if t.kind == sshcfg.KindJump {
			return &jumpKeyUnknownError{learnAs: t.learnAs}
		}
		if !t.tofu {
			// Nothing is recorded and no credential is sent: a password must not go to a host nobody has vouched for.
			return &hostKeyUnknownError{host: hostport, presented: fp, learnAs: t.learnAs, profile: t.name}
		}
		if err := rt.cfg.Store.AddHostKey(jump, hostport, key); err != nil {
			return localErr{fmt.Errorf("recording the host key: %w", err)}
		}
		s.firstUse = true
		return nil
	}
	var pw *onceAuth
	if !t.captureOnly {
		if cfg.Auth, pw, err = rt.authMethods(t); err != nil {
			return nil, localErr{err}
		}
	}
	c, chans, reqs, err := ssh.NewClientConn(raw, hostport, cfg)
	if err != nil {
		if pw != nil && pw.sent() {
			err = &passwordSentError{err}
		}
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// localErr marks an error whose text the probe wrote itself (the store, its own checks), so it may be shown as is.
type localErr struct{ err error }

func (e localErr) Error() string { return e.err.Error() }
func (e localErr) Unwrap() error { return e.err }

var noCommonAlgo = regexp.MustCompile(`no common algorithm for (key exchange|host key|client to server cipher|server to client cipher|client to server MAC|server to client MAC)`)

// classify turns a connection or session error into an outcome and a detail. The detail is built from fixed phrases
// and the probe's own text only: messages a device or jump host chose (disconnect reasons, algorithm names, exit
// signals) never reach it, since text the target controls is returned only as untrusted output.
func classify(ctx context.Context, err error) (string, string) {
	var hk *hostKeyChangedError
	var hu *hostKeyUnknownError
	var ju *jumpKeyUnknownError
	var se *stageError
	prefix := ""
	if errors.As(err, &se) && se.stage != "" {
		prefix = se.stage + ": "
	}
	var oce *ssh.OpenChannelError
	var le localErr
	var pe *protocol.Error
	var ope *net.OpError
	msg := err.Error()
	switch {
	case errors.As(err, &hk):
		return "host_key_changed", prefix + hk.Error()
	case errors.As(err, &hu):
		return "host_key_unknown", prefix + hu.Error()
	case errors.As(err, &ju):
		return "host_key_unknown", prefix + ju.Error()
	case errors.Is(err, errDisclaimer), errors.Is(err, errNoPrompt):
		if errors.Is(err, errNoPrompt) {
			return "timeout", prefix + errNoPrompt.Error()
		}
		return "error", prefix + rootCause(err).Error()
	case errors.As(err, &pe):
		return "error", prefix + pe.Message
	case errors.Is(err, errAuthOnce):
		return "auth_failed", prefix + errAuthOnce.Error()
	case errors.Is(err, errAuthReprompt), errors.Is(err, errOddPrompt):
		return "auth_failed", prefix + "login refused: " + rootCause(err).Error()
	case strings.Contains(msg, "unable to authenticate"), strings.Contains(msg, "no supported methods remain"):
		return "auth_failed", prefix + "login refused; it is not retried, so a wrong password cannot lock the account"
	case errors.As(err, &le):
		return "error", prefix + le.Error()
	case ctx.Err() != nil, errors.Is(err, context.DeadlineExceeded):
		return "timeout", prefix + "the login and command did not finish within timeout_ms"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused", prefix + "connection refused on the SSH port"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable", prefix + "no route to the host"
	case errors.As(err, &oce):
		if oce.Reason == ssh.ConnectionFailed {
			if strings.Contains(strings.ToLower(oce.Message), "refused") {
				return "refused", prefix + "the jump host could not connect to the device: connection refused"
			}
			return "unreachable", prefix + "the jump host could not connect to the device"
		}
		return "error", prefix + "the jump host would not open a connection to the device (" + oce.Reason.String() + ")"
	case noCommonAlgo.MatchString(msg):
		if se != nil && se.stage != "" {
			return "error", prefix + noCommonAlgo.FindString(msg) +
				"; for an old jump host, turn on legacy algorithms for it: probe ssh jump set JUMP --legacy"
		}
		return "error", prefix + noCommonAlgo.FindString(msg) +
			"; for an old device, turn on legacy_algorithms for its profile: probe ssh profile set PROFILE --legacy"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timeout", prefix + "the connection timed out"
	}
	if errors.As(err, &ope) {
		// A local socket error: the address and the kernel's reason, nothing from the device.
		return "error", prefix + ope.Error()
	}
	switch {
	case strings.Contains(msg, "disconnect"):
		return "error", prefix + "the host ended the SSH session"
	case errors.Is(err, io.EOF), strings.Contains(msg, "connection reset"):
		return "error", prefix + "the connection closed during the SSH exchange"
	case strings.Contains(msg, "handshake failed"):
		return "error", prefix + "the SSH handshake failed"
	}
	return "error", prefix + "the SSH session failed"
}

// rootCause is the innermost wrapped error.
func rootCause(err error) error {
	for {
		u := errors.Unwrap(err)
		if u == nil {
			return err
		}
		err = u
	}
}

// FetchHostKey connects to host:port (directly, or through the named jump host) and returns the host key it
// presents, without logging in to it. host is resolved and checked by the policy. It is how `probe ssh jump add` and
// `probe ssh hostkey add` show a fingerprint for the operator to confirm.
func (rt *Runtime) FetchHostKey(ctx context.Context, pol *policy.Policy, host string, port int, jumpName string, legacy bool) (ssh.PublicKey, netip.Addr, error) {
	addrs, perr := pol.Resolve(ctx, host, "")
	if perr != nil {
		return nil, netip.Addr{}, perr
	}
	t := target{addr: addrs[0], port: port, legacy: legacy, captureOnly: true}
	if jumpName != "" {
		c, err := rt.cfg.Store.Load()
		if err != nil {
			return nil, netip.Addr{}, err
		}
		j, ok := c.Jump(jumpName)
		if !ok {
			return nil, netip.Addr{}, fmt.Errorf("no jump host %q", jumpName)
		}
		jaddrs, perr := pol.Resolve(ctx, j.Address, "")
		if perr != nil {
			return nil, netip.Addr{}, fmt.Errorf("jump host %s: %s", j.Name, perr.Message)
		}
		t.jump, t.jumpAddr = j, jaddrs[0]
	}
	s, err := rt.connect(ctx, t)
	if s != nil && s.key != nil {
		s.close()
		return s.key, addrs[0], nil
	}
	if err == nil {
		err = errors.New("the host presented no key")
	}
	_, detail := classify(ctx, err)
	return nil, addrs[0], errors.New(detail)
}
