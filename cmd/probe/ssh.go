package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"probetools/internal/checks/devssh"
	"probetools/internal/devcmd"
	"probetools/internal/policy"
	"probetools/internal/probe"
	"probetools/internal/protocol"
	"probetools/internal/sshcfg"
)

// maxKeyFile bounds a private key file read by `profile add` / `jump add`.
const maxKeyFile = 64 << 10

// fetchTimeout bounds the connection `jump add` and `hostkey add` make to read a host key.
const fetchTimeout = 15 * time.Second

// cli runs `probe ssh ...`. Terminal access is behind functions so tests can stand in for a terminal.
type cli struct {
	stdin      *bufio.Reader
	stdout     io.Writer
	stderr     io.Writer
	isTerminal func() bool
	// readSecret prompts on stderr and reads a line without echo.
	readSecret func(prompt string) ([]byte, error)
	// readLine prompts on stderr and reads a line with echo.
	readLine func(prompt string) (string, error)
}

func newCLI(stdin *os.File, stdout, stderr io.Writer) *cli {
	c := &cli{stdin: bufio.NewReader(stdin), stdout: stdout, stderr: stderr}
	fd := int(stdin.Fd())
	c.isTerminal = func() bool { return term.IsTerminal(fd) }
	c.readSecret = func(prompt string) ([]byte, error) {
		fmt.Fprint(stderr, prompt)
		b, err := term.ReadPassword(fd)
		fmt.Fprintln(stderr)
		return b, err
	}
	c.readLine = func(prompt string) (string, error) {
		fmt.Fprint(stderr, prompt)
		return c.stdinLine()
	}
	return c
}

// stdinLine reads one line from stdin without its line ending.
func (c *cli) stdinLine() (string, error) {
	s, err := c.stdin.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		if errors.Is(err, io.EOF) {
			return "", errors.New("nothing to read on stdin")
		}
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func (c *cli) usage(w io.Writer) {
	fmt.Fprint(w, `usage: probe ssh COMMAND [--config FILE]

Profiles say which credentials and platform device_show uses for which device addresses. They, their secrets and the
known host keys are kept on this probe only, under <state_dir>/ssh/. Changes apply to the next command; no restart.

  probe ssh profile add --name N --cidr C [--cidr C2 ...] --platform P --username U --auth password|key
                        [--key-file PATH] [--port 22] [--jump J] [--legacy] [--trust-on-first-use] [--password-stdin]
  probe ssh profile set NAME [--legacy | --no-legacy] [--trust-on-first-use | --no-trust-on-first-use]
                        [--password | --key-file PATH] [--password-stdin]
  probe ssh profile move NAME --before OTHER | --last
  probe ssh profile list
  probe ssh profile remove NAME
  probe ssh jump add --name N --address A [--port 22] --username U --auth password|key [--key-file PATH]
                     [--legacy] [--password-stdin] [--accept-host-key SHA256:...]
  probe ssh jump set NAME [--legacy | --no-legacy] [--password | --key-file PATH] [--password-stdin]
  probe ssh jump list
  probe ssh jump remove NAME
  probe ssh hostkey list
  probe ssh hostkey learn ADDR[:PORT] [ADDR[:PORT] ...] [--jump J] [--legacy] [--yes]
  probe ssh hostkey add ADDR[:PORT] SHA256:FINGERPRINT|"PUBLIC KEY" [--jump J] [--legacy]
  probe ssh hostkey forget ADDR[:PORT] [--jump J]
  probe ssh test --device ADDR --command "show version" [--timeout-ms 20000]

Passwords and key passphrases are asked for without echo, never taken from a flag or an environment variable. For
automation, --password-stdin reads one line from stdin (a pipe or file, not a terminal) instead. A key file is copied
into the store.

set --password or --key-file rotates a secret in place (the profile or jump host keeps its place and settings): --password
asks for the new password twice, --key-file replaces the stored key of a key profile. A password stays a password and a
key stays a key; to change the auth type, remove and add again. The new secret applies to the next command, and a
cool-down after failed logins ends with it.

Profiles are tried in the order profile list numbers them; the first whose ranges contain a device's address is used.
profile move puts a profile just --before another one, or --last, without removing it.

A password profile logs in only to a device whose host key is recorded: record keys first with hostkey learn (it
connects without logging in, shows each fingerprint and asks), or hostkey add. A key profile, or a profile with
--trust-on-first-use, records an unknown key on first use instead.
Platforms: `+strings.Join(protocol.Platforms, ", ")+`.

Run it as the user that owns the store (the probe's own user):
Docker:  docker compose exec -it probe probe ssh profile add ...
systemd: sudo -u probe probe ssh profile add ...   (a --key-file must be readable by user probe)
`)
}

func (c *cli) run(args []string) int {
	if len(args) == 0 {
		c.usage(c.stderr)
		return 2
	}
	sub, rest := args[0], args[1:]
	if sub != "help" && sub != "-h" && sub != "--help" {
		// Refused before anything is read or asked for: without the store's protections a secret must not be written.
		if err := sshPlatformError(); err != nil {
			fmt.Fprintln(c.stderr, "error:", err)
			return 1
		}
	}
	action := ""
	if actions, ok := subActions[sub]; ok {
		if len(rest) == 0 || strings.HasPrefix(rest[0], "-") {
			fmt.Fprintf(c.stderr, "probe ssh %s needs an action (%s)\n", sub, actions)
			return 2
		}
		action, rest = rest[0], rest[1:]
	}
	var err error
	switch sub + " " + action {
	case "help ", "-h ", "--help ":
		c.usage(c.stdout)
		return 0
	case "profile add":
		err = c.profileAdd(rest)
	case "profile set":
		err = c.profileSet(rest)
	case "profile move":
		err = c.profileMove(rest)
	case "profile list":
		err = c.profileList(rest)
	case "profile remove":
		err = c.profileRemove(rest)
	case "jump add":
		err = c.jumpAdd(rest)
	case "jump set":
		err = c.jumpSet(rest)
	case "jump list":
		err = c.jumpList(rest)
	case "jump remove":
		err = c.jumpRemove(rest)
	case "hostkey list":
		err = c.hostkeyList(rest)
	case "hostkey add":
		err = c.hostkeyAdd(rest)
	case "hostkey learn":
		err = c.hostkeyLearn(rest)
	case "hostkey forget":
		err = c.hostkeyForget(rest)
	case "test ":
		var ok bool
		ok, err = c.test(rest)
		if err == nil && !ok {
			return 1
		}
	default:
		fmt.Fprintf(c.stderr, "unknown command: probe ssh %s\n", strings.TrimSpace(sub+" "+action))
		c.usage(c.stderr)
		return 2
	}
	var ue usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		fmt.Fprintln(c.stderr, err)
		return 2
	default:
		fmt.Fprintln(c.stderr, "error:", err)
		return 1
	}
}

// subActions are the actions of each probe ssh subcommand that takes one, as its "needs an action" message lists them.
var subActions = map[string]string{
	"profile": "add, set, move, list or remove",
	"jump":    "add, set, list or remove",
	"hostkey": "list, add, learn or forget",
}

// sshPlatformError refuses every probe ssh command on a build whose SSH store has no protections (replaced in tests).
var sshPlatformError = sshcfg.PlatformError

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, args ...any) error { return usageError{fmt.Sprintf(format, args...)} }

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// parse parses flags and positional arguments in any order (Go's flag package stops at the first positional), and
// returns the positionals. Every command takes --config.
func parse(fs *flag.FlagSet, args []string, positionals int) (configPath string, pos []string, err error) {
	cfg := fs.String("config", "", "configuration file (default $PROBE_CONFIG, else "+probe.DefaultConfigPath+")")
	fs.SetOutput(io.Discard)
	var flags []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			pos = append(pos, a)
			continue
		}
		flags = append(flags, a)
		name := strings.TrimLeft(a, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue // fs.Parse reports it
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	if err := fs.Parse(flags); err != nil {
		return "", nil, usagef("probe ssh %s: %v", fs.Name(), err)
	}
	if positionals >= 0 && len(pos) != positionals {
		if positionals == 0 {
			return "", nil, usagef("probe ssh %s takes no arguments, got: %s", fs.Name(), strings.Join(pos, " "))
		}
		return "", nil, usagef("probe ssh %s needs %d argument(s), got %d", fs.Name(), positionals, len(pos))
	}
	return probe.ConfigPath(*cfg), pos, nil
}

func loadConfig(path string) (probe.Config, error) {
	cfg, err := probe.LoadConfig(path)
	if err != nil {
		return probe.Config{}, fmt.Errorf("configuration is not valid:\n%v", err)
	}
	return cfg, nil
}

// storeFor loads the configuration and opens its SSH store, refusing at once (before anything is asked for) when the
// store cannot be used by this user: root in the probe user's state directory, a link, the wrong owner or mode.
func (c *cli) storeFor(path string) (probe.Config, *sshcfg.Store, error) {
	cfg, err := loadConfig(path)
	if err != nil {
		return probe.Config{}, nil, err
	}
	store := sshcfg.New(cfg.StateDir)
	if err := store.Check(); err != nil {
		return probe.Config{}, nil, err
	}
	return cfg, store, nil
}

// stdinFlag refuses --password-stdin when stdin is a terminal: the secret would be typed with echo. Without the flag
// the hidden prompt is used.
func (c *cli) stdinFlag(fromStdin bool) error {
	if fromStdin && c.isTerminal() {
		return usagef("--password-stdin reads a pipe or a file, but stdin is a terminal; leave it out to be asked without echo")
	}
	return nil
}

// secret collects a password, or a key file and its passphrase if it has one.
func (c *cli) secret(auth, keyFile string, fromStdin bool) (sshcfg.Secret, error) {
	switch auth {
	case sshcfg.AuthPassword:
		if keyFile != "" {
			return sshcfg.Secret{}, usagef("--key-file is for --auth key")
		}
		pw, err := c.hidden("Password: ", fromStdin, true)
		if err != nil {
			return sshcfg.Secret{}, err
		}
		return sshcfg.Secret{Password: pw}, nil
	case sshcfg.AuthKey:
		if keyFile == "" {
			return sshcfg.Secret{}, usagef("--auth key needs --key-file PATH")
		}
		key, err := readKeyFile(keyFile)
		if err != nil {
			return sshcfg.Secret{}, err
		}
		_, err = sshcfg.CheckKey(key, "")
		if err == nil {
			return sshcfg.Secret{Key: key}, nil
		}
		if !errors.Is(err, sshcfg.ErrPassphraseNeeded) {
			return sshcfg.Secret{}, fmt.Errorf("%s: %v", keyFile, err)
		}
		pp, err := c.hidden("Key passphrase: ", fromStdin, false)
		if err != nil {
			return sshcfg.Secret{}, err
		}
		if _, err := sshcfg.CheckKey(key, pp); err != nil {
			return sshcfg.Secret{}, fmt.Errorf("%s: %v", keyFile, err)
		}
		return sshcfg.Secret{Key: key, Passphrase: pp}, nil
	}
	return sshcfg.Secret{}, usagef("--auth must be password or key")
}

// hidden reads a secret: one line from stdin with --password-stdin, otherwise from the terminal without echo (twice,
// to catch typos, when confirm is set). Without a terminal and without --password-stdin it refuses.
func (c *cli) hidden(prompt string, fromStdin, confirm bool) (string, error) {
	if fromStdin {
		if err := c.stdinFlag(true); err != nil {
			return "", err
		}
		s, err := c.stdinLine()
		if err != nil {
			return "", fmt.Errorf("reading the secret from stdin: %v", err)
		}
		if s == "" {
			return "", errors.New("the secret read from stdin is empty")
		}
		return s, nil
	}
	if !c.isTerminal() {
		return "", errors.New("stdin is not a terminal, so the secret cannot be asked for; " +
			"run in a terminal (docker compose exec -it ...), or pass --password-stdin and send it on stdin")
	}
	a, err := c.readSecret(prompt)
	if err != nil {
		return "", err
	}
	if len(a) == 0 {
		return "", errors.New("empty; nothing saved")
	}
	if confirm {
		b, err := c.readSecret("Again: ")
		if err != nil {
			return "", err
		}
		if string(a) != string(b) {
			return "", errors.New("the two entries differ; nothing saved")
		}
	}
	return string(a), nil
}

func readKeyFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrPermission) {
		return nil, fmt.Errorf("%v; the key file must be readable by the user this runs as (for systemd, user probe: e.g. "+
			"sudo install -m 0400 -o probe KEY /var/lib/probe/import.key, add the profile with --key-file /var/lib/probe/import.key, "+
			"then remove that file)", err)
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxKeyFile {
		return nil, fmt.Errorf("%s is larger than %d bytes; is it a private key?", path, maxKeyFile)
	}
	return b, nil
}

func (c *cli) profileAdd(args []string) error {
	fs := flag.NewFlagSet("profile add", flag.ContinueOnError)
	var cidrs stringList
	fs.Var(&cidrs, "cidr", "device range this profile covers (repeat for more)")
	name := fs.String("name", "", "profile name, [a-z0-9-]{1,32}")
	platform := fs.String("platform", "", "device platform")
	user := fs.String("username", "", "login user name")
	auth := fs.String("auth", "", "password or key")
	keyFile := fs.String("key-file", "", "private key file to copy into the store (--auth key)")
	port := fs.Int("port", sshcfg.DefaultPort, "SSH port")
	jump := fs.String("jump", "", "jump host to go through")
	legacy := fs.Bool("legacy", false, "also offer old SSH algorithms (SHA-1 key exchange, CBC ciphers, ssh-rsa)")
	tofu := fs.Bool("trust-on-first-use", false, "record an unknown device key and log in (a password profile otherwise needs the key recorded first)")
	fromStdin := fs.Bool("password-stdin", false, "read the password or key passphrase as one line from stdin")
	path, _, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	if err := c.stdinFlag(*fromStdin); err != nil {
		return err
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	p := sshcfg.Profile{Name: *name, CIDRs: cidrs, Platform: strings.ToLower(*platform), Username: *user, Auth: *auth,
		Port: *port, Jump: *jump, Legacy: *legacy, TrustOnFirstUse: *tofu}
	// Check everything before asking for the secret.
	cur, err := store.Load()
	if err != nil {
		return err
	}
	if _, dup := cur.Profile(p.Name); dup {
		return fmt.Errorf("profile %q already exists; remove it first", p.Name)
	}
	trial := *cur
	trial.Profiles = append(append([]sshcfg.Profile(nil), cur.Profiles...), cloneProfile(p))
	if err := trial.Validate(); err != nil {
		return err
	}
	sec, err := c.secret(p.Auth, *keyFile, *fromStdin)
	if err != nil {
		return err
	}
	if err := store.AddProfile(p, sec); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "added profile %s (%s, %s) for %s\n", p.Name, p.Platform, p.Auth, strings.Join(trial.Profiles[len(trial.Profiles)-1].CIDRs, ", "))
	if covered := shadowedBy(cur, trial.Profiles[len(trial.Profiles)-1]); covered != "" {
		fmt.Fprintf(c.stdout, "note: profile %s comes first and covers some of these addresses; the first matching profile wins\n", covered)
	}
	c.tofuNote(p)
	return nil
}

// tofuNote warns about a password profile that trusts on first use, or tells how to record keys for one that does
// not.
func (c *cli) tofuNote(p sshcfg.Profile) {
	if p.Auth != sshcfg.AuthPassword {
		return
	}
	if p.TrustOnFirstUse {
		fmt.Fprintf(c.stderr, "warning: profile %s sends its password to a device whose host key is not yet recorded (trust on first use); whoever answers at that address first gets the password\n", p.Name)
		return
	}
	fmt.Fprintf(c.stdout, "profile %s logs in only to devices whose host key is recorded: record them with probe ssh hostkey learn ADDR ...\n", p.Name)
}

// rotation holds what `profile set` and `jump set` were asked to do to a secret.
type rotation struct {
	password  bool
	keyFile   string
	fromStdin bool
}

func (r rotation) wanted() bool { return r.password || r.keyFile != "" }

// check refuses a rotation that does not fit the entry's auth (kind is "profile" or "jump host"), and flags that only
// make sense with one.
func (r rotation) check(kind, name, auth string) error {
	if r.password && r.keyFile != "" {
		return usagef("give --password or --key-file, not both: a %s keeps the auth type it was added with", kind)
	}
	if r.fromStdin && !r.wanted() {
		return usagef("--password-stdin goes with --password or --key-file")
	}
	switch {
	case r.password && auth != sshcfg.AuthPassword:
		return fmt.Errorf("%s %q logs in with a key, so --password does not apply; replace its key with --key-file PATH "+
			"(to change the auth type, remove it and add it again)", kind, name)
	case r.keyFile != "" && auth != sshcfg.AuthKey:
		return fmt.Errorf("%s %q logs in with a password, so --key-file does not apply; change it with --password "+
			"(to change the auth type, remove it and add it again)", kind, name)
	}
	return nil
}

// collect asks for the new secret (nothing is stored here).
func (r rotation) collect(c *cli, auth string) (sshcfg.Secret, error) {
	if auth == sshcfg.AuthPassword {
		pw, err := c.hidden("New password: ", r.fromStdin, true)
		if err != nil {
			return sshcfg.Secret{}, err
		}
		return sshcfg.Secret{Password: pw}, nil
	}
	return c.secret(sshcfg.AuthKey, r.keyFile, r.fromStdin)
}

// rotationNote says what a rotated secret does.
func rotationNote(auth, what string, same bool) string {
	noun := "password"
	if auth == sshcfg.AuthKey {
		noun = "key"
	}
	if same {
		return fmt.Sprintf("%s unchanged (the new one is the same as the stored one), so a cool-down for this %s does not end", noun, what)
	}
	return fmt.Sprintf("%s updated; takes effect on the next command; any cool-down for this %s ends", noun, what)
}

func (c *cli) profileSet(args []string) error {
	fs := flag.NewFlagSet("profile set", flag.ContinueOnError)
	legacy := fs.Bool("legacy", false, "also offer old SSH algorithms")
	noLegacy := fs.Bool("no-legacy", false, "offer only current SSH algorithms")
	tofu := fs.Bool("trust-on-first-use", false, "record an unknown device key and log in")
	noTofu := fs.Bool("no-trust-on-first-use", false, "log in only to devices whose key is recorded (password profiles)")
	password := fs.Bool("password", false, "ask for a new password (password profiles)")
	keyFile := fs.String("key-file", "", "private key file to copy into the store in place of the current one (key profiles)")
	fromStdin := fs.Bool("password-stdin", false, "read the new password or key passphrase as one line from stdin")
	path, pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	var o sshcfg.ProfileOptions
	switch {
	case *legacy && *noLegacy:
		return usagef("give --legacy or --no-legacy, not both")
	case *legacy || *noLegacy:
		v := *legacy
		o.Legacy = &v
	}
	switch {
	case *tofu && *noTofu:
		return usagef("give --trust-on-first-use or --no-trust-on-first-use, not both")
	case *tofu || *noTofu:
		v := *tofu
		o.TrustOnFirstUse = &v
	}
	rot := rotation{password: *password, keyFile: *keyFile, fromStdin: *fromStdin}
	if o.Legacy == nil && o.TrustOnFirstUse == nil && !rot.wanted() {
		return usagef("probe ssh profile set NAME needs --legacy, --no-legacy, --trust-on-first-use, --no-trust-on-first-use, --password or --key-file")
	}
	if rot.password && rot.keyFile != "" || rot.fromStdin && !rot.wanted() {
		return rot.check("profile", pos[0], "")
	}
	if err := c.stdinFlag(rot.fromStdin); err != nil {
		return err
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	// Check everything before asking for the secret.
	cur, err := store.Load()
	if err != nil {
		return err
	}
	prof, ok := cur.Profile(pos[0])
	if !ok {
		return fmt.Errorf("no profile %q", pos[0])
	}
	if err := rot.check("profile", prof.Name, prof.Auth); err != nil {
		return err
	}
	if o.TrustOnFirstUse != nil && prof.Auth == "key" {
		return fmt.Errorf("profile %q logs in with a key, which always records a device's key on first use (a key login gives "+
			"a fake server nothing it can reuse); --trust-on-first-use and --no-trust-on-first-use apply to password profiles", prof.Name)
	}
	same := false
	if rot.wanted() {
		sec, err := rot.collect(c, prof.Auth)
		if err != nil {
			return err
		}
		if old, err := store.Credentials(sshcfg.KindProfile, prof.Name, prof.Auth); err == nil && prof.Auth == sshcfg.AuthPassword {
			same = old.Password == sec.Password
		}
		o.Secret = &sec
	}
	p, err := store.SetProfileOptions(prof.Name, o)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "profile %s: legacy_algorithms %s, trust_on_first_use %s\n", p.Name, yesNo(p.Legacy), yesNo(p.TrustOnFirstUse))
	if o.Secret != nil {
		fmt.Fprintf(c.stdout, "profile %s: %s\n", p.Name, rotationNote(p.Auth, "profile", same))
	}
	if o.TrustOnFirstUse != nil && *o.TrustOnFirstUse {
		c.tofuNote(p)
	}
	return nil
}

func (c *cli) profileMove(args []string) error {
	fs := flag.NewFlagSet("profile move", flag.ContinueOnError)
	before := fs.String("before", "", "put the profile just before this one")
	last := fs.Bool("last", false, "put the profile last")
	path, pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	switch {
	case *before != "" && *last:
		return usagef("give --before OTHER or --last, not both")
	case *before == "" && !*last:
		return usagef("probe ssh profile move NAME needs --before OTHER or --last")
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	position, changed, err := store.MoveProfile(pos[0], *before)
	if err != nil {
		return err
	}
	cur, err := store.Load()
	if err != nil {
		return err
	}
	names := make([]string, len(cur.Profiles))
	for i, p := range cur.Profiles {
		names[i] = p.Name
	}
	verb := "moved"
	if !changed {
		verb = "already in place:"
	}
	where := "last"
	if *before != "" {
		where = "before " + *before
	}
	fmt.Fprintf(c.stdout, "%s profile %s %s (now #%d of %d)\norder: %s\n(the first profile whose ranges contain a device's address is used)\n",
		verb, pos[0], where, position, len(names), strings.Join(names, ", "))
	return nil
}

func cloneProfile(p sshcfg.Profile) sshcfg.Profile {
	p.CIDRs = append([]string(nil), p.CIDRs...)
	return p
}

// shadowedBy names an earlier profile that overlaps p's ranges.
func shadowedBy(cur *sshcfg.Config, p sshcfg.Profile) string {
	for _, q := range cur.Profiles {
		for _, a := range q.CIDRs {
			pa, err := netip.ParsePrefix(a)
			if err != nil {
				continue
			}
			for _, b := range p.CIDRs {
				pb, err := netip.ParsePrefix(b)
				if err == nil && pa.Overlaps(pb) {
					return q.Name
				}
			}
		}
	}
	return ""
}

func (c *cli) profileList(args []string) error {
	path, _, err := parse(flag.NewFlagSet("profile list", flag.ContinueOnError), args, 0)
	if err != nil {
		return err
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	cur, err := store.Load()
	if err != nil {
		return err
	}
	if len(cur.Profiles) == 0 {
		fmt.Fprintln(c.stdout, "no profiles (add one with: probe ssh profile add ...)")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "#\tNAME\tPLATFORM\tCIDRS\tUSERNAME\tAUTH\tPORT\tJUMP\tLEGACY\tFIRST-USE")
	for i, p := range cur.Profiles {
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", i+1, p.Name, p.Platform, strings.Join(p.CIDRs, ","), p.Username, p.Auth,
			p.Port, dash(p.Jump), yesNo(p.Legacy), firstUse(p))
	}
	tw.Flush()
	fmt.Fprintln(c.stdout, "(the first profile whose ranges contain a device's address is used)")
	return nil
}

func (c *cli) profileRemove(args []string) error {
	path, pos, err := parse(flag.NewFlagSet("profile remove", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	if err := store.RemoveProfile(pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "removed profile %s and its secret\n", pos[0])
	return nil
}

// policyHook lets tests adjust the policy (the probe's own addresses are refused, and test servers run on them).
var policyHook func(*policy.Policy)

// runtimeFor builds what the commands that connect need: the policy from the configuration and a devssh Runtime.
func runtimeFor(cfg probe.Config, store *sshcfg.Store, logger *slog.Logger, cat devssh.Commands) (*policy.Policy, *devssh.Runtime, error) {
	pol, err := policy.New(cfg.Targets)
	if err != nil {
		return nil, nil, err
	}
	pol.Logger = logger
	pol.SetRateLimit(cfg.Limits.PerTargetPerMinute)
	if policyHook != nil {
		policyHook(pol)
	}
	rt := devssh.New(devssh.Config{Store: store, Commands: cat, MaxOutputBytes: cfg.SSH.MaxOutputBytes,
		ConnectTimeout: time.Duration(cfg.SSH.ConnectTimeoutMS) * time.Millisecond, Logger: logger,
		AuthFailureCooldown: cfg.SSH.AuthFailureCooldown()})
	return pol, rt, nil
}

func signalContext(d time.Duration) (context.Context, context.CancelFunc) {
	ctx, stop := signal.NotifyContext(policy.WithJob(context.Background()), os.Interrupt, syscall.SIGTERM)
	if d <= 0 {
		return ctx, stop
	}
	tctx, cancel := context.WithTimeout(ctx, d)
	return tctx, func() { cancel(); stop() }
}

func (c *cli) jumpAdd(args []string) error {
	fs := flag.NewFlagSet("jump add", flag.ContinueOnError)
	name := fs.String("name", "", "jump host name, [a-z0-9-]{1,32}")
	address := fs.String("address", "", "IP address or host name")
	port := fs.Int("port", sshcfg.DefaultPort, "SSH port")
	user := fs.String("username", "", "login user name")
	auth := fs.String("auth", "", "password or key")
	keyFile := fs.String("key-file", "", "private key file to copy into the store (--auth key)")
	legacy := fs.Bool("legacy", false, "also offer old SSH algorithms")
	fromStdin := fs.Bool("password-stdin", false, "read the password or key passphrase as one line from stdin")
	accept := fs.String("accept-host-key", "", "the jump host's key fingerprint (SHA256:...), to confirm it without a prompt")
	path, _, err := parse(fs, args, 0)
	if err != nil {
		return err
	}
	if err := c.stdinFlag(*fromStdin); err != nil {
		return err
	}
	cfg, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	j := sshcfg.Jump{Name: *name, Address: *address, Port: *port, Username: *user, Auth: *auth, Legacy: *legacy}
	cur, err := store.Load()
	if err != nil {
		return err
	}
	if _, dup := cur.Jump(j.Name); dup {
		return fmt.Errorf("jump host %q already exists; remove it first", j.Name)
	}
	trial := *cur
	trial.Jumps = append(append([]sshcfg.Jump(nil), cur.Jumps...), j)
	if err := trial.Validate(); err != nil {
		return err
	}
	if *auth == sshcfg.AuthPassword && *keyFile != "" {
		return usagef("--key-file is for --auth key")
	}
	if *auth == sshcfg.AuthKey && *keyFile == "" {
		return usagef("--auth key needs --key-file PATH")
	}

	logger := slog.New(slog.NewTextHandler(c.stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	pol, rt, err := runtimeFor(cfg, store, logger, nil)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext(fetchTimeout)
	defer cancel()
	key, addr, err := rt.FetchHostKey(ctx, pol, j.Address, j.Port, "", j.Legacy)
	if err != nil {
		return fmt.Errorf("could not read the host key of %s port %d: %v", j.Address, j.Port, err)
	}
	fp := ssh.FingerprintSHA256(key)
	fmt.Fprintf(c.stdout, "host key of %s (%s) port %d: %s %s\n", j.Address, addr, j.Port, key.Type(), fp)
	if err := c.confirmKey(fp, *accept, "Record this key and add the jump host? [y/N] "); err != nil {
		return err
	}
	sec, err := c.secret(j.Auth, *keyFile, *fromStdin)
	if err != nil {
		return err
	}
	if err := store.AddHostKey("", sshcfg.HostPort(strings.ToLower(j.Address), j.Port), key); err != nil {
		return err
	}
	if err := store.AddJump(j, sec); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "added jump host %s (%s port %d) and recorded its key\n", j.Name, j.Address, j.Port)
	return nil
}

// confirmKey accepts the key when --accept-host-key names its fingerprint, or when the operator says yes at the
// terminal.
func (c *cli) confirmKey(fp, accept, question string) error {
	if accept != "" {
		if accept != fp {
			return fmt.Errorf("the host presented %s, not the %s given with --accept-host-key; nothing saved", fp, accept)
		}
		return nil
	}
	if !c.isTerminal() {
		return errors.New("stdin is not a terminal; confirm the key with --accept-host-key " + fp)
	}
	ans, err := c.readLine(question)
	if err != nil {
		return err
	}
	if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
		return errors.New("not confirmed; nothing saved")
	}
	return nil
}

func (c *cli) jumpSet(args []string) error {
	fs := flag.NewFlagSet("jump set", flag.ContinueOnError)
	legacy := fs.Bool("legacy", false, "also offer old SSH algorithms")
	noLegacy := fs.Bool("no-legacy", false, "offer only current SSH algorithms")
	password := fs.Bool("password", false, "ask for a new password (password jump hosts)")
	keyFile := fs.String("key-file", "", "private key file to copy into the store in place of the current one (key jump hosts)")
	fromStdin := fs.Bool("password-stdin", false, "read the new password or key passphrase as one line from stdin")
	path, pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	var o sshcfg.JumpOptions
	switch {
	case *legacy && *noLegacy:
		return usagef("give --legacy or --no-legacy, not both")
	case *legacy || *noLegacy:
		v := *legacy
		o.Legacy = &v
	}
	rot := rotation{password: *password, keyFile: *keyFile, fromStdin: *fromStdin}
	if o.Legacy == nil && !rot.wanted() {
		return usagef("probe ssh jump set NAME needs --legacy, --no-legacy, --password or --key-file")
	}
	if rot.password && rot.keyFile != "" || rot.fromStdin && !rot.wanted() {
		return rot.check("jump host", pos[0], "")
	}
	if err := c.stdinFlag(rot.fromStdin); err != nil {
		return err
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	cur, err := store.Load()
	if err != nil {
		return err
	}
	jh, ok := cur.Jump(pos[0])
	if !ok {
		return fmt.Errorf("no jump host %q", pos[0])
	}
	if err := rot.check("jump host", jh.Name, jh.Auth); err != nil {
		return err
	}
	same := false
	if rot.wanted() {
		sec, err := rot.collect(c, jh.Auth)
		if err != nil {
			return err
		}
		if old, err := store.Credentials(sshcfg.KindJump, jh.Name, jh.Auth); err == nil && jh.Auth == sshcfg.AuthPassword {
			same = old.Password == sec.Password
		}
		o.Secret = &sec
	}
	j, err := store.SetJumpOptions(jh.Name, o)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "jump host %s: legacy_algorithms %s\n", j.Name, yesNo(j.Legacy))
	if o.Secret != nil {
		fmt.Fprintf(c.stdout, "jump host %s: %s\n", j.Name, rotationNote(j.Auth, "jump host", same))
	}
	return nil
}

func (c *cli) jumpList(args []string) error {
	path, _, err := parse(flag.NewFlagSet("jump list", flag.ContinueOnError), args, 0)
	if err != nil {
		return err
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	cur, err := store.Load()
	if err != nil {
		return err
	}
	if len(cur.Jumps) == 0 {
		fmt.Fprintln(c.stdout, "no jump hosts")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tADDRESS\tPORT\tUSERNAME\tAUTH\tLEGACY\tUSED BY")
	for _, j := range cur.Jumps {
		var users []string
		for _, p := range cur.Profiles {
			if p.Jump == j.Name {
				users = append(users, p.Name)
			}
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\t%s\t%s\n", j.Name, j.Address, j.Port, j.Username, j.Auth, yesNo(j.Legacy),
			dash(strings.Join(users, ",")))
	}
	return tw.Flush()
}

func (c *cli) jumpRemove(args []string) error {
	path, pos, err := parse(flag.NewFlagSet("jump remove", flag.ContinueOnError), args, 1)
	if err != nil {
		return err
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	if err := store.RemoveJump(pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "removed jump host %s, its secret and the host keys learnt through it\n", pos[0])
	return nil
}

func (c *cli) hostkeyList(args []string) error {
	path, _, err := parse(flag.NewFlagSet("hostkey list", flag.ContinueOnError), args, 0)
	if err != nil {
		return err
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	keys, err := store.ListHostKeys()
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Fprintln(c.stdout, "no host keys recorded")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "VIA\tHOST\tTYPE\tFINGERPRINT")
	for _, k := range keys {
		via := k.Jump
		if via == "" {
			via = "direct"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", via, k.Host, k.Type, k.Fingerprint)
	}
	return tw.Flush()
}

// splitHostPort reads "addr", "addr:port", "[v6]:port" or a bare IPv6 address; port 22 by default.
func splitHostPort(s string) (string, int, error) {
	host, port, _, err := splitHostPortExplicit(s)
	return host, port, err
}

// splitHostPortExplicit is splitHostPort that also says whether a port was given. An IPv6 zone is refused.
func splitHostPortExplicit(s string) (host string, port int, explicit bool, err error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "%") {
		return "", 0, false, fmt.Errorf("%q: an address must not have a zone", s)
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		if ap.Port() == 0 {
			return "", 0, false, fmt.Errorf("%q has a bad port", s)
		}
		return ap.Addr().Unmap().String(), int(ap.Port()), true, nil
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return a.Unmap().String(), sshcfg.DefaultPort, false, nil
	}
	host, port = s, sshcfg.DefaultPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", 0, false, fmt.Errorf("%q has a bad port", s)
		}
		host, port, explicit = h, n, true
	}
	if err := sshcfg.ValidAddress(host); err != nil {
		return "", 0, false, fmt.Errorf("%q: %v", s, err)
	}
	return strings.ToLower(host), port, explicit, nil
}

func (c *cli) hostkeyAdd(args []string) error {
	fs := flag.NewFlagSet("hostkey add", flag.ContinueOnError)
	jump := fs.String("jump", "", "the device is reached through this jump host")
	legacy := fs.Bool("legacy", false, "also offer old SSH algorithms when connecting to read the key")
	path, pos, err := parse(fs, args, 2)
	if err != nil {
		return err
	}
	cfg, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	host, port, err := splitHostPort(pos[0])
	if err != nil {
		return err
	}
	cur, err := store.Load()
	if err != nil {
		return err
	}
	if *jump != "" {
		if _, ok := cur.Jump(*jump); !ok {
			return fmt.Errorf("no jump host %q", *jump)
		}
	}
	// A jump host is recorded under the address it is configured with (a name stays a name); a device is recorded
	// under its IP address, which is how device_show looks it up.
	isJump := false
	if *jump == "" {
		for _, j := range cur.Jumps {
			if strings.EqualFold(j.Address, host) && j.Port == port {
				isJump = true
			}
		}
	}
	_, ipErr := netip.ParseAddr(host)
	spec := strings.TrimSpace(pos[1])

	var key ssh.PublicKey
	recordAs := host
	if strings.HasPrefix(spec, "SHA256:") {
		logger := slog.New(slog.NewTextHandler(c.stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
		pol, rt, err := runtimeFor(cfg, store, logger, nil)
		if err != nil {
			return err
		}
		ctx, cancel := signalContext(fetchTimeout)
		defer cancel()
		k, addr, err := rt.FetchHostKey(ctx, pol, host, port, *jump, *legacy)
		if err != nil {
			return fmt.Errorf("could not read the host key of %s port %d: %v", host, port, err)
		}
		if fp := ssh.FingerprintSHA256(k); fp != spec {
			return fmt.Errorf("%s port %d presented %s %s, not %s; nothing saved", host, port, k.Type(), fp, spec)
		}
		key = k
		if !isJump {
			recordAs = addr.String()
		}
	} else {
		if ipErr != nil && !isJump {
			return fmt.Errorf("give the device's IP address (device host keys are kept by address), or a SHA256 fingerprint to look the name up")
		}
		k, err := parsePublicKey(spec)
		if err != nil {
			return err
		}
		key = k
	}
	hp := sshcfg.HostPort(recordAs, port)
	if err := store.AddHostKey(*jump, hp, key); err != nil {
		return err
	}
	via := "directly"
	if *jump != "" {
		via = "through jump host " + *jump
	}
	fmt.Fprintf(c.stdout, "recorded %s %s for %s (reached %s)\n", key.Type(), ssh.FingerprintSHA256(key), hp, via)
	return nil
}

// hostkeyLearn connects to each address without logging in, shows the host key it presents, and records it once the
// operator confirms (or at once with --yes, still printing what it records). A device is recorded under its IP address,
// with the port and jump host of the profile that covers it unless --jump or a port is given; a configured jump host
// is recorded under its configured address.
func (c *cli) hostkeyLearn(args []string) error {
	fs := flag.NewFlagSet("hostkey learn", flag.ContinueOnError)
	jump := fs.String("jump", "", "the devices are reached through this jump host (default: the covering profile's)")
	legacy := fs.Bool("legacy", false, "also offer old SSH algorithms when connecting to read the key")
	yes := fs.Bool("yes", false, "record every key without asking (each is still printed)")
	path, pos, err := parse(fs, args, -1)
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return usagef("probe ssh hostkey learn needs at least one ADDR[:PORT]")
	}
	if !*yes && !c.isTerminal() {
		return usagef("stdin is not a terminal, so the keys cannot be confirmed; check the fingerprints (probe ssh hostkey learn in a terminal) or pass --yes")
	}
	cfg, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	cur, err := store.Load()
	if err != nil {
		return err
	}
	if *jump != "" {
		if _, ok := cur.Jump(*jump); !ok {
			return fmt.Errorf("no jump host %q", *jump)
		}
	}
	logger := slog.New(slog.NewTextHandler(c.stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	pol, rt, err := runtimeFor(cfg, store, logger, nil)
	if err != nil {
		return err
	}
	failed := 0
	for _, arg := range pos {
		if err := c.learnOne(cur, store, pol, rt, arg, *jump, *legacy, *yes); err != nil {
			fmt.Fprintf(c.stderr, "%s: %v\n", arg, err)
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d host keys not recorded", failed, len(pos))
	}
	return nil
}

func (c *cli) learnOne(cur *sshcfg.Config, store *sshcfg.Store, pol *policy.Policy, rt *devssh.Runtime, arg, jump string,
	legacy, yes bool) error {
	host, port, explicit, err := splitHostPortExplicit(arg)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext(fetchTimeout)
	defer cancel()

	// A configured jump host (by its configured address) is recorded as such: directly, under that address.
	if jump == "" {
		for _, j := range cur.Jumps {
			if strings.EqualFold(j.Address, host) && (j.Port == port || !explicit) {
				k, addr, err := rt.FetchHostKey(ctx, pol, j.Address, j.Port, "", j.Legacy || legacy)
				if err != nil {
					return fmt.Errorf("could not read the host key: %v", err)
				}
				hp := sshcfg.HostPort(strings.ToLower(j.Address), j.Port)
				return c.recordLearnt(store, "", hp, fmt.Sprintf("jump host %s, %s (%s) port %d", j.Name, j.Address, addr, j.Port), k, yes)
			}
		}
	}
	// A device: the policy resolves and checks it, and the profile covering its address supplies the port, jump host
	// and algorithms device_show will use.
	addrs, perr := pol.Resolve(ctx, host, "")
	if perr != nil {
		return fmt.Errorf("%s: %s", perr.Code, perr.Message)
	}
	addr := addrs[0]
	via, profName := jump, ""
	if prof, ok := cur.Match(addr); ok {
		profName = prof.Name
		if !explicit {
			port = prof.Port
		}
		if jump == "" {
			via = prof.Jump
		}
		legacy = legacy || prof.Legacy
	}
	// The host is passed as given, so a name the policy allows only by name (allow_hosts) is allowed here too; the
	// key is recorded under the address it was read from, which must be the one the profile was matched on.
	k, got, err := rt.FetchHostKey(ctx, pol, host, port, via, legacy)
	if err != nil {
		return fmt.Errorf("could not read the host key of %s port %d: %v", addr, port, err)
	}
	if got != addr {
		return fmt.Errorf("%s resolved to %s and then to %s; nothing saved", host, addr, got)
	}
	what := fmt.Sprintf("%s (%s) port %d", host, addr, port)
	if via != "" {
		what += " through jump host " + via
	}
	if profName != "" {
		what += ", profile " + profName
	} else {
		what += ", no profile covers it"
	}
	return c.recordLearnt(store, via, sshcfg.HostPort(addr.String(), port), what, k, yes)
}

func (c *cli) recordLearnt(store *sshcfg.Store, via, hp, what string, k ssh.PublicKey, yes bool) error {
	fp := ssh.FingerprintSHA256(k)
	fmt.Fprintf(c.stdout, "host key of %s: %s %s\n", what, k.Type(), fp)
	known, err := store.LookupHostKeys(via, hp)
	if err != nil {
		return err
	}
	for _, kk := range known {
		if kk.Type() == k.Type() && string(kk.Marshal()) == string(k.Marshal()) {
			fmt.Fprintf(c.stdout, "already recorded for %s%s\n", hp, viaText(via))
			return nil
		}
	}
	if !yes {
		ans, err := c.readLine(fmt.Sprintf("Record %s %s for %s%s? [y/N] ", k.Type(), fp, hp, viaText(via)))
		if err != nil {
			return err
		}
		if a := strings.ToLower(strings.TrimSpace(ans)); a != "y" && a != "yes" {
			return errors.New("not confirmed; nothing saved")
		}
	}
	if err := store.AddHostKey(via, hp, k); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "recorded %s %s for %s%s\n", k.Type(), fp, hp, viaText(via))
	return nil
}

// parsePublicKey reads an OpenSSH public key ("ssh-ed25519 AAAA... comment") or a known_hosts line.
func parsePublicKey(s string) (ssh.PublicKey, error) {
	if k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s)); err == nil {
		return k, nil
	}
	if _, _, k, _, _, err := ssh.ParseKnownHosts([]byte(s)); err == nil {
		return k, nil
	}
	return nil, errors.New(`the key must be a SHA256:... fingerprint, a public key ("ssh-ed25519 AAAA...") or a known_hosts line`)
}

func (c *cli) hostkeyForget(args []string) error {
	fs := flag.NewFlagSet("hostkey forget", flag.ContinueOnError)
	jump := fs.String("jump", "", "the device is reached through this jump host")
	path, pos, err := parse(fs, args, 1)
	if err != nil {
		return err
	}
	_, store, err := c.storeFor(path)
	if err != nil {
		return err
	}
	hp, err := sshcfg.ParseHostPort(pos[0])
	if err != nil {
		return err
	}
	n, err := store.ForgetHostKey(*jump, hp)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("no key recorded for %s%s", hp, viaText(*jump))
	}
	fmt.Fprintf(c.stdout, "forgot %d key(s) for %s%s; record the new key with probe ssh hostkey learn (a key profile, or one with trust_on_first_use, records it on its next connection)\n",
		n, hp, viaText(*jump))
	return nil
}

func viaText(jump string) string {
	if jump == "" {
		return ""
	}
	return " through jump host " + jump
}

// test runs one command exactly as device_show would, and prints the result. ok is false for any outcome but "ok".
func (c *cli) test(args []string) (bool, error) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	device := fs.String("device", "", "device IP address or name")
	command := fs.String("command", "", "the command, written out in full")
	timeout := fs.Int("timeout-ms", 0, "whole login and command, 2000 to 35000, default 20000")
	path, _, err := parse(fs, args, 0)
	if err != nil {
		return false, err
	}
	cfg, store, err := c.storeFor(path)
	if err != nil {
		return false, err
	}
	if !cfg.SSH.Enabled {
		fmt.Fprintf(c.stderr, "note: ssh.enabled is false in %s, so the probe does not offer device_show; testing anyway\n", path)
	}
	cat, err := devcmd.Load(cfg.SSH.CommandsFile)
	if err != nil {
		return false, fmt.Errorf("ssh.commands_file: %v", err)
	}
	p := protocol.DeviceShowParams{Device: *device, Command: *command, TimeoutMS: *timeout}
	if perr := p.Normalize(); perr != nil {
		return false, usagef("%s", perr.Message)
	}
	logger := probe.NewLogger(c.stderr, cfg.LogLevel)
	pol, rt, err := runtimeFor(cfg, store, logger, cat)
	if err != nil {
		return false, err
	}
	ctx, cancel := signalContext(0)
	defer cancel()
	res, perr := rt.Show(ctx, pol, p)
	if perr != nil {
		fmt.Fprintf(c.stdout, "refused: %s: %s\n", perr.Code, perr.Message)
		return false, nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 0, 1, ' ', 0)
	fmt.Fprintf(tw, "outcome:\t%s\n", res.Outcome)
	if res.Detail != "" {
		fmt.Fprintf(tw, "detail:\t%s\n", res.Detail)
	}
	fmt.Fprintf(tw, "device:\t%s (%s)\n", res.Device, res.Address)
	fmt.Fprintf(tw, "profile:\t%s (%s)\n", res.Profile, res.Platform)
	if res.Jump != "" {
		fmt.Fprintf(tw, "jump:\t%s\n", res.Jump)
	}
	if res.HostKey != "" {
		first := ""
		if res.HostKeyFirstUse {
			first = " (recorded on first use)"
		}
		fmt.Fprintf(tw, "host key:\t%s%s\n", res.HostKey, first)
	}
	if res.ExitStatus != nil {
		fmt.Fprintf(tw, "exit status:\t%d\n", *res.ExitStatus)
	}
	trunc := ""
	if res.Truncated {
		trunc = " (truncated)"
	}
	fmt.Fprintf(tw, "output:\t%d bytes%s\n", res.OutputBytes, trunc)
	fmt.Fprintf(tw, "duration:\t%d ms\n", res.DurationMS)
	tw.Flush()
	if res.Output != nil && res.Output.Text != "" {
		fmt.Fprintln(c.stdout, "---")
		fmt.Fprint(c.stdout, res.Output.Text)
		if !strings.HasSuffix(res.Output.Text, "\n") {
			fmt.Fprintln(c.stdout)
		}
	}
	return res.Outcome == "ok", nil
}

// firstUse says what a profile does with an unknown device key.
func firstUse(p sshcfg.Profile) string {
	switch {
	case p.Auth == sshcfg.AuthKey:
		return "trust"
	case p.TrustOnFirstUse:
		return "trust (opted in)"
	}
	return "refuse"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
