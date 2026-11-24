package sshcfg

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKey is one known host key.
type HostKey struct {
	Jump        string // "" for a host reached directly (or a jump host itself)
	Host        string // as written in the file: "addr" for port 22, "[addr]:port" otherwise
	Type        string
	Fingerprint string // SHA256:...
	Key         ssh.PublicKey
}

// HostPort is the known_hosts spelling of host and port.
func HostPort(host string, port int) string {
	return knownhosts.Normalize(net.JoinHostPort(host, strconv.Itoa(port)))
}

// ParseHostPort reads "addr", "addr:port", "[v6]:port" or a bare IPv6 address, with port 22 by default, and returns
// its known_hosts spelling. An IPv6 zone ("%eth0") is refused.
func ParseHostPort(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "%") {
		return "", fmt.Errorf("%q: an address must not have a zone", s)
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return HostPort(ap.Addr().Unmap().String(), int(ap.Port())), nil
	}
	if a, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return HostPort(a.Unmap().String(), DefaultPort), nil
	}
	host, port := s, DefaultPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("%q has a bad port", s)
		}
		host, port = h, n
	}
	if err := ValidAddress(host); err != nil {
		return "", fmt.Errorf("%q: %v", s, err)
	}
	return HostPort(strings.ToLower(host), port), nil
}

// CheckHostPort accepts only what HostPort writes for a valid address: "host" (port 22) or "[host]:port", where host
// is an IP address without a zone or a host name. Anything else (whitespace, a comma, a zone, a pattern, a marker)
// could change the meaning of a known_hosts line, so it is never written.
func CheckHostPort(hp string) error {
	bad := func() error { return fmt.Errorf("%q is not an address and port this store records", hp) }
	if hp == "" || len(hp) > maxAddress+8 {
		return bad()
	}
	host, port := hp, DefaultPort
	if strings.HasPrefix(hp, "[") {
		h, p, err := net.SplitHostPort(hp)
		if err != nil {
			return bad()
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return bad()
		}
		host, port = h, n
	}
	if ValidAddress(host) != nil || HostPort(host, port) != hp {
		return bad()
	}
	return nil
}

// knownHostsName is the file, relative to the store, for hosts reached through jump ("" for directly).
func (s *Store) knownHostsName(jump string) string {
	if jump == "" {
		return knownHosts
	}
	return knownViaPrefx + jump
}

type khEntry struct {
	hosts []string
	key   ssh.PublicKey
	line  string
}

func (s *Store) readKnownHosts(name string) ([]khEntry, error) {
	path := filepath.Join(s.dir, name)
	data, err := s.readFile(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var out []khEntry
	for n, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		marker, hosts, key, _, _, err := ssh.ParseKnownHosts([]byte(t))
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %v", path, n+1, err)
		}
		if marker != "" {
			// @revoked and @cert-authority are not used by this store; such a line is kept but never matches.
			continue
		}
		out = append(out, khEntry{hosts: hosts, key: key, line: t})
	}
	return out, nil
}

// LookupHostKeys returns the keys recorded for hostport, reached through jump ("" for directly).
func (s *Store) LookupHostKeys(jump, hostport string) ([]ssh.PublicKey, error) {
	entries, err := s.readKnownHosts(s.knownHostsName(jump))
	if err != nil {
		return nil, err
	}
	var keys []ssh.PublicKey
	for _, e := range entries {
		for _, h := range e.hosts {
			if h == hostport {
				keys = append(keys, e.key)
				break
			}
		}
	}
	return keys, nil
}

// AddHostKey records key for hostport. It refuses when another key is already recorded for that host: a changed key is
// for the operator to look into, then `probe ssh hostkey forget`. Recording the same key again does nothing. hostport
// must be as HostPort writes it (CheckHostPort), and the line written must read back as exactly that host and key.
func (s *Store) AddHostKey(jump, hostport string, key ssh.PublicKey) error {
	if jump != "" && !ValidName(jump) {
		return fmt.Errorf("%q is not a jump host name", jump)
	}
	if err := CheckHostPort(hostport); err != nil {
		return err
	}
	line := knownhosts.Line([]string{hostport}, key)
	marker, hosts, k, _, rest, err := ssh.ParseKnownHosts([]byte(line))
	if err != nil || marker != "" || len(hosts) != 1 || hosts[0] != hostport || !bytes.Equal(k.Marshal(), key.Marshal()) ||
		len(bytes.TrimSpace(rest)) != 0 || strings.ContainsAny(line, "\r\n") {
		return fmt.Errorf("%q cannot be recorded as a known host", hostport)
	}
	return s.locked(func() error { return s.addHostKey(jump, hostport, key) })
}

func (s *Store) addHostKey(jump, hostport string, key ssh.PublicKey) error {
	name := s.knownHostsName(jump)
	entries, err := s.readKnownHosts(name)
	if err != nil {
		return err
	}
	for _, e := range entries {
		for _, h := range e.hosts {
			if h != hostport {
				continue
			}
			if bytes.Equal(e.key.Marshal(), key.Marshal()) {
				return nil
			}
			if e.key.Type() == key.Type() {
				return fmt.Errorf("%s already has a different %s key (%s); forget it first if the change is expected",
					hostport, e.key.Type(), ssh.FingerprintSHA256(e.key))
			}
		}
	}
	old, err := s.readFile(name)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if len(old) > 0 && old[len(old)-1] != '\n' {
		old = append(old, '\n')
	}
	data := append(old, []byte(knownhosts.Line([]string{hostport}, key)+"\n")...)
	return s.writeFile(name, data)
}

// ForgetHostKey removes every key recorded for hostport through jump and says how many there were.
func (s *Store) ForgetHostKey(jump, hostport string) (int, error) {
	n := 0
	err := s.locked(func() error {
		var err error
		n, err = s.forgetHostKey(jump, hostport)
		return err
	})
	return n, err
}

func (s *Store) forgetHostKey(jump, hostport string) (int, error) {
	data, err := s.readFile(s.knownHostsName(jump))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var keep []string
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if !strings.HasPrefix(t, "#") {
			if _, hosts, _, _, _, err := ssh.ParseKnownHosts([]byte(t)); err == nil && len(hosts) == 1 && hosts[0] == hostport {
				n++
				continue
			}
		}
		keep = append(keep, t)
	}
	if n == 0 {
		return 0, nil
	}
	out := strings.Join(keep, "\n")
	if out != "" {
		out += "\n"
	}
	return n, s.writeFile(s.knownHostsName(jump), []byte(out))
}

// ListHostKeys lists every recorded key: direct ones first, then per jump host by name.
func (s *Store) ListHostKeys() ([]HostKey, error) {
	files := []string{""}
	d, err := s.openDir(false)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names, err := d.names()
	d.close()
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	for _, m := range names {
		if j, ok := strings.CutPrefix(m, knownViaPrefx); ok && ValidName(j) {
			files = append(files, j)
		}
	}
	var out []HostKey
	for _, j := range files {
		entries, err := s.readKnownHosts(s.knownHostsName(j))
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			out = append(out, HostKey{Jump: j, Host: strings.Join(e.hosts, ","), Type: e.key.Type(),
				Fingerprint: ssh.FingerprintSHA256(e.key), Key: e.key})
		}
	}
	return out, nil
}
