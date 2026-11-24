// Package policy decides which addresses a probe may reach. It is the probe's own rule: the hub and the agent can ask
// for less, never more.
//
// Every check reaches its target through this package. Names are resolved here, each address is checked, and the
// connection is made to the checked address, so a DNS answer that changes between the check and the connection, or an
// HTTP redirect to another host, cannot reach an address the policy refuses. Checks never use a proxy.
package policy

import (
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"probetools/internal/protocol"
)

// Modes. There is no default: a probe refuses to start until its operator chooses one.
const (
	ModeOpen   = "open"   // any address except the always-refused ones and deny_cidrs
	ModeClosed = "closed" // only allow_cidrs and names matching allow_hosts, minus the refused ones
)

// Config is the target policy from the probe's configuration file.
type Config struct {
	Mode       string   `yaml:"mode"`
	AllowCIDRs []string `yaml:"allow_cidrs"`
	AllowHosts []string `yaml:"allow_hosts"` // exact names, or "*.example.com" for any name below example.com
	DenyCIDRs  []string `yaml:"deny_cidrs"`
	// DenyHosts is the name half of the no-touch list: names, or "*.example.com", that no check may reach by that name.
	// It matches only requests made by name; list the addresses in deny_cidrs to refuse them however they are asked for.
	DenyHosts []string `yaml:"deny_hosts"`
}

// alwaysDenied are refused in every mode: the probe's own host, link-local addresses where cloud metadata services
// live, and addresses that are not a single remote host.
var alwaysDenied = mustPrefixes(
	"0.0.0.0/8",          // "this network"
	"127.0.0.0/8",        // loopback
	"169.254.0.0/16",     // link-local, including 169.254.169.254 cloud metadata
	"224.0.0.0/4",        // multicast
	"240.0.0.0/4",        // reserved, including 255.255.255.255 broadcast
	"100.100.100.200/32", // Alibaba Cloud metadata
	"::/128",             // unspecified
	"::1/128",            // loopback
	"fe80::/10",          // link-local
	"ff00::/8",           // multicast
	"fd00:ec2::254/128",  // AWS IPv6 metadata
	"2001::/32",          // Teredo: tunnels to an IPv4 relay and host the probe cannot vet
)

// IPv6 ranges that carry an IPv4 address. A packet to one of them can end up at that IPv4 address (through a NAT64
// gateway, a 6to4 relay or a translator), so the IPv4 address is put through the same refusals as a plain one.
var (
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")    // RFC 6052: IPv4 in the last 32 bits
	nat64Local     = netip.MustParsePrefix("64:ff9b:1::/48")  // RFC 8215: local-use, any RFC 6052 prefix length inside it
	sixToFour      = netip.MustParsePrefix("2002::/16")       // RFC 3056: IPv4 in bits 16 to 47
	v4Compatible   = netip.MustParsePrefix("::/96")           // RFC 4291 (deprecated): IPv4 in the last 32 bits
	v4Translated   = netip.MustParsePrefix("::ffff:0:0:0/96") // RFC 2765 SIIT: IPv4 in the last 32 bits
)

const (
	// selfCacheTTL bounds how long a new interface address can go unrefused after it appears.
	selfCacheTTL = 5 * time.Second
	// maxRateKeys bounds the rate limiter's memory. Targets come from the hub, so a full table first drops buckets that
	// have refilled, then the least recently used one: the limit is a courtesy to targets, and refusing every new address
	// would be the worse failure.
	maxRateKeys = 4096
	// rateSweepInterval stops a full table of busy buckets from costing a full scan on every new address.
	rateSweepInterval = time.Second
	// maxResolveAddrs caps the addresses one Resolve returns, and so charges. Checks use the first address or try them
	// in order, so a name with thousands of records gains nothing from the rest and must not fill the rate table.
	maxResolveAddrs = 8
)

// Policy is a compiled Config. It is safe for concurrent use.
type Policy struct {
	mode       string
	allow      []netip.Prefix
	allowHosts []string
	denyHosts  []string
	deny       []netip.Prefix
	summary    protocol.PolicySummary

	// Resolver can be replaced in tests.
	Resolver interface {
		LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
	}
	// SelfAddrs lists this host's interface addresses with their prefix lengths. Each address is refused, and so is
	// the broadcast address of each IPv4 prefix. An error makes the policy refuse every target, since it can no longer
	// tell which addresses are the probe's own. Tests replace it; nil means the host has no addresses to refuse.
	SelfAddrs func() ([]netip.Prefix, error)
	// Logger receives the warning when SelfAddrs fails. nil uses slog.Default().
	Logger *slog.Logger

	selfMu     sync.Mutex
	self       []netip.Addr
	bcast      []netip.Addr
	selfErr    error
	selfTime   time.Time
	selfLogged bool // the current run of SelfAddrs failures has been logged

	rl  rateLimiter
	now func() time.Time // replaced in tests
}

// New compiles cfg, refusing a missing mode or a malformed entry.
func New(cfg Config) (*Policy, error) {
	p := &Policy{Resolver: net.DefaultResolver}
	switch cfg.Mode {
	case ModeOpen, ModeClosed:
		p.mode = cfg.Mode
	case "":
		return nil, errors.New(`targets.mode is required: "open" (anything but always-refused addresses) or "closed" (only what allow_cidrs and allow_hosts list)`)
	default:
		return nil, fmt.Errorf("targets.mode %q must be open or closed", cfg.Mode)
	}
	var err error
	if p.allow, err = parsePrefixes(cfg.AllowCIDRs); err != nil {
		return nil, fmt.Errorf("targets.allow_cidrs: %w", err)
	}
	if p.deny, err = parsePrefixes(cfg.DenyCIDRs); err != nil {
		return nil, fmt.Errorf("targets.deny_cidrs: %w", err)
	}
	if p.allowHosts, err = parseHostPatterns(cfg.AllowHosts); err != nil {
		return nil, fmt.Errorf("targets.allow_hosts: %w", err)
	}
	if p.denyHosts, err = parseHostPatterns(cfg.DenyHosts); err != nil {
		return nil, fmt.Errorf("targets.deny_hosts: %w", err)
	}
	if p.mode == ModeClosed && len(p.allow) == 0 && len(p.allowHosts) == 0 {
		return nil, errors.New("targets.mode is closed but allow_cidrs and allow_hosts are both empty, so nothing could be probed")
	}
	p.summary = protocol.PolicySummary{Mode: p.mode, AllowCIDRs: cfg.AllowCIDRs, AllowHosts: p.allowHosts, DenyCIDRs: cfg.DenyCIDRs,
		DenyHosts: p.denyHosts}
	p.SelfAddrs = interfacePrefixes
	return p, nil
}

// Summary is what the probe reports to the hub.
func (p *Policy) Summary() protocol.PolicySummary { return p.summary }

// Allowed reports whether addr may be reached. host is the name the address was reached through, or "" when the target
// was an address literal; it matters only for allow_hosts in closed mode.
func (p *Policy) Allowed(host string, addr netip.Addr) *protocol.Error {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() {
		return protocol.Errorf(protocol.CodeDenied, "not a valid address")
	}
	if host != "" && hostMatches(p.denyHosts, host) {
		return protocol.Errorf(protocol.CodeDenied, "%s is in this probe's deny_hosts", normalizeName(host))
	}
	self, bcast, err := p.selfInfo()
	if err != nil {
		return protocol.Errorf(protocol.CodeDenied, "this probe cannot list its own addresses (%v), so it refuses every target until it can", err)
	}
	if d := p.refused(addr, self, bcast); d != nil {
		return d
	}
	v4, embeds := embeddedIPv4(addr)
	if embeds {
		if d := p.refused(v4, self, bcast); d != nil {
			return protocol.Errorf(protocol.CodeDenied, "%s carries the IPv4 address %s, which is refused: %s", addr, v4, d.Message)
		}
	}
	// The local-use NAT64 prefix may hold the IPv4 address at any of several offsets, so it cannot be checked; the
	// operator must name it.
	if nat64Local.Contains(addr) && !p.inAllow(addr) {
		return protocol.Errorf(protocol.CodeDenied, "%s is in the local-use NAT64 prefix 64:ff9b:1::/48, whose IPv4 address cannot be checked; it is probed only when allow_cidrs lists it", addr)
	}
	if p.mode == ModeOpen {
		return nil
	}
	if p.inAllow(addr) || (embeds && p.inAllow(v4)) {
		return nil
	}
	if embeds {
		// allow_hosts does not admit these: a name would otherwise reach any IPv4 address through a translator.
		return protocol.Errorf(protocol.CodeDenied, "%s carries the IPv4 address %s; in closed mode it is allowed only when allow_cidrs lists the IPv6 address or the IPv4 address", addr, v4)
	}
	if host != "" && p.hostAllowed(host) {
		return nil
	}
	return protocol.Errorf(protocol.CodeDenied, "%s is not in this probe's allowed targets", addr)
}

// refused applies the refusals that hold in every mode: always-denied ranges, the probe's own addresses, the broadcast
// addresses of its networks, and deny_cidrs.
func (p *Policy) refused(addr netip.Addr, self, bcast []netip.Addr) *protocol.Error {
	for _, pre := range alwaysDenied {
		if pre.Contains(addr) {
			return protocol.Errorf(protocol.CodeDenied, "%s is never probed (loopback, link-local, metadata, multicast, reserved or a tunnel)", addr)
		}
	}
	for _, a := range self {
		if a == addr {
			return protocol.Errorf(protocol.CodeDenied, "%s is this probe's own address", addr)
		}
	}
	for _, a := range bcast {
		if a == addr {
			return protocol.Errorf(protocol.CodeDenied, "%s is the broadcast address of one of this probe's networks", addr)
		}
	}
	for _, pre := range p.deny {
		if pre.Contains(addr) {
			return protocol.Errorf(protocol.CodeDenied, "%s is in this probe's deny_cidrs", addr)
		}
	}
	return nil
}

func (p *Policy) inAllow(addr netip.Addr) bool {
	for _, pre := range p.allow {
		if pre.Contains(addr) {
			return true
		}
	}
	return false
}

// embeddedIPv4 returns the IPv4 address an IPv6 address carries in the NAT64 well-known prefix, 6to4, IPv4-compatible
// or IPv4-translated form. IPv4-mapped addresses are not handled here: callers unmap them first.
func embeddedIPv4(a netip.Addr) (netip.Addr, bool) {
	if !a.Is6() || a.Is4In6() {
		return netip.Addr{}, false
	}
	b := a.As16()
	switch {
	case nat64WellKnown.Contains(a), v4Compatible.Contains(a), v4Translated.Contains(a):
		return netip.AddrFrom4([4]byte(b[12:16])), true
	case sixToFour.Contains(a):
		return netip.AddrFrom4([4]byte(b[2:6])), true
	}
	return netip.Addr{}, false
}

// Resolve turns a target (a name or an address literal) into the addresses the policy allows, in resolver order,
// limited to family "4" or "6" when given. It fails with CodeDenied when the target resolves only to refused addresses,
// and with CodeUnresolved when the name does not resolve. Checks connect only to addresses this returns.
//
// It considers at most the first 8 allowed addresses (maxResolveAddrs), in resolver order, and returns no more than
// those: a name with thousands of records costs no more than one with eight.
//
// Each address it returns is charged to the rate limit (see SetRateLimit and WithJob). An address over its limit is
// left out like a refused one; when that leaves nothing, Resolve fails with CodeBusy.
func (p *Policy) Resolve(ctx context.Context, target, family string) ([]netip.Addr, *protocol.Error) {
	host, addrs, err := p.lookup(ctx, target, family)
	if err != nil {
		return nil, err
	}
	var candidates []netip.Addr
	var firstDenial, firstBusy *protocol.Error
	for _, a := range addrs {
		if len(candidates) == maxResolveAddrs {
			break
		}
		if d := p.Allowed(host, a); d != nil {
			if firstDenial == nil {
				firstDenial = d
			}
			continue
		}
		candidates = append(candidates, a.Unmap().WithZone(""))
	}
	var allowed []netip.Addr
	for _, a := range candidates {
		if b := p.Charge(ctx, a); b != nil {
			if firstBusy == nil {
				firstBusy = b
			}
			continue
		}
		allowed = append(allowed, a)
	}
	if len(allowed) == 0 {
		if firstBusy != nil {
			return nil, firstBusy
		}
		return nil, firstDenial
	}
	return allowed, nil
}

// jobKey is the context key for a job's charged addresses.
type jobKey struct{}

// jobCharges records the addresses one job has been charged for, so a job that resolves its target several times (one
// dial per port, an HTTP redirect to the same host, diagnose's layers) spends one token per address.
type jobCharges struct {
	mu      sync.Mutex
	charged map[netip.Addr]bool
}

// WithJob marks ctx as one job's, so the rate limit charges the job at most once per address. Without it every Resolve
// and Charge spends a token.
func WithJob(ctx context.Context) context.Context {
	return context.WithValue(ctx, jobKey{}, &jobCharges{charged: map[netip.Addr]bool{}})
}

// SetRateLimit limits how often jobs may contact each address, per minute; 0 turns the limit off. It is keyed on the
// address rather than on the target as written, so other spellings of one host (a v4-mapped form, a NAT64 or 6to4
// form, another name for it) share its limit. Call it at start-up.
func (p *Policy) SetRateLimit(perMinute int) {
	if perMinute < 0 {
		perMinute = 0
	}
	p.rl.mu.Lock()
	defer p.rl.mu.Unlock()
	p.rl.perMinute = perMinute
	if perMinute == 0 {
		p.rl.m, p.rl.lru = nil, nil
		return
	}
	now := p.clock()
	for _, b := range p.rl.m {
		b.lim.SetLimitAt(now, perMinuteRate(perMinute))
		b.lim.SetBurstAt(now, perMinute)
	}
}

// Charge spends one of addr's rate-limit tokens, once per job when ctx carries WithJob. It fails with CodeBusy when
// addr is over its limit. Resolve charges what it returns; a check that contacts an address it only put to Allowed
// (dns_lookup's explicit server) calls Charge itself.
func (p *Policy) Charge(ctx context.Context, addr netip.Addr) *protocol.Error {
	addr = addr.Unmap().WithZone("")
	key := addr
	if v4, ok := embeddedIPv4(addr); ok {
		key = v4
	}
	job, _ := ctx.Value(jobKey{}).(*jobCharges)
	if job != nil {
		job.mu.Lock()
		defer job.mu.Unlock()
		if job.charged[key] {
			return nil
		}
	}
	if perr := p.rl.take(key, p.clock()); perr != nil {
		return perr
	}
	if job != nil {
		job.charged[key] = true
	}
	return nil
}

// rateLimiter holds one token bucket per address, in a table of at most maxRateKeys buckets kept in least recently
// used order.
type rateLimiter struct {
	mu        sync.Mutex
	perMinute int
	m         map[netip.Addr]*rateBucket
	lru       *list.List // of netip.Addr, most recently used at the front
	lastSweep time.Time
}

type rateBucket struct {
	lim  *rate.Limiter
	elem *list.Element // this bucket's place in lru
}

func perMinuteRate(n int) rate.Limit { return rate.Limit(float64(n) / 60) }

// take spends one of key's tokens. key is the address the bucket is kept under: the IPv4 address an IPv6 address
// carries, or the address itself.
func (r *rateLimiter) take(key netip.Addr, now time.Time) *protocol.Error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.perMinute == 0 {
		return nil
	}
	b, ok := r.m[key]
	if ok {
		r.lru.MoveToFront(b.elem)
	} else {
		if len(r.m) >= maxRateKeys {
			r.evictIdle(now)
		}
		for len(r.m) >= maxRateKeys {
			// Every bucket is still in use. Forgetting the least recently used one hands its address a fresh limit,
			// which is better than refusing every new address until one refills.
			r.remove(r.lru.Back().Value.(netip.Addr))
		}
		if r.m == nil {
			r.m, r.lru = map[netip.Addr]*rateBucket{}, list.New()
		}
		b = &rateBucket{lim: rate.NewLimiter(perMinuteRate(r.perMinute), r.perMinute), elem: r.lru.PushFront(key)}
		r.m[key] = b
	}
	if !b.lim.AllowN(now, 1) {
		return protocol.Errorf(protocol.CodeBusy, "rate limit for %s reached (%d per minute on this probe)", key, r.perMinute)
	}
	return nil
}

func (r *rateLimiter) remove(key netip.Addr) {
	if b, ok := r.m[key]; ok {
		r.lru.Remove(b.elem)
		delete(r.m, key)
	}
}

// evictIdle drops buckets that have refilled: they hold no information, so dropping them never resets a limit.
func (r *rateLimiter) evictIdle(now time.Time) {
	if !r.lastSweep.IsZero() && now.Sub(r.lastSweep) < rateSweepInterval && !now.Before(r.lastSweep) {
		return
	}
	r.lastSweep = now
	for k, b := range r.m {
		if b.lim.TokensAt(now) >= float64(b.lim.Burst()) {
			r.remove(k)
		}
	}
}

func (p *Policy) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *Policy) lookup(ctx context.Context, target, family string) (string, []netip.Addr, *protocol.Error) {
	target = strings.TrimSpace(target)
	// A zone ("fe80::1%eth0") is never accepted: zones only matter for link-local addresses, which are always refused,
	// and a zone carries arbitrary text that would otherwise travel with the address into host:port strings, logs and
	// known_hosts entries.
	if strings.Contains(target, "%") {
		return "", nil, protocol.Errorf(protocol.CodeInvalidParams, "an address must not have a zone (%%...)")
	}
	if a, err := netip.ParseAddr(strings.Trim(target, "[]")); err == nil {
		if a.Zone() != "" {
			return "", nil, protocol.Errorf(protocol.CodeInvalidParams, "an address must not have a zone (%%...)")
		}
		a = a.Unmap()
		if !familyMatches(a, family) {
			return "", nil, protocol.Errorf(protocol.CodeInvalidParams, "%s is not an IPv%s address", a, family)
		}
		return "", []netip.Addr{a}, nil
	}
	host := normalizeName(target)
	if host == "" {
		return "", nil, protocol.Errorf(protocol.CodeInvalidParams, "empty target")
	}
	network := "ip"
	if family == "4" || family == "6" {
		network = "ip" + family
	}
	addrs, err := p.Resolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return host, nil, protocol.Errorf(protocol.CodeUnresolved, "could not resolve %s: %v", host, err)
	}
	if len(addrs) == 0 {
		return host, nil, protocol.Errorf(protocol.CodeUnresolved, "%s has no IPv%s address", host, family)
	}
	// A resolver may hand back a zone with a link-local address; no address leaves the policy with one.
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.WithZone(""))
	}
	return host, out, nil
}

// DialContext dials network ("tcp", "tcp4", "tcp6", "udp", "udp4", "udp6") to address ("host:port") through the policy:
// it resolves host, refuses denied addresses, and connects to each allowed address in turn until one connects. Use it as
// http.Transport.DialContext and for every TCP or UDP connection a check makes. d supplies timeouts and a source address.
func (p *Policy) DialContext(ctx context.Context, d *net.Dialer, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeInvalidParams, "bad address %q: %v", address, err)
	}
	family := ""
	if strings.HasSuffix(network, "4") {
		family = "4"
	} else if strings.HasSuffix(network, "6") {
		family = "6"
	}
	addrs, perr := p.Resolve(ctx, host, family)
	if perr != nil {
		return nil, perr
	}
	if d == nil {
		d = &net.Dialer{}
	}
	var lastErr error
	for _, a := range addrs {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// Dialer returns a DialContext bound to d, in the shape http.Transport wants.
func (p *Policy) Dialer(d *net.Dialer) func(ctx context.Context, network, address string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return p.DialContext(ctx, d, network, address)
	}
}

// IsDenied reports whether err is a policy refusal.
func IsDenied(err error) bool {
	var pe *protocol.Error
	return errors.As(err, &pe) && pe.Code == protocol.CodeDenied
}

func (p *Policy) hostAllowed(host string) bool { return hostMatches(p.allowHosts, host) }

// parseHostPatterns normalises name patterns: exact names, or "*.name" for any name below name.
func parseHostPatterns(list []string) ([]string, error) {
	var out []string
	for _, h := range list {
		h = normalizeName(h)
		rest := strings.TrimPrefix(h, "*.")
		if rest == "" || strings.ContainsAny(rest, "*/ ") {
			return nil, fmt.Errorf("%q must be a name or *.name", h)
		}
		out = append(out, h)
	}
	return out, nil
}

func hostMatches(patterns []string, host string) bool {
	host = normalizeName(host)
	for _, h := range patterns {
		if suffix, ok := strings.CutPrefix(h, "*."); ok {
			if strings.HasSuffix(host, "."+suffix) {
				return true
			}
		} else if host == h {
			return true
		}
	}
	return false
}

// selfInfo returns the probe's own addresses and its networks' broadcast addresses, refreshed every selfCacheTTL, or
// the error from listing them.
func (p *Policy) selfInfo() (self, bcast []netip.Addr, err error) {
	if p.SelfAddrs == nil {
		return nil, nil, nil
	}
	p.selfMu.Lock()
	defer p.selfMu.Unlock()
	now := p.clock()
	if p.selfTime.IsZero() || now.Sub(p.selfTime) > selfCacheTTL || now.Before(p.selfTime) {
		prefixes, err := p.SelfAddrs()
		p.selfTime, p.selfErr, p.self, p.bcast = now, err, nil, nil
		if err != nil {
			if !p.selfLogged {
				p.logger().Error("cannot list this host's addresses; refusing every target until it works", "error", err.Error())
				p.selfLogged = true
			}
		} else {
			if p.selfLogged {
				p.logger().Info("listing this host's addresses works again; targets are no longer all refused")
			}
			p.selfLogged = false
			for _, pre := range prefixes {
				p.self = append(p.self, pre.Addr().Unmap().WithZone(""))
				if b, ok := broadcastAddr(pre); ok {
					p.bcast = append(p.bcast, b)
				}
			}
		}
	}
	return p.self, p.bcast, p.selfErr
}

func (p *Policy) logger() *slog.Logger {
	if p.Logger != nil {
		return p.Logger
	}
	return slog.Default()
}

// broadcastAddr is the directed broadcast address of an IPv4 interface prefix. /31 and /32 have none (RFC 3021), and
// IPv6 has no broadcast.
func broadcastAddr(pre netip.Prefix) (netip.Addr, bool) {
	a, bits := pre.Addr(), pre.Bits()
	if a.Is4In6() {
		a, bits = a.Unmap(), bits-96
	}
	if !a.Is4() || bits < 0 || bits >= 31 {
		return netip.Addr{}, false
	}
	b := a.As4()
	v := binary.BigEndian.Uint32(b[:]) | (uint32(1)<<(32-bits) - 1)
	binary.BigEndian.PutUint32(b[:], v)
	return netip.AddrFrom4(b), true
}

// InterfaceAddrs lists this host's own addresses, loopback included, or nothing when they cannot be listed. The probe
// reports the non-loopback ones to the hub.
func InterfaceAddrs() []netip.Addr {
	prefixes, err := interfacePrefixes()
	if err != nil {
		return nil
	}
	out := make([]netip.Addr, 0, len(prefixes))
	for _, pre := range prefixes {
		out = append(out, pre.Addr())
	}
	return out
}

// interfacePrefixes lists this host's interface addresses with their prefix lengths.
func interfacePrefixes() ([]netip.Prefix, error) {
	raw, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, a := range raw {
		var ip net.IP
		ones := -1
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
			if o, bits := v.Mask.Size(); bits != 0 {
				ones = o
				if ip.To4() != nil && bits == 128 {
					ones -= 96
				}
			}
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap().WithZone("")
		if ones < 0 || ones > addr.BitLen() {
			ones = addr.BitLen() // no usable mask: the address alone, with no broadcast derived from it
		}
		out = append(out, netip.PrefixFrom(addr, ones))
	}
	return out, nil
}

func familyMatches(a netip.Addr, family string) bool {
	switch family {
	case "4":
		return a.Is4()
	case "6":
		return a.Is6()
	}
	return true
}

func normalizeName(h string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(h)), ".")
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		s = strings.TrimSpace(s)
		if !strings.Contains(s, "/") {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("%q is not an address or CIDR", s)
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		pre, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("%q is not a CIDR", s)
		}
		out = append(out, pre.Masked())
	}
	return out, nil
}

func mustPrefixes(list ...string) []netip.Prefix {
	out, err := parsePrefixes(list)
	if err != nil {
		panic(err)
	}
	return out
}
