package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"probetools/internal/protocol"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	addrs, ok := f[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	var out []netip.Addr
	for _, a := range addrs {
		if (network == "ip4" && !a.Is4()) || (network == "ip6" && !a.Is6()) {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func newPolicy(t *testing.T, cfg Config) *Policy {
	t.Helper()
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.SelfAddrs = func() ([]netip.Prefix, error) { return []netip.Prefix{netip.MustParsePrefix("10.9.9.9/24")}, nil }
	p.Resolver = fakeResolver{
		"good.corp.example":  {netip.MustParseAddr("10.1.2.3")},
		"rebind.example":     {netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("203.0.113.5")},
		"meta.example":       {netip.MustParseAddr("169.254.169.254")},
		"public.example":     {netip.MustParseAddr("203.0.113.7")},
		"mixed.corp.example": {netip.MustParseAddr("192.0.2.1")},
	}
	return p
}

func code(e *protocol.Error) string {
	if e == nil {
		return ""
	}
	return e.Code
}

func TestModeRequired(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("a missing mode must be refused")
	}
	if _, err := New(Config{Mode: ModeClosed}); err == nil {
		t.Fatal("closed mode with nothing allowed must be refused")
	}
	if _, err := New(Config{Mode: ModeOpen, DenyCIDRs: []string{"nonsense"}}); err == nil {
		t.Fatal("a malformed CIDR must be refused")
	}
}

func TestOpenMode(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen, DenyCIDRs: []string{"192.0.2.0/24"}})
	cases := map[string]string{
		"203.0.113.9":                          "",
		"127.0.0.1":                            protocol.CodeDenied,
		"::1":                                  protocol.CodeDenied,
		"::ffff:127.0.0.1":                     protocol.CodeDenied,
		"169.254.169.254":                      protocol.CodeDenied,
		"fd00:ec2::254":                        protocol.CodeDenied,
		"224.0.0.1":                            protocol.CodeDenied,
		"255.255.255.255":                      protocol.CodeDenied,
		"10.9.9.9":                             protocol.CodeDenied, // the probe itself
		"10.9.9.255":                           protocol.CodeDenied, // its network's broadcast address
		"10.9.9.254":                           "",
		"2001:0:4136:e378:8000:63bf:3fff:fdd2": protocol.CodeDenied, // Teredo
		"192.0.2.44":                           protocol.CodeDenied, // deny_cidrs
		"meta.example":                         protocol.CodeDenied,
		"public.example":                       "",
		"no-such-name.example":                 protocol.CodeUnresolved,
	}
	for target, want := range cases {
		_, err := p.Resolve(context.Background(), target, "")
		if code(err) != want {
			t.Errorf("%s: got %q, want %q (%v)", target, code(err), want, err)
		}
	}
	// A name with one refused and one allowed address yields only the allowed one.
	addrs, err := p.Resolve(context.Background(), "rebind.example", "")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "203.0.113.5" {
		t.Fatalf("rebind.example: %v %v", addrs, err)
	}
}

func TestClosedMode(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeClosed, AllowCIDRs: []string{"10.0.0.0/8"}, AllowHosts: []string{"*.corp.example"}, DenyCIDRs: []string{"10.66.0.0/16"}})
	cases := map[string]string{
		"10.1.2.3":           "",
		"10.66.1.1":          protocol.CodeDenied, // deny wins over allow
		"203.0.113.9":        protocol.CodeDenied,
		"good.corp.example":  "",
		"mixed.corp.example": "", // allowed by name although its address is not in allow_cidrs
		"public.example":     protocol.CodeDenied,
		"127.0.0.1":          protocol.CodeDenied,
	}
	for target, want := range cases {
		_, err := p.Resolve(context.Background(), target, "")
		if code(err) != want {
			t.Errorf("%s: got %q, want %q (%v)", target, code(err), want, err)
		}
	}
	// A name pattern never allows an always-refused address.
	p.Resolver = fakeResolver{"evil.corp.example": {netip.MustParseAddr("169.254.169.254")}}
	if _, err := p.Resolve(context.Background(), "evil.corp.example", ""); code(err) != protocol.CodeDenied {
		t.Fatalf("metadata via allowed name: %v", err)
	}
}

func TestFamily(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	if _, err := p.Resolve(context.Background(), "203.0.113.9", "6"); code(err) != protocol.CodeInvalidParams {
		t.Fatalf("v4 literal with family 6: %v", err)
	}
}

func TestDialRefusesDeniedAddress(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, err = p.DialContext(context.Background(), nil, "tcp", ln.Addr().String())
	if !IsDenied(err) {
		t.Fatalf("dial to loopback must be denied, got %v", err)
	}
}

// checkCases resolves each target and compares the error code.
func checkCases(t *testing.T, p *Policy, cases map[string]string) {
	t.Helper()
	for target, want := range cases {
		_, err := p.Resolve(context.Background(), target, "")
		if code(err) != want {
			t.Errorf("%s: got %q, want %q (%v)", target, code(err), want, err)
		}
	}
}

func TestEmbeddedIPv4(t *testing.T) {
	// Each form carries one of: 169.254.169.254 (metadata), 127.0.0.1, 10.9.9.9 (the probe), 10.9.9.255 (its
	// broadcast), 192.0.2.44 (deny_cidrs) or 203.0.113.9 (allowed).
	p := newPolicy(t, Config{Mode: ModeOpen, DenyCIDRs: []string{"192.0.2.0/24"}})
	checkCases(t, p, map[string]string{
		// NAT64 well-known prefix, RFC 6052
		"64:ff9b::a9fe:a9fe":       protocol.CodeDenied,
		"64:ff9b::169.254.169.254": protocol.CodeDenied,
		"64:ff9b::7f00:1":          protocol.CodeDenied,
		"64:ff9b::a09:909":         protocol.CodeDenied,
		"64:ff9b::a09:9ff":         protocol.CodeDenied,
		"64:ff9b::c000:22c":        protocol.CodeDenied,
		"64:ff9b::cb00:7109":       "",
		// 6to4, RFC 3056: the IPv4 address is bits 16 to 47
		"2002:a9fe:a9fe::1":   protocol.CodeDenied,
		"2002:a09:909:1::5":   protocol.CodeDenied,
		"2002:c000:22c::":     protocol.CodeDenied,
		"2002:cb00:7109:1::1": "",
		// IPv4-compatible
		"::169.254.169.254": protocol.CodeDenied,
		"::a09:909":         protocol.CodeDenied,
		"::cb00:7109":       "",
		// IPv4-translated, RFC 2765
		"::ffff:0:a9fe:a9fe": protocol.CodeDenied,
		"::ffff:0:a09:909":   protocol.CodeDenied,
		"::ffff:0:cb00:7109": "",
		// IPv4-mapped is unmapped before anything else
		"::ffff:169.254.169.254": protocol.CodeDenied,
		"::ffff:10.9.9.9":        protocol.CodeDenied,
		// RFC 8215 local-use prefix: refused unless listed
		"64:ff9b:1::cb00:7109": protocol.CodeDenied,
		// Teredo
		"2001:0:4136:e378:8000:63bf:3fff:fdd2": protocol.CodeDenied,
	})
	_, err := p.Resolve(context.Background(), "64:ff9b::a9fe:a9fe", "")
	if err == nil || !strings.Contains(err.Message, "169.254.169.254") {
		t.Fatalf("the denial should name the embedded address: %v", err)
	}

	// Listing the local-use prefix in allow_cidrs admits it, even in open mode, but never an embedded refusal.
	p = newPolicy(t, Config{Mode: ModeOpen, AllowCIDRs: []string{"64:ff9b:1::/48"}})
	checkCases(t, p, map[string]string{
		"64:ff9b:1::cb00:7109": "",
		"64:ff9b::a9fe:a9fe":   protocol.CodeDenied,
	})
}

func TestEmbeddedIPv4ClosedMode(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeClosed, AllowCIDRs: []string{"10.0.0.0/8", "64:ff9b::cb00:7100/120"},
		AllowHosts: []string{"*.corp.example"}, DenyCIDRs: []string{"10.66.0.0/16"}})
	p.Resolver = fakeResolver{
		"v4.corp.example":     {netip.MustParseAddr("64:ff9b::a01:203")},
		"other.corp.example":  {netip.MustParseAddr("64:ff9b::c633:6401")},
		"sixto4.corp.example": {netip.MustParseAddr("2002:c633:6401::1")},
		"plain.corp.example":  {netip.MustParseAddr("198.51.100.1")},
	}
	checkCases(t, p, map[string]string{
		"64:ff9b::a01:203":   "",                  // embedded 10.1.2.3 is in allow_cidrs
		"2002:a01:203::1":    "",                  // the same through 6to4
		"64:ff9b::cb00:7109": "",                  // the IPv6 address itself is in allow_cidrs
		"64:ff9b::c633:6401": protocol.CodeDenied, // neither is listed
		"64:ff9b::a42:101":   protocol.CodeDenied, // embedded 10.66.1.1 is in deny_cidrs
		"64:ff9b::a09:909":   protocol.CodeDenied, // embedded probe address, although 10/8 is allowed
		"v4.corp.example":    "",
		// allow_hosts admits a plain address, but not one carrying an IPv4 address that allow_cidrs does not list.
		"plain.corp.example":  "",
		"other.corp.example":  protocol.CodeDenied,
		"sixto4.corp.example": protocol.CodeDenied,
	})
}

func TestBroadcastAddresses(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	p.SelfAddrs = func() ([]netip.Prefix, error) {
		return []netip.Prefix{
			netip.MustParsePrefix("10.9.9.9/24"),
			netip.MustParsePrefix("172.20.0.3/16"),
			netip.MustParsePrefix("192.168.50.0/31"), // point-to-point: both addresses are hosts
			netip.MustParsePrefix("100.64.1.1/32"),
			netip.MustParsePrefix("2001:db8::5/64"),
			netip.MustParsePrefix("::ffff:198.18.0.1/120"), // an IPv4 /24 written in its mapped form
		}, nil
	}
	checkCases(t, p, map[string]string{
		"10.9.9.255":                    protocol.CodeDenied,
		"10.9.9.0":                      "",
		"172.20.255.255":                protocol.CodeDenied,
		"172.20.0.255":                  "",
		"192.168.50.0":                  protocol.CodeDenied, // the probe's own
		"192.168.50.1":                  "",                  // its /31 peer
		"100.64.1.1":                    protocol.CodeDenied, // own /32
		"100.64.1.2":                    "",
		"198.18.0.255":                  protocol.CodeDenied,
		"198.18.0.1":                    protocol.CodeDenied,
		"255.255.255.255":               protocol.CodeDenied,
		"2001:db8::5":                   protocol.CodeDenied,
		"2001:db8::ffff:ffff:ffff:ffff": "",
		"64:ff9b::ac14:ffff":            protocol.CodeDenied, // the broadcast address, embedded
	})
	_, err := p.Resolve(context.Background(), "10.9.9.255", "")
	if err == nil || !strings.Contains(err.Message, "broadcast") {
		t.Fatalf("message: %v", err)
	}
}

func TestBroadcastAddr(t *testing.T) {
	for in, want := range map[string]string{
		"10.1.2.3/8":         "10.255.255.255",
		"10.1.2.3/30":        "10.1.2.3",
		"10.1.2.3/0":         "255.255.255.255",
		"10.1.2.3/31":        "",
		"10.1.2.3/32":        "",
		"2001:db8::1/64":     "",
		"::ffff:1.2.3.4/112": "1.2.255.255",
	} {
		b, ok := broadcastAddr(netip.MustParsePrefix(in))
		got := ""
		if ok {
			got = b.String()
		}
		if got != want {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func TestSelfListFailureRefusesEverything(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.now = clk.now
	var logs bytes.Buffer
	p.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	calls := 0
	failing := true
	p.SelfAddrs = func() ([]netip.Prefix, error) {
		calls++
		if failing {
			return nil, errors.New("netlink exploded")
		}
		return []netip.Prefix{netip.MustParsePrefix("10.9.9.9/24")}, nil
	}
	for i := 0; i < 3; i++ {
		_, err := p.Resolve(context.Background(), "203.0.113.9", "")
		if code(err) != protocol.CodeDenied || !strings.Contains(err.Message, "cannot list its own addresses") {
			t.Fatalf("listing failure must refuse: %v", err)
		}
		clk.add(6 * time.Second) // past the cache, so the listing is retried
	}
	if calls != 3 {
		t.Fatalf("listing retried %d times, want 3", calls)
	}
	if n := strings.Count(logs.String(), "cannot list"); n != 1 {
		t.Fatalf("logged %d times, want once:\n%s", n, logs.String())
	}
	failing = false
	if _, err := p.Resolve(context.Background(), "203.0.113.9", ""); err != nil {
		t.Fatalf("after recovery: %v", err)
	}
}

func TestSelfCache(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.now = clk.now
	calls := 0
	self := "10.9.9.9/24"
	p.SelfAddrs = func() ([]netip.Prefix, error) {
		calls++
		return []netip.Prefix{netip.MustParsePrefix(self)}, nil
	}
	p.Resolve(context.Background(), "203.0.113.9", "")
	self = "203.0.113.9/24"
	clk.add(4 * time.Second)
	if _, err := p.Resolve(context.Background(), "203.0.113.9", ""); err != nil || calls != 1 {
		t.Fatalf("within the cache: calls=%d err=%v", calls, err)
	}
	clk.add(2 * time.Second)
	if _, err := p.Resolve(context.Background(), "203.0.113.9", ""); code(err) != protocol.CodeDenied || calls != 2 {
		t.Fatalf("a new address must be refused within 5 s: calls=%d err=%v", calls, err)
	}
}

func TestRateLimit(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.now = clk.now
	p.SetRateLimit(2)
	p.Resolver = fakeResolver{
		"a.example":     {netip.MustParseAddr("203.0.113.9")},
		"alias.example": {netip.MustParseAddr("203.0.113.9")},
		"two.example":   {netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("203.0.113.10")},
	}
	bg := context.Background()
	resolve := func(ctx context.Context, target string) ([]netip.Addr, *protocol.Error) {
		return p.Resolve(ctx, target, "")
	}
	// Without a job every call is charged, whatever the spelling: literal, mapped, NAT64, 6to4 and names all
	// share 203.0.113.9's bucket.
	if _, err := resolve(bg, "203.0.113.9"); err != nil {
		t.Fatal(err)
	}
	if _, err := resolve(bg, "alias.example"); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range []string{"203.0.113.9", "::ffff:203.0.113.9", "[::ffff:cb00:7109]", "64:ff9b::cb00:7109",
		"2002:cb00:7109::1", "a.example", "A.Example."} {
		_, err := resolve(bg, spelling)
		if code(err) != protocol.CodeBusy || !strings.Contains(err.Message, "rate limit for 203.0.113.9 ") {
			t.Errorf("%s: got %v, want busy naming the IPv4 bucket", spelling, err)
		}
	}
	// A name with one exhausted and one fresh address yields the fresh one.
	addrs, err := resolve(bg, "two.example")
	if err != nil || len(addrs) != 1 || addrs[0].String() != "203.0.113.10" {
		t.Fatalf("two.example: %v %v", addrs, err)
	}
	// Refill: 2 per minute is one token every 30 s.
	clk.add(31 * time.Second)
	if _, err := resolve(bg, "203.0.113.9"); err != nil {
		t.Fatalf("after refill: %v", err)
	}
	if _, err := resolve(bg, "203.0.113.9"); code(err) != protocol.CodeBusy {
		t.Fatalf("only one token refilled: %v", err)
	}

	// Within one job each address is charged once, however often it is resolved or charged.
	job := WithJob(bg)
	for i := 0; i < 5; i++ {
		if _, err := resolve(job, "198.51.100.7"); err != nil {
			t.Fatalf("same job, resolve %d: %v", i, err)
		}
		if err := p.Charge(job, netip.MustParseAddr("::ffff:198.51.100.7")); err != nil {
			t.Fatalf("same job, charge %d: %v", i, err)
		}
	}
	if _, err := resolve(WithJob(bg), "198.51.100.7"); err != nil {
		t.Fatalf("second job: %v", err)
	}
	if _, err := resolve(WithJob(bg), "198.51.100.7"); code(err) != protocol.CodeBusy {
		t.Fatalf("third job: %v", err)
	}
	if err := p.Charge(bg, netip.MustParseAddr("198.51.100.7")); err == nil || err.Code != protocol.CodeBusy {
		t.Fatalf("charge over the limit: %v", err)
	}
	// A refused address is never charged.
	p.SetRateLimit(1)
	for i := 0; i < 3; i++ {
		if _, err := resolve(bg, "127.0.0.1"); code(err) != protocol.CodeDenied {
			t.Fatalf("denied stays denied: %v", err)
		}
	}
	// Off means off.
	p.SetRateLimit(0)
	for i := 0; i < 10; i++ {
		if _, err := resolve(bg, "203.0.113.9"); err != nil {
			t.Fatalf("limit off: %v", err)
		}
	}
}

func TestResolveCapsAddresses(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.now = clk.now
	p.SetRateLimit(10)
	// A refused address first: it does not count towards the cap.
	many := []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	for i := 0; i < maxRateKeys; i++ {
		many = append(many, netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}))
	}
	p.Resolver = fakeResolver{"huge.example": many}
	addrs, err := p.Resolve(WithJob(context.Background()), "huge.example", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != maxResolveAddrs || maxResolveAddrs != 8 {
		t.Fatalf("returned %d addresses, want 8", len(addrs))
	}
	for i, a := range addrs {
		if a != many[i+1] {
			t.Fatalf("address %d is %s, want %s (resolver order)", i, a, many[i+1])
		}
	}
	if n := len(p.rl.m); n > maxResolveAddrs {
		t.Fatalf("one Resolve charged %d addresses, want at most %d", n, maxResolveAddrs)
	}
	// The next job, to an unrelated target, is not refused.
	if _, err := p.Resolve(WithJob(context.Background()), "203.0.113.77", ""); err != nil {
		t.Fatalf("unrelated target after a huge name: %v", err)
	}
}

func TestRateLimitTableFullEvictsLRU(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.now = clk.now
	p.SetRateLimit(2)
	bg := context.Background()
	nth := func(i int) netip.Addr { return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}) }
	// Fill the table with buckets that are all in use (one token spent), so the idle sweep frees nothing.
	for i := 0; i < maxRateKeys; i++ {
		if err := p.Charge(bg, nth(i)); err != nil {
			t.Fatalf("filling %s: %v", nth(i), err)
		}
	}
	// Touch the oldest, so the second oldest becomes the least recently used.
	oldest, second := nth(0), nth(1)
	if err := p.Charge(bg, oldest); err != nil {
		t.Fatal(err)
	}
	fresh := netip.MustParseAddr("203.0.113.200")
	if err := p.Charge(bg, fresh); err != nil {
		t.Fatalf("full table must still take a new address: %v", err)
	}
	if n := len(p.rl.m); n != maxRateKeys {
		t.Fatalf("table has %d buckets, want %d", n, maxRateKeys)
	}
	if _, ok := p.rl.m[second]; ok {
		t.Fatal("least recently used bucket kept")
	}
	if _, ok := p.rl.m[oldest]; !ok {
		t.Fatal("recently used bucket evicted")
	}
	// The touched bucket is still limited; the evicted one starts afresh.
	if err := p.Charge(bg, oldest); code(err) != protocol.CodeBusy {
		t.Fatalf("recently used bucket lost its limit: %v", err)
	}
	if err := p.Charge(bg, second); err != nil {
		t.Fatalf("evicted address: %v", err)
	}
	if n := len(p.rl.m); n != maxRateKeys || p.rl.lru.Len() != n {
		t.Fatalf("table %d, lru %d, want %d", n, p.rl.lru.Len(), maxRateKeys)
	}
}

func TestRateLimitIdleSweep(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	p.now = clk.now
	p.SetRateLimit(2)
	bg := context.Background()
	busy := netip.MustParseAddr("198.51.100.1")
	p.Charge(bg, busy)
	p.Charge(bg, busy) // empty: it must survive the idle sweep
	for i := 1; i < maxRateKeys; i++ {
		a := netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
		if err := p.Charge(bg, a); err != nil {
			t.Fatalf("filling %s: %v", a, err)
		}
	}
	// After 31 s every one-token bucket has refilled and is swept; the emptied bucket has not and is kept, although it
	// is the least recently used.
	clk.add(31 * time.Second)
	fresh := netip.MustParseAddr("203.0.113.200")
	if err := p.Charge(bg, fresh); err != nil {
		t.Fatalf("after idle eviction: %v", err)
	}
	if n := len(p.rl.m); n != 2 || p.rl.lru.Len() != 2 {
		t.Fatalf("table has %d buckets (lru %d) after the sweep, want 2", n, p.rl.lru.Len())
	}
	if err := p.Charge(bg, busy); err != nil {
		t.Fatalf("one token refilled: %v", err)
	}
	if err := p.Charge(bg, busy); code(err) != protocol.CodeBusy {
		t.Fatalf("the sweep must not reset a bucket in use: %v", err)
	}
}

func TestRateLimitConcurrentJob(t *testing.T) {
	p := newPolicy(t, Config{Mode: ModeOpen})
	p.SetRateLimit(1)
	job := WithJob(context.Background())
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := p.Resolve(job, "203.0.113.50", ""); err != nil {
				errs <- fmt.Errorf("%v", err)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("one job charged twice: %v", err)
	}
}
