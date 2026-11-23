package hub

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// maxLimiters bounds each per-client table, so a flood from many addresses costs bounded memory.
const maxLimiters = 10000

// sweepInterval is how often a full table may be scanned for idle entries. Without it, a flood that keeps the table
// full would cost a scan of every entry, under the lock, on each request.
const sweepInterval = time.Second

// clientKey is what per-client limits are keyed on: the connection's IPv4 address, or its IPv6 /64. One host or site
// usually holds a whole /64, so a per-address IPv6 limit would cost an attacker nothing to sidestep. It uses the
// connection's address, not a forwarded header a client could set; behind a proxy all clients share the proxy's key.
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	// Unmap first, or every IPv4 client of a dual-stack listener would share one ::ffff:0:0/64 key.
	a = a.Unmap().WithZone("")
	if a.Is4() {
		return a.String()
	}
	return netip.PrefixFrom(a, 64).Masked().String()
}

// ipLimiter holds a token-bucket rate limiter per client key, in a bounded table.
type ipLimiter struct {
	mu        sync.Mutex
	r         rate.Limit
	burst     int
	max       int
	m         map[string]*rate.Limiter
	nextSweep time.Time
}

func newIPLimiter(r rate.Limit, burst, max int) *ipLimiter {
	return &ipLimiter{r: r, burst: burst, max: max, m: map[string]*rate.Limiter{}}
}

// room reports whether a new key fits, first evicting limiters that have refilled completely: a fresh limiter is
// identical to one of those, so evicting them loses nothing. The caller holds mu.
func (l *ipLimiter) room(now time.Time) bool {
	if len(l.m) < l.max {
		return true
	}
	if now.Before(l.nextSweep) {
		return false
	}
	l.nextSweep = now.Add(sweepInterval)
	for k, v := range l.m {
		if v.TokensAt(now) >= float64(l.burst) {
			delete(l.m, k)
		}
	}
	return len(l.m) < l.max
}

// allow takes one token for key. A new key that does not fit in a full table is refused: failing closed limits a
// flood from many addresses, where starting the table again would reset everyone, attackers included.
func (l *ipLimiter) allow(key string) bool { return l.allowAt(key, time.Now()) }

func (l *ipLimiter) allowAt(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim, ok := l.m[key]
	if !ok {
		if !l.room(now) {
			return false
		}
		lim = rate.NewLimiter(l.r, l.burst)
		l.m[key] = lim
	}
	return lim.AllowN(now, 1)
}

// slots caps how many handlers run at once, in total and per client key, so slow clients cannot hold every handler.
type slots struct {
	mu        sync.Mutex
	maxTotal  int
	maxPerKey int
	total     int
	perKey    map[string]int // only keys with a handler running, so at most maxTotal entries
}

func newSlots(maxTotal, maxPerKey int) *slots {
	return &slots{maxTotal: maxTotal, maxPerKey: maxPerKey, perKey: map[string]int{}}
}

// acquire takes a slot for key. It returns a release function, or the HTTP status to refuse with: 429 when this
// client already has its share, 503 when the hub as a whole is full.
func (s *slots) acquire(key string) (release func(), status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perKey[key] >= s.maxPerKey {
		return nil, http.StatusTooManyRequests
	}
	if s.total >= s.maxTotal {
		return nil, http.StatusServiceUnavailable
	}
	s.total++
	s.perKey[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.total--
			if s.perKey[key]--; s.perKey[key] <= 0 {
				delete(s.perKey, key)
			}
		})
	}, 0
}

func (s *slots) inUse() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.total
}

// logThrottle lets through at most one log line per key per interval and counts the rest, so a flood of refused
// requests cannot flood the log. When its table is full, new keys share one overflow entry.
type logThrottle struct {
	mu        sync.Mutex
	every     time.Duration
	max       int
	m         map[string]*throttleEntry
	nextSweep time.Time
}

type throttleEntry struct {
	last       time.Time
	suppressed int
}

// overflowKey is the shared entry for keys that do not fit; it cannot clash with a clientKey.
const overflowKey = "(other)"

func newLogThrottle(every time.Duration, max int) *logThrottle {
	return &logThrottle{every: every, max: max, m: map[string]*throttleEntry{}}
}

// admit reports whether a line for key may be logged now, and how many lines for it were suppressed since the last.
func (t *logThrottle) admit(key string, now time.Time) (ok bool, suppressed int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	e, found := t.m[key]
	if !found && len(t.m) >= t.max {
		if !now.Before(t.nextSweep) {
			t.nextSweep = now.Add(sweepInterval)
			// An entry quiet for a whole interval would let its next line through anyway; only its count is lost.
			for k, v := range t.m {
				if now.Sub(v.last) >= t.every {
					delete(t.m, k)
				}
			}
		}
		if len(t.m) >= t.max {
			key = overflowKey
			e, found = t.m[key]
		}
	}
	if !found {
		t.m[key] = &throttleEntry{last: now}
		return true, 0
	}
	if now.Sub(e.last) >= t.every {
		n := e.suppressed
		e.last, e.suppressed = now, 0
		return true, n
	}
	e.suppressed++
	return false, 0
}

// idPrefix is the most of an unauthenticated, attacker-supplied probe id that goes in a log line: enough to match it
// with a real probe's id, too short to carry anything, and limited to the characters real ids use.
func idPrefix(id string) string {
	const n = 8
	var b strings.Builder
	for i := 0; i < len(id) && i < n; i++ {
		c := id[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			b.WriteByte(c)
		} else {
			b.WriteByte('?')
		}
	}
	return b.String()
}
