package icmp

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

// Smallest packet every IPv4 host must accept (RFC 791) and the IPv6 minimum link MTU (RFC 8200).
const (
	minSizeV4 = 576
	minSizeV6 = 1280

	mtuTryTimeout = time.Second
	mtuTries      = 2 // sends per size before silence counts as "too big"
)

// PathMTUResult is path_mtu's answer.
type PathMTUResult struct {
	Target        string   `json:"target"`
	Address       string   `json:"address"`
	Socket        string   `json:"socket"`
	PathMTU       int      `json:"path_mtu"` // largest IP packet that passed unfragmented; 0 when not even the minimum did
	MaxSizeTested int      `json:"max_size_tested"`
	Attempts      int      `json:"attempts"` // echo requests sent
	Notes         []string `json:"notes,omitempty"`
}

func runPathMTU(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.PathMTUParams
	if err := check.Decode(raw, &p); err != nil {
		return nil, err
	}
	if !pathMTUSupported {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "path_mtu needs Linux socket options to set the don't-fragment bit")
	}
	dst, perr := resolveTarget(ctx, env, p.Target, p.Family)
	if perr != nil {
		return nil, perr
	}
	s, perr := openEcho(dst.Is6(), env.Capabilities)
	if perr != nil {
		return nil, perr
	}
	sess := newSession(s, dst)
	defer sess.Close()
	if err := setDontFragment(s); err != nil {
		return nil, protocol.Errorf(protocol.CodeUnavailable, "cannot set the don't-fragment option: %v", err)
	}
	res := pathMTU(ctx, sess, p.MaxSize, checkDeadline(ctx, time.Now()))
	res.Target = p.Target
	return res, nil
}

// ipOverhead is the IP plus ICMP header size: max_size counts the whole IP packet, the socket sends only the payload.
func ipOverhead(v6 bool) int {
	if v6 {
		return 40 + 8
	}
	return 20 + 8
}

type sizeOutcome int

const (
	sizeFits sizeOutcome = iota
	sizeTooBig
	sizeSilent    // no answer after retries: taken as too big
	sizeFailed    // an error unrelated to size, such as destination unreachable; the search cannot go on
	sizeOutOfTime // no time left to test this size
)

// mtuProber tests one packet size at a time on an echo session.
type mtuProber struct {
	ctx      context.Context
	sess     *echoSession
	deadline time.Time
	seq      uint16
	attempts int
	failure  string
}

func pathMTU(ctx context.Context, sess *echoSession, maxSize int, deadline time.Time) PathMTUResult {
	v6 := sess.dst.Is6()
	res := PathMTUResult{Address: sess.dst.String(), Socket: sess.s.kind.String()}
	minSize := minSizeV4
	if v6 {
		minSize = minSizeV6
	}
	if maxSize < minSize {
		res.Notes = append(res.Notes, fmt.Sprintf("max_size raised to the IPv6 minimum of %d", minSize))
		maxSize = minSize
	}
	pr := &mtuProber{ctx: ctx, sess: sess, deadline: deadline}
	more := func() bool { return ctx.Err() == nil && time.Until(deadline) >= mtuTryTimeout }
	sr := searchMTU(minSize, maxSize, pr.test, more)
	res.PathMTU, res.MaxSizeTested, res.Notes = sr.mtu, sr.maxTested, append(res.Notes, sr.notes...)
	if pr.failure != "" {
		res.Notes = append(res.Notes, pr.failure)
	}
	res.Attempts = pr.attempts
	return res
}

// test sends echo requests of size bytes (the whole IP packet) with fragmentation forbidden.
func (pr *mtuProber) test(size int) (sizeOutcome, int) {
	payload := size - ipOverhead(pr.sess.s.v6)
	mine := map[uint16]bool{}
	for try := 0; try < mtuTries; try++ {
		if pr.ctx.Err() != nil || time.Until(pr.deadline) < mtuTryTimeout {
			if try == 0 {
				return sizeOutOfTime, 0
			}
			break
		}
		pr.seq++
		mine[pr.seq] = true
		pr.attempts++
		if err := pr.sess.send(pr.seq, payload); err != nil {
			if isMsgSize(err) {
				return sizeTooBig, 0 // larger than this host's own interface allows
			}
			pr.failure = fmt.Sprintf("sending %d bytes failed: %s", size, errnoText(err))
			return sizeFailed, 0
		}
		t := time.NewTimer(mtuTryTimeout)
		for waiting := true; waiting; {
			select {
			case <-pr.ctx.Done():
				t.Stop()
				return sizeOutOfTime, 0
			case <-t.C:
				waiting = false
			case ev := <-pr.sess.events:
				if !mine[ev.seq] {
					continue // an answer to an earlier size, arriving late
				}
				t.Stop()
				if ev.err == nil {
					return sizeFits, 0
				}
				if isTooBig(ev.err.v6, ev.err.typ, ev.err.code) {
					return sizeTooBig, ev.err.mtu
				}
				pr.failure = ev.err.String()
				return sizeFailed, 0
			}
		}
	}
	return sizeSilent, 0
}

type searchResult struct {
	mtu       int
	maxTested int
	notes     []string
}

// searchMTU finds the largest size in [min, max] for which test reports sizeFits. It tests the minimum first (nothing
// else is worth trying if that fails), then the maximum, then bisects, jumping to the next-hop MTU when a router names
// one. more reports whether there is time for another size.
func searchMTU(min, max int, test func(size int) (sizeOutcome, int), more func() bool) searchResult {
	var r searchResult
	if !more() {
		r.notes = append(r.notes, "no time left to test any size")
		return r
	}
	r.maxTested = min
	switch o, _ := test(min); o {
	case sizeFits:
	case sizeSilent:
		r.notes = append(r.notes, "no reply even at minimum size: ICMP may be filtered")
		return r
	case sizeTooBig:
		r.notes = append(r.notes, fmt.Sprintf("even the minimum size %d was reported too big", min))
		return r
	case sizeOutOfTime:
		r.notes = append(r.notes, "no time left to test any size")
		return r
	default:
		return r
	}
	good, bad := min, max+1
	next := max
	silent := false
	for bad-good > 1 {
		if !more() {
			r.notes = append(r.notes, fmt.Sprintf("stopped early to fit the time budget: the path MTU is at least %d and below %d", good, bad))
			break
		}
		o, hint := test(next)
		if o == sizeOutOfTime {
			r.notes = append(r.notes, fmt.Sprintf("stopped early to fit the time budget: the path MTU is at least %d and below %d", good, bad))
			break
		}
		if next > r.maxTested {
			r.maxTested = next
		}
		candidate := 0
		switch o {
		case sizeFits:
			good = next
		case sizeTooBig, sizeSilent:
			bad = next
			silent = silent || o == sizeSilent
			if hint > good && hint < bad {
				// A router said what fits through it; nothing larger can pass, so try exactly that next.
				bad = hint + 1
				candidate = hint
			}
		case sizeFailed:
			r.mtu = good
			return r
		}
		if candidate != 0 {
			next = candidate
		} else {
			next = (good + bad) / 2
		}
	}
	if silent {
		r.notes = append(r.notes, "some sizes got no reply and were taken as too big; if fragmentation-needed messages "+
			"are filtered on the path, packets above the MTU are silently dropped (a PMTU black hole)")
	}
	r.mtu = good
	return r
}
