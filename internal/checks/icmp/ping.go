package icmp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"math"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

// PingResult is ping's answer.
type PingResult struct {
	Target      string      `json:"target"`
	Address     string      `json:"address"`
	Socket      string      `json:"socket"` // "datagram" or "raw"
	Sent        int         `json:"sent"`
	Received    int         `json:"received"`
	LossPct     float64     `json:"loss_pct"`
	RTTMinMS    float64     `json:"rtt_min_ms,omitempty"`
	RTTAvgMS    float64     `json:"rtt_avg_ms,omitempty"`
	RTTMaxMS    float64     `json:"rtt_max_ms,omitempty"`
	RTTStddevMS float64     `json:"rtt_stddev_ms,omitempty"`
	Replies     []PingReply `json:"replies"`
	ICMPErrors  []ICMPError `json:"icmp_errors,omitempty"`
	Note        string      `json:"note,omitempty"`
}

// PingReply is one echo reply that arrived within the timeout.
type PingReply struct {
	Seq   int     `json:"seq"`
	RTTMS float64 `json:"rtt_ms"`
	TTL   int     `json:"ttl,omitempty"`
}

// ICMPError is an ICMP error received instead of a reply.
type ICMPError struct {
	Seq     int    `json:"seq"`
	From    string `json:"from,omitempty"`
	Message string `json:"message"` // e.g. "destination unreachable / host unreachable from 10.0.0.1"
}

func runPing(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.PingParams
	if err := check.Decode(raw, &p); err != nil {
		return nil, err
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
	res := ping(ctx, sess, p, checkDeadline(ctx, time.Now()))
	res.Target = p.Target
	return res, nil
}

// ping sends p.Count echo requests p.IntervalMS apart and waits up to p.TimeoutMS for each reply. It stops sending
// when the next request could not get its full timeout before deadline, and returns what it has.
func ping(ctx context.Context, sess *echoSession, p protocol.PingParams, deadline time.Time) PingResult {
	res := PingResult{Address: sess.dst.String(), Socket: sess.s.kind.String(), Replies: []PingReply{}}
	interval := time.Duration(p.IntervalMS) * time.Millisecond
	timeout := time.Duration(p.TimeoutMS) * time.Millisecond

	var b [2]byte
	rand.Read(b[:])
	base := binary.BigEndian.Uint16(b[:])
	sentAt := map[uint16]time.Time{}
	seqIndex := map[uint16]int{}
	replied := map[uint16]bool{}
	var rtts []float64

	start := time.Now()
	sendTimer := time.NewTimer(0)
	defer sendTimer.Stop()
	var endTimer <-chan time.Time
	next := 0
	stoppedEarly := false
	sending := true
	var lastSend time.Time

	finish := func() {
		res.Received = len(rtts)
		if res.Sent > 0 {
			res.LossPct = roundMS(100 * float64(res.Sent-res.Received) / float64(res.Sent))
		}
		res.RTTMinMS, res.RTTAvgMS, res.RTTMaxMS, res.RTTStddevMS = stats(rtts)
		if stoppedEarly {
			res.Note = "stopped early to fit the time budget"
		}
	}

	for {
		select {
		case <-ctx.Done():
			stoppedEarly = next < p.Count
			finish()
			return res
		case <-endTimer:
			finish()
			return res
		case <-sendTimer.C:
			now := time.Now()
			if now.Add(timeout).After(deadline) {
				// Stop sending but still wait for the requests already out; their timeouts fit the budget.
				stoppedEarly = true
				sending = false
				if res.Sent == 0 || len(replied) == res.Sent {
					finish()
					return res
				}
				endTimer = time.After(time.Until(lastSend.Add(timeout)))
				continue
			}
			lastSend = now
			seq := base + uint16(next)
			sentAt[seq] = now
			seqIndex[seq] = next
			res.Sent++
			if err := sess.send(seq, p.Size); err != nil {
				// A local failure (no route, message too long) is this request's error, not the check's.
				res.ICMPErrors = append(res.ICMPErrors, ICMPError{Seq: next, Message: "send failed: " + errnoText(err)})
			}
			next++
			if next == p.Count {
				sending = false
			}
			if sending {
				sendTimer.Reset(time.Until(start.Add(time.Duration(next) * interval)))
			} else {
				endTimer = time.After(timeout)
			}
		case ev := <-sess.events:
			t0, ok := sentAt[ev.seq]
			if !ok || replied[ev.seq] {
				continue
			}
			if ev.err != nil {
				res.ICMPErrors = append(res.ICMPErrors, ICMPError{Seq: seqIndex[ev.seq], From: addrString(ev.err.from), Message: ev.err.String()})
				replied[ev.seq] = true
				if !sending && len(replied) == res.Sent {
					finish()
					return res
				}
				continue
			}
			rtt := ev.at.Sub(t0)
			if rtt > timeout {
				continue // too late to count
			}
			replied[ev.seq] = true
			rtts = append(rtts, ms(rtt))
			res.Replies = append(res.Replies, PingReply{Seq: seqIndex[ev.seq], RTTMS: ms(rtt), TTL: ev.ttl})
			if !sending && len(replied) == res.Sent {
				finish()
				return res
			}
		}
	}
}

// stats returns min, average, max and population standard deviation, rounded to microseconds.
func stats(v []float64) (lo, avg, hi, sd float64) {
	if len(v) == 0 {
		return 0, 0, 0, 0
	}
	lo, hi = v[0], v[0]
	var sum float64
	for _, x := range v {
		lo, hi = math.Min(lo, x), math.Max(hi, x)
		sum += x
	}
	avg = sum / float64(len(v))
	var ss float64
	for _, x := range v {
		ss += (x - avg) * (x - avg)
	}
	sd = math.Sqrt(ss / float64(len(v)))
	return roundMS(lo), roundMS(avg), roundMS(hi), roundMS(sd)
}
