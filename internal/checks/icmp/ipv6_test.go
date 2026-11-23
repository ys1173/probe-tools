package icmp

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"probetools/internal/protocol"
)

// TestIPv6Loopback exercises the IPv6 code paths against ::1. The policy never allows loopback, so this calls the
// functions below the policy directly with the address.
func TestIPv6Loopback(t *testing.T) {
	if c, err := net.ListenPacket("udp6", "[::1]:0"); err != nil {
		t.Skip("no ::1 here")
	} else {
		c.Close()
	}
	dst := netip.IPv6Loopback()
	ctx := context.Background()
	deadline := time.Now().Add(20 * time.Second)

	for _, k := range []sockKind{kindDgram, kindRaw} {
		t.Run(k.String(), func(t *testing.T) {
			s, err := openKinds(true, nil, []sockKind{k})
			if err != nil {
				t.Skipf("cannot open %s ICMPv6 socket: %v", k, err)
			}
			sess := newSession(s, dst)
			defer sess.Close()
			p := protocol.PingParams{Target: "::1", Count: 2, IntervalMS: 200}
			if perr := p.Normalize(); perr != nil {
				t.Fatal(perr)
			}
			r := ping(ctx, sess, p, deadline)
			if r.Received != 2 || r.Replies[0].TTL == 0 {
				t.Fatalf("ping: %+v", r)
			}

			if !pathMTUSupported {
				return
			}
			s2, err := openKinds(true, nil, []sockKind{k})
			if err != nil {
				t.Fatal(err)
			}
			sess2 := newSession(s2, dst)
			defer sess2.Close()
			if err := setDontFragment(s2); err != nil {
				t.Fatal(err)
			}
			m := pathMTU(ctx, sess2, 9000, deadline)
			if m.PathMTU != 9000 || m.Attempts != 2 {
				t.Fatalf("path_mtu: %+v", m)
			}
		})
	}

	for _, mode := range []string{"icmp", "udp", "tcp"} {
		t.Run("traceroute_"+mode, func(t *testing.T) {
			s, err := openKinds(true, nil, []sockKind{kindRaw})
			if err != nil {
				t.Skipf("no raw ICMPv6 socket: %v", err)
			}
			p := protocol.TracerouteParams{Target: "::1", Mode: mode, Port: 1, MaxHops: 3, Queries: 2, WaitMS: 500}
			if perr := p.Normalize(); perr != nil {
				t.Fatal(perr)
			}
			tr := newTracer(s, dst, p)
			defer tr.close()
			r := tr.run(ctx, deadline)
			if !r.Reached || !r.Complete || len(r.Hops) != 1 || r.Hops[0].Probes[0].Addr != "::1" {
				t.Fatalf("result %+v", r)
			}
		})
	}
}
