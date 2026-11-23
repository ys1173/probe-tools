package app

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"sync"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

const (
	maxConcurrentPorts = 5
	bannerWait         = 2 * time.Second
	bannerMore         = 200 * time.Millisecond // after the first bytes, how long to wait for the rest of the banner
)

type portResult struct {
	Port      int                 `json:"port"`
	Outcome   string              `json:"outcome"` // open | refused | timeout | unreachable | error
	ConnectMS float64             `json:"connect_ms"`
	LocalAddr string              `json:"local_addr,omitempty"`
	Detail    string              `json:"detail,omitempty"`
	TLS       *tlsInfo            `json:"tls,omitempty"`
	Banner    *protocol.Untrusted `json:"banner,omitempty"`
}

type tcpConnectResult struct {
	Target  string       `json:"target"`
	Address string       `json:"address"`
	Ports   []portResult `json:"ports"`
}

func tcpConnect(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.TCPConnectParams
	if e := check.Decode(raw, &p); e != nil {
		return nil, e
	}
	addr, e := resolveTarget(ctx, env, p.Target, p.Family)
	if e != nil {
		return nil, e
	}
	d, e := check.SourceDialer(p.SourceInterface, familyOf(addr))
	if e != nil {
		return nil, e
	}
	d.Timeout = millis(p.TimeoutMS)
	serverName := p.ServerName
	if serverName == "" {
		serverName = p.Target
	}

	res := &tcpConnectResult{Target: p.Target, Address: addr.String(), Ports: make([]portResult, len(p.Ports))}
	sem := make(chan struct{}, maxConcurrentPorts)
	var wg sync.WaitGroup
	for i, port := range p.Ports {
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				res.Ports[i] = portResult{Port: port, Outcome: "error", Detail: "not tried: the job's time ran out first"}
				return
			}
			res.Ports[i] = connectPort(ctx, d, addr, port, &p, serverName)
		}()
	}
	wg.Wait()
	return res, nil
}

func connectPort(ctx context.Context, d *net.Dialer, addr netip.Addr, port int, p *protocol.TCPConnectParams, serverName string) portResult {
	pr := portResult{Port: port}
	start := time.Now()
	conn, err := dialChecked(ctx, d, "tcp", addr, port)
	pr.ConnectMS = msSince(start)
	pr.Outcome = dialOutcome(err)
	if err != nil {
		pr.Detail = err.Error()
		return pr
	}
	defer conn.Close()
	stop := watch(ctx, conn)
	defer stop()
	pr.LocalAddr = conn.LocalAddr().String()

	if p.TLS {
		tc, info := handshake(ctx, conn, serverName, serverName, []string{"h2", "http/1.1"}, millis(p.TimeoutMS))
		pr.TLS = info
		if tc == nil {
			return pr
		}
		conn = tc
	}
	if p.ReadBanner {
		pr.Banner = readBanner(ctx, conn)
	}
	return pr
}

// readBanner reads what a service sends first: it waits up to bannerWait for the first bytes, then briefly for more, and
// stops at MaxBannerBytes. It returns nil when the service sent nothing.
func readBanner(ctx context.Context, conn net.Conn) *protocol.Untrusted {
	buf := make([]byte, protocol.MaxBannerBytes)
	n := 0
	wait := bannerWait
	for n < len(buf) {
		_ = conn.SetReadDeadline(within(ctx, wait))
		m, err := conn.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
		wait = bannerMore
	}
	if n == 0 {
		return nil
	}
	return untrusted(string(buf[:n]), protocol.MaxBannerBytes)
}
