package app

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
)

// The policy always refuses loopback, so test servers listen on this host's first non-loopback IPv4 address and the
// test policy does not count it as the probe's own.

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

func hostIP(t *testing.T) netip.Addr {
	t.Helper()
	raw, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range raw {
		pre, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		ip := pre.Addr()
		if ip.Is4() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return ip
		}
	}
	t.Skip("no non-loopback IPv4 address to run test servers on")
	return netip.Addr{}
}

func testEnv(t *testing.T, names map[string][]netip.Addr) *check.Env {
	return envWith(t, policy.Config{Mode: policy.ModeOpen}, names)
}

func envWith(t *testing.T, cfg policy.Config, names map[string][]netip.Addr) *check.Env {
	t.Helper()
	p, err := policy.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p.SelfAddrs = func() ([]netip.Prefix, error) { return nil, nil }
	p.Resolver = fakeResolver(names)
	return &check.Env{Policy: p}
}

// runCheck runs f with params and returns its result as decoded JSON, which is what the hub and agents see.
func runCheck(t *testing.T, f check.Func, env *check.Env, params any) (map[string]any, *protocol.Error) {
	t.Helper()
	raw, err := json.Marshal(params)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, perr := f(ctx, env, raw)
	if perr != nil {
		return nil, perr
	}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("result does not encode: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m, nil
}

func mustRun(t *testing.T, f check.Func, env *check.Env, params any) map[string]any {
	t.Helper()
	m, perr := runCheck(t, f, env, params)
	if perr != nil {
		t.Fatalf("check failed: %v", perr)
	}
	return m
}

func wantCode(t *testing.T, perr *protocol.Error, code string) {
	t.Helper()
	if perr == nil || perr.Code != code {
		t.Fatalf("want error code %q, got %v", code, perr)
	}
}

// untrustedText asserts v is an Untrusted object and returns its text.
func untrustedText(t *testing.T, v any) string {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok || m["untrusted"] != true {
		t.Fatalf("want an untrusted object, got %#v", v)
	}
	s, _ := m["text"].(string)
	return s
}

func isTruncated(v any) bool {
	m, _ := v.(map[string]any)
	return m["truncated"] == true
}

func get(m map[string]any, path ...any) any {
	var cur any = m
	for _, p := range path {
		switch k := p.(type) {
		case string:
			mm, _ := cur.(map[string]any)
			cur = mm[k]
		case int:
			l, _ := cur.([]any)
			if k >= len(l) {
				return nil
			}
			cur = l[k]
		}
	}
	return cur
}

// tcpServer listens on the test address and runs handle for each connection.
func tcpServer(t *testing.T, ip netip.Addr, handle func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				handle(c)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// freePort returns a port on ip with nothing listening, for TCP or UDP.
func freePort(t *testing.T, ip netip.Addr, network string) int {
	t.Helper()
	if strings.HasPrefix(network, "udp") {
		pc, err := net.ListenPacket(network, netip.AddrPortFrom(ip, 0).String())
		if err != nil {
			t.Fatal(err)
		}
		defer pc.Close()
		return pc.LocalAddr().(*net.UDPAddr).Port
	}
	ln, err := net.Listen(network, netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
