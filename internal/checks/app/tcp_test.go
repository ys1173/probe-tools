package app

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"probetools/internal/policy"
	"probetools/internal/protocol"
)

// tlsServer starts an httptest TLS server on ip. Its certificate is for example.com, 127.0.0.1 and ::1, so it verifies
// only under the name example.com when the test trusts it.
func tlsServer(t *testing.T, ip netip.Addr, h http.Handler) (*httptest.Server, int) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener.Close()
	srv.Listener = ln
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, ln.Addr().(*net.TCPAddr).Port
}

func httpServer(t *testing.T, ip netip.Addr, h http.Handler) (*httptest.Server, int) {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, ln.Addr().(*net.TCPAddr).Port
}

func trust(t *testing.T, srv *httptest.Server) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	old := rootCAs
	rootCAs = pool
	t.Cleanup(func() { rootCAs = old })
}

func TestTCPConnectOpenRefusedBanner(t *testing.T) {
	ip := hostIP(t)
	open := tcpServer(t, ip, func(c net.Conn) { io.WriteString(c, "SSH-2.0-test\r\n\x1b[31mred") })
	closed := freePort(t, ip, "tcp")
	env := testEnv(t, nil)

	m := mustRun(t, tcpConnect, env, protocol.TCPConnectParams{Target: ip.String(), Ports: []int{open, closed}, ReadBanner: true, TimeoutMS: 2000})
	if m["address"] != ip.String() {
		t.Fatalf("address %v", m["address"])
	}
	if got := get(m, "ports", 0, "outcome"); got != "open" {
		t.Fatalf("open port: %v", got)
	}
	if get(m, "ports", 0, "local_addr") == nil {
		t.Fatal("no local_addr")
	}
	banner := untrustedText(t, get(m, "ports", 0, "banner"))
	if !strings.HasPrefix(banner, "SSH-2.0-test\\r\n") || strings.Contains(banner, "\x1b") {
		t.Fatalf("banner not sanitised: %q", banner)
	}
	if got := get(m, "ports", 1, "outcome"); got != "refused" {
		t.Fatalf("closed port: %v", got)
	}
}

func TestTCPConnectBannerCapped(t *testing.T) {
	ip := hostIP(t)
	port := tcpServer(t, ip, func(c net.Conn) { io.WriteString(c, strings.Repeat("A", 5000)) })
	m := mustRun(t, tcpConnect, testEnv(t, nil), protocol.TCPConnectParams{Target: ip.String(), Ports: []int{port}, ReadBanner: true})
	b := get(m, "ports", 0, "banner")
	if text := untrustedText(t, b); len(text) > protocol.MaxBannerBytes {
		t.Fatalf("banner is %d bytes", len(text))
	}
}

func TestTCPConnectTLS(t *testing.T) {
	ip := hostIP(t)
	srv, port := tlsServer(t, ip, http.NotFoundHandler())
	env := testEnv(t, nil)

	// Untrusted CA: the handshake completes and the result says why it does not verify.
	m := mustRun(t, tcpConnect, env, protocol.TCPConnectParams{Target: ip.String(), Ports: []int{port}, TLS: true, ServerName: "example.com"})
	if get(m, "ports", 0, "tls", "verified") != false || get(m, "ports", 0, "tls", "verify_error") == nil {
		t.Fatalf("want unverified with a reason: %v", get(m, "ports", 0, "tls"))
	}
	if v := get(m, "ports", 0, "tls", "version"); v == nil || v == "" {
		t.Fatal("no TLS version")
	}
	untrustedText(t, get(m, "ports", 0, "tls", "cert", "issuer"))

	trust(t, srv)
	m = mustRun(t, tcpConnect, env, protocol.TCPConnectParams{Target: ip.String(), Ports: []int{port}, TLS: true, ServerName: "example.com"})
	if get(m, "ports", 0, "tls", "verified") != true {
		t.Fatalf("want verified: %v", get(m, "ports", 0, "tls"))
	}
}

func TestTCPConnectPolicy(t *testing.T) {
	ip := hostIP(t)
	port := tcpServer(t, ip, func(net.Conn) {})

	_, perr := runCheck(t, tcpConnect, testEnv(t, nil), protocol.TCPConnectParams{Target: "127.0.0.1", Ports: []int{port}})
	wantCode(t, perr, protocol.CodeDenied)
	_, perr = runCheck(t, tcpConnect, testEnv(t, nil), protocol.TCPConnectParams{Target: "missing.test", Ports: []int{port}})
	wantCode(t, perr, protocol.CodeUnresolved)

	// A closed policy that allows the target only by name must still let the check connect to what the name resolved to.
	env := envWith(t, policy.Config{Mode: policy.ModeClosed, AllowHosts: []string{"svc.test"}}, map[string][]netip.Addr{"svc.test": {ip}})
	m := mustRun(t, tcpConnect, env, protocol.TCPConnectParams{Target: "svc.test", Ports: []int{port}})
	if get(m, "ports", 0, "outcome") != "open" {
		t.Fatalf("allowed name: %v", m)
	}
	_, perr = runCheck(t, tcpConnect, env, protocol.TCPConnectParams{Target: ip.String(), Ports: []int{port}})
	wantCode(t, perr, protocol.CodeDenied)
}

func TestTCPConnectManyPorts(t *testing.T) {
	ip := hostIP(t)
	var ports []int
	for i := 0; i < 8; i++ {
		ports = append(ports, tcpServer(t, ip, func(net.Conn) {}))
	}
	m := mustRun(t, tcpConnect, testEnv(t, nil), protocol.TCPConnectParams{Target: ip.String(), Ports: ports})
	for i, p := range ports {
		if get(m, "ports", i, "port") != float64(p) || get(m, "ports", i, "outcome") != "open" {
			t.Fatalf("port %d: %v", i, get(m, "ports", i))
		}
	}
}
