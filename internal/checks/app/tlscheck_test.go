package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"probetools/internal/protocol"
)

func TestTLSCheck(t *testing.T) {
	ip := hostIP(t)
	srv, port := tlsServer(t, ip, http.NotFoundHandler())
	env := testEnv(t, nil)

	m := mustRun(t, tlsCheck, env, protocol.TLSCheckParams{Target: ip.String(), Port: port, ServerName: "example.com"})
	if m["outcome"] != "ok" || m["verified"] != false || m["verify_error"] == nil || m["hostname_match"] != true {
		t.Fatalf("untrusted CA: %v", m)
	}
	trust(t, srv)
	m = mustRun(t, tlsCheck, env, protocol.TLSCheckParams{Target: ip.String(), Port: port, ServerName: "example.com"})
	if m["verified"] != true || m["version"] == "" || m["cipher"] == "" || m["alpn"] != "http/1.1" {
		t.Fatalf("trusted: %v", m)
	}
	leaf := get(m, "chain", 0).(map[string]any)
	sans := leaf["sans"].([]any)
	if untrustedText(t, sans[0]) != "example.com" || leaf["signature_algorithm"] == "" || leaf["serial"] == "" {
		t.Fatalf("leaf: %v", leaf)
	}
	untrustedText(t, leaf["subject"])
	untrustedText(t, leaf["issuer"])

	// For an IP target the IP SANs are what count, and this certificate does not list the test address.
	m = mustRun(t, tlsCheck, env, protocol.TLSCheckParams{Target: ip.String(), Port: port})
	if m["verified"] != false || m["hostname_match"] != false || m["server_name"] != ip.String() {
		t.Fatalf("IP target: %v", m)
	}
}

func TestTLSCheckFailuresAreResults(t *testing.T) {
	ip := hostIP(t)
	env := testEnv(t, nil)
	m := mustRun(t, tlsCheck, env, protocol.TLSCheckParams{Target: ip.String(), Port: freePort(t, ip, "tcp")})
	if m["outcome"] != "refused" {
		t.Fatalf("refused: %v", m)
	}
	plain := tcpServer(t, ip, func(c net.Conn) { io.WriteString(c, "SSH-2.0-not-tls\r\n") })
	m = mustRun(t, tlsCheck, env, protocol.TLSCheckParams{Target: ip.String(), Port: plain})
	if m["outcome"] != "handshake_failed" || m["detail"] == nil {
		t.Fatalf("not TLS: %v", m)
	}
	_, perr := runCheck(t, tlsCheck, env, protocol.TLSCheckParams{Target: "127.0.0.1"})
	wantCode(t, perr, protocol.CodeDenied)
}

// A certificate full of hostile text: a long subject with control characters and more SANs than are reported.
func TestTLSCheckCapsCertificateText(t *testing.T) {
	ip := hostIP(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "evil\x1b[2J" + strings.Repeat("s", 900)},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(-time.Minute), // expired
	}
	for i := 0; i < 70; i++ {
		tmpl.DNSNames = append(tmpl.DNSNames, fmt.Sprintf("n%d.test", i))
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", netip.AddrPortFrom(ip, 0).String(), &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
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
			go func() { c.(*tls.Conn).Handshake(); c.Close() }()
		}
	}()
	m := mustRun(t, tlsCheck, testEnv(t, nil), protocol.TLSCheckParams{Target: ip.String(), Port: ln.Addr().(*net.TCPAddr).Port, ServerName: "n1.test"})
	leaf := get(m, "chain", 0).(map[string]any)
	subj := untrustedText(t, leaf["subject"])
	if len(subj) > protocol.MaxHeaderBytes || !isTruncated(leaf["subject"]) || strings.Contains(subj, "\x1b") {
		t.Fatalf("subject not capped: %q", subj)
	}
	if n := len(leaf["sans"].([]any)); n != 50 || leaf["sans_cut"] != true {
		t.Fatalf("%d SANs reported", n)
	}
	if leaf["days_left"].(float64) >= 0 || m["verified"] != false {
		t.Fatalf("expired certificate: %v", m)
	}
}
