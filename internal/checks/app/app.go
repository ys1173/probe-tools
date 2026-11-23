// Package app holds the application-layer checks: dns_lookup, tcp_connect, tcp_template, udp_probe, tls_check and
// http_check. Every target is reached through the probe's policy, and text the target controls is returned as
// protocol.Untrusted.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

// Register adds the application-layer checks to r.
func Register(r *check.Registry) {
	r.Register(protocol.CheckDNSLookup, dnsLookup)
	r.Register(protocol.CheckTCPConnect, tcpConnect)
	r.Register(protocol.CheckTCPTemplate, tcpTemplate)
	r.Register(protocol.CheckUDPProbe, udpProbe)
	r.Register(protocol.CheckTLSCheck, tlsCheck)
	r.Register(protocol.CheckHTTPCheck, httpCheck)
}

// rootCAs is the trust store certificate chains are verified against; nil means the system roots. Tests replace it so
// that a successful verification can be exercised against a local test server.
var rootCAs *x509.CertPool

// resolveTarget resolves target once through the policy and returns the first allowed address. A check then connects to
// that exact address, so the address it reports is the one it tested.
func resolveTarget(ctx context.Context, env *check.Env, target, family string) (netip.Addr, *protocol.Error) {
	addrs, perr := env.Policy.Resolve(ctx, target, family)
	if perr != nil {
		return netip.Addr{}, perr
	}
	return addrs[0], nil
}

// dialChecked connects to an address that policy.Resolve has already allowed. It does not go back through
// Policy.DialContext with the address literal: that would check the bare address without the name it was resolved from,
// and a closed-mode policy that allows the target only by name (allow_hosts) would then refuse it.
func dialChecked(ctx context.Context, d *net.Dialer, network string, addr netip.Addr, port int) (net.Conn, error) {
	return d.DialContext(ctx, network, netip.AddrPortFrom(addr, uint16(port)).String())
}

// dialOutcome names the reason a connection attempt failed, in the words the results use.
func dialOutcome(err error) string {
	switch {
	case err == nil:
		return "open"
	case isDenied(err):
		return "denied"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTDOWN):
		return "unreachable"
	case isTimeout(err):
		return "timeout"
	}
	return "error"
}

func isDenied(err error) bool { return isCode(err, protocol.CodeDenied) }

func isCode(err error, code string) bool {
	var pe *protocol.Error
	return errors.As(err, &pe) && pe.Code == code
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isClosed reports whether a read failed because the peer closed or reset the connection.
func isClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// within returns the earlier of now+d and ctx's deadline, for socket deadlines that must not outlive the job.
func within(ctx context.Context, d time.Duration) time.Time {
	t := time.Now().Add(d)
	if dl, ok := ctx.Deadline(); ok && dl.Before(t) {
		return dl
	}
	return t
}

// watch makes blocking reads and writes on conn return as soon as ctx is cancelled, not only at its deadline. Call the
// returned function when done with conn.
func watch(ctx context.Context, conn net.Conn) func() bool {
	return context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
}

// msSince is the time since t in milliseconds, kept to two decimals: sub-millisecond differences matter on a LAN.
func msSince(t time.Time) float64 { return msOf(time.Since(t)) }

func msOf(d time.Duration) float64 { return math.Round(float64(d)/1e4) / 100 }

func millis(ms int) time.Duration { return time.Duration(ms) * time.Millisecond }

// untrusted wraps target-controlled text, returning a pointer for optional result fields.
func untrusted(s string, max int) *protocol.Untrusted {
	u := protocol.UntrustedString(s, max)
	return &u
}

// errText wraps an error message as untrusted: TLS and HTTP errors can quote certificate names or URLs from the target.
func errText(err error) *protocol.Untrusted {
	if err == nil {
		return nil
	}
	return untrusted(err.Error(), protocol.MaxRecordBytes)
}

// capPlain cuts a string that is not free text (a DNS name, a serial number) to n bytes, marking the cut.
func capPlain(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// isAddr reports whether s is an IP address literal, with or without brackets.
func isAddr(s string) bool {
	_, err := netip.ParseAddr(strings.Trim(s, "[]"))
	return err == nil
}

// familyOf gives "4" or "6" for addr, so a source interface's address can be matched to the target.
func familyOf(addr netip.Addr) string {
	if addr.Is4() {
		return "4"
	}
	return "6"
}

// tlsInfo is what a TLS handshake on a connected socket showed.
type tlsInfo struct {
	Version     string              `json:"version,omitempty"`
	Cipher      string              `json:"cipher,omitempty"`
	ALPN        string              `json:"alpn,omitempty"`
	HandshakeMS float64             `json:"handshake_ms"`
	Verified    bool                `json:"verified"`
	VerifyError *protocol.Untrusted `json:"verify_error,omitempty"`
	Cert        *certInfo           `json:"cert,omitempty"`
	Error       *protocol.Untrusted `json:"error,omitempty"` // the handshake failed; the other fields are empty
}

type certInfo struct {
	Subject  protocol.Untrusted `json:"subject"`
	Issuer   protocol.Untrusted `json:"issuer"`
	NotAfter time.Time          `json:"not_after"`
	DaysLeft int                `json:"days_left"`
}

// clientTLS is the configuration for every handshake a check makes. Verification is done afterwards by verifyChain, so
// that a bad certificate is reported rather than ending the check. Old protocol versions are allowed because finding a
// server that only speaks them is a useful result.
func clientTLS(serverName string, alpn []string) *tls.Config {
	return &tls.Config{
		ServerName:         strings.Trim(serverName, "[]"),
		InsecureSkipVerify: true,
		NextProtos:         alpn,
		MinVersion:         tls.VersionTLS10,
	}
}

// handshake runs a TLS client handshake on conn and reports it, verifying the chain against verifyName. It returns a nil
// connection when the handshake fails.
func handshake(ctx context.Context, conn net.Conn, serverName, verifyName string, alpn []string, timeout time.Duration) (*tls.Conn, *tlsInfo) {
	tc := tls.Client(conn, clientTLS(serverName, alpn))
	hctx, cancel := context.WithDeadline(ctx, within(ctx, timeout))
	defer cancel()
	start := time.Now()
	err := tc.HandshakeContext(hctx)
	info := &tlsInfo{HandshakeMS: msSince(start)}
	if err != nil {
		info.Error = errText(err)
		return nil, info
	}
	cs := tc.ConnectionState()
	info.Version = tls.VersionName(cs.Version)
	info.Cipher = tls.CipherSuiteName(cs.CipherSuite)
	info.ALPN = capPlain(cs.NegotiatedProtocol, 64)
	info.Verified, info.VerifyError, _ = verifyChain(cs.PeerCertificates, verifyName)
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		info.Cert = &certInfo{
			Subject:  protocol.UntrustedString(leaf.Subject.String(), protocol.MaxHeaderBytes),
			Issuer:   protocol.UntrustedString(leaf.Issuer.String(), protocol.MaxHeaderBytes),
			NotAfter: leaf.NotAfter.UTC(),
			DaysLeft: daysLeft(leaf.NotAfter),
		}
	}
	return tc, info
}

// verifyChain checks the peer's chain against the trust store for name, a DNS name or an IP address literal (which is
// matched against the certificate's IP SANs). An empty name checks the chain only.
func verifyChain(certs []*x509.Certificate, name string) (verified bool, verifyErr *protocol.Untrusted, hostnameMatch bool) {
	if len(certs) == 0 {
		return false, untrusted("the server sent no certificate", protocol.MaxRecordBytes), false
	}
	name = strings.Trim(name, "[]")
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: rootCAs, Intermediates: inter, DNSName: name})
	hostnameMatch = name == "" || certs[0].VerifyHostname(name) == nil
	if err != nil {
		return false, errText(err), hostnameMatch
	}
	return true, nil, hostnameMatch
}

func daysLeft(notAfter time.Time) int {
	return int(math.Floor(time.Until(notAfter).Hours() / 24))
}
