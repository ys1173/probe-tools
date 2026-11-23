package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

const (
	maxChainCerts = 10
	maxSANs       = 50
)

type certEntry struct {
	Subject            protocol.Untrusted   `json:"subject"`
	Issuer             protocol.Untrusted   `json:"issuer"`
	Serial             string               `json:"serial"` // hex
	NotBefore          time.Time            `json:"not_before"`
	NotAfter           time.Time            `json:"not_after"`
	DaysLeft           int                  `json:"days_left"`
	SANs               []protocol.Untrusted `json:"sans"`
	SANsCut            bool                 `json:"sans_cut,omitempty"` // more than 50 SANs; the rest are left out
	SignatureAlgorithm string               `json:"signature_algorithm"`
	IsCA               bool                 `json:"is_ca"`
}

type tlsCheckResult struct {
	Target      string              `json:"target"`
	Address     string              `json:"address"`
	Port        int                 `json:"port"`
	ServerName  string              `json:"server_name"` // the name verified against (and sent as SNI when it is not an address)
	Outcome     string              `json:"outcome"`     // ok | refused | timeout | unreachable | handshake_failed | error
	Detail      *protocol.Untrusted `json:"detail,omitempty"`
	ConnectMS   float64             `json:"connect_ms"`
	HandshakeMS float64             `json:"handshake_ms,omitempty"`

	Version       string              `json:"version,omitempty"`
	Cipher        string              `json:"cipher,omitempty"`
	ALPN          string              `json:"alpn,omitempty"`
	OCSPStapled   bool                `json:"ocsp_stapled"`
	Verified      bool                `json:"verified"`
	VerifyError   *protocol.Untrusted `json:"verify_error,omitempty"`
	HostnameMatch bool                `json:"hostname_match"`
	Chain         []certEntry         `json:"chain"`
}

func tlsCheck(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.TLSCheckParams
	if e := check.Decode(raw, &p); e != nil {
		return nil, e
	}
	addr, e := resolveTarget(ctx, env, p.Target, p.Family)
	if e != nil {
		return nil, e
	}
	name := p.ServerName
	if name == "" {
		name = p.Target
	}
	res := &tlsCheckResult{Target: p.Target, Address: addr.String(), Port: p.Port, ServerName: name, Chain: []certEntry{}}

	deadline := within(ctx, millis(p.TimeoutMS))
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	start := time.Now()
	conn, err := dialChecked(ctx, &net.Dialer{}, "tcp", addr, p.Port)
	res.ConnectMS = msSince(start)
	if err != nil {
		res.Outcome = dialOutcome(err)
		res.Detail = errText(err)
		return res, nil
	}
	defer conn.Close()
	stop := watch(ctx, conn)
	defer stop()

	tc := tls.Client(conn, clientTLS(name, []string{"h2", "http/1.1"}))
	start = time.Now()
	err = tc.HandshakeContext(ctx)
	res.HandshakeMS = msSince(start)
	if err != nil {
		res.Outcome = "handshake_failed"
		if isTimeout(err) {
			res.Outcome = "timeout"
		}
		res.Detail = errText(err)
		return res, nil
	}
	res.Outcome = "ok"
	cs := tc.ConnectionState()
	res.Version = tls.VersionName(cs.Version)
	res.Cipher = tls.CipherSuiteName(cs.CipherSuite)
	res.ALPN = capPlain(cs.NegotiatedProtocol, 64)
	res.OCSPStapled = len(cs.OCSPResponse) > 0
	res.Verified, res.VerifyError, res.HostnameMatch = verifyChain(cs.PeerCertificates, name)
	for i, c := range cs.PeerCertificates {
		if i == maxChainCerts {
			break
		}
		res.Chain = append(res.Chain, certSummary(c))
	}
	return res, nil
}

func certSummary(c *x509.Certificate) certEntry {
	e := certEntry{
		Subject:            protocol.UntrustedString(c.Subject.String(), protocol.MaxHeaderBytes),
		Issuer:             protocol.UntrustedString(c.Issuer.String(), protocol.MaxHeaderBytes),
		NotBefore:          c.NotBefore.UTC(),
		NotAfter:           c.NotAfter.UTC(),
		DaysLeft:           daysLeft(c.NotAfter),
		SANs:               []protocol.Untrusted{},
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		IsCA:               c.IsCA,
	}
	if c.SerialNumber != nil {
		e.Serial = capPlain(c.SerialNumber.Text(16), 64)
	}
	var sans []string
	sans = append(sans, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	sans = append(sans, c.EmailAddresses...)
	for _, u := range c.URIs {
		sans = append(sans, u.String())
	}
	for i, s := range sans {
		if i == maxSANs {
			e.SANsCut = true
			break
		}
		e.SANs = append(e.SANs, protocol.UntrustedString(s, protocol.MaxHeaderBytes))
	}
	return e
}
