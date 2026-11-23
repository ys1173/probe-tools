package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"sync"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

const (
	bodyHashLimit  = 1 << 20  // bytes hashed and searched for expect_text
	bodyCountLimit = 10 << 20 // bytes counted before reading stops
)

type httpHop struct {
	Status int                `json:"status"` // the redirect status that pointed here
	URL    protocol.Untrusted `json:"url"`    // where it pointed, from the target's Location header
	Error  *httpError         `json:"error,omitempty"`
}

type httpError struct {
	Code    string              `json:"code"` // denied | unresolved | refused | timeout | unreachable | tls_failed | tls_verify_failed | unsupported_scheme | error
	Message *protocol.Untrusted `json:"message,omitempty"`
}

type httpTimings struct {
	DNSMS     float64 `json:"dns_ms"`
	ConnectMS float64 `json:"connect_ms"`
	TLSMS     float64 `json:"tls_ms"`
	TTFBMS    float64 `json:"ttfb_ms"`
	TotalMS   float64 `json:"total_ms"`
}

type httpTLS struct {
	Version       string              `json:"version"`
	Verified      bool                `json:"verified"`
	VerifyError   *protocol.Untrusted `json:"verify_error,omitempty"`
	HostnameMatch bool                `json:"hostname_match"`
	NotAfter      *time.Time          `json:"not_after,omitempty"`
}

type httpBody struct {
	Bytes       int64  `json:"bytes"`
	Truncated   bool   `json:"truncated"`    // more than 10 MiB; counting stopped
	SHA256      string `json:"sha256"`       // of the first hashed_bytes bytes
	HashedBytes int64  `json:"hashed_bytes"` // at most 1 MiB
	ReadError   string `json:"read_error,omitempty"`
}

type httpResult struct {
	URL                  string                        `json:"url"`
	FinalURL             protocol.Untrusted            `json:"final_url"` // the last URL that answered
	Status               int                           `json:"status"`
	Outcome              string                        `json:"outcome"` // ok, or the error code of the request that failed
	Error                *httpError                    `json:"error,omitempty"`
	Redirects            []httpHop                     `json:"redirects"`
	RedirectLimitReached bool                          `json:"redirect_limit_reached,omitempty"`
	Timings              httpTimings                   `json:"timings"` // of the last request made
	TLS                  *httpTLS                      `json:"tls,omitempty"`
	Headers              map[string]protocol.Untrusted `json:"headers,omitempty"`
	Body                 *httpBody                     `json:"body,omitempty"`
	ExpectStatusMet      *bool                         `json:"expect_status_met,omitempty"`
	ExpectTextFound      *bool                         `json:"expect_text_found,omitempty"`
}

// tlsVerifyError ends a request whose certificate does not verify when verify_tls is on.
type tlsVerifyError struct{ msg string }

func (e *tlsVerifyError) Error() string { return "certificate verification failed: " + e.msg }

// tlsHandshakeError marks a failed handshake, as distinct from a failed TCP connection.
type tlsHandshakeError struct{ err error }

func (e *tlsHandshakeError) Error() string { return "TLS handshake: " + e.err.Error() }
func (e *tlsHandshakeError) Unwrap() error { return e.err }

// httpRun is the state of one http_check: the redirect chain and the measurements of the latest request. Dials run on
// the transport's goroutines, so it is guarded by a mutex.
type httpRun struct {
	env    *check.Env
	verify bool
	max    int

	mu           sync.Mutex
	hops         []httpHop
	lastRedirect *http.Response // the redirect response that led to the request now in flight
	limitReached bool
	hopStart     time.Time
	timings      httpTimings
	tls          *httpTLS
}

func httpCheck(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.HTTPCheckParams
	if e := check.Decode(raw, &p); e != nil {
		return nil, e
	}
	ctx, cancel := context.WithDeadline(ctx, within(ctx, millis(p.TimeoutMS)))
	defer cancel()

	run := &httpRun{env: env, verify: *p.VerifyTLS, max: *p.MaxRedirects}
	tr := &http.Transport{
		Proxy:                  nil, // never a proxy: HTTPS_PROXY is for the probe's link to the hub only
		DialContext:            run.dial,
		DialTLSContext:         run.dialTLS,
		DisableKeepAlives:      true, // every request, redirects included, dials afresh and so is checked by the policy
		DisableCompression:     true, // ask for the body as stored, so size and hash describe what the server sends
		MaxResponseHeaderBytes: 64 << 10,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{}, // HTTP/1.1 only
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: run.checkRedirect}

	trace := &httptrace.ClientTrace{
		GetConn: func(string) {
			run.mu.Lock()
			run.hopStart = time.Now()
			run.timings = httpTimings{}
			run.tls = nil
			run.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			run.mu.Lock()
			run.timings.TTFBMS = msSince(run.hopStart)
			run.mu.Unlock()
		},
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), p.Method, p.URL, nil)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeInvalidParams, "url: %v", err)
	}
	req.Header.Set("User-Agent", "probe")

	res := &httpResult{URL: p.URL}
	resp, err := client.Do(req)

	run.mu.Lock()
	defer run.mu.Unlock()
	res.Redirects = append([]httpHop{}, run.hops...)
	res.RedirectLimitReached = run.limitReached

	if err != nil {
		herr := classifyHTTPError(err)
		if (herr.Code == "denied" || herr.Code == "unresolved" || herr.Code == "busy") && len(run.hops) == 0 {
			// The URL the agent gave is refused by the policy, over its rate limit or its name does not resolve: that
			// is the check's answer, with the same codes every other check uses.
			var pe *protocol.Error
			errors.As(err, &pe)
			return nil, pe
		}
		res.Outcome, res.Error = herr.Code, herr
		res.Timings = run.timings
		res.Timings.TotalMS = msSince(run.hopStart)
		res.TLS = run.tls // the failed request's handshake, if it got that far; reset for every request
		if n := len(res.Redirects); n > 0 {
			// The chain so far: the last response that came back was the redirect, and following it failed.
			res.Redirects[n-1].Error = herr
			last := run.lastRedirect
			res.FinalURL = protocol.UntrustedString(last.Request.URL.String(), protocol.MaxRecordBytes)
			res.Status = last.StatusCode
			res.Headers = pickHeaders(last.Header)
		} else {
			res.FinalURL = protocol.UntrustedString(p.URL, protocol.MaxRecordBytes)
		}
		return res, nil
	}
	defer resp.Body.Close()

	res.Outcome = "ok"
	if n := len(res.Redirects); n > 0 && res.Redirects[n-1].Error != nil {
		// A redirect to a scheme other than http or https was not followed; the redirect itself is the final response.
		res.Error = res.Redirects[n-1].Error
		res.Outcome = res.Error.Code
	}
	res.Status = resp.StatusCode
	res.FinalURL = protocol.UntrustedString(resp.Request.URL.String(), protocol.MaxRecordBytes)
	res.Headers = pickHeaders(resp.Header)
	if resp.Request.URL.Scheme == "https" {
		res.TLS = run.tls
	}
	if p.ExpectStatus != 0 {
		met := resp.StatusCode == p.ExpectStatus
		res.ExpectStatusMet = &met
	}
	hopStart := run.hopStart
	run.mu.Unlock()
	var kept []byte
	if p.Method == http.MethodGet {
		res.Body, kept = readBody(resp.Body, p.ExpectText != "")
	}
	run.mu.Lock()
	res.Timings = run.timings
	res.Timings.TotalMS = msSince(hopStart)
	if p.ExpectText != "" {
		found := bytes.Contains(kept, []byte(p.ExpectText))
		res.ExpectTextFound = &found
	}
	return res, nil
}

// checkRedirect records each redirect and decides whether to follow it. The policy check for the new target happens
// when its connection is dialled, not here, so that a name that resolves differently by then is still caught.
func (r *httpRun) checkRedirect(req *http.Request, via []*http.Request) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(via) > r.max {
		r.limitReached = true
		return http.ErrUseLastResponse
	}
	hop := httpHop{URL: protocol.UntrustedString(req.URL.String(), protocol.MaxRecordBytes)}
	if req.Response != nil {
		hop.Status = req.Response.StatusCode
	}
	if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
		hop.Error = &httpError{Code: "unsupported_scheme", Message: untrusted("redirects are followed to http and https only", protocol.MaxRecordBytes)}
		r.hops = append(r.hops, hop)
		return http.ErrUseLastResponse
	}
	r.hops = append(r.hops, hop)
	r.lastRedirect = req.Response
	return nil
}

// dial connects through the policy, timing the lookup and the connection separately. It resolves with Policy.Resolve and
// connects to the addresses it allows, in order, which is what Policy.DialContext does, but split so DNS time can be
// reported.
func (r *httpRun) dial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	addrs, perr := r.env.Policy.Resolve(ctx, host, "")
	dnsMS := msSince(start)
	r.mu.Lock()
	r.timings.DNSMS = dnsMS
	r.mu.Unlock()
	if perr != nil {
		return nil, perr
	}
	start = time.Now()
	d := &net.Dialer{}
	var lastErr error
	for _, a := range addrs {
		conn, err := d.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			r.mu.Lock()
			r.timings.ConnectMS = msSince(start)
			r.mu.Unlock()
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// dialTLS connects and handshakes with verification off, then verifies the chain itself so the outcome is recorded either
// way. With verify_tls on, a chain that does not verify ends the request.
func (r *httpRun) dialTLS(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := r.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(address)
	tc := tls.Client(conn, clientTLS(host, []string{"http/1.1"}))
	start := time.Now()
	if err := tc.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, &tlsHandshakeError{err}
	}
	tlsMS := msSince(start)
	cs := tc.ConnectionState()
	info := &httpTLS{Version: tls.VersionName(cs.Version)}
	info.Verified, info.VerifyError, info.HostnameMatch = verifyChain(cs.PeerCertificates, host)
	if len(cs.PeerCertificates) > 0 {
		na := cs.PeerCertificates[0].NotAfter.UTC()
		info.NotAfter = &na
	}
	r.mu.Lock()
	r.timings.TLSMS = tlsMS
	r.tls = info
	r.mu.Unlock()
	if !info.Verified && r.verify {
		tc.Close()
		msg := ""
		if info.VerifyError != nil {
			msg = info.VerifyError.Text
		}
		return nil, &tlsVerifyError{msg}
	}
	return tc, nil
}

func classifyHTTPError(err error) *httpError {
	var tv *tlsVerifyError
	var th *tlsHandshakeError
	code := ""
	switch {
	case isDenied(err):
		code = "denied"
	case isCode(err, protocol.CodeBusy):
		code = "busy" // the probe's rate limit for the address was reached
	case isCode(err, protocol.CodeUnresolved):
		code = "unresolved"
	case errors.As(err, &tv):
		code = "tls_verify_failed"
	case errors.As(err, &th) && !isTimeout(err):
		code = "tls_failed"
	default:
		code = dialOutcome(err)
		if code == "open" {
			code = "error"
		}
	}
	return &httpError{Code: code, Message: errText(err)}
}

// readBody counts up to bodyCountLimit bytes, hashing the first bodyHashLimit and, when keep is set, keeping them for the
// expect_text search. The body itself is never returned.
func readBody(body io.Reader, keep bool) (*httpBody, []byte) {
	out := &httpBody{}
	h := sha256.New()
	var kept []byte
	buf := make([]byte, 32<<10)
	for out.Bytes < bodyCountLimit {
		n, err := body.Read(buf[:min(int64(len(buf)), bodyCountLimit-out.Bytes)])
		if n > 0 {
			if room := bodyHashLimit - out.HashedBytes; room > 0 {
				part := buf[:min(int64(n), room)]
				h.Write(part)
				out.HashedBytes += int64(len(part))
				if keep {
					kept = append(kept, part...)
				}
			}
			out.Bytes += int64(n)
		}
		if err == io.EOF {
			out.SHA256 = hex.EncodeToString(h.Sum(nil))
			return out, kept
		}
		if err != nil {
			out.ReadError = dialOutcome(err)
			if out.ReadError == "open" || out.ReadError == "refused" {
				out.ReadError = "error"
			}
			out.SHA256 = hex.EncodeToString(h.Sum(nil))
			return out, kept
		}
	}
	// Reached the counting limit: one more byte says whether the body went on.
	var one [1]byte
	if n, _ := io.ReadFull(body, one[:]); n > 0 {
		out.Truncated = true
	}
	out.SHA256 = hex.EncodeToString(h.Sum(nil))
	return out, kept
}
