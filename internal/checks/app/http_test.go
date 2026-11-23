package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"probetools/internal/policy"
	"probetools/internal/protocol"
)

func TestHTTPCheckBasic(t *testing.T) {
	ip := hostIP(t)
	_, port := httpServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.UserAgent() != "probe" {
			w.WriteHeader(400)
			return
		}
		// Go's client refuses control bytes in headers, so the hostile text here is a bidirectional override.
		w.Header().Set("Server", "test\u202e"+strings.Repeat("v", 400))
		w.Header().Set("Set-Cookie", "secret=1")
		io.WriteString(w, "hello world")
	}))
	u := fmt.Sprintf("http://%s:%d/x", ip, port)
	m := mustRun(t, httpCheck, testEnv(t, nil), protocol.HTTPCheckParams{URL: u, ExpectStatus: 200, ExpectText: "world"})
	sum := sha256.Sum256([]byte("hello world"))
	if m["outcome"] != "ok" || m["status"] != float64(200) || m["expect_status_met"] != true || m["expect_text_found"] != true ||
		get(m, "body", "bytes") != float64(11) || get(m, "body", "sha256") != hex.EncodeToString(sum[:]) {
		t.Fatalf("result: %v", m)
	}
	if untrustedText(t, m["final_url"]) != u {
		t.Fatalf("final_url %v", m["final_url"])
	}
	srvHdr := get(m, "headers", "Server")
	if text := untrustedText(t, srvHdr); len(text) > protocol.MaxHeaderBytes || !isTruncated(srvHdr) || !strings.HasPrefix(text, `test\u202e`) {
		t.Fatalf("Server header: %v", srvHdr)
	}
	if get(m, "headers", "Set-Cookie") != nil {
		t.Fatal("reported a header outside the fixed set")
	}
	if get(m, "timings", "total_ms") == nil || get(m, "timings", "ttfb_ms") == nil {
		t.Fatalf("timings: %v", m["timings"])
	}
	if _, ok := m["body"].(map[string]any)["text"]; ok {
		t.Fatal("body text must never be returned")
	}
}

func TestHTTPCheckRedirects(t *testing.T) {
	ip := hostIP(t)
	_, port := httpServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusMovedPermanently)
		case "/ftp":
			http.Redirect(w, r, "ftp://files.test/x", http.StatusFound)
		default:
			io.WriteString(w, "done")
		}
	}))
	base := fmt.Sprintf("http://%s:%d", ip, port)
	env := testEnv(t, nil)

	m := mustRun(t, httpCheck, env, protocol.HTTPCheckParams{URL: base + "/a"})
	if m["status"] != float64(200) || untrustedText(t, m["final_url"]) != base+"/c" || len(m["redirects"].([]any)) != 2 ||
		get(m, "redirects", 0, "status") != float64(302) || untrustedText(t, get(m, "redirects", 1, "url")) != base+"/c" {
		t.Fatalf("chain: %v", m)
	}

	zero := 0
	m = mustRun(t, httpCheck, env, protocol.HTTPCheckParams{URL: base + "/a", MaxRedirects: &zero})
	if m["status"] != float64(302) || m["redirect_limit_reached"] != true || len(m["redirects"].([]any)) != 0 {
		t.Fatalf("limit: %v", m)
	}

	m = mustRun(t, httpCheck, env, protocol.HTTPCheckParams{URL: base + "/ftp"})
	if m["outcome"] != "unsupported_scheme" || m["status"] != float64(302) || get(m, "redirects", 0, "error", "code") != "unsupported_scheme" {
		t.Fatalf("ftp redirect: %v", m)
	}
}

// A redirect to an address the policy refuses is stopped when its connection would be made, and the chain so far is
// reported.
func TestHTTPCheckRedirectToDeniedAddress(t *testing.T) {
	ip := hostIP(t)
	var loopHits atomic.Int32
	loop, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { loop.Close() })
	go func() {
		for {
			c, err := loop.Accept()
			if err != nil {
				return
			}
			loopHits.Add(1)
			c.Close()
		}
	}()
	_, port := httpServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/loop":
			http.Redirect(w, r, "http://"+loop.Addr().String()+"/", http.StatusFound)
		case "/meta":
			http.Redirect(w, r, "http://metadata.test/latest", http.StatusFound)
		}
	}))
	env := testEnv(t, map[string][]netip.Addr{"metadata.test": {netip.MustParseAddr("169.254.169.254")}})
	for _, path := range []string{"/loop", "/meta"} {
		m := mustRun(t, httpCheck, env, protocol.HTTPCheckParams{URL: fmt.Sprintf("http://%s:%d%s", ip, port, path)})
		if m["outcome"] != "denied" || get(m, "error", "code") != "denied" || m["status"] != float64(302) ||
			get(m, "redirects", 0, "error", "code") != "denied" || get(m, "redirects", 0, "status") != float64(302) {
			t.Fatalf("%s: %v", path, m)
		}
		untrustedText(t, get(m, "redirects", 0, "url"))
	}
	if n := loopHits.Load(); n != 0 {
		t.Fatalf("the loopback server was reached %d times", n)
	}

	_, perr := runCheck(t, httpCheck, env, protocol.HTTPCheckParams{URL: "http://" + loop.Addr().String() + "/"})
	wantCode(t, perr, protocol.CodeDenied)
}

func TestHTTPCheckUnresolved(t *testing.T) {
	ip := hostIP(t)
	_, port := httpServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://gone.test/", http.StatusFound)
	}))
	env := testEnv(t, nil)
	_, perr := runCheck(t, httpCheck, env, protocol.HTTPCheckParams{URL: "http://gone.test/"})
	wantCode(t, perr, protocol.CodeUnresolved)
	m := mustRun(t, httpCheck, env, protocol.HTTPCheckParams{URL: fmt.Sprintf("http://%s:%d/", ip, port)})
	if m["outcome"] != "unresolved" || get(m, "redirects", 0, "error", "code") != "unresolved" || m["status"] != float64(302) {
		t.Fatalf("result: %v", m)
	}
}

func TestHTTPCheckNeverUsesProxy(t *testing.T) {
	ip := hostIP(t)
	var proxyHits atomic.Int32
	proxyPort := tcpServer(t, ip, func(c net.Conn) {
		proxyHits.Add(1)
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	})
	proxy := fmt.Sprintf("http://%s:%d", ip, proxyPort)
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"} {
		t.Setenv(k, proxy)
	}
	t.Setenv("NO_PROXY", "")
	_, plainPort := httpServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "direct") }))
	_, tlsPort := tlsServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "direct") }))
	no := false
	env := testEnv(t, nil)
	for _, u := range []string{fmt.Sprintf("http://%s:%d/", ip, plainPort), fmt.Sprintf("https://%s:%d/", ip, tlsPort)} {
		m := mustRun(t, httpCheck, env, protocol.HTTPCheckParams{URL: u, VerifyTLS: &no, ExpectText: "direct"})
		if m["status"] != float64(200) || m["expect_text_found"] != true {
			t.Fatalf("%s: %v", u, m)
		}
	}
	if n := proxyHits.Load(); n != 0 {
		t.Fatalf("the proxy was used %d times", n)
	}
}

func TestHTTPCheckTLSVerification(t *testing.T) {
	ip := hostIP(t)
	srv, port := tlsServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	env := testEnv(t, map[string][]netip.Addr{"example.com": {ip}})
	byIP := fmt.Sprintf("https://%s:%d/", ip, port)

	// Verification on and an untrusted certificate: the request is refused, with the reason.
	m := mustRun(t, httpCheck, env, protocol.HTTPCheckParams{URL: byIP})
	if m["outcome"] != "tls_verify_failed" || get(m, "tls", "verified") != false || get(m, "tls", "verify_error") == nil || m["status"] != float64(0) {
		t.Fatalf("verify on: %v", m)
	}
	// Verification off: the request goes ahead and the result still says it would not have verified.
	no := false
	m = mustRun(t, httpCheck, env, protocol.HTTPCheckParams{URL: byIP, VerifyTLS: &no})
	if m["status"] != float64(200) || get(m, "tls", "verified") != false || get(m, "tls", "verify_error") == nil || get(m, "tls", "not_after") == nil {
		t.Fatalf("verify off: %v", m)
	}
	// Trusted CA and the certificate's name: verified.
	trust(t, srv)
	m = mustRun(t, httpCheck, env, protocol.HTTPCheckParams{URL: fmt.Sprintf("https://example.com:%d/", port)})
	if m["status"] != float64(200) || get(m, "tls", "verified") != true || get(m, "tls", "hostname_match") != true || get(m, "tls", "version") != "TLS 1.3" {
		t.Fatalf("trusted: %v", m)
	}
}

func TestHTTPCheckBodyLimits(t *testing.T) {
	ip := hostIP(t)
	_, port := httpServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := strings.Repeat("a", 1<<20)
		for i := 0; i < 11; i++ {
			io.WriteString(w, chunk)
		}
		io.WriteString(w, "needle")
	}))
	m := mustRun(t, httpCheck, testEnv(t, nil), protocol.HTTPCheckParams{URL: fmt.Sprintf("http://%s:%d/", ip, port), ExpectText: "needle"})
	if get(m, "body", "bytes") != float64(10<<20) || get(m, "body", "truncated") != true || get(m, "body", "hashed_bytes") != float64(1<<20) ||
		m["expect_text_found"] != false {
		t.Fatalf("body: %v found=%v", m["body"], m["expect_text_found"])
	}
}

func TestHTTPCheckRefused(t *testing.T) {
	ip := hostIP(t)
	m := mustRun(t, httpCheck, testEnv(t, nil), protocol.HTTPCheckParams{URL: fmt.Sprintf("http://%s:%d/", ip, freePort(t, ip, "tcp"))})
	if m["outcome"] != "refused" || get(m, "error", "code") != "refused" {
		t.Fatalf("result: %v", m)
	}
}

// Every redirect hop dials afresh through the policy. Within one job the address is charged once, so a chain on one
// host passes a limit of one; the next job is over it.
func TestHTTPCheckRateLimitPerJob(t *testing.T) {
	ip := hostIP(t)
	_, port := httpServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			http.Redirect(w, r, "/b", http.StatusFound)
		case "/b":
			http.Redirect(w, r, "/c", http.StatusFound)
		default:
			io.WriteString(w, "ok")
		}
	}))
	env := testEnv(t, map[string][]netip.Addr{"web.test": {ip}})
	env.Policy.SetRateLimit(1)
	u := fmt.Sprintf("http://web.test:%d/a", port)
	run := func() (map[string]any, *protocol.Error) {
		raw, _ := json.Marshal(protocol.HTTPCheckParams{URL: u})
		ctx, cancel := context.WithTimeout(policy.WithJob(context.Background()), 10*time.Second)
		defer cancel()
		out, perr := httpCheck(ctx, env, raw)
		if perr != nil {
			return nil, perr
		}
		b, _ := json.Marshal(out)
		var m map[string]any
		json.Unmarshal(b, &m)
		return m, nil
	}
	m, perr := run()
	if perr != nil || m["outcome"] != "ok" || m["status"] != float64(200) || len(m["redirects"].([]any)) != 2 {
		t.Fatalf("first job: %v %v", m, perr)
	}
	_, perr = run()
	wantCode(t, perr, protocol.CodeBusy)
}
