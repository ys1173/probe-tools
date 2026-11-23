package app

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"probetools/internal/protocol"
)

// lineServer runs a scripted exchange: it records every line the client sends.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, s)
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

func TestTemplateHTTPHead(t *testing.T) {
	ip := hostIP(t)
	var got *http.Request
	var mu sync.Mutex
	_, port := httpServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Clone(r.Context())
		mu.Unlock()
		w.Header().Set("Server", "evil\x01"+strings.Repeat("x", 600))
		w.Header().Set("X-Secret", "not reported")
		w.WriteHeader(204)
	}))
	m := mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "http_head", Path: "/health"})
	if m["outcome"] != "ok" || m["status_code"] != float64(204) {
		t.Fatalf("result: %v", m)
	}
	if line := untrustedText(t, m["status_line"]); line != "HTTP/1.1 204 No Content" {
		t.Fatalf("status line %q", line)
	}
	server := get(m, "headers", "Server")
	if text := untrustedText(t, server); len(text) > protocol.MaxHeaderBytes || !isTruncated(server) || strings.Contains(text, "\x01") {
		t.Fatalf("Server header not capped or sanitised: %v", server)
	}
	if get(m, "headers", "X-Secret") != nil {
		t.Fatal("reported a header outside the fixed set")
	}
	mu.Lock()
	defer mu.Unlock()
	if got.Method != "HEAD" || got.URL.Path != "/health" || got.Host != fmt.Sprintf("%s:%d", ip, port) || got.UserAgent() != "probe" {
		t.Fatalf("request was %s %s Host=%s UA=%s", got.Method, got.URL, got.Host, got.UserAgent())
	}
}

func TestTemplateHTTPHeadLongHeaders(t *testing.T) {
	ip := hostIP(t)
	_, port := httpServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", strings.Repeat("default-src 'self'; ", 150)) // about 3 KiB
		w.Header().Set("Server", "after-the-long-one")
	}))
	m := mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "http_head"})
	if m["outcome"] != "ok" || m["status_code"] != float64(200) {
		t.Fatalf("result: %v", m)
	}
	if v := get(m, "headers", "Server"); v == nil || untrustedText(t, v) != "after-the-long-one" {
		t.Fatalf("headers after a long line were lost: %v", m["headers"])
	}
}

// Once the status line has parsed, a stalled response must not leak headers outside the fixed set through raw.
func TestTemplateHTTPHeadNoRawAfterStatus(t *testing.T) {
	ip := hostIP(t)
	port := tcpServer(t, ip, func(c net.Conn) {
		bufio.NewReader(c).ReadString('\n')
		io.WriteString(c, "HTTP/1.1 200 OK\r\nSet-Cookie: session=secret\r\n")
		io.Copy(io.Discard, c)
	})
	m := mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "http_head", TimeoutMS: 400})
	if m["outcome"] != "timeout" || m["raw"] != nil {
		t.Fatalf("result: %v", m)
	}
}

func TestTemplateHTTPHeadRefusesHeaderInjection(t *testing.T) {
	_, perr := runCheck(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: "a\r\nX-Injected:1", Template: "http_head"})
	wantCode(t, perr, protocol.CodeInvalidParams)
	_, perr = runCheck(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: "example.com", Template: "redis_ping", Path: "/x"})
	wantCode(t, perr, protocol.CodeInvalidParams)
}

func TestTemplateRedis(t *testing.T) {
	ip := hostIP(t)
	for _, tc := range []struct{ reply, interp, outcome string }{
		{"+PONG\r\n", "pong", "ok"},
		{"-NOAUTH Authentication required.\r\n", "auth_required", "ok"},
		{"-ERR unknown\r\n", "error", "ok"},
		{"HTTP/1.1 400 Bad Request\r\n", "other", "unexpected_reply"},
	} {
		rec := &recorder{}
		port := tcpServer(t, ip, func(c net.Conn) {
			line, _ := bufio.NewReader(c).ReadString('\n')
			rec.add(line)
			io.WriteString(c, tc.reply)
		})
		m := mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "redis_ping"})
		if m["outcome"] != tc.outcome || m["interpretation"] != tc.interp {
			t.Fatalf("%q: %v", tc.reply, m)
		}
		untrustedText(t, m["reply"])
		if l := rec.all(); len(l) != 1 || l[0] != "PING\r\n" {
			t.Fatalf("sent %q", l)
		}
	}
}

func TestTemplateSMTP(t *testing.T) {
	ip := hostIP(t)
	rec := &recorder{}
	port := tcpServer(t, ip, func(c net.Conn) {
		br := bufio.NewReader(c)
		io.WriteString(c, "220-mail.test ESMTP\r\n220 ready\r\n")
		for {
			line, err := br.ReadString('\n')
			if err != nil {
				return
			}
			rec.add(line)
			switch {
			case strings.HasPrefix(line, "EHLO"):
				io.WriteString(c, "250-mail.test hello\r\n250-PIPELINING\r\n250-SIZE 1000\r\n250 STARTTLS\r\n")
			case strings.HasPrefix(line, "QUIT"):
				io.WriteString(c, "221 bye\r\n")
				return
			}
		}
	})
	m := mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "smtp_ehlo"})
	if m["outcome"] != "ok" || m["greeting_code"] != float64(220) || m["ehlo_code"] != float64(250) || m["starttls_offered"] != true {
		t.Fatalf("result: %v", m)
	}
	if g := untrustedText(t, m["greeting"]); g != "mail.test ESMTP\nready" {
		t.Fatalf("greeting %q", g)
	}
	exts, _ := m["extensions"].([]any)
	if len(exts) != 3 || untrustedText(t, exts[2]) != "STARTTLS" {
		t.Fatalf("extensions %v", exts)
	}
	if l := rec.all(); len(l) != 2 || l[0] != "EHLO probe.invalid\r\n" || l[1] != "QUIT\r\n" {
		t.Fatalf("sent %q", l)
	}
}

func TestTemplateSSHAndFTP(t *testing.T) {
	ip := hostIP(t)
	ssh := tcpServer(t, ip, func(c net.Conn) { io.WriteString(c, "hello first\r\nSSH-2.0-OpenSSH_9.6\r\n") })
	m := mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: ssh, Template: "ssh_banner"})
	if m["outcome"] != "ok" || untrustedText(t, m["banner"]) != "SSH-2.0-OpenSSH_9.6" {
		t.Fatalf("ssh: %v", m)
	}

	rec := &recorder{}
	ftp := tcpServer(t, ip, func(c net.Conn) {
		io.WriteString(c, "220-Welcome\r\n free text line\r\n220 FTP ready\r\n")
		line, _ := bufio.NewReader(c).ReadString('\n')
		rec.add(line)
		io.WriteString(c, "221 Goodbye\r\n")
	})
	m = mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: ftp, Template: "ftp_banner"})
	if m["outcome"] != "ok" || m["greeting_code"] != float64(220) || untrustedText(t, m["greeting"]) != "Welcome\n free text line\nFTP ready" {
		t.Fatalf("ftp: %v", m)
	}
	if l := rec.all(); len(l) != 1 || l[0] != "QUIT\r\n" {
		t.Fatalf("ftp sent %q", l)
	}
}

func mysqlPacket(payload []byte) []byte {
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), 0}
	return append(hdr, payload...)
}

func TestTemplateMySQL(t *testing.T) {
	ip := hostIP(t)
	hello := append([]byte{10}, []byte("8.0.36-log\x00\x01\x02\x03\x04salt")...)
	port := tcpServer(t, ip, func(c net.Conn) { c.Write(mysqlPacket(hello)) })
	m := mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "mysql_greeting"})
	if m["outcome"] != "ok" || m["protocol_version"] != float64(10) || untrustedText(t, m["server_version"]) != "8.0.36-log" {
		t.Fatalf("handshake: %v", m)
	}

	errPkt := []byte{0xff}
	errPkt = binary.LittleEndian.AppendUint16(errPkt, 1130)
	errPkt = append(errPkt, "Host '10.0.0.1' is not allowed to connect"...)
	port = tcpServer(t, ip, func(c net.Conn) { c.Write(mysqlPacket(errPkt)) })
	m = mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "mysql_greeting"})
	if m["outcome"] != "ok" || m["error_code"] != float64(1130) || !strings.HasPrefix(untrustedText(t, m["error_message"]), "Host '10.0.0.1'") {
		t.Fatalf("error packet: %v", m)
	}

	port = tcpServer(t, ip, func(c net.Conn) { io.WriteString(c, "SSH-2.0-x\r\n") })
	m = mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "mysql_greeting"})
	if m["outcome"] != "unexpected_reply" || m["raw"] == nil {
		t.Fatalf("garbage: %v", m)
	}
}

func TestTemplatePostgres(t *testing.T) {
	ip := hostIP(t)
	for _, tc := range []struct {
		reply byte
		want  bool
	}{{'S', true}, {'N', false}} {
		var got []byte
		var mu sync.Mutex
		port := tcpServer(t, ip, func(c net.Conn) {
			b := make([]byte, 8)
			io.ReadFull(c, b)
			mu.Lock()
			got = b
			mu.Unlock()
			c.Write([]byte{tc.reply})
		})
		m := mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "postgres_ssl"})
		if m["outcome"] != "ok" || m["tls_offered"] != tc.want {
			t.Fatalf("%c: %v", tc.reply, m)
		}
		mu.Lock()
		if !bytes.Equal(got, []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}) {
			t.Fatalf("SSLRequest was % x", got)
		}
		mu.Unlock()
	}
}

func TestTemplateOutcomes(t *testing.T) {
	ip := hostIP(t)
	env := testEnv(t, nil)
	closes := tcpServer(t, ip, func(net.Conn) {})
	silent := tcpServer(t, ip, func(c net.Conn) { io.Copy(io.Discard, c) })

	m := mustRun(t, tcpTemplate, env, protocol.TCPTemplateParams{Target: ip.String(), Port: closes, Template: "ssh_banner"})
	if m["outcome"] != "closed" {
		t.Fatalf("closed: %v", m)
	}
	m = mustRun(t, tcpTemplate, env, protocol.TCPTemplateParams{Target: ip.String(), Port: silent, Template: "ssh_banner", TimeoutMS: 300})
	if m["outcome"] != "timeout" {
		t.Fatalf("timeout: %v", m)
	}
	m = mustRun(t, tcpTemplate, env, protocol.TCPTemplateParams{Target: ip.String(), Port: freePort(t, ip, "tcp"), Template: "ssh_banner"})
	if m["outcome"] != "refused" {
		t.Fatalf("refused: %v", m)
	}
	_, perr := runCheck(t, tcpTemplate, env, protocol.TCPTemplateParams{Target: "127.0.0.1", Port: closes, Template: "ssh_banner"})
	wantCode(t, perr, protocol.CodeDenied)
}

func TestTemplateTLSWrap(t *testing.T) {
	ip := hostIP(t)
	_, port := tlsServer(t, ip, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	m := mustRun(t, tcpTemplate, testEnv(t, nil), protocol.TCPTemplateParams{Target: ip.String(), Port: port, Template: "http_head", TLS: true, ServerName: "example.com"})
	if m["outcome"] != "ok" || m["status_code"] != float64(200) || get(m, "tls", "verified") != false {
		t.Fatalf("result: %v", m)
	}
}
