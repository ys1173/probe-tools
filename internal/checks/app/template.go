package app

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

const (
	maxReplyBytes = 32 << 10 // the most any template reads from a service
	maxLineBytes  = 1024
	maxReplyLines = 50
	quitWait      = time.Second // how long to wait for the reply to QUIT, which is only a courtesy
)

// headerSet is the fixed set of response headers reported by http_head and http_check.
var headerSet = []string{"Server", "Location", "Content-Type", "Content-Length", "Strict-Transport-Security", "Via",
	"X-Cache", "Retry-After"}

// templateResult carries the common fields and, flattened, the fields of each template; only the template's own are
// set.
type templateResult struct {
	Target    string              `json:"target"`
	Address   string              `json:"address"`
	Port      int                 `json:"port"`
	Template  string              `json:"template"`
	ConnectMS float64             `json:"connect_ms"`
	Outcome   string              `json:"outcome"` // ok | refused | timeout | closed | unexpected_reply | unreachable | tls_failed | error
	Detail    string              `json:"detail,omitempty"`
	TLS       *tlsInfo            `json:"tls,omitempty"`
	Raw       *protocol.Untrusted `json:"raw,omitempty"` // the first bytes received, when they did not parse

	// noRaw is set once an HTTP status line has parsed: from then on the raw bytes are headers outside the fixed set
	// (cookies, for one), which are not reported.
	noRaw bool

	// http_head
	StatusCode int                           `json:"status_code,omitempty"`
	StatusLine *protocol.Untrusted           `json:"status_line,omitempty"`
	Headers    map[string]protocol.Untrusted `json:"headers,omitempty"`
	// redis_ping
	Reply          *protocol.Untrusted `json:"reply,omitempty"`
	Interpretation string              `json:"interpretation,omitempty"` // pong | auth_required | error | other
	// smtp_ehlo and ftp_banner
	GreetingCode    int                  `json:"greeting_code,omitempty"`
	Greeting        *protocol.Untrusted  `json:"greeting,omitempty"`
	EHLOCode        int                  `json:"ehlo_code,omitempty"`
	Extensions      []protocol.Untrusted `json:"extensions,omitempty"`
	StartTLSOffered *bool                `json:"starttls_offered,omitempty"`
	// ssh_banner
	Banner *protocol.Untrusted `json:"banner,omitempty"`
	// mysql_greeting
	ProtocolVersion *int                `json:"protocol_version,omitempty"`
	ServerVersion   *protocol.Untrusted `json:"server_version,omitempty"`
	ErrorCode       int                 `json:"error_code,omitempty"`
	ErrorMessage    *protocol.Untrusted `json:"error_message,omitempty"`
	// postgres_ssl
	TLSOffered *bool `json:"tls_offered,omitempty"`
}

// errUnexpected marks a reply that arrived but is not what the protocol sends.
var errUnexpected = errors.New("unexpected reply")

func tcpTemplate(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.TCPTemplateParams
	if e := check.Decode(raw, &p); e != nil {
		return nil, e
	}
	host := ""
	if p.Template == protocol.TemplateHTTPHead {
		var e *protocol.Error
		if host, e = httpHostHeader(&p); e != nil {
			return nil, e
		}
	}
	addr, e := resolveTarget(ctx, env, p.Target, p.Family)
	if e != nil {
		return nil, e
	}
	res := &templateResult{Target: p.Target, Address: addr.String(), Port: p.Port, Template: p.Template}

	// One deadline covers connecting and the whole exchange.
	deadline := within(ctx, millis(p.TimeoutMS))
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	start := time.Now()
	conn, err := dialChecked(ctx, &net.Dialer{}, "tcp", addr, p.Port)
	res.ConnectMS = msSince(start)
	if err != nil {
		res.Outcome, res.Detail = dialOutcome(err), err.Error()
		return res, nil
	}
	defer conn.Close()
	stop := watch(ctx, conn)
	defer stop()
	_ = conn.SetDeadline(deadline)

	if p.TLS {
		serverName := p.ServerName
		if serverName == "" && !isAddr(p.Target) {
			serverName = p.Target
		}
		verifyName := serverName
		if verifyName == "" {
			verifyName = p.Target
		}
		var alpn []string
		if p.Template == protocol.TemplateHTTPHead {
			alpn = []string{"http/1.1"}
		}
		tc, info := handshake(ctx, conn, serverName, verifyName, alpn, time.Until(deadline))
		res.TLS = info
		if tc == nil {
			res.Outcome = "tls_failed"
			return res, nil
		}
		conn = tc
		_ = conn.SetDeadline(deadline)
	}

	cr := &captureReader{r: io.LimitReader(conn, maxReplyBytes)}
	br := bufio.NewReaderSize(cr, 4096)
	switch p.Template {
	case protocol.TemplateHTTPHead:
		err = runHTTPHead(conn, br, host, p.Path, res)
	case protocol.TemplateRedisPing:
		err = runRedisPing(conn, br, res)
	case protocol.TemplateSMTPEHLO:
		err = runSMTP(conn, br, res)
	case protocol.TemplateSSHBanner:
		err = runSSH(br, res)
	case protocol.TemplateMySQLGreeting:
		err = runMySQL(br, res)
	case protocol.TemplatePostgresSSL:
		err = runPostgresSSL(conn, br, res)
	case protocol.TemplateFTPBanner:
		err = runFTP(conn, br, res)
	}
	switch {
	case err == nil:
		res.Outcome = "ok"
	case errors.Is(err, errUnexpected) || (len(cr.buf) > 0 && !isTimeout(err) && !isClosed(err)):
		res.Outcome = "unexpected_reply"
	case isTimeout(err):
		res.Outcome = "timeout"
		res.Detail = "no complete reply before the deadline"
	case isClosed(err):
		res.Outcome = "closed"
		res.Detail = "the service closed the connection"
	default:
		res.Outcome, res.Detail = "error", err.Error()
	}
	if res.Outcome != "ok" && !res.noRaw && len(cr.buf) > 0 {
		res.Raw = untrusted(string(cr.buf), protocol.MaxBannerBytes)
	}
	return res, nil
}

// httpHostHeader builds the Host header for http_head: host_header as given, or the target with the port when it is not
// the scheme's default. The result is checked here again before it is written to the wire, so the request stays safe
// even if target validation elsewhere changes.
func httpHostHeader(p *protocol.TCPTemplateParams) (string, *protocol.Error) {
	host := p.HostHeader
	if host == "" {
		host = p.Target
		if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && a.Is6() {
			host = "[" + a.String() + "]"
		}
		def := 80
		if p.TLS {
			def = 443
		}
		if p.Port != def {
			host += ":" + strconv.Itoa(p.Port)
		}
	}
	if host == "" || len(host) > 300 {
		return "", protocol.Errorf(protocol.CodeInvalidParams, "Host header must be 1 to 300 characters")
	}
	for i := 0; i < len(host); i++ {
		if host[i] <= 0x20 || host[i] >= 0x7f {
			return "", protocol.Errorf(protocol.CodeInvalidParams, "Host header must be printable ASCII without spaces")
		}
	}
	return host, nil
}

func runHTTPHead(w io.Writer, br *bufio.Reader, host, path string, res *templateResult) error {
	req := "HEAD " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: probe\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(w, req); err != nil {
		return err
	}
	// The response is parsed here rather than with http.ReadResponse, which refuses headers with control characters:
	// a server that sends them should still be described, with the odd bytes escaped.
	status, err := readLine(br)
	if err != nil {
		return err
	}
	status = strings.TrimRight(status, "\r\n")
	f := strings.SplitN(status, " ", 3)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/") || len(f[1]) != 3 {
		return errUnexpected
	}
	code, err := strconv.Atoi(f[1])
	if err != nil || code < 100 || code > 599 {
		return errUnexpected
	}
	res.noRaw = true
	h := http.Header{}
	last := ""
	for i := 0; ; i++ {
		if i == 100 {
			return errUnexpected
		}
		line, err := readHeaderLine(br)
		if err != nil {
			return err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && last != "" { // obsolete line folding continues the previous header
			vals := h[last]
			vals[len(vals)-1] += " " + strings.TrimSpace(line)
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return errUnexpected
		}
		last = http.CanonicalHeaderKey(strings.TrimSpace(name))
		h[last] = append(h[last], strings.TrimSpace(value))
	}
	res.StatusCode = code
	res.StatusLine = untrusted(status, protocol.MaxHeaderBytes)
	res.Headers = pickHeaders(h)
	return nil
}

// readHeaderLine reads one header line, keeping its first maxLineBytes and discarding the rest: long headers
// (Content-Security-Policy, Set-Cookie) are normal, and maxReplyBytes still bounds the whole response.
func readHeaderLine(br *bufio.Reader) (string, error) {
	line, err := readLine(br)
	if !errors.Is(err, errUnexpected) || len(line) < maxLineBytes {
		return line, err
	}
	for {
		b, err := br.ReadByte()
		if err != nil {
			return line, err
		}
		if b == '\n' {
			return line, nil
		}
	}
}

// pickHeaders returns the fixed header set, each as untrusted text, joining repeated headers with ", ".
func pickHeaders(h http.Header) map[string]protocol.Untrusted {
	out := map[string]protocol.Untrusted{}
	for _, name := range headerSet {
		if v := h.Values(name); len(v) > 0 {
			out[name] = protocol.UntrustedString(strings.Join(v, ", "), protocol.MaxHeaderBytes)
		}
	}
	return out
}

func runRedisPing(w io.Writer, br *bufio.Reader, res *templateResult) error {
	if _, err := io.WriteString(w, "PING\r\n"); err != nil {
		return err
	}
	line, err := readLine(br)
	if err != nil {
		return err
	}
	text := strings.TrimRight(line, "\r\n")
	res.Reply = untrusted(text, protocol.MaxBannerBytes)
	upper := strings.ToUpper(text)
	switch {
	case upper == "+PONG":
		res.Interpretation = "pong"
	case strings.HasPrefix(upper, "-NOAUTH") || strings.Contains(upper, "AUTHENTICATION REQUIRED"):
		res.Interpretation = "auth_required"
	case strings.HasPrefix(text, "-"):
		res.Interpretation = "error"
	default:
		res.Interpretation = "other"
	}
	if text == "" || !strings.ContainsRune("+-:$*_#,(!=%~>|", rune(text[0])) {
		return errUnexpected // not RESP at all
	}
	return nil
}

func runSMTP(w io.Writer, br *bufio.Reader, res *templateResult) error {
	code, lines, err := readCodedReply(br)
	if err != nil {
		return err
	}
	res.GreetingCode = code
	res.Greeting = untrusted(strings.Join(lines, "\n"), protocol.MaxBannerBytes)
	if code == 220 {
		if _, err := io.WriteString(w, "EHLO probe.invalid\r\n"); err != nil {
			return err
		}
		code, lines, err = readCodedReply(br)
		if err != nil {
			return err
		}
		res.EHLOCode = code
		offered := false
		if code == 250 && len(lines) > 1 {
			for _, ext := range lines[1:] {
				res.Extensions = append(res.Extensions, protocol.UntrustedString(ext, protocol.MaxHeaderBytes))
				if f := strings.Fields(ext); len(f) > 0 && strings.EqualFold(f[0], "STARTTLS") {
					offered = true
				}
			}
		}
		res.StartTLSOffered = &offered
	}
	sayQuit(w, br)
	return nil
}

func runFTP(w io.Writer, br *bufio.Reader, res *templateResult) error {
	code, lines, err := readCodedReply(br)
	if err != nil {
		return err
	}
	res.GreetingCode = code
	res.Greeting = untrusted(strings.Join(lines, "\n"), protocol.MaxBannerBytes)
	sayQuit(w, br)
	return nil
}

// sayQuit ends an SMTP or FTP session politely. Its reply does not change the result, so errors are ignored.
func sayQuit(w io.Writer, br *bufio.Reader) {
	if _, err := io.WriteString(w, "QUIT\r\n"); err != nil {
		return
	}
	if c, ok := w.(net.Conn); ok {
		_ = c.SetReadDeadline(time.Now().Add(quitWait))
	}
	_, _, _ = readCodedReply(br)
}

func runSSH(br *bufio.Reader, res *templateResult) error {
	// RFC 4253 lets a server send other lines before its version line.
	for i := 0; i < 10; i++ {
		line, err := readLine(br)
		if err != nil {
			return err
		}
		if strings.HasPrefix(line, "SSH-") {
			res.Banner = untrusted(strings.TrimRight(line, "\r\n"), protocol.MaxBannerBytes)
			return nil
		}
	}
	return errUnexpected
}

func runMySQL(br *bufio.Reader, res *templateResult) error {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return err
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if length == 0 || length > 1<<16 {
		return errUnexpected
	}
	payload := make([]byte, min(length, 1024))
	if _, err := io.ReadFull(br, payload); err != nil {
		if isTimeout(err) {
			return err
		}
		return errUnexpected
	}
	switch payload[0] {
	case 0xff: // error packet: the server refuses this client, e.g. "Host is not allowed to connect"
		if len(payload) < 3 {
			return errUnexpected
		}
		res.ErrorCode = int(binary.LittleEndian.Uint16(payload[1:3]))
		msg := payload[3:]
		if len(msg) >= 6 && msg[0] == '#' { // SQL state marker and five-character state
			msg = msg[6:]
		}
		res.ErrorMessage = untrusted(string(msg), protocol.MaxBannerBytes)
	case 9, 10: // handshake v9 and v10: the server version follows as a NUL-terminated string
		v := int(payload[0])
		res.ProtocolVersion = &v
		ver := payload[1:]
		if i := strings.IndexByte(string(ver), 0); i >= 0 {
			ver = ver[:i]
		}
		res.ServerVersion = untrusted(string(ver), protocol.MaxHeaderBytes)
	default:
		return errUnexpected
	}
	return nil
}

func runPostgresSSL(w io.Writer, br *bufio.Reader, res *templateResult) error {
	// SSLRequest: length 8, then the request code 80877103.
	req := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
	if _, err := w.Write(req); err != nil {
		return err
	}
	b, err := br.ReadByte()
	if err != nil {
		return err
	}
	var offered bool
	switch b {
	case 'S':
		offered = true
	case 'N':
	default:
		return errUnexpected
	}
	res.TLSOffered = &offered
	return nil
}

// readLine reads one line of at most maxLineBytes, newline included.
func readLine(br *bufio.Reader) (string, error) {
	var sb strings.Builder
	for sb.Len() < maxLineBytes {
		b, err := br.ReadByte()
		if err != nil {
			if sb.Len() > 0 && isClosed(err) {
				return sb.String(), errUnexpected // a partial line, then the connection closed
			}
			return sb.String(), err
		}
		sb.WriteByte(b)
		if b == '\n' {
			return sb.String(), nil
		}
	}
	return sb.String(), errUnexpected
}

// readCodedReply reads an SMTP or FTP reply: "ddd text", or "ddd-text" lines up to a final "ddd text". It returns the
// code and each line's text without the code.
func readCodedReply(br *bufio.Reader) (int, []string, error) {
	var lines []string
	code := 0
	for i := 0; i < maxReplyLines; i++ {
		line, err := readLine(br)
		if err != nil {
			return code, lines, err
		}
		line = strings.TrimRight(line, "\r\n")
		if i == 0 {
			if len(line) < 3 {
				return 0, nil, errUnexpected
			}
			c, err := strconv.Atoi(line[:3])
			if err != nil || c < 100 || c > 599 {
				return 0, nil, errUnexpected
			}
			code = c
		}
		prefix := strconv.Itoa(code)
		if !strings.HasPrefix(line, prefix) {
			lines = append(lines, line) // FTP allows free-form lines inside a multi-line reply
			continue
		}
		rest := line[3:]
		if rest == "" || rest[0] == ' ' {
			lines = append(lines, strings.TrimPrefix(rest, " "))
			return code, lines, nil
		}
		if rest[0] != '-' {
			return code, lines, errUnexpected
		}
		lines = append(lines, rest[1:])
	}
	return code, lines, errUnexpected
}

// captureReader keeps the first bytes read through it, to show when a reply does not parse.
type captureReader struct {
	r   io.Reader
	buf []byte
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if room := protocol.MaxBannerBytes - len(c.buf); room > 0 && n > 0 {
		c.buf = append(c.buf, p[:min(n, room)]...)
	}
	return n, err
}
