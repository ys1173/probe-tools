package devssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Test SSH servers that behave like the device CLIs the drivers are written for. They run on this host's
// non-loopback address, since the policy refuses loopback.

type serverOpts struct {
	kind     string // "exec" (IOS-like), "panos", "edgeos", "routeros", "jump"
	user     string
	password string
	kbdOnly  bool          // offer keyboard-interactive only
	both     bool          // offer password and keyboard-interactive
	pubkey   ssh.PublicKey // accept this key
	legacy   bool          // offer only group1-sha1, aes128-cbc and ssh-rsa (SHA-1)
	reprompt int           // keyboard-interactive asks again after a wrong answer, up to this many times
	prompt   string        // the keyboard-interactive question; "Password: " by default
	hostKey  ssh.Signer
}

type devServer struct {
	t        *testing.T
	opts     serverOpts
	port     int
	conns    atomic.Int32 // TCP connections accepted
	attempts atomic.Int32 // passwords received (password or keyboard-interactive)
	release  chan struct{}

	mu       sync.Mutex
	lines    []string // exec commands and shell lines, in order
	ptySeen  bool
	directTo []string // direct-tcpip destinations asked of a jump
}

func newServer(t *testing.T, ip netip.Addr, o serverOpts) *devServer {
	t.Helper()
	if o.user == "" {
		o.user = "netops"
	}
	if o.hostKey == nil {
		o.hostKey = edSigner(t)
	}
	s := &devServer{t: t, opts: o, release: make(chan struct{})}
	cfg := &ssh.ServerConfig{ServerVersion: "SSH-2.0-TestDevice"}
	if o.legacy {
		cfg.Config = ssh.Config{KeyExchanges: []string{ssh.InsecureKeyExchangeDH1SHA1}, Ciphers: []string{ssh.InsecureCipherAES128CBC},
			MACs: []string{ssh.HMACSHA1}}
		rk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		sg, _ := ssh.NewSignerFromKey(rk)
		alg, err := ssh.NewSignerWithAlgorithms(sg.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
		if err != nil {
			t.Fatal(err)
		}
		cfg.AddHostKey(alg)
	} else {
		cfg.AddHostKey(o.hostKey)
	}
	if o.password != "" && !o.kbdOnly {
		cfg.PasswordCallback = func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			s.attempts.Add(1)
			if c.User() == o.user && string(pw) == o.password {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		}
	}
	if o.password != "" && (o.kbdOnly || o.both) {
		cfg.KeyboardInteractiveCallback = func(c ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for range max(1, o.reprompt) {
				prompt := o.prompt
				if prompt == "" {
					prompt = "Password: "
				}
				ans, err := ch("", "", []string{prompt}, []bool{false})
				if err != nil {
					return nil, err
				}
				s.attempts.Add(1)
				if c.User() == o.user && len(ans) == 1 && ans[0] == o.password {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("denied")
		}
	}
	if o.pubkey != nil {
		cfg.PublicKeyCallback = func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if c.User() == o.user && bytes.Equal(k.Marshal(), o.pubkey.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		}
	}
	ln, err := net.Listen("tcp", netip.AddrPortFrom(ip, 0).String())
	if err != nil {
		t.Fatal(err)
	}
	s.port = ln.Addr().(*net.TCPAddr).Port
	t.Cleanup(func() {
		ln.Close()
		select {
		case <-s.release:
		default:
			close(s.release)
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.conns.Add(1)
			go s.serve(c, cfg)
		}
	}()
	return s
}

func (s *devServer) record(line string) {
	s.mu.Lock()
	s.lines = append(s.lines, line)
	s.mu.Unlock()
}

func (s *devServer) seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.lines...)
}

func (s *devServer) serve(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, creqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go s.session(ch, creqs)
		case "direct-tcpip":
			if s.opts.kind != "jump" {
				nc.Reject(ssh.Prohibited, "no forwarding")
				continue
			}
			go s.direct(nc)
		default:
			nc.Reject(ssh.UnknownChannelType, "unknown")
		}
	}
}

func (s *devServer) direct(nc ssh.NewChannel) {
	var d struct {
		Host     string
		Port     uint32
		OrigHost string
		OrigPort uint32
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &d); err != nil {
		nc.Reject(ssh.ConnectionFailed, "bad request")
		return
	}
	s.mu.Lock()
	s.directTo = append(s.directTo, d.Host)
	s.mu.Unlock()
	conn, err := net.Dial("tcp", net.JoinHostPort(d.Host, strconv.Itoa(int(d.Port))))
	if err != nil {
		nc.Reject(ssh.ConnectionFailed, "Connection refused")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go func() { io.Copy(ch, conn); ch.CloseWrite(); ch.Close() }()
	go func() { io.Copy(conn, ch); conn.Close() }()
}

func (s *devServer) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			s.mu.Lock()
			s.ptySeen = true
			s.mu.Unlock()
			req.Reply(true, nil)
		case "exec":
			var p struct{ Command string }
			ssh.Unmarshal(req.Payload, &p)
			req.Reply(true, nil)
			s.record(p.Command)
			go s.exec(ch, p.Command)
		case "shell":
			req.Reply(true, nil)
			go s.shell(ch)
		default:
			req.Reply(false, nil)
		}
	}
}

func exit(ch ssh.Channel, status int) {
	ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
	ch.Close()
}

// exec emulates a CLI that runs one command given on the exec channel.
func (s *devServer) exec(ch ssh.Channel, cmd string) {
	w := func(t string) { io.WriteString(ch, t) }
	switch s.opts.kind {
	case "edgeos":
		// EdgeOS's exec channel runs a plain bash: operational commands do not exist there.
		w("bash: " + strings.Fields(cmd + " x")[0] + ": command not found\r\n")
		exit(ch, 127)
		return
	case "routeros":
		switch cmd {
		case "/interface print":
			w("Flags: R - RUNNING\r\n #   NAME      TYPE   MTU\r\n 0 R ether1    ether  1500\r\n")
		default:
			w("bad command name " + strings.Fields(cmd + " x")[0] + " (line 1 column 1)\r\n")
		}
		exit(ch, 0)
		return
	}
	switch cmd {
	case "show version":
		w("Cisco IOS Software, Test Software\r\nuptime is 1 day\r\n")
	case "show big":
		line := strings.Repeat("x", 99) + "\n"
		for i := 0; i < 2000; i++ {
			if _, err := io.WriteString(ch, line); err != nil {
				break
			}
		}
	case "show color":
		w("\x1b[31mred\x1b[0m and a nul \x00 and <tag>\r\n")
	case "show paged":
		w("page one\r\n --More-- ")
		b := make([]byte, 1)
		if _, err := ch.Read(b); err != nil || b[0] != ' ' {
			ch.Close()
			return
		}
		w("\b\b\b\b\b\b\b\b\b\b          \b\b\b\b\b\b\b\b\b\bpage two\r\n")
	case "show slow":
		select {
		case <-s.release:
		case <-time.After(15 * time.Second):
		}
		w("late\r\n")
	default:
		w("              ^\r\n% Invalid input detected at '^' marker.\r\n")
	}
	exit(ch, 0)
}

// shell emulates an interactive CLI with a prompt and echo (PAN-OS and EdgeOS shapes).
func (s *devServer) shell(ch ssh.Channel) {
	defer ch.Close()
	s.mu.Lock()
	pty := s.ptySeen
	s.mu.Unlock()
	if !pty {
		io.WriteString(ch, "no terminal\r\n")
		return
	}
	var prompt string
	pagerOn := true
	switch s.opts.kind {
	case "panos":
		prompt = "admin@PA-VM> "
		// PAN-OS prints its prompt, then more, then the prompt again.
		io.WriteString(ch, "\x1b[?1h\x1b=Last login: Mon\r\n\r\n"+prompt)
		time.Sleep(50 * time.Millisecond)
		io.WriteString(ch, "\r\nNumber of failed attempts since last successful login: 0\r\n\r\n"+prompt)
	case "edgeos":
		prompt = "ubnt@edge:~$ "
		io.WriteString(ch, "Welcome to EdgeOS\r\n"+prompt)
	}
	var line []byte
	buf := make([]byte, 256)
	for {
		n, err := ch.Read(buf)
		if err != nil {
			return
		}
		for _, c := range buf[:n] {
			if c != '\r' && c != '\n' {
				line = append(line, c)
				ch.Write([]byte{c}) // echo
				continue
			}
			cmd := string(line)
			line = line[:0]
			s.record(cmd)
			io.WriteString(ch, "\r\n")
			switch {
			case cmd == "":
			case s.opts.kind == "panos" && cmd == "set cli pager off":
				pagerOn = false
			case s.opts.kind == "edgeos" && cmd == "terminal length 0":
				pagerOn = false
			case cmd == "show system info" || cmd == "show interfaces":
				if pagerOn {
					// A pager the driver did not turn off would hang here.
					io.WriteString(ch, "first page\r\n:")
					ch.Read(make([]byte, 1))
				}
				io.WriteString(ch, "hostname: test-device\r\nip-address: 192.0.2.1\r\n")
			case s.opts.kind == "panos":
				io.WriteString(ch, "Unknown command: "+strings.Fields(cmd)[0]+"\r\n")
			default:
				io.WriteString(ch, "\r\n  Invalid command: ["+strings.Fields(cmd)[0]+"]\r\n\r\n")
			}
			io.WriteString(ch, prompt)
		}
	}
}

func edSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
