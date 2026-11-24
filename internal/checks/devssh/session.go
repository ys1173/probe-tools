package devssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// runOutput is what a command produced.
type runOutput struct {
	raw       []byte
	truncated bool
	exit      *int
	err       error
}

// capBuf collects output up to a limit and signals each arrival.
type capBuf struct {
	mu        sync.Mutex
	buf       []byte
	limit     int
	truncated bool
	full      chan struct{} // closed once the limit is reached
	data      chan struct{} // gets a token whenever data arrives
}

func newCapBuf(limit int) *capBuf {
	return &capBuf{limit: limit, full: make(chan struct{}), data: make(chan struct{}, 1)}
}

func (c *capBuf) Write(p []byte) (int, error) {
	c.mu.Lock()
	if !c.truncated {
		room := c.limit - len(c.buf)
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
			c.truncated = true
			close(c.full)
		} else {
			c.buf = append(c.buf, p...)
		}
	}
	c.mu.Unlock()
	select {
	case c.data <- struct{}{}:
	default:
	}
	// Report everything as written: once full, the rest is discarded and the session is closed.
	return len(p), nil
}

func (c *capBuf) snapshot() ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf), c.truncated
}

func (c *capBuf) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.buf)
}

// tail returns the last n bytes from offset from on.
func (c *capBuf) tail(from, n int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.buf[min(from, len(c.buf)):]
	if len(b) > n {
		b = b[len(b)-n:]
	}
	return bytes.Clone(b)
}

// cut forgets bytes [from, len) of the buffer; used to drop a pager prompt that was answered.
func (c *capBuf) since(from int) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.buf[min(from, len(c.buf)):])
}

var disclaimer = regexp.MustCompile(`(?i)press 'a' to accept`)

// runExec runs command on the exec channel: the device's CLI runs it and closes the channel. Nothing else is sent
// except, if the device pages anyway, the pager key.
func runExec(ctx context.Context, client *ssh.Client, d driver, command string, limit int) runOutput {
	sess, err := client.NewSession()
	if err != nil {
		return runOutput{err: err}
	}
	defer sess.Close()
	buf := newCapBuf(limit)
	sess.Stdout = buf
	sess.Stderr = buf
	stdin, err := sess.StdinPipe()
	if err != nil {
		return runOutput{err: err}
	}
	if err := sess.Start(command); err != nil {
		return runOutput{err: err}
	}
	waited := make(chan error, 1)
	go func() { waited <- sess.Wait() }()

	var waitErr error
	answered := 0
loop:
	for {
		select {
		case waitErr = <-waited:
			break loop
		case <-buf.full:
			break loop
		case <-ctx.Done():
			waitErr = ctx.Err()
			break loop
		case <-buf.data:
			tail := buf.tail(0, 256)
			if disclaimer.Match(tail) {
				waitErr = errDisclaimer
				break loop
			}
			if d.atPager(tail) && answered < 10000 {
				answered++
				io.WriteString(stdin, d.pagerKey)
			}
		}
	}
	out, truncated := buf.snapshot()
	res := runOutput{raw: out, truncated: truncated}
	var ee *ssh.ExitError
	var missing *ssh.ExitMissingError
	switch {
	case waitErr == nil:
		zero := 0
		res.exit = &zero
	case errors.As(waitErr, &ee):
		st := ee.ExitStatus()
		res.exit = &st
	case errors.As(waitErr, &missing), errors.Is(waitErr, io.EOF):
		// Many device CLIs close the channel without an exit status; that is a normal end.
	case truncated && !errors.Is(waitErr, context.DeadlineExceeded):
	default:
		res.err = waitErr
	}
	return res
}

// shellSlack is room above the output limit for the login banner, the setup lines and the prompts in a shell
// session; the command's own output is still cut to the limit.
const shellSlack = 64 << 10

// promptSettle is how long the first prompt must stand without more output before it is taken as the prompt: some
// devices print the prompt, then more of the banner, then the prompt again.
const promptSettle = 300 * time.Millisecond

// runShell runs command in an interactive shell: it waits for the prompt, sends the driver's session-only setup lines,
// then the command, and collects what comes back until the prompt returns. The echoed command line and the final
// prompt are removed.
func runShell(ctx context.Context, client *ssh.Client, d driver, command string, limit int) runOutput {
	sess, err := client.NewSession()
	if err != nil {
		return runOutput{err: err}
	}
	defer sess.Close()
	buf := newCapBuf(limit + shellSlack)
	sess.Stdout = buf
	sess.Stderr = buf
	stdin, err := sess.StdinPipe()
	if err != nil {
		return runOutput{err: err}
	}
	// Height 0 asks for no paging where the device honours it; the width keeps long lines whole.
	if err := sess.RequestPty("vt100", 0, 511, ssh.TerminalModes{ssh.TTY_OP_ISPEED: 38400, ssh.TTY_OP_OSPEED: 38400}); err != nil {
		return runOutput{err: err}
	}
	if err := sess.Shell(); err != nil {
		return runOutput{err: err}
	}
	ended := make(chan error, 1)
	go func() { ended <- sess.Wait() }()

	prompt, err := waitFirstPrompt(ctx, buf, d, ended)
	if err != nil {
		out, tr := buf.snapshot()
		return runOutput{raw: out, truncated: tr, err: err}
	}
	for _, line := range d.setup {
		mark := buf.len()
		if _, err := io.WriteString(stdin, line+"\n"); err != nil {
			return runOutput{err: err}
		}
		if err := waitPrompt(ctx, buf, d, prompt, mark, stdin, ended); err != nil {
			return runOutput{err: err}
		}
	}
	mark := buf.len()
	if _, err := io.WriteString(stdin, command+"\n"); err != nil {
		return runOutput{err: err}
	}
	werr := waitPrompt(ctx, buf, d, prompt, mark, stdin, ended)
	out := clean(buf.since(mark))
	_, truncated := buf.snapshot()
	// Drop the echoed command: the first line, when it carries the command.
	if i := bytes.IndexByte(out, '\n'); i >= 0 && bytes.Contains(out[:i], []byte(command)) {
		out = out[i+1:]
	} else if i < 0 && bytes.Contains(out, []byte(command)) {
		out = nil
	}
	// Drop the prompt that ended the output.
	if werr == nil {
		if i := bytes.LastIndexByte(out, '\n'); i >= 0 {
			out = out[:i+1]
		} else {
			out = nil
		}
	}
	if len(out) > limit {
		out, truncated = out[:limit], true
	}
	res := runOutput{raw: out, truncated: truncated}
	if werr != nil && !(truncated && errors.Is(werr, errFull)) {
		res.err = werr
	}
	return res
}

var errFull = errors.New("output limit reached")

// waitFirstPrompt waits until the output ends with a line the driver's prompt pattern matches, and stays so for
// promptSettle; it returns that line.
func waitFirstPrompt(ctx context.Context, buf *capBuf, d driver, ended <-chan error) (string, error) {
	var candidate string
	settle := time.NewTimer(time.Hour)
	defer settle.Stop()
	for {
		select {
		case <-ctx.Done():
			return "", errNoPrompt
		case <-ended:
			return "", localErr{errors.New("the device closed the session before showing a prompt")}
		case <-buf.full:
			return "", localErr{errors.New("the device sent too much before showing a prompt")}
		case <-buf.data:
			tail := buf.tail(0, 512)
			if disclaimer.Match(tail) {
				return "", errDisclaimer
			}
			last := string(bytes.TrimRight(lastLine(clean(tail)), "\r"))
			if d.prompt.MatchString(last) {
				candidate = last
				settle.Reset(promptSettle)
			} else {
				candidate = ""
				settle.Stop()
			}
		case <-settle.C:
			if candidate != "" {
				return candidate, nil
			}
		}
	}
}

// waitPrompt waits until the output after mark ends with exactly the prompt, answering pager prompts on the way.
func waitPrompt(ctx context.Context, buf *capBuf, d driver, prompt string, mark int, stdin io.Writer, ended <-chan error) error {
	want := []byte(trimRightSpace(prompt))
	answered := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ended:
			return localErr{errors.New("the device closed the session before the command finished")}
		case <-buf.full:
			return errFull
		case <-buf.data:
			tail := clean(buf.tail(mark, 1024))
			last := bytes.TrimRight(lastLine(tail), " \r")
			// The prompt must follow a newline: the echoed command line itself starts with the prompt.
			if bytes.Equal(last, want) && bytes.IndexByte(tail, '\n') >= 0 {
				return nil
			}
			if d.atPager(tail) && answered < 10000 {
				answered++
				io.WriteString(stdin, d.pagerKey)
			}
		}
	}
}

func trimRightSpace(s string) string { return string(bytes.TrimRight([]byte(s), " \r")) }
