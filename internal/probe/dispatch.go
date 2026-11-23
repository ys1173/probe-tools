package probe

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
)

const (
	maxResultBytes = 900 << 10 // leaves room under the 1 MiB frame for the envelope
	// deadlineGrace is how long past a job's deadline the probe waits for the check to hand back a partial result. It
	// is well under protocol.HubSlackMS so the answer still reaches the hub in time.
	deadlineGrace = 500 * time.Millisecond
)

// Reasons a job's context ends early, told apart with context.Cause.
var (
	errCancelledByHub = errors.New("cancelled by the hub")
	errSessionEnded   = errors.New("link to the hub closed")
)

// dispatcher runs jobs under the probe's concurrency limit. It lives as long as the process: the Env (with path_test's
// listeners in its State, and the policy holding the per-address rate limit) and the concurrency count must survive
// reconnects.
type dispatcher struct {
	reg           *check.Registry
	env           *check.Env
	logger        *slog.Logger
	maxConcurrent int64
	running       atomic.Int64
	closing       atomic.Bool
	now           func() time.Time
	grace         time.Duration
}

func newDispatcher(reg *check.Registry, env *check.Env, limits Limits, logger *slog.Logger, now func() time.Time) *dispatcher {
	d := &dispatcher{
		reg:           reg,
		env:           env,
		logger:        logger,
		maxConcurrent: int64(limits.MaxConcurrent),
		now:           now,
		grace:         deadlineGrace,
	}
	env.Run = d.runNested
	return d
}

// stopAccepting makes every later job answer busy, for shutdown.
func (d *dispatcher) stopAccepting() { d.closing.Store(true) }

func (d *dispatcher) acquire() bool {
	if d.running.Add(1) > d.maxConcurrent {
		d.running.Add(-1)
		return false
	}
	return true
}

func (d *dispatcher) release() { d.running.Add(-1) }

// session tracks the jobs started on one connection, so a cancel can find its job and a dropped connection can stop
// them all.
type session struct {
	send func(any) error
	mu   sync.Mutex
	jobs map[string]context.CancelCauseFunc
	done bool
	wg   sync.WaitGroup
}

func newSession(send func(any) error) *session {
	return &session{send: send, jobs: map[string]context.CancelCauseFunc{}}
}

// add registers a job; false when the id is already running or the session has ended.
func (s *session) add(id string, cancel context.CancelCauseFunc) (dup, ended bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return false, true
	}
	if _, ok := s.jobs[id]; ok {
		return true, false
	}
	s.jobs[id] = cancel
	s.wg.Add(1)
	return false, false
}

func (s *session) remove(id string) {
	s.mu.Lock()
	delete(s.jobs, id)
	s.mu.Unlock()
	s.wg.Done()
}

func (s *session) cancel(id string) bool {
	s.mu.Lock()
	c, ok := s.jobs[id]
	s.mu.Unlock()
	if ok {
		c(errCancelledByHub)
	}
	return ok
}

func (s *session) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.jobs)
}

// abort stops every job; their results are not sent, since there is no connection to send them on.
func (s *session) abort() {
	s.mu.Lock()
	s.done = true
	for _, c := range s.jobs {
		c(errSessionEnded)
	}
	s.mu.Unlock()
}

// handleJob starts one job, or answers it at once when it cannot run. It is called from the read loop, so it must not
// block.
func (d *dispatcher) handleJob(s *session, job protocol.Job) {
	started := d.now()
	// The target is only for the log line. The rate limit is enforced by the policy on the addresses a check resolves,
	// since the parameters can spell one host many ways.
	key := logTarget(job.Check, job.Params)
	if job.ID == "" {
		d.logger.Warn("ignoring job without an id", "check", logText(job.Check))
		return
	}
	answer := func(perr *protocol.Error) {
		d.finish(s, job, key, started, nil, perr)
	}
	f, ok := d.reg.Get(job.Check)
	if !ok {
		answer(protocol.Errorf(protocol.CodeNotFound, "this probe has no check %q", logText(job.Check)))
		return
	}
	if d.closing.Load() {
		answer(protocol.Errorf(protocol.CodeBusy, "the probe is shutting down"))
		return
	}
	if !d.acquire() {
		answer(protocol.Errorf(protocol.CodeBusy, "the probe is already running its limit of %d jobs", d.maxConcurrent))
		return
	}
	budget := time.Duration(protocol.MaxCheckBudgetMS) * time.Millisecond
	if job.DeadlineMS > 0 && job.DeadlineMS < protocol.MaxCheckBudgetMS {
		budget = time.Duration(job.DeadlineMS) * time.Millisecond
	}
	// WithJob makes the policy charge this job, nested checks included, once per address it contacts.
	base, cancelCause := context.WithCancelCause(policy.WithJob(context.Background()))
	ctx, cancelTimeout := context.WithTimeout(base, budget)
	dup, ended := s.add(job.ID, cancelCause)
	if dup || ended {
		cancelTimeout()
		cancelCause(nil)
		d.release()
		if dup {
			answer(protocol.Errorf(protocol.CodeInvalidParams, "a job with this id is already running"))
		}
		return
	}
	go func() {
		defer s.remove(job.ID)
		defer cancelCause(nil)
		defer cancelTimeout()
		v, perr, deliver := d.runJob(ctx, f, job)
		if !deliver {
			d.logger.Info("job", "job_id", logText(job.ID), "check", job.Check, "target", key,
				"code", "dropped", "duration_ms", d.now().Sub(started).Milliseconds())
			return
		}
		d.finish(s, job, key, started, v, perr)
	}()
}

type outcome struct {
	v    any
	perr *protocol.Error
}

// runJob runs the check in its own goroutine and waits for it, its cancellation or its deadline. A check that ignores
// its context is abandoned after the grace period so the hub still gets an answer; it keeps its concurrency slot until
// it really returns, so a misbehaving check cannot make the probe run more than its limit. deliver is false when the
// session ended and there is nobody to answer.
func (d *dispatcher) runJob(ctx context.Context, f check.Func, job protocol.Job) (any, *protocol.Error, bool) {
	done := make(chan outcome, 1)
	go func() {
		defer d.release()
		defer func() {
			if r := recover(); r != nil {
				d.logger.Error("check panicked", "job_id", logText(job.ID), "check", job.Check, "stack", string(debug.Stack()))
				done <- outcome{perr: protocol.Errorf(protocol.CodeInternal, "the check failed unexpectedly")}
			}
		}()
		v, perr := f(ctx, d.env, job.Params)
		done <- outcome{v: v, perr: perr}
	}()

	var out outcome
	select {
	case out = <-done:
	case <-ctx.Done():
		if errors.Is(context.Cause(ctx), context.DeadlineExceeded) {
			t := time.NewTimer(d.grace)
			select {
			case out = <-done:
			case <-t.C:
				d.logger.Warn("check overran its deadline", "job_id", logText(job.ID), "check", job.Check)
				out = outcome{perr: protocol.Errorf(protocol.CodeTimeout, "the check did not finish within its deadline")}
			}
			t.Stop()
		}
	}
	switch context.Cause(ctx) {
	case errSessionEnded:
		return nil, nil, false
	case errCancelledByHub:
		return nil, protocol.Errorf(protocol.CodeCancelled, "the hub cancelled the job"), true
	}
	return out.v, out.perr, true
}

// finish encodes and sends the one result for a job, and logs it.
func (d *dispatcher) finish(s *session, job protocol.Job, key string, started time.Time, v any, perr *protocol.Error) {
	res := protocol.Result{Type: protocol.TypeResult, ID: job.ID, StartedAt: started.UTC()}
	if perr == nil {
		data, err := json.Marshal(v)
		switch {
		case err != nil:
			d.logger.Error("could not encode a check's result", "job_id", logText(job.ID), "check", job.Check, "error", err.Error())
			perr = protocol.Errorf(protocol.CodeInternal, "the result could not be encoded")
		case len(data) > maxResultBytes:
			perr = protocol.Errorf(protocol.CodeInternal, "result too large (%d bytes, limit %d)", len(data), maxResultBytes)
		default:
			res.Data = data
		}
	}
	res.Error = perr
	dur := d.now().Sub(started)
	res.DurationMS = dur.Milliseconds()
	code := "ok"
	if perr != nil {
		code = perr.Code
	}
	attrs := []any{"job_id", logText(job.ID), "check", logText(job.Check), "target", key, "code", code, "duration_ms", res.DurationMS}
	if err := s.send(res); err != nil {
		d.logger.Warn("job result could not be sent", append(attrs, "error", err.Error())...)
		return
	}
	d.logger.Info("job", attrs...)
}

// runNested is Env.Run: a composite check runs another check as part of its own job. It shares the outer job's
// context, so it is not counted again against the concurrency limit, and the policy charges an address the outer job
// already paid for only once.
func (d *dispatcher) runNested(ctx context.Context, name string, params any) (v any, perr *protocol.Error) {
	f, ok := d.reg.Get(name)
	if !ok {
		return nil, protocol.Errorf(protocol.CodeNotFound, "this probe has no check %q", name)
	}
	var raw json.RawMessage
	switch p := params.(type) {
	case nil:
	case json.RawMessage:
		raw = p
	case []byte:
		raw = p
	default:
		b, err := json.Marshal(p)
		if err != nil {
			return nil, protocol.Errorf(protocol.CodeInternal, "encoding parameters for %s: %v", name, err)
		}
		raw = b
	}
	defer func() {
		if r := recover(); r != nil {
			d.logger.Error("check panicked", "check", name, "nested", true, "stack", string(debug.Stack()))
			v, perr = nil, protocol.Errorf(protocol.CodeInternal, "the check %s failed unexpectedly", name)
		}
	}()
	return f(ctx, d.env, raw)
}

// logTarget names what a job is aimed at, for its log line: the "target" parameter, else the host of "url", else
// "name", else "address". path_test's receiving side is aimed at nothing.
func logTarget(checkName string, params json.RawMessage) string {
	if checkName == protocol.CheckListenStart || checkName == protocol.CheckListenCollect {
		return ""
	}
	var m map[string]json.RawMessage
	if len(params) == 0 || json.Unmarshal(params, &m) != nil {
		return ""
	}
	for _, field := range []string{"target", "url", "name", "address"} {
		raw, ok := m[field]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			continue
		}
		if k := normalizeKey(s); k != "" {
			return k
		}
	}
	return ""
}

// normalizeKey tidies a target for the log, and keeps only the host of a URL so user info in it never reaches the logs.
func normalizeKey(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return ""
		}
		s = u.Hostname()
	}
	s = strings.TrimSuffix(strings.Trim(s, "[]"), ".")
	return logText(s)
}

// logText bounds text from the hub before it goes into a log line. slog's JSON handler escapes control characters;
// this keeps lines short.
func logText(s string) string {
	const max = 255
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}
