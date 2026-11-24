package hub

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"probetools/internal/hubapi"
	"probetools/internal/protocol"
)

var _ hubapi.Router = (*Hub)(nil)

// Run sends one job to the named probe and waits for its result. It never queues: a probe that is not connected
// answers CodeProbeOffline at once. On the deadline (plus slack) or when ctx ends it sends Cancel to the probe.
func (h *Hub) Run(ctx context.Context, probe, check string, params json.RawMessage, deadline time.Duration) protocol.ProbeResult {
	start := time.Now()
	out := protocol.ProbeResult{Probe: probe, StartedAt: start.UTC()}
	fail := func(code, format string, args ...any) protocol.ProbeResult {
		out.OK = false
		out.Error = protocol.Errorf(code, format, args...)
		out.DurationMS = time.Since(start).Milliseconds()
		return out
	}

	rec, err := h.store.ActiveProbe(context.WithoutCancel(ctx), probe)
	if errors.Is(err, ErrNotFound) {
		return fail(protocol.CodeProbeUnknown, "no probe is named %q", probe)
	}
	if err != nil {
		h.log.Error("probe lookup failed", "probe", probe, "err", err)
		return fail(protocol.CodeInternal, "probe lookup failed")
	}
	out.Site = rec.Site

	h.mu.Lock()
	s := h.sessions[rec.ID]
	h.mu.Unlock()
	if s == nil || s.isDone() {
		return fail(protocol.CodeProbeOffline, "probe is not connected")
	}

	// The hub never asks a probe for more than one job's budget.
	maxBudget := protocol.MaxCheckBudgetMS * time.Millisecond
	if deadline <= 0 || deadline > maxBudget {
		deadline = maxBudget
	}
	if len(params) == 0 {
		params = json.RawMessage("{}")
	}

	jobID := randomID(12)
	ch := make(chan protocol.Result, 1)
	// Register before sending, so a fast result cannot arrive before anyone waits for it.
	s.mu.Lock()
	s.pending[jobID] = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.pending, jobID)
		s.mu.Unlock()
	}()

	log := s.log.With("job_id", jobID, "check", check)
	job := protocol.Job{Type: protocol.TypeJob, ID: jobID, Check: check, Params: params, DeadlineMS: int(deadline.Milliseconds())}
	if err := s.write(job); err != nil {
		log.Warn("sending job failed", "err", err)
		return fail(protocol.CodeProbeOffline, "probe disconnected during the check")
	}

	timer := time.NewTimer(deadline + h.opts.Slack)
	defer timer.Stop()
	cancelJob := func() {
		if err := s.write(protocol.Cancel{Type: protocol.TypeCancel, ID: jobID}); err != nil {
			log.Warn("sending cancel failed", "err", err)
		}
	}

	select {
	case res := <-ch:
		out.DurationMS = res.DurationMS
		if !res.StartedAt.IsZero() {
			out.StartedAt = res.StartedAt
		}
		switch {
		case res.Error != nil:
			out.Error = res.Error
		case len(res.Data) > 0:
			out.OK = true
			out.Result = res.Data
		default:
			log.Warn("probe sent a result with neither data nor error")
			out.Error = protocol.Errorf(protocol.CodeInternal, "probe sent an empty result")
		}
		return out
	case <-s.done:
		return fail(protocol.CodeProbeOffline, "probe disconnected during the check")
	case <-timer.C:
		log.Info("job timed out; cancelling")
		cancelJob()
		return fail(protocol.CodeTimeout, "no result from the probe within %s", deadline+h.opts.Slack)
	case <-ctx.Done():
		cancelJob()
		if errors.Is(ctx.Err(), context.Canceled) {
			return fail(protocol.CodeCancelled, "the call was cancelled")
		}
		return fail(protocol.CodeTimeout, "the call's deadline passed before the probe answered")
	}
}

func (s *session) isDone() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

// Probes lists enrolled, unrevoked probes with their live state, sorted by name.
func (h *Hub) Probes() []hubapi.ProbeStatus {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	recs, err := h.store.ListProbes(ctx, false)
	if err != nil {
		h.log.Error("listing probes failed", "err", err)
		return nil
	}
	out := make([]hubapi.ProbeStatus, 0, len(recs))
	for _, r := range recs {
		out = append(out, h.status(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Probe returns one probe's status.
func (h *Hub) Probe(name string) (hubapi.ProbeStatus, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := h.store.ActiveProbe(ctx, name)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			h.log.Error("probe lookup failed", "probe", name, "err", err)
		}
		return hubapi.ProbeStatus{}, false
	}
	return h.status(r), true
}

// status merges a stored probe with its live session, if any. An offline probe shows its last hello.
func (h *Hub) status(r ProbeRecord) hubapi.ProbeStatus {
	st := hubapi.ProbeStatus{Name: r.Name, Site: r.Site, EnrolledAt: r.EnrolledAt, LastSeen: r.LastSeen}
	// Hellos stored before they were validated on arrival may hold anything; one that fails now is not shown.
	var hello *protocol.Hello
	if r.LastHello != nil {
		if v, err := validateHello(*r.LastHello); err == nil {
			hello = &v
		}
	}
	h.mu.Lock()
	s := h.sessions[r.ID]
	h.mu.Unlock()
	if s != nil && !s.isDone() {
		st.Online = true
		st.ConnectedAt = s.connectedAt
		st.LastSeen = s.lastSeen()
		hello = &s.hello
	}
	if hello != nil {
		st.Version = hello.Version
		st.OS = hello.OS
		st.Arch = hello.Arch
		st.Hostname = hello.Hostname
		st.Addresses = hello.Addresses
		st.Checks = hello.Checks
		st.Capabilities = hello.Capabilities
		st.Policy = hello.Policy
		st.ListenPorts = hello.ListenPorts
		st.SSH = hello.SSH
	}
	return st
}
