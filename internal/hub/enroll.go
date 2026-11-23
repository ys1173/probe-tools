package hub

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"probetools/internal/protocol"
)

// maxEnrollBody is far more than an EnrollRequest needs; anything larger is not a probe.
const maxEnrollBody = 4 << 10

// handleEnroll exchanges a single-use token for a probe identity. Every refusal of a token is the same 401, so a caller
// cannot tell an unknown token from a used, revoked or expired one; the reason is logged instead.
//
// The endpoint is unauthenticated and internet-facing, so it is bounded on every axis: attempts per client, handlers
// running at once (per client and in total), time to send the body, and the body's size.
func (h *Hub) handleEnroll(w http.ResponseWriter, r *http.Request) {
	key := clientKey(r.RemoteAddr)
	if !h.enrollRate.allow(key) {
		h.logRefusal(h.enrollLog, "enrolment refused", key, r, "reason", "rate_limited")
		w.Header().Set("Retry-After", "60")
		refuse(w, "too many requests", http.StatusTooManyRequests)
		return
	}
	release, status := h.enrollSlots.acquire(key)
	if status != 0 {
		reason := "too_many_from_client"
		if status == http.StatusServiceUnavailable {
			reason = "too_many_in_total"
		}
		h.logRefusal(h.enrollLog, "enrolment refused", key, r, "reason", reason)
		w.Header().Set("Retry-After", strconv.Itoa(int(h.opts.EnrollReadTimeout.Seconds())+1))
		refuse(w, http.StatusText(status), status)
		return
	}
	defer release()

	log := h.log.With("remote", r.RemoteAddr)
	unauthorized := func(reason string) {
		log.Warn("enrolment refused", "reason", reason)
		refuse(w, "unauthorized", http.StatusUnauthorized)
	}

	// Handler already set a read deadline for the whole request; this one bounds how long a client trickling its body
	// can hold this handler, and its slot, from the moment it got the slot.
	if err := http.NewResponseController(w).SetReadDeadline(time.Now().Add(h.opts.EnrollReadTimeout)); err != nil {
		log.Error("enrolment refused", "reason", "no_read_deadline", "err", err)
		refuse(w, "internal error", http.StatusInternalServerError)
		return
	}
	var req protocol.EnrollRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxEnrollBody))
	if err != nil {
		unauthorized("bad_body")
		return
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Token == "" {
		unauthorized("bad_body")
		return
	}

	enr, err := h.store.Enroll(r.Context(), req.Token)
	var ee *EnrollError
	if errors.As(err, &ee) {
		unauthorized(ee.Reason)
		return
	}
	if err != nil {
		log.Error("enrolment failed", "err", err)
		refuse(w, "internal error", http.StatusInternalServerError)
		return
	}
	log.Info("probe enrolled", "probe", enr.Name, "site", enr.Site, "probe_id", enr.ProbeID,
		"hostname", protocol.UntrustedString(req.Hostname, 128).Text, "version", protocol.UntrustedString(req.Version, 64).Text)
	if enr.ReplacedID != "" {
		log.Info("probe replaced", "probe", enr.Name, "old_probe_id", enr.ReplacedID)
		// Close the old probe's session now rather than at the next revocation check.
		h.mu.Lock()
		old := h.sessions[enr.ReplacedID]
		h.mu.Unlock()
		if old != nil {
			old.closeWith(statusRevoked, "probe replaced")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(enr.EnrollResponse)
}
