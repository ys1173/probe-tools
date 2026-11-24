package mcpserver

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"probetools/internal/hubapi"
	"probetools/internal/protocol"
)

// path_test verdicts.
const (
	VerdictReached          = "reached"            // the nonce arrived from one of the sender's own addresses
	VerdictReachedViaNAT    = "reached_via_nat"    // the nonce arrived, from an address the sender does not have
	VerdictIntercepted      = "intercepted"        // TCP connected but the nonce never arrived: something in between answered
	VerdictRefusedInPath    = "refused_in_path"    // the sender was refused while the receiver was listening
	VerdictBlockedOrDropped = "blocked_or_dropped" // the sender timed out or was unreachable, or UDP was sent, and nothing arrived
	VerdictListenFailed     = "listen_failed"      // the receiver could not open the port, so nothing was tested
	VerdictDeniedByPolicy   = "denied_by_policy"   // the sender's target policy refused the receiver's address
	VerdictSendFailed       = "send_failed"        // the sender could not run the test for another reason (offline, busy, error)
	VerdictInconclusive     = "inconclusive"       // the receiver could not report what arrived
)

const (
	pathListenDurationMS = 20_000
	pathCollectWaitMS    = 3_000
	pathListenDeadline   = 5 * time.Second
)

type pathTestInput struct {
	From      string `json:"from" jsonschema:"name of the probe that sends"`
	To        string `json:"to" jsonschema:"name of the probe that listens"`
	Protocol  string `json:"protocol,omitempty" jsonschema:"tcp or udp, default tcp"`
	Port      int    `json:"port,omitempty" jsonschema:"port to listen on, within the receiving probe's listen_ports; default the receiver picks one"`
	ToAddress string `json:"to_address,omitempty" jsonschema:"address the sender should use to reach the receiver; one of the receiver's reported addresses, or any address (e.g. a public or NAT address) if you may also use tcp_connect; default a receiver address on the same subnet as one of the sender's, else the receiver's first"`
	TimeoutMS int    `json:"timeout_ms,omitempty" jsonschema:"sender's connect timeout in ms, 200 to 10000, default 5000"`
}

type pathTestOutput struct {
	Verdict        string                `json:"verdict"`
	Summary        string                `json:"summary"`
	From           string                `json:"from"`
	To             string                `json:"to"`
	Protocol       string                `json:"protocol"`
	Port           int                   `json:"port"`
	AddressUsed    string                `json:"address_used"`
	ObservedSource string                `json:"observed_source,omitempty"` // where the receiver saw the nonce come from
	Listen         *protocol.ProbeResult `json:"listen,omitempty"`          // listen_start on the receiver
	Sender         *protocol.ProbeResult `json:"sender,omitempty"`          // path_send on the sender
	Receiver       *protocol.ProbeResult `json:"receiver,omitempty"`        // listen_collect on the receiver
}

// pathTest has `to` listen, `from` send a nonce to it, then asks `to` what arrived. Failures before anything runs
// (probes unknown or outside the scope, offline probes, a forbidden to_address, bad input) are tool errors; anything
// after is a verdict.
func (h *hub) pathTest(ctx context.Context, c *clientState, in pathTestInput) (pathTestOutput, error) {
	rec := auditFrom(ctx)
	rec.Target = in.From + "→" + in.To
	rec.Probes = []string{in.From, in.To}
	if !c.allowsTool(toolPathTest) {
		return pathTestOutput{}, forbiddenTool(toolPathTest)
	}
	proto := strings.ToLower(strings.TrimSpace(in.Protocol))
	if proto == "" {
		proto = "tcp"
	}
	if proto != "tcp" && proto != "udp" {
		return pathTestOutput{}, fmt.Errorf("%s: protocol must be tcp or udp", protocol.CodeInvalidParams)
	}
	if in.Port < 0 || in.Port > 65535 {
		return pathTestOutput{}, fmt.Errorf("%s: port must be 1 to 65535, or 0 to let the receiver pick", protocol.CodeInvalidParams)
	}
	if in.From == "" || in.To == "" || in.From == in.To {
		return pathTestOutput{}, fmt.Errorf("%s: from and to must name two different probes", protocol.CodeInvalidParams)
	}
	from, err := h.scopedProbe(c, in.From)
	if err != nil {
		return pathTestOutput{}, err
	}
	to, err := h.scopedProbe(c, in.To)
	if err != nil {
		return pathTestOutput{}, err
	}
	for _, p := range []hubapi.ProbeStatus{from, to} {
		if !p.Online {
			return pathTestOutput{}, fmt.Errorf("%s: probe %q is not connected", protocol.CodeProbeOffline, p.Name)
		}
	}
	address := strings.TrimSpace(in.ToAddress)
	autoAddress := address == ""
	switch {
	case autoAddress:
		address = pickAddress(from.Addresses, to.Addresses)
		if address == "" {
			return pathTestOutput{}, fmt.Errorf("%s: probe %q reports no addresses; give to_address", protocol.CodeInvalidParams, to.Name)
		}
	case !c.allowsTool(protocol.CheckTCPConnect):
		// Any other address would make path_test a TCP or UDP connect to a target of the client's choosing, which is
		// tcp_connect's job; a client without that tool may only test the path to the receiver itself.
		ip, ok := parseAddr(address)
		if !ok || !hasAddress(to.Addresses, ip.String()) {
			return pathTestOutput{}, fmt.Errorf("%s: to_address must be one of the receiver's addresses", protocol.CodeForbidden)
		}
		address = ip.String()
	}
	nonce, err := newNonce()
	if err != nil {
		return pathTestOutput{}, fmt.Errorf("%s: %v", protocol.CodeInternal, err)
	}
	// Validate what will be sent before opening a port, so bad input never leaves a listener behind.
	send := protocol.PathSendParams{Address: address, Port: 1, Protocol: proto, Nonce: nonce, TimeoutMS: in.TimeoutMS}
	if perr := send.Normalize(); perr != nil {
		return pathTestOutput{}, fmt.Errorf("%s: %s", perr.Code, strings.Replace(perr.Message, "target", "to_address", 1))
	}
	listen := protocol.ListenStartParams{Protocol: proto, Port: in.Port, Nonce: nonce, DurationMS: pathListenDurationMS}
	if perr := listen.Normalize(); perr != nil {
		return pathTestOutput{}, fmt.Errorf("%s: %s", perr.Code, perr.Message)
	}

	ctx, cancel := context.WithTimeout(ctx, h.callBudget)
	defer cancel()
	out := pathTestOutput{From: from.Name, To: to.Name, Protocol: proto, Port: in.Port, AddressUsed: address}
	defer func() { rec.Verdict = out.Verdict }()

	// 1. The receiver opens the port.
	var started protocol.ListenStartResult
	lr := h.runJSON(ctx, to, protocol.CheckListenStart, listen, pathListenDeadline, &started)
	out.Listen = &lr
	rec.Outcomes["listen_start"] = outcome(lr)
	if !lr.OK {
		out.Verdict = VerdictListenFailed
		out.Summary = listenFailedSummary(to.Name, lr.Error)
		return out, nil
	}
	out.Port = started.Port
	send.Port = started.Port

	// 2. The sender connects and sends the nonce.
	var sent protocol.PathSendResult
	sendDeadline := time.Duration(send.TimeoutMS+2000) * time.Millisecond
	sr := h.runJSON(ctx, from, protocol.CheckPathSend, send, sendDeadline, &sent)
	out.Sender = &sr
	rec.Outcomes["path_send"] = outcome(sr)

	// 3. The receiver reports what arrived and closes the port. This runs even when the call's budget is spent, so
	// the listener is always closed. When the send cannot have happened there is nothing to wait for.
	wait := pathCollectWaitMS
	if (sr.Error != nil && sendNeverRan(sr.Error.Code)) || ctx.Err() != nil {
		wait = 1 // 0 would mean the default wait; past the budget, just close the listener
	}
	collect := protocol.ListenCollectParams{ListenID: started.ListenID, WaitMS: wait}
	cctx, ccancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(wait)*time.Millisecond+5*time.Second)
	defer ccancel()
	var got protocol.ListenCollectResult
	cr := h.runJSON(cctx, to, protocol.CheckListenCollect, collect, time.Duration(wait+2000)*time.Millisecond, &got)
	out.Receiver = &cr
	rec.Outcomes["listen_collect"] = outcome(cr)

	judge(&out, from, sr, sent, cr, got)
	if autoAddress && out.Verdict != VerdictReached && out.Verdict != VerdictReachedViaNAT {
		out.Summary += autoAddressNote(to, address)
	}
	return out, nil
}

// autoAddressNote is added to a verdict that is not a success when the hub chose the address: on a multi-homed
// receiver the chosen one may simply not be routable from the sender, which would look like a blocked path.
func autoAddressNote(to hubapi.ProbeStatus, address string) string {
	var addrs []string
	for _, a := range to.Addresses {
		if ip, ok := parseAddr(a); ok {
			addrs = append(addrs, ip.String())
		}
	}
	return fmt.Sprintf(" The hub chose %s automatically from %s's addresses (%s); it may not be the one the sender can reach, so give to_address to test another.",
		address, to.Name, strings.Join(addrs, ", "))
}

// judge sets the verdict and summary from both sides' views.
func judge(out *pathTestOutput, from hubapi.ProbeStatus, sr protocol.ProbeResult, sent protocol.PathSendResult,
	cr protocol.ProbeResult, got protocol.ListenCollectResult) {
	dest := fmt.Sprintf("%s %s:%d", out.Protocol, out.AddressUsed, out.Port)
	if sr.Error != nil && sr.Error.Code == protocol.CodeDenied {
		out.Verdict = VerdictDeniedByPolicy
		out.Summary = fmt.Sprintf("Probe %s's target policy does not allow %s, so nothing was sent; this says nothing about the network path.",
			out.From, out.AddressUsed)
		return
	}
	if cr.OK && got.Received {
		src := hostOf(got.From)
		out.ObservedSource = got.From
		if len(from.Addresses) == 0 || hasAddress(from.Addresses, src) {
			out.Verdict = VerdictReached
			out.Summary = fmt.Sprintf("The nonce sent by %s to %s arrived at %s from %s.", out.From, dest, out.To, src)
		} else {
			out.Verdict = VerdictReachedViaNAT
			out.Summary = fmt.Sprintf("The nonce sent by %s to %s arrived at %s, but from %s, which is not one of %s's addresses, so the path translates the source address.",
				out.From, dest, out.To, src, out.From)
		}
		return
	}
	if !cr.OK {
		if sr.Error != nil {
			out.Verdict = VerdictSendFailed
			out.Summary = fmt.Sprintf("Probe %s could not run the send (%s: %s), and %s could not report arrivals.",
				out.From, sr.Error.Code, sr.Error.Message, out.To)
			return
		}
		out.Verdict = VerdictInconclusive
		code := protocol.CodeInternal
		if cr.Error != nil {
			code = cr.Error.Code
		}
		out.Summary = fmt.Sprintf("Probe %s reported %q sending to %s, but %s could not report what arrived (%s).",
			out.From, sent.Outcome, dest, out.To, code)
		return
	}
	// The receiver answered and the nonce did not arrive.
	if sr.Error != nil {
		out.Verdict = VerdictSendFailed
		out.Summary = fmt.Sprintf("Probe %s could not run the send to %s (%s: %s); nothing arrived at %s.",
			out.From, dest, sr.Error.Code, sr.Error.Message, out.To)
		return
	}
	others := ""
	if got.OtherArrivals > 0 {
		others = fmt.Sprintf(" %d other connection(s) or datagram(s) without the nonce reached the port.", got.OtherArrivals)
	}
	switch {
	case out.Protocol == "tcp" && sent.Outcome == "connected":
		out.Verdict = VerdictIntercepted
		out.Summary = fmt.Sprintf("Probe %s connected to %s, but the nonce never reached %s, so something in between (a proxy, firewall or another host) answered the connection.%s",
			out.From, dest, out.To, others)
	case sent.Outcome == "refused":
		out.Verdict = VerdictRefusedInPath
		out.Summary = fmt.Sprintf("Probe %s was refused connecting to %s while %s was listening, so something in the path rejected it or the address leads elsewhere.%s",
			out.From, dest, out.To, others)
	case sent.Outcome == "timeout" || sent.Outcome == "unreachable" || sent.Outcome == "sent":
		out.Verdict = VerdictBlockedOrDropped
		how := map[string]string{"timeout": "timed out", "unreachable": "was told the destination is unreachable", "sent": "sent the datagram"}[sent.Outcome]
		out.Summary = fmt.Sprintf("Probe %s %s to %s and nothing arrived at %s, so the traffic is blocked or dropped on the way.%s",
			out.From, how, dest, out.To, others)
	default:
		out.Verdict = VerdictSendFailed
		out.Summary = fmt.Sprintf("Probe %s reported %q sending to %s and nothing arrived at %s.", out.From, sent.Outcome, dest, out.To)
	}
}

func listenFailedSummary(to string, e *protocol.Error) string {
	if e == nil {
		return fmt.Sprintf("Probe %s could not open a port, so the path was not tested.", to)
	}
	var why string
	switch e.Code {
	case protocol.CodeUnavailable:
		why = "it cannot listen: " + e.Message
	case protocol.CodeDenied:
		why = "its policy does not allow that port; pick one within its listen_ports"
	case protocol.CodeBusy:
		why = "it is busy (no free port in its listen range, or too many jobs); try again shortly"
	case protocol.CodeInvalidParams:
		why = "the port was not acceptable: " + e.Message
	case protocol.CodeProbeOffline:
		why = "it went offline"
	default:
		why = e.Code + ": " + e.Message
	}
	return fmt.Sprintf("Probe %s could not open a port because %s, so the path was not tested.", to, why)
}

// sendNeverRan reports error codes after which the sender cannot have sent anything.
func sendNeverRan(code string) bool {
	switch code {
	case protocol.CodeDenied, protocol.CodeProbeOffline, protocol.CodeInvalidParams, protocol.CodeUnavailable,
		protocol.CodeBusy, protocol.CodeNotFound, protocol.CodeUnresolved:
		return true
	}
	return false
}

// scopedProbe looks up a probe named in path_test and checks the client may use it. A probe outside the scope gets the
// same error as one that does not exist, so a client cannot discover the names of probes it may not use.
func (h *hub) scopedProbe(c *clientState, name string) (hubapi.ProbeStatus, error) {
	p, ok := h.router.Probe(name)
	if !ok || !c.allowsProbe(p) {
		e := unknownProbe(name)
		return hubapi.ProbeStatus{}, fmt.Errorf("%s: %s", e.Code, e.Message)
	}
	return p, nil
}

// runJSON runs one internal job and decodes a successful result into dst. The returned ProbeResult carries the decoded
// value, so the tool's output shows typed fields rather than the probe's raw bytes.
func (h *hub) runJSON(ctx context.Context, p hubapi.ProbeStatus, check string, params any, deadline time.Duration, dst any) protocol.ProbeResult {
	raw, err := json.Marshal(params)
	if err != nil {
		return protocol.ProbeResult{Probe: p.Name, Site: p.Site, Error: protocol.Errorf(protocol.CodeInternal, "encoding parameters: %v", err)}
	}
	// Wait for the router or the context, whichever is first, so a router that does not honour ctx cannot hold the
	// call past its budget.
	ch := make(chan protocol.ProbeResult, 1)
	go func() { ch <- h.router.Run(ctx, p.Name, check, raw, deadline) }()
	var r protocol.ProbeResult
	select {
	case r = <-ch:
	case <-ctx.Done():
		r = protocol.ProbeResult{Probe: p.Name, Site: p.Site, StartedAt: time.Now().UTC(),
			Error: protocol.Errorf(protocol.CodeTimeout, "the hub's time budget ran out before the probe answered")}
	}
	if r.Probe == "" {
		r.Probe, r.Site = p.Name, p.Site
	}
	if !r.OK {
		if r.Error == nil {
			r.Error = protocol.Errorf(protocol.CodeInternal, "the probe returned neither a result nor an error")
		}
		return r
	}
	b, err := json.Marshal(r.Result)
	if err == nil {
		err = json.Unmarshal(b, dst)
	}
	if err != nil {
		r.OK = false
		r.Error = protocol.Errorf(protocol.CodeInternal, "the probe's %s result could not be read: %v", check, err)
		r.Result = nil
		return r
	}
	r.Result = dst
	return r
}

// newNonce returns 24 random characters from [A-Za-z0-9_-].
func newNonce() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pickAddress chooses the receiver address the sender is most likely to reach: the first on the same subnet (/24 for
// IPv4, /64 for IPv6) as one of the sender's addresses, else the receiver's first. A multi-homed receiver may list
// first an address that only its own network can reach.
func pickAddress(from, to []string) string {
	for _, t := range to {
		ta, ok := parseAddr(t)
		if !ok {
			continue
		}
		bits := 64
		if ta.Is4() {
			bits = 24
		}
		subnet := netip.PrefixFrom(ta, bits).Masked()
		for _, f := range from {
			if fa, ok := parseAddr(f); ok && subnet.Contains(fa) {
				return ta.String()
			}
		}
	}
	return firstAddress(to)
}

// firstAddress returns a probe's first reported address without any prefix length.
func firstAddress(addrs []string) string {
	for _, a := range addrs {
		if ip, ok := parseAddr(a); ok {
			return ip.String()
		}
	}
	return ""
}

func hasAddress(addrs []string, host string) bool {
	want, ok := parseAddr(host)
	if !ok {
		return false
	}
	for _, a := range addrs {
		if ip, ok := parseAddr(a); ok && ip == want {
			return true
		}
	}
	return false
}

// parseAddr accepts "10.0.0.5", "10.0.0.5/24" or "fe80::1%eth0" and returns the bare, unmapped address.
func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Addr().Unmap().WithZone(""), true
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return ip.Unmap().WithZone(""), true
}

func hostOf(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}
