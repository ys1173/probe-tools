// Package diagnose runs a layered check of one target: DNS, then ping, then TCP, then TLS, then HTTP, each only where it
// applies, and names the first layer that failed. It runs the other checks through Env.Run, so they keep their own
// policy checks and limits.
package diagnose

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

// Register adds the diagnose check to r.
func Register(r *check.Registry) { r.Register(protocol.CheckDiagnose, diagnose) }

// Layer statuses.
const (
	statusOK          = "ok"
	statusFailed      = "failed"
	statusNoReply     = "no_reply" // ping only: no echo replies, which is often a firewall rather than a fault
	statusSkipped     = "skipped"
	statusDenied      = "denied"
	statusUnavailable = "unavailable"
	statusError       = "error" // the layer's check could not give an answer
)

// Per-layer budgets, out of the job's 40 s. Each is also cut short by the job's own deadline.
var budgets = map[string]time.Duration{
	"dns":  5 * time.Second,
	"ping": 6 * time.Second,
	"tcp":  6 * time.Second,
	"tls":  7 * time.Second,
	"http": 14 * time.Second,
}

const totalBudget = time.Duration(protocol.MaxCheckBudgetMS) * time.Millisecond

type layerResult struct {
	Layer      string          `json:"layer"`
	Status     string          `json:"status"`
	Summary    string          `json:"summary"`
	DurationMS int64           `json:"duration_ms"`
	Result     any             `json:"result,omitempty"`
	Error      *protocol.Error `json:"error,omitempty"`
}

type result struct {
	Target       string        `json:"target"`
	Host         string        `json:"host"`
	Port         int           `json:"port,omitempty"`
	Layers       []layerResult `json:"layers"`
	FirstFailure string        `json:"first_failure"`
	Verdict      string        `json:"verdict"`
}

// target is the parsed form of DiagnoseParams.Target.
type target struct {
	host   string
	port   int
	scheme string // "http" or "https" when a URL was given
	url    string
	isAddr bool
}

func diagnose(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	var p protocol.DiagnoseParams
	if e := check.Decode(raw, &p); e != nil {
		return nil, e
	}
	tg, e := parseTarget(&p)
	if e != nil {
		return nil, e
	}
	if env.Run == nil {
		return nil, protocol.Errorf(protocol.CodeInternal, "diagnose needs Env.Run")
	}
	ctx, cancel := context.WithTimeout(ctx, totalBudget)
	defer cancel()

	d := &diag{env: env, tg: tg, family: p.Family, res: &result{Target: p.Target, Host: tg.host, Port: tg.port, Layers: []layerResult{}}}
	d.runLayers(ctx)
	d.res.FirstFailure, d.res.Verdict = verdict(d.res.Layers, tg)
	return d.res, nil
}

func parseTarget(p *protocol.DiagnoseParams) (target, *protocol.Error) {
	raw := strings.TrimSpace(p.Target)
	var tg target
	if strings.Contains(raw, "://") {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
			return tg, protocol.Errorf(protocol.CodeInvalidParams, "target URL must be http or https with a host and no user info")
		}
		tg.scheme, tg.url, tg.host = u.Scheme, u.String(), u.Hostname()
		if ps := u.Port(); ps != "" {
			n, err := strconv.Atoi(ps)
			if err != nil || n < 1 || n > 65535 {
				return tg, protocol.Errorf(protocol.CodeInvalidParams, "the URL's port must be 1 to 65535")
			}
			tg.port = n
		} else if u.Scheme == "https" {
			tg.port = 443
		} else {
			tg.port = 80
		}
	} else {
		tg.host = strings.Trim(raw, "[]")
		// Accept host:port as a convenience when no port parameter is given.
		if h, ps, err := net.SplitHostPort(raw); err == nil && p.Port == 0 {
			if n, err := strconv.Atoi(ps); err == nil && n >= 1 && n <= 65535 {
				tg.host, tg.port = h, n
			}
		}
	}
	if p.Port != 0 {
		tg.port = p.Port
	}
	if tg.host == "" || len(tg.host) > 253 || strings.ContainsAny(tg.host, " /\\@?#") {
		return tg, protocol.Errorf(protocol.CodeInvalidParams, "target must be a host name, an IP address or an http/https URL")
	}
	for i := 0; i < len(tg.host); i++ {
		if tg.host[i] < 0x21 || tg.host[i] > 0x7e {
			return tg, protocol.Errorf(protocol.CodeInvalidParams, "target host must be printable ASCII")
		}
	}
	_, err := netip.ParseAddr(tg.host)
	tg.isAddr = err == nil
	return tg, nil
}

type diag struct {
	env    *check.Env
	tg     target
	family string
	res    *result
}

func (d *diag) add(l layerResult) { d.res.Layers = append(d.res.Layers, l) }

func (d *diag) skip(layer, why string) {
	d.add(layerResult{Layer: layer, Status: statusSkipped, Summary: why})
}

// skipRest marks every layer after the given one as skipped for the same reason.
func (d *diag) skipRest(after, why string) {
	order := []string{"dns", "ping", "tcp", "tls", "http"}
	for i, l := range order {
		if l == after {
			for _, next := range order[i+1:] {
				d.skip(next, why)
			}
			return
		}
	}
}

func (d *diag) runLayers(ctx context.Context) {
	tg := d.tg
	host := tg.host

	// 1. DNS, only for a name. An address is still put to the policy (no lookup happens), so a refused address
	// stops here rather than depending on a later layer to notice.
	if tg.isAddr {
		if _, e := d.env.Policy.Resolve(ctx, host, d.family); e != nil {
			l := errorLayer("dns", e, 0)
			why := "Skipped because the probe's policy does not allow this target."
			switch e.Code {
			case protocol.CodeDenied:
				l.Summary = fmt.Sprintf("The probe's policy does not allow %s.", host)
			case protocol.CodeBusy:
				why = "Skipped because the probe's rate limit for this target was reached."
			}
			d.add(l)
			d.skipRest("dns", why)
			return
		}
		d.skip("dns", "The target is an IP address, so there is nothing to resolve.")
	} else {
		l := d.dnsLayer(ctx)
		d.add(l)
		if l.Status != statusOK {
			why := "Skipped because DNS did not give an address."
			if l.Error != nil && l.Error.Code == protocol.CodeBusy {
				why = "Skipped because the probe's rate limit for this target was reached."
			}
			d.skipRest("dns", why)
			return
		}
	}

	// 2. Ping. No reply is noted but never stops the diagnosis: ICMP is often filtered.
	if d.outOfTime(ctx, "ping") {
		return
	}
	l := d.pingLayer(ctx, host)
	d.add(l)
	if l.Status == statusDenied {
		d.skipRest("ping", "Skipped because the probe's policy does not allow this target.")
		return
	}

	// 3. TCP.
	if tg.port == 0 {
		d.skip("tcp", "No port was given, so TCP was not tested.")
		d.skip("tls", "No port was given, so TLS was not tested.")
		d.skip("http", "No URL was given, so HTTP was not tested.")
		return
	}
	if d.outOfTime(ctx, "tcp") {
		return
	}
	l = d.tcpLayer(ctx, host)
	d.add(l)
	if l.Status != statusOK {
		d.skipRest("tcp", fmt.Sprintf("Skipped because TCP %d did not connect.", tg.port))
		return
	}

	// 4. TLS, for https or port 443.
	verifyHTTP := true
	if tg.scheme == "https" || tg.port == 443 {
		if d.outOfTime(ctx, "tls") {
			return
		}
		l, handshakeOK := d.tlsLayer(ctx, host)
		d.add(l)
		if !handshakeOK {
			d.skipRest("tls", "Skipped because the TLS handshake did not complete.")
			return
		}
		// The handshake worked but the certificate did not verify: still try HTTP, so the result shows whether the
		// application itself answers.
		verifyHTTP = l.Status == statusOK
	} else {
		d.skip("tls", "Not an https URL or port 443, so TLS was not tested.")
	}

	// 5. HTTP, only when a URL was given.
	if tg.url == "" {
		d.skip("http", "No URL was given, so HTTP was not tested.")
		return
	}
	if d.outOfTime(ctx, "http") {
		return
	}
	d.add(d.httpLayer(ctx, verifyHTTP))
}

// outOfTime marks layer and the ones after it as skipped when the job's time is up.
func (d *diag) outOfTime(ctx context.Context, layer string) bool {
	if ctx.Err() == nil {
		return false
	}
	why := "Skipped because the job ran out of time."
	d.skip(layer, why)
	d.skipRest(layer, why)
	return true
}

func (d *diag) run(ctx context.Context, layer, name string, params any) (any, *protocol.Error, int64) {
	lctx, cancel := context.WithTimeout(ctx, budgets[layer])
	defer cancel()
	start := time.Now()
	out, err := d.env.Run(lctx, name, params)
	if err == nil && out == nil && lctx.Err() != nil {
		err = protocol.Errorf(protocol.CodeTimeout, "%s ran out of time", name)
	}
	return out, err, time.Since(start).Milliseconds()
}

// errorLayer describes a layer whose check returned an error instead of a result.
func errorLayer(layer string, e *protocol.Error, ms int64) layerResult {
	l := layerResult{Layer: layer, DurationMS: ms, Error: e}
	name := layerName(layer, 0)
	switch e.Code {
	case protocol.CodeDenied:
		l.Status, l.Summary = statusDenied, "The probe's policy does not allow this target."
	case protocol.CodeUnavailable:
		l.Status, l.Summary = statusUnavailable, fmt.Sprintf("This probe cannot run the %s check.", name)
	case protocol.CodeUnresolved:
		l.Status, l.Summary = statusFailed, "The name does not resolve."
	case protocol.CodeBusy:
		l.Status, l.Summary = statusError, "The probe's rate limit for this target was reached; try again in a minute."
	case protocol.CodeTimeout, protocol.CodeCancelled:
		l.Status, l.Summary = statusError, fmt.Sprintf("The %s check ran out of time.", name)
	default:
		l.Status, l.Summary = statusError, fmt.Sprintf("The %s check could not run.", name)
	}
	return l
}

func (d *diag) dnsLayer(ctx context.Context) layerResult {
	lctx, cancel := context.WithTimeout(ctx, budgets["dns"])
	defer cancel()
	start := time.Now()
	addrs, e := d.env.Policy.Resolve(lctx, d.tg.host, d.family)
	ms := time.Since(start).Milliseconds()
	if e != nil {
		l := errorLayer("dns", e, ms)
		if e.Code == protocol.CodeUnresolved {
			l.Summary = fmt.Sprintf("%s does not resolve from this probe.", d.tg.host)
		}
		return l
	}
	list := make([]string, 0, len(addrs))
	for i, a := range addrs {
		if i == 10 {
			break
		}
		list = append(list, a.String())
	}
	summary := fmt.Sprintf("%s resolves to %s.", d.tg.host, list[0])
	if len(addrs) > 1 {
		summary = fmt.Sprintf("%s resolves to %s and %d more.", d.tg.host, list[0], len(addrs)-1)
	}
	return layerResult{Layer: "dns", Status: statusOK, Summary: summary, DurationMS: ms, Result: map[string]any{"addresses": list}}
}

func (d *diag) pingLayer(ctx context.Context, host string) layerResult {
	out, e, ms := d.run(ctx, "ping", protocol.CheckPing, protocol.PingParams{Target: host, Count: 3, Family: d.family})
	if e != nil {
		l := errorLayer("ping", e, ms)
		if e.Code == protocol.CodeUnavailable {
			// No raw ICMP on this probe: not a finding about the target.
			l.Status = statusNoReply
			l.Summary = "This probe cannot send ICMP, so ping was not tested."
		}
		return l
	}
	l := layerResult{Layer: "ping", DurationMS: ms, Result: out}
	sent, received, avg, known := readPing(out)
	switch {
	case !known:
		l.Status, l.Summary = statusOK, "Ping ran; its result is attached."
	case received == 0:
		l.Status = statusNoReply
		l.Summary = fmt.Sprintf("No reply to %d pings; ICMP is often filtered, so this alone is not a fault.", sent)
	case avg > 0:
		l.Status = statusOK
		l.Summary = fmt.Sprintf("%d of %d pings answered, average %.1f ms.", received, sent, avg)
	default:
		l.Status = statusOK
		l.Summary = fmt.Sprintf("%d of %d pings answered.", received, sent)
	}
	return l
}

// readPing reads the ping result leniently, since it belongs to another package: it looks for a count of replies
// (received) or a loss percentage, with sent or transmitted, and an average round trip, at the top level or one level
// down.
func readPing(out any) (sent, received int, avgMS float64, known bool) {
	m := asMap(out)
	if m == nil {
		return 0, 0, 0, false
	}
	flat := map[string]any{}
	for _, v := range m {
		if sub, ok := v.(map[string]any); ok {
			for k2, v2 := range sub {
				if _, dup := flat[k2]; !dup {
					flat[k2] = v2
				}
			}
		}
	}
	for k, v := range m {
		flat[k] = v
	}
	num := func(keys ...string) (float64, bool) {
		for _, k := range keys {
			if f, ok := flat[k].(float64); ok {
				return f, true
			}
		}
		return 0, false
	}
	s, hasSent := num("sent", "transmitted", "packets_sent", "count")
	sent = int(s)
	if r, ok := num("received", "replies", "packets_received"); ok {
		received, known = int(r), true
	} else if loss, ok := num("loss_pct", "loss_percent", "packet_loss", "packet_loss_pct", "loss"); ok {
		known = true
		if loss < 100 {
			received = -1 // some replies, count unknown
			if hasSent {
				received = int(s*(100-loss)/100 + 0.5)
			}
		}
	}
	avgMS, _ = num("avg_ms", "rtt_avg_ms", "avg_rtt_ms", "rtt_avg")
	if received < 0 {
		received = max(1, sent)
	}
	if !hasSent {
		sent = 3
	}
	return sent, received, avgMS, known
}

type tcpView struct {
	Ports []struct {
		Port      int     `json:"port"`
		Outcome   string  `json:"outcome"`
		ConnectMS float64 `json:"connect_ms"`
	} `json:"ports"`
}

func (d *diag) tcpLayer(ctx context.Context, host string) layerResult {
	port := d.tg.port
	out, e, ms := d.run(ctx, "tcp", protocol.CheckTCPConnect, protocol.TCPConnectParams{Target: host, Ports: []int{port}, TimeoutMS: 5000, Family: d.family})
	if e != nil {
		return errorLayer("tcp", e, ms)
	}
	l := layerResult{Layer: "tcp", DurationMS: ms, Result: out, Status: statusFailed}
	var v tcpView
	if !decode(out, &v) || len(v.Ports) == 0 {
		l.Status, l.Summary = statusError, "The TCP check gave a result that could not be read."
		return l
	}
	pr := v.Ports[0]
	switch pr.Outcome {
	case "open":
		l.Status = statusOK
		l.Summary = fmt.Sprintf("TCP %d accepts connections (%.1f ms).", port, pr.ConnectMS)
	case "refused":
		l.Summary = fmt.Sprintf("TCP %d is refused: the host answers but nothing accepts connections on that port.", port)
	case "timeout":
		l.Summary = fmt.Sprintf("TCP %d times out from this probe.", port)
	case "unreachable":
		l.Summary = fmt.Sprintf("TCP %d is unreachable: the network reports no route to the host.", port)
	default:
		l.Summary = fmt.Sprintf("TCP %d could not be connected.", port)
	}
	return l
}

type tlsView struct {
	Outcome       string `json:"outcome"`
	Version       string `json:"version"`
	Verified      bool   `json:"verified"`
	HostnameMatch bool   `json:"hostname_match"`
	Chain         []struct {
		DaysLeft int `json:"days_left"`
	} `json:"chain"`
}

// tlsLayer returns the layer and whether the handshake completed.
func (d *diag) tlsLayer(ctx context.Context, host string) (layerResult, bool) {
	out, e, ms := d.run(ctx, "tls", protocol.CheckTLSCheck, protocol.TLSCheckParams{Target: host, Port: d.tg.port, Family: d.family})
	if e != nil {
		return errorLayer("tls", e, ms), false
	}
	l := layerResult{Layer: "tls", DurationMS: ms, Result: out, Status: statusFailed}
	var v tlsView
	if !decode(out, &v) {
		l.Status, l.Summary = statusError, "The TLS check gave a result that could not be read."
		return l, false
	}
	switch {
	case v.Outcome == "timeout":
		l.Summary = fmt.Sprintf("The TLS handshake on port %d times out.", d.tg.port)
		return l, false
	case v.Outcome != "ok":
		l.Summary = fmt.Sprintf("The TLS handshake on port %d fails.", d.tg.port)
		return l, false
	}
	days := 0
	if len(v.Chain) > 0 {
		days = v.Chain[0].DaysLeft
	}
	switch {
	case v.Verified:
		l.Status = statusOK
		l.Summary = fmt.Sprintf("%s handshake works and the certificate is valid for %d more days.", v.Version, days)
	case len(v.Chain) > 0 && days < 0:
		l.Summary = fmt.Sprintf("The certificate expired %d days ago.", -days)
	case !v.HostnameMatch:
		l.Summary = fmt.Sprintf("The certificate does not cover %s.", host)
	default:
		l.Summary = "The certificate does not chain to a root this probe trusts."
	}
	return l, true
}

type httpView struct {
	Outcome string `json:"outcome"`
	Status  int    `json:"status"`
	Timings struct {
		TotalMS float64 `json:"total_ms"`
	} `json:"timings"`
}

func (d *diag) httpLayer(ctx context.Context, verify bool) layerResult {
	params := protocol.HTTPCheckParams{URL: d.tg.url, TimeoutMS: 12000, VerifyTLS: &verify}
	out, e, ms := d.run(ctx, "http", protocol.CheckHTTPCheck, params)
	if e != nil {
		return errorLayer("http", e, ms)
	}
	l := layerResult{Layer: "http", DurationMS: ms, Result: out, Status: statusFailed}
	var v httpView
	if !decode(out, &v) {
		l.Status, l.Summary = statusError, "The HTTP check gave a result that could not be read."
		return l
	}
	switch {
	case v.Outcome == "denied":
		l.Status, l.Summary = statusDenied, "A redirect led to an address the probe's policy does not allow."
	case v.Outcome != "ok" && v.Status == 0:
		l.Summary = fmt.Sprintf("The HTTP request failed (%s).", plainOutcome(v.Outcome))
	case v.Outcome != "ok":
		l.Summary = fmt.Sprintf("HTTP answered %d, but its redirect could not be followed (%s).", v.Status, plainOutcome(v.Outcome))
	case v.Status >= 400:
		l.Summary = fmt.Sprintf("HTTP answers with status %d.", v.Status)
	default:
		l.Status = statusOK
		l.Summary = fmt.Sprintf("HTTP answers with status %d in %.0f ms.", v.Status, v.Timings.TotalMS)
	}
	return l
}

// plainOutcome turns an http_check outcome code into words for a summary.
func plainOutcome(code string) string {
	switch code {
	case "refused":
		return "connection refused"
	case "timeout":
		return "timed out"
	case "unreachable":
		return "no route"
	case "tls_failed":
		return "TLS handshake failed"
	case "tls_verify_failed":
		return "certificate did not verify"
	case "unsupported_scheme":
		return "redirect to a scheme other than http or https"
	}
	return "error"
}

func layerName(layer string, port int) string {
	switch layer {
	case "dns":
		return "DNS"
	case "ping":
		return "ICMP"
	case "tcp":
		if port > 0 {
			return fmt.Sprintf("TCP %d", port)
		}
		return "TCP"
	case "tls":
		return "TLS"
	case "http":
		return "HTTP"
	}
	return layer
}

// verdict names the first failing layer and says in one sentence what failed, what is fine and what could not be
// tested.
func verdict(layers []layerResult, tg target) (string, string) {
	var first *layerResult
	var fine, untested []string
	icmpNote := ""
	for i := range layers {
		l := &layers[i]
		name := layerName(l.Layer, tg.port)
		switch l.Status {
		case statusFailed, statusDenied:
			if first == nil {
				first = l
			}
		case statusOK:
			fine = append(fine, name)
		case statusNoReply:
			if l.Error != nil {
				icmpNote = "ICMP could not be tested from this probe"
			} else {
				icmpNote = "ICMP gets no reply, which is often just filtering"
			}
		case statusError, statusUnavailable:
			untested = append(untested, name)
		}
	}
	var parts []string
	if first != nil {
		if first.Status == statusDenied && len(fine) == 0 {
			return first.Layer, fmt.Sprintf("This probe's policy does not allow %s, so it was not tested.", tg.host)
		}
		parts = append(parts, strings.TrimSuffix(first.Summary, "."))
	}
	if len(fine) > 0 {
		s := joinNames(fine) + " " + isAre(len(fine)) + " fine"
		if first == nil {
			s += " from this probe"
		}
		parts = append(parts, s)
	}
	if len(untested) > 0 {
		parts = append(parts, joinNames(untested)+" could not be tested")
	}
	if icmpNote != "" {
		parts = append(parts, icmpNote)
	}
	firstName := ""
	if first != nil {
		firstName = first.Layer
	}
	if len(parts) == 0 {
		return "", "No layer could be tested from this probe."
	}
	return firstName, strings.Join(parts, "; ") + "."
}

func joinNames(n []string) string {
	if len(n) == 1 {
		return n[0]
	}
	return strings.Join(n[:len(n)-1], ", ") + " and " + n[len(n)-1]
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// decode reads an inner result into a view by way of JSON, so it works whether Env.Run returns the check's own struct or
// an already decoded map.
func decode(v any, into any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	return json.Unmarshal(b, into) == nil
}

func asMap(v any) map[string]any {
	var m map[string]any
	if !decode(v, &m) {
		return nil
	}
	return m
}
