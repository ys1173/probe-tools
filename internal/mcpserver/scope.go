package mcpserver

import (
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"probetools/internal/hubapi"
	"probetools/internal/protocol"
)

func (c *clientState) allowsTool(name string) bool {
	return slices.Contains(c.Tools, "*") || slices.Contains(c.Tools, name)
}

// allowsProbe reports whether the client's probe patterns cover p. An empty list allows nothing.
func (c *clientState) allowsProbe(p hubapi.ProbeStatus) bool {
	for _, pat := range c.Probes {
		switch {
		case pat == "*":
			return true
		case strings.HasPrefix(pat, "site:"):
			if p.Site == strings.TrimPrefix(pat, "site:") {
				return true
			}
		default:
			if ok, _ := path.Match(pat, p.Name); ok {
				return true
			}
		}
	}
	return false
}

// unknownProbe is the one answer for a probe name the client may not use, whether no probe has it or the probe is
// outside the client's scope: different answers would let a client list the hub's other probes by guessing names.
func unknownProbe(name string) *protocol.Error {
	return protocol.Errorf(protocol.CodeProbeUnknown, "no probe named %q in your scope; list_probes shows the probes you may use", name)
}

func forbiddenTool(tool string) error {
	return fmt.Errorf("%s: this client may not use the %s tool", protocol.CodeForbidden, tool)
}

// selection is the result of expanding a tool call's probe selectors: probes to run on, and entries for explicitly
// named probes that cannot be run (unknown, or outside the client's scope; the two look the same).
type selection struct {
	run     []hubapi.ProbeStatus
	refused []protocol.ProbeResult
}

func (s selection) names() []string {
	var out []string
	for _, p := range s.run {
		out = append(out, p.Name)
	}
	for _, r := range s.refused {
		out = append(out, r.Probe)
	}
	slices.Sort(out)
	return out
}

// selectProbes expands selectors: exact names, globs, "site:<site>" or "*". Globs, sites and "*" only ever expand to
// probes within the client's scope, so they never reveal other probes. An exact name the client may not use is
// reported back as probe_unknown, whether or not a probe outside the scope has it.
func (h *hub) selectProbes(c *clientState, selectors []string) (selection, error) {
	var sel selection
	if len(selectors) == 0 {
		return sel, fmt.Errorf("%s: probes is required: give probe names, globs, site:<site> or *", protocol.CodeInvalidParams)
	}
	all := h.router.Probes()
	byName := make(map[string]hubapi.ProbeStatus, len(all))
	for _, p := range all {
		byName[p.Name] = p
	}
	seen := map[string]bool{}
	add := func(p hubapi.ProbeStatus) {
		if !seen[p.Name] {
			seen[p.Name] = true
			sel.run = append(sel.run, p)
		}
	}
	now := time.Now().UTC()
	for _, s := range selectors {
		s = strings.TrimSpace(s)
		switch {
		case s == "":
			return sel, fmt.Errorf("%s: an entry in probes is empty", protocol.CodeInvalidParams)
		case s == "*":
			for _, p := range all {
				if c.allowsProbe(p) {
					add(p)
				}
			}
		case strings.HasPrefix(s, "site:"):
			site := strings.TrimPrefix(s, "site:")
			if site == "" {
				return sel, fmt.Errorf("%s: %q names no site", protocol.CodeInvalidParams, s)
			}
			for _, p := range all {
				if p.Site == site && c.allowsProbe(p) {
					add(p)
				}
			}
		case strings.ContainsAny(s, `*?[\`):
			if _, err := path.Match(s, ""); err != nil {
				return sel, fmt.Errorf("%s: %q is not a valid glob", protocol.CodeInvalidParams, s)
			}
			for _, p := range all {
				if ok, _ := path.Match(s, p.Name); ok && c.allowsProbe(p) {
					add(p)
				}
			}
		default:
			if seen[s] {
				continue
			}
			if p, ok := byName[s]; ok && c.allowsProbe(p) {
				add(p)
			} else {
				seen[s] = true
				sel.refused = append(sel.refused, refusedResult(s, now, unknownProbe(s)))
			}
		}
	}
	total := len(sel.run) + len(sel.refused)
	if total == 0 {
		return sel, fmt.Errorf("%s: no probe within this client's scope matches %s; list_probes shows the probes you may use",
			protocol.CodeInvalidParams, strings.Join(selectors, ", "))
	}
	if total > maxProbesPerCall {
		return sel, fmt.Errorf("%s: the selection matches %d probes; at most %d may run in one call, so narrow it",
			protocol.CodeInvalidParams, total, maxProbesPerCall)
	}
	return sel, nil
}

func refusedResult(name string, at time.Time, err *protocol.Error) protocol.ProbeResult {
	// Site stays empty: for a probe outside the scope it would tell the client something about a probe it may not use.
	return protocol.ProbeResult{Probe: name, Error: err, StartedAt: at}
}
