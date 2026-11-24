package hub

import (
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"probetools/internal/protocol"
)

// Limits on a probe's hello. A probe is authenticated but not trusted: whatever it reports is shown to agents, so it
// is held to the shapes a real probe sends and to sizes that keep list_probes small.
const (
	maxHelloText      = 64 // version, os, arch, hostname
	maxHelloAddresses = 32
	maxHelloChecks    = 64
	maxHelloCaps      = 32
	maxPolicyEntries  = 256 // each of allow_cidrs, allow_hosts, deny_cidrs, deny_hosts
	maxPolicyHost     = 253
	maxSSHProfiles    = 64
	maxSSHProfileNets = 16 // CIDRs per SSH profile
)

var (
	// helloText covers hostnames, GOOS/GOARCH and version strings set with -ldflags (v1.2.3-4-gabc+dirty).
	helloText     = regexp.MustCompile(`^[A-Za-z0-9._+~:-]*$`)
	checkName     = regexp.MustCompile(`^[a-z_]{1,32}$`)
	capName       = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)
	policyHost    = regexp.MustCompile(`^[A-Za-z0-9.*_-]+$`)
	listenPortsRE = regexp.MustCompile(`^\d{1,5}(-\d{1,5})?$`)
	// sshName is a profile or jump host name as the probe's SSH store writes it.
	sshName = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

// validateHello checks a hello and returns the copy the hub keeps. Addresses and CIDRs are re-written from their parsed
// form, so the hub stores and serves what it checked rather than the probe's text. Errors name the field, never its
// content.
func validateHello(in protocol.Hello) (protocol.Hello, error) {
	out := protocol.Hello{Type: in.Type, Policy: protocol.PolicySummary{Mode: in.Policy.Mode}, ListenPorts: in.ListenPorts}
	for _, f := range []struct {
		name string
		v    string
		dst  *string
	}{{"version", in.Version, &out.Version}, {"os", in.OS, &out.OS}, {"arch", in.Arch, &out.Arch}, {"hostname", in.Hostname, &out.Hostname}} {
		if len(f.v) > maxHelloText || !helloText.MatchString(f.v) {
			return protocol.Hello{}, fmt.Errorf("%s is longer than %d characters or has characters outside [A-Za-z0-9._+~:-]", f.name, maxHelloText)
		}
		*f.dst = f.v
	}

	if len(in.Addresses) > maxHelloAddresses {
		return protocol.Hello{}, fmt.Errorf("more than %d addresses", maxHelloAddresses)
	}
	for i, a := range in.Addresses {
		v, ok := canonicalAddr(a)
		if !ok {
			return protocol.Hello{}, fmt.Errorf("addresses[%d] is not an IP address or address/prefix", i)
		}
		out.Addresses = append(out.Addresses, v)
	}

	if len(in.Checks) > maxHelloChecks {
		return protocol.Hello{}, fmt.Errorf("more than %d checks", maxHelloChecks)
	}
	for i, c := range in.Checks {
		if !checkName.MatchString(c) {
			return protocol.Hello{}, fmt.Errorf("checks[%d] is not a check name", i)
		}
	}
	out.Checks = in.Checks

	if len(in.Capabilities) > maxHelloCaps {
		return protocol.Hello{}, fmt.Errorf("more than %d capabilities", maxHelloCaps)
	}
	for k := range in.Capabilities {
		if !capName.MatchString(k) {
			return protocol.Hello{}, fmt.Errorf("a capability name is not of the form [a-z0-9_]{1,32}")
		}
	}
	out.Capabilities = in.Capabilities

	if in.Policy.Mode != "open" && in.Policy.Mode != "closed" {
		return protocol.Hello{}, fmt.Errorf("policy.mode is neither open nor closed")
	}
	var err error
	if out.Policy.AllowCIDRs, err = canonicalCIDRs("policy.allow_cidrs", in.Policy.AllowCIDRs); err != nil {
		return protocol.Hello{}, err
	}
	if out.Policy.DenyCIDRs, err = canonicalCIDRs("policy.deny_cidrs", in.Policy.DenyCIDRs); err != nil {
		return protocol.Hello{}, err
	}
	if out.Policy.AllowHosts, err = checkPolicyHosts("policy.allow_hosts", in.Policy.AllowHosts); err != nil {
		return protocol.Hello{}, err
	}
	if out.Policy.DenyHosts, err = checkPolicyHosts("policy.deny_hosts", in.Policy.DenyHosts); err != nil {
		return protocol.Hello{}, err
	}

	// The ssh section is optional: a probe without device access, or from before it existed, leaves it out.
	if in.SSH != nil {
		if out.SSH, err = validateSSH(*in.SSH); err != nil {
			return protocol.Hello{}, err
		}
	}

	if in.ListenPorts != "" && !listenPortsRE.MatchString(in.ListenPorts) {
		return protocol.Hello{}, fmt.Errorf("listen_ports is not a port or port range")
	}
	return out, nil
}

// checkPolicyHosts accepts what a probe's policy takes as host patterns: names, or *.name.
func checkPolicyHosts(field string, list []string) ([]string, error) {
	if len(list) > maxPolicyEntries {
		return nil, fmt.Errorf("%s has more than %d entries", field, maxPolicyEntries)
	}
	for i, h := range list {
		if len(h) > maxPolicyHost || !policyHost.MatchString(h) {
			return nil, fmt.Errorf("%s[%d] is not a host name or *.name", field, i)
		}
	}
	return list, nil
}

// validateSSH checks the summary of a probe's SSH profiles and returns the copy the hub keeps. It is shown to agents
// beside the probe, so names and platforms are held to the shapes the probe's own store produces.
func validateSSH(in protocol.SSHSummary) (*protocol.SSHSummary, error) {
	if len(in.Profiles) > maxSSHProfiles {
		return nil, fmt.Errorf("ssh.profiles has more than %d entries", maxSSHProfiles)
	}
	out := &protocol.SSHSummary{Profiles: make([]protocol.SSHProfileSummary, 0, len(in.Profiles))}
	for i, p := range in.Profiles {
		field := fmt.Sprintf("ssh.profiles[%d]", i)
		if !sshName.MatchString(p.Name) {
			return nil, fmt.Errorf("%s.name is not of the form [a-z0-9-]{1,32}", field)
		}
		if !slices.Contains(protocol.Platforms, p.Platform) {
			return nil, fmt.Errorf("%s.platform is not a supported platform", field)
		}
		if p.Jump != "" && !sshName.MatchString(p.Jump) {
			return nil, fmt.Errorf("%s.jump is not of the form [a-z0-9-]{1,32}", field)
		}
		if len(p.CIDRs) > maxSSHProfileNets {
			return nil, fmt.Errorf("%s.cidrs has more than %d entries", field, maxSSHProfileNets)
		}
		cidrs, err := canonicalCIDRsMax(field+".cidrs", p.CIDRs, maxSSHProfileNets)
		if err != nil {
			return nil, err
		}
		out.Profiles = append(out.Profiles, protocol.SSHProfileSummary{Name: p.Name, CIDRs: cidrs, Platform: p.Platform, Jump: p.Jump})
	}
	return out, nil
}

// canonicalAddr accepts "10.0.0.5" or "10.0.0.5/24" and returns it as netip writes it. Zones are refused: netip
// accepts any text after %, and a probe does not report the link-local addresses that need one.
func canonicalAddr(s string) (string, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return "", false
		}
		return p.String(), true
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return "", false
	}
	return a.String(), true
}

// canonicalCIDRs accepts what the probe's policy accepts in its config: CIDRs or bare addresses, with spaces around.
func canonicalCIDRs(field string, list []string) ([]string, error) {
	return canonicalCIDRsMax(field, list, maxPolicyEntries)
}

func canonicalCIDRsMax(field string, list []string, max int) ([]string, error) {
	if len(list) > max {
		return nil, fmt.Errorf("%s has more than %d entries", field, max)
	}
	var out []string
	for i, c := range list {
		v, ok := canonicalAddr(strings.TrimSpace(c))
		if !ok {
			return nil, fmt.Errorf("%s[%d] is not a CIDR or address", field, i)
		}
		out = append(out, v)
	}
	return out, nil
}
