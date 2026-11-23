// Package info implements probe_info: what this probe is, where it sits and what it may do. It reads only local state
// (interfaces, routing table, resolver configuration) and contacts nothing on the network.
package info

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"time"

	"probetools/internal/check"
	"probetools/internal/protocol"
)

// started approximates the process start: the package is initialised as the binary starts.
var started = time.Now()

// Result is probe_info's answer.
type Result struct {
	Name            string                  `json:"name"`
	Site            string                  `json:"site"`
	Version         string                  `json:"version"`
	Hostname        string                  `json:"hostname"`
	OS              string                  `json:"os"`
	Arch            string                  `json:"arch"`
	UptimeS         int64                   `json:"uptime_s"`
	TimeUTC         string                  `json:"time_utc"`
	Interfaces      []Interface             `json:"interfaces"`
	DefaultGateways []Gateway               `json:"default_gateways,omitempty"`
	DNSServers      []string                `json:"dns_servers"`
	Capabilities    map[string]bool         `json:"capabilities"`
	Policy          *protocol.PolicySummary `json:"policy,omitempty"`
	ListenPorts     string                  `json:"listen_ports"`
}

// Interface is one network interface of the probe host.
type Interface struct {
	Name      string   `json:"name"`
	Up        bool     `json:"up"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses"`
}

// Gateway is one default route.
type Gateway struct {
	Interface string `json:"interface"`
	Gateway   string `json:"gateway"`
	Family    string `json:"family"` // "4" or "6"
}

// params wraps protocol.ProbeInfoParams, which has no Normalize method, so check.Decode can still refuse unknown fields.
type params struct{ protocol.ProbeInfoParams }

func (*params) Normalize() *protocol.Error { return nil }

// Register adds probe_info to r.
func Register(r *check.Registry) {
	r.Register(protocol.CheckProbeInfo, run)
}

func run(ctx context.Context, env *check.Env, raw json.RawMessage) (any, *protocol.Error) {
	if err := check.Decode(raw, &params{}); err != nil {
		return nil, err
	}
	res := Result{
		Name:         env.ProbeName,
		Site:         env.Site,
		Version:      env.Version,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		UptimeS:      int64(time.Since(started) / time.Second),
		TimeUTC:      time.Now().UTC().Format(time.RFC3339),
		Interfaces:   interfaces(),
		DNSServers:   dnsServers("/etc/resolv.conf"),
		Capabilities: env.Capabilities,
		ListenPorts:  listenPorts(env.ListenPortMin, env.ListenPortMax),
	}
	if res.Capabilities == nil {
		res.Capabilities = map[string]bool{}
	}
	if h, err := os.Hostname(); err == nil {
		res.Hostname = h
	}
	if env.Policy != nil {
		s := env.Policy.Summary()
		res.Policy = &s
	}
	res.DefaultGateways = defaultGateways()
	return res, nil
}

func listenPorts(min, max int) string {
	if min == 0 {
		return ""
	}
	return fmt.Sprintf("%d-%d", min, max)
}

func interfaces() []Interface {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := make([]Interface, 0, len(ifs))
	for _, ifi := range ifs {
		it := Interface{Name: ifi.Name, Up: ifi.Flags&net.FlagUp != 0, MTU: ifi.MTU, Addresses: []string{}}
		if addrs, err := ifi.Addrs(); err == nil {
			for _, a := range addrs {
				it.Addresses = append(it.Addresses, a.String())
			}
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
