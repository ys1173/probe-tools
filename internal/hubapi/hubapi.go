// Package hubapi is the boundary inside the hub between the probe side (enrolment, the probe link, routing jobs) and the
// agent side (the MCP server). The MCP server only ever reaches probes through Router.
package hubapi

import (
	"context"
	"encoding/json"
	"time"

	"probetools/internal/protocol"
)

// ProbeStatus is what the hub knows about one enrolled, unrevoked probe.
type ProbeStatus struct {
	Name         string                 `json:"name"`
	Site         string                 `json:"site"`
	Online       bool                   `json:"online"`
	LastSeen     time.Time              `json:"last_seen,omitzero"`
	ConnectedAt  time.Time              `json:"connected_at,omitzero"`
	EnrolledAt   time.Time              `json:"enrolled_at"`
	Version      string                 `json:"version,omitempty"`
	OS           string                 `json:"os,omitempty"`
	Arch         string                 `json:"arch,omitempty"`
	Hostname     string                 `json:"hostname,omitempty"`
	Addresses    []string               `json:"addresses,omitempty"`
	Checks       []string               `json:"checks,omitempty"`
	Capabilities map[string]bool        `json:"capabilities,omitempty"`
	Policy       protocol.PolicySummary `json:"policy"`
	ListenPorts  string                 `json:"listen_ports,omitempty"`
}

// Router runs checks on probes. It never queues: a probe that is offline answers CodeProbeOffline at once.
type Router interface {
	// Run sends one job to the named probe and waits up to deadline (plus protocol.HubSlackMS) for its result, or until
	// ctx ends, in which case it cancels the job on the probe. The ProbeResult always has Probe and Site set (Site empty
	// for an unknown probe) and either OK with Result as the probe's raw JSON, or an Error.
	Run(ctx context.Context, probe, check string, params json.RawMessage, deadline time.Duration) protocol.ProbeResult

	// Probes lists every enrolled, unrevoked probe, sorted by name.
	Probes() []ProbeStatus

	// Probe returns one probe's status.
	Probe(name string) (ProbeStatus, bool)
}

// Client is one MCP client allowed to call the hub, from the hub's configuration.
type Client struct {
	Name     string   `yaml:"name"`
	TokenEnv string   `yaml:"token_env"` // environment variable holding the client's bearer token
	Probes   []string `yaml:"probes"`    // probe name globs ("syd-*"), "site:<site>", or "*"; empty allows none
	Tools    []string `yaml:"tools"`     // tool names, or "*"; empty allows none
}
