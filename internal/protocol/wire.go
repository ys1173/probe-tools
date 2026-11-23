// Package protocol is the contract shared by the hub and the probes: the messages on the probe link, the parameters of
// every check, the result envelope and its error codes. Nothing here does I/O.
package protocol

import (
	"encoding/json"
	"time"
)

// WireVersion is the WebSocket subprotocol both sides speak. A probe and a hub with different versions refuse each other.
const WireVersion = "probe.v1"

// HTTP paths the hub serves to probes, on its probe listener.
const (
	PathEnroll  = "/v1/enroll"  // POST EnrollRequest, answers EnrollResponse
	PathConnect = "/v1/connect" // WebSocket upgrade, Authorization: Bearer <probe_id>.<secret>
)

// EnrollRequest exchanges a single-use enrolment token for the probe's lasting identity.
type EnrollRequest struct {
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	Version  string `json:"version"`
}

// EnrollResponse gives the probe its identity. The name and site come from the token, never from the probe, so a probe
// cannot claim another's name. The secret is shown once; the hub keeps only its hash.
type EnrollResponse struct {
	ProbeID string `json:"probe_id"`
	Name    string `json:"name"`
	Site    string `json:"site"`
	Secret  string `json:"secret"`
}

// Message types on the probe link. Every frame is one JSON object with a "type" field.
const (
	TypeHello   = "hello"   // probe -> hub, first frame after the upgrade
	TypeWelcome = "welcome" // hub -> probe, answer to hello
	TypeJob     = "job"     // hub -> probe, run one check
	TypeCancel  = "cancel"  // hub -> probe, stop a running job
	TypeResult  = "result"  // probe -> hub, the outcome of one job
)

// Envelope is read first to learn a frame's type.
type Envelope struct {
	Type string `json:"type"`
}

// Hello tells the hub what this probe is and can do. The hub shows it in list_probes and uses Addresses as the default
// address for path_test.
type Hello struct {
	Type         string          `json:"type"`
	Version      string          `json:"version"`
	OS           string          `json:"os"`
	Arch         string          `json:"arch"`
	Hostname     string          `json:"hostname"`
	Addresses    []string        `json:"addresses"`    // the probe's own interface addresses, loopback excluded
	Checks       []string        `json:"checks"`       // check names this probe will run
	Capabilities map[string]bool `json:"capabilities"` // e.g. "raw_icmp": false when the probe lacks NET_RAW
	Policy       PolicySummary   `json:"policy"`
	ListenPorts  string          `json:"listen_ports"` // the range path_test may open on this probe, e.g. "40000-40100"; empty means none
}

// PolicySummary is what a probe reports of its local target policy. It is information for agents, not enforcement: the
// probe enforces its own policy whatever the hub sends.
type PolicySummary struct {
	Mode       string   `json:"mode"` // "open" or "closed"
	AllowCIDRs []string `json:"allow_cidrs,omitempty"`
	AllowHosts []string `json:"allow_hosts,omitempty"`
	DenyCIDRs  []string `json:"deny_cidrs,omitempty"`
}

// Welcome confirms the session.
type Welcome struct {
	Type string `json:"type"`
	Name string `json:"name"`
	Site string `json:"site"`
}

// Job asks the probe to run one check. DeadlineMS is the time the hub will wait; the probe must answer within it, with a
// partial result where the check has one.
type Job struct {
	Type       string          `json:"type"`
	ID         string          `json:"id"`
	Check      string          `json:"check"`
	Params     json.RawMessage `json:"params"`
	DeadlineMS int             `json:"deadline_ms"`
}

// Cancel asks the probe to stop a job; the probe still sends its result, with code "cancelled".
type Cancel struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Result is the probe's answer to a job. Exactly one of Data and Error is set.
type Result struct {
	Type       string          `json:"type"`
	ID         string          `json:"id"`
	Data       json.RawMessage `json:"data,omitempty"`
	Error      *Error          `json:"error,omitempty"`
	StartedAt  time.Time       `json:"started_at"`
	DurationMS int64           `json:"duration_ms"`
}
