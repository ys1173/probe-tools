// Package check is the interface between the probe's runtime and the checks it runs. A check gets its parameters as
// JSON, validates them, reaches targets only through Env.Policy, and returns a JSON-encodable result or a
// *protocol.Error. The runtime enforces the job deadline through ctx and the concurrency limit; the policy enforces the
// per-address rate limit when a check resolves or charges an address, so a check must pass the job's ctx to it. Checks
// must still honour ctx and return a partial result where they have one.
package check

import (
	"context"
	"encoding/json"
	"net"
	"sort"
	"sync"

	"probetools/internal/policy"
	"probetools/internal/protocol"
)

// Env is what a check may use. It is shared by every job, so checks must not change it.
type Env struct {
	Policy *policy.Policy

	// ProbeName and Site are the probe's identity, for checks that report it (probe_info).
	ProbeName string
	Site      string
	Version   string

	// ListenPorts is the inclusive range listen_start may open. Zero values mean listening is off.
	ListenPortMin, ListenPortMax int

	// Capabilities found at start-up, e.g. "raw_icmp". Checks that need one return CodeUnavailable without it.
	Capabilities map[string]bool

	// Run lets a composite check (diagnose) run another registered check with the same Env and limits.
	Run func(ctx context.Context, name string, params any) (any, *protocol.Error)

	// Shared state for checks that outlive one job (path_test's listeners). Keyed by the owning package.
	State sync.Map
}

// Func runs one check.
type Func func(ctx context.Context, env *Env, params json.RawMessage) (any, *protocol.Error)

// Registry maps check names to functions.
type Registry struct {
	mu    sync.RWMutex
	funcs map[string]Func
}

func NewRegistry() *Registry { return &Registry{funcs: map[string]Func{}} }

// Register adds a check; registering a name twice panics, since it is a programming error.
func (r *Registry) Register(name string, f Func) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.funcs[name]; dup {
		panic("check registered twice: " + name)
	}
	r.funcs[name] = f
}

// Get returns the check named name.
func (r *Registry) Get(name string) (Func, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	f, ok := r.funcs[name]
	return f, ok
}

// Names lists the registered checks, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.funcs))
	for n := range r.funcs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Normalizer is implemented by every params type in package protocol.
type Normalizer interface{ Normalize() *protocol.Error }

// Decode unmarshals raw into p, refusing unknown fields, and normalises it.
func Decode[P Normalizer](raw json.RawMessage, p P) *protocol.Error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(p); err != nil {
		return protocol.Errorf(protocol.CodeInvalidParams, "parameters: %v", err)
	}
	return p.Normalize()
}

// SourceDialer returns a TCP net.Dialer bound to the first address of the named interface, or a plain dialer for "". The
// interface must exist on the probe; its address must match the family of the target, which the dial will enforce.
func SourceDialer(iface string, family string) (*net.Dialer, *protocol.Error) {
	d := &net.Dialer{}
	if iface == "" {
		return d, nil
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeInvalidParams, "no interface %q on this probe", iface)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, protocol.Errorf(protocol.CodeInternal, "reading interface %q: %v", iface, err)
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLinkLocalUnicast() {
			continue
		}
		is4 := ipn.IP.To4() != nil
		if (family == "6" && is4) || (family == "4" && !is4) {
			continue
		}
		d.LocalAddr = &net.TCPAddr{IP: ipn.IP}
		return d, nil
	}
	return nil, protocol.Errorf(protocol.CodeInvalidParams, "interface %q has no usable IPv%s address", iface, map[string]string{"": "4/6", "4": "4", "6": "6"}[family])
}
