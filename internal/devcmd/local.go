package devcmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"

	"gopkg.in/yaml.v3"

	"probetools/internal/protocol"
)

// localFile is the probe's own changes to the built-in lists:
//
//	platforms:
//	  ios:
//	    allow: ['^show ip interface brief$']   # added to the built-in list; still subject to the floor
//	    deny:  ['^show ip route vrf .*$']       # removes matches; deny always wins
//	  routeros:
//	    deny: ['^/ip neighbor print.*$']
//	  fortios:
//	    builtin: false                          # don't use the built-in list: only the allow patterns below run
//	    allow: ['^get system status$']
//
// A deny pattern matches the command as written (and lower-cased); nothing is canonicalised. Device CLIs accept several
// spellings of one argument, and the built-in patterns admit them: an interface as Vlan10 or Vlan 10, Gi1/0/1 or
// GigabitEthernet1/0/1, Port-Channel10 or Po10. A deny pattern meant to keep one interface, VRF or peer out must match
// every spelling the allow patterns admit (for example '^show interfaces (?:vlan ?10|vl ?10)(?: .*)?$'), or deny the
// whole command. The same holds for keyword abbreviations a local allow admits. Deny patterns ignore case: a removal
// must not be side-stepped by typing a keyword or argument in another case.
type localFile struct {
	Platforms map[string]localPlatform `yaml:"platforms"`
}

type localPlatform struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
	// Builtin false drops the platform's built-in list on this probe, so the allow patterns here are the whole list
	// (none means no command runs on that platform). Left out, the built-in list is used.
	Builtin *bool `yaml:"builtin"`
}

type localChanges struct {
	allow, deny []pattern
	noBuiltin   bool
}

// readLocal parses and compiles the local file. Unknown keys, unknown platforms, unanchored, over-long or
// non-compiling patterns are all errors.
func readLocal(path string) (map[string]localChanges, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("device commands file: %w", err)
	}
	var f localFile
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("device commands file %s: %w", path, err)
	}
	// A second document would be silently ignored; refuse it instead.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("device commands file %s: holds more than one YAML document", path)
	}
	out := make(map[string]localChanges, len(f.Platforms))
	for name, lp := range f.Platforms {
		if !slices.Contains(protocol.Platforms, name) {
			return nil, fmt.Errorf("device commands file %s: unknown platform %q (supported: %v)", path, name,
				protocol.Platforms)
		}
		var ch localChanges
		for _, src := range lp.Allow {
			p, err := compilePattern(src, MaxPatternLength)
			if err != nil {
				return nil, fmt.Errorf("device commands file %s: %s allow: %w", path, name, err)
			}
			ch.allow = append(ch.allow, p)
		}
		for _, src := range lp.Deny {
			p, err := compileDenyPattern(src, MaxPatternLength)
			if err != nil {
				return nil, fmt.Errorf("device commands file %s: %s deny: %w", path, name, err)
			}
			ch.deny = append(ch.deny, p)
		}
		ch.noBuiltin = lp.Builtin != nil && !*lp.Builtin
		out[name] = ch
	}
	return out, nil
}
