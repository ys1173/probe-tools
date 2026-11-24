package devcmd

import (
	"embed"
	"fmt"
	"regexp"

	"gopkg.in/yaml.v3"
)

// The built-in lists are one YAML file per platform under lists/, embedded in the binary. Each file is a list of
// groups; each group names the vendor reference its commands were taken from and lists anchored patterns. Patterns
// use placeholders for argument shapes so that every list admits the same, narrow arguments:
//
//	<IF>    an interface name with a number, e.g. GigabitEthernet1/0/1, Ethernet1, ge-0/0/0.0, ethernet1/1, ae0,
//	        Port-Channel10, Vlan 10 (type and number may be separated by one space)
//	<NIF>   a free-form interface name, for platforms whose names need no number: port1, internal, wan1, ether1,
//	        sfp-sfpplus1, bridge
//	<V4> <V4P> <V6> <V6P> <PFX>  IPv4 and IPv6 addresses and prefixes; PFX is any of them
//	<VRF>   a VRF or routing-instance name
//	<NAME>  another object name: a routing table (inet.0), a logical router, a peer group
//	<NUM> <VLAN> <VLANS> <MAC>
//
//go:embed lists/*.yaml
var listFS embed.FS

// maxBuiltinPatternLength is the expanded length a built-in pattern may reach. Placeholders expand to tens of
// characters each, so built-ins get more room than the local file's 512; the tests hold them to it.
const maxBuiltinPatternLength = 1024

const (
	v4  = `[0-9]{1,3}(?:\.[0-9]{1,3}){3}`
	v6  = `[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}`
	v4p = v4 + `/[0-9]{1,2}`
	v6p = v6 + `/[0-9]{1,3}`
)

var fragments = map[string]string{
	"IF":    `[A-Za-z][A-Za-z.-]{0,31} ?[0-9][A-Za-z0-9./:-]{0,31}`,
	"NIF":   `[A-Za-z0-9][A-Za-z0-9._-]{0,31}`,
	"V4":    v4,
	"V4P":   v4p,
	"V6":    v6,
	"V6P":   v6p,
	"PFX":   `(?:` + v4 + `(?:/[0-9]{1,2})?|` + v6 + `(?:/[0-9]{1,3})?)`,
	"VRF":   `[A-Za-z0-9_.-]{1,32}`,
	"NAME":  `[A-Za-z0-9_.-]{1,64}`,
	"NUM":   `[0-9]{1,10}`,
	"VLAN":  `[0-9]{1,4}`,
	"VLANS": `[0-9]{1,4}(?:[,-][0-9]{1,4}){0,15}`,
	"MAC":   `(?:[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}|[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})`,

	// RouterOS print arguments that only shape the output (Scripting manual, print parameters), up to three.
	"ROSOPT": `(?: (?:detail|terse|brief|count-only|without-paging|value-list|show-ids|as-value)){0,3}`,
	// One optional RouterOS where condition with a plain value: no quotes, regex matches or logic.
	"ROSWHERE": `(?: where (?:(?:name|interface|address|dst-address|gateway|mac-address|vrf|routing-table|network)=` +
		`[A-Za-z0-9._:/-]{1,64}|dst-address in (?:` + v4p + `|` + v6p + `)|dynamic|static|active|running|disabled|inactive))?`,
}

var placeholder = regexp.MustCompile(`<([A-Z0-9]+)>`)

type listFile struct {
	Groups []listGroup `yaml:"groups"`
}

type listGroup struct {
	Source string   `yaml:"source"`
	Allow  []string `yaml:"allow"`
}

// builtinGroups reads one platform's embedded list.
func builtinGroups(platform string) ([]listGroup, error) {
	data, err := listFS.ReadFile("lists/" + platform + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("built-in list for %s: %w", platform, err)
	}
	var f listFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("built-in list for %s: %w", platform, err)
	}
	return f.Groups, nil
}

// builtinPatterns compiles one platform's embedded list, placeholders expanded.
func builtinPatterns(platform string) ([]pattern, error) {
	groups, err := builtinGroups(platform)
	if err != nil {
		return nil, err
	}
	var out []pattern
	for _, g := range groups {
		for _, src := range g.Allow {
			exp, err := expand(src)
			if err != nil {
				return nil, fmt.Errorf("built-in list for %s: %w", platform, err)
			}
			p, err := compilePattern(exp, maxBuiltinPatternLength)
			if err != nil {
				return nil, fmt.Errorf("built-in list for %s: %w", platform, err)
			}
			out = append(out, p)
		}
	}
	return out, nil
}

func expand(src string) (string, error) {
	var bad string
	out := placeholder.ReplaceAllStringFunc(src, func(m string) string {
		f, ok := fragments[m[1:len(m)-1]]
		if !ok {
			bad = m
			return m
		}
		return f
	})
	if bad != "" {
		return "", fmt.Errorf("pattern %q: unknown placeholder %s", src, bad)
	}
	return out, nil
}
