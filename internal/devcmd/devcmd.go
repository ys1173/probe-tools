// Package devcmd decides which commands device_show may run. Each platform has a built-in list of allowed command
// patterns, a probe may add or remove patterns in a local file, and a fixed floor that no list can override keeps
// every command read-only: one command, printable, no pipes, separators or redirection, starting with the platform's
// read verb.
//
// This file holds the API the SSH runtime builds against. The floor is in floor.go, the built-in lists in lists/*.yaml
// (compiled by builtin.go), and the local file's format in local.go.
package devcmd

import (
	"fmt"
	"regexp"
	"strings"

	"probetools/internal/protocol"
)

// Catalog is a compiled set of per-platform lists. It is safe for concurrent use and never changes after Load.
type Catalog struct {
	platforms map[string]*platformList
}

type platformList struct {
	allow []pattern // built-in patterns first, then the local file's additions
	deny  []pattern // the local file's removals
	local bool      // the local file changes this platform
}

// pattern is one anchored regular expression. source is the pattern as written (built-in placeholders expanded); re
// is compiled as ^(?:inner)$ so that an alternation in the source can never escape the anchors.
type pattern struct {
	source string
	re     *regexp.Regexp
}

// MaxPatternLength bounds one pattern in the local file.
const MaxPatternLength = 512

// Load compiles the built-in lists plus the local file's changes. An empty path means the built-in lists only. A
// platform with builtin: false in the local file uses only the file's allow patterns. A local
// file that fails to parse, or holds a pattern that is not anchored or does not compile, is an error: the probe refuses
// to start rather than run with a list the operator did not intend.
func Load(localFile string) (*Catalog, error) {
	c := &Catalog{platforms: make(map[string]*platformList, len(protocol.Platforms))}
	for _, p := range protocol.Platforms {
		allow, err := builtinPatterns(p)
		if err != nil {
			return nil, err // a bug in the embedded lists; the tests catch it
		}
		c.platforms[p] = &platformList{allow: allow}
	}
	if localFile == "" {
		return c, nil
	}
	changes, err := readLocal(localFile)
	if err != nil {
		return nil, err
	}
	for p, ch := range changes {
		pl := c.platforms[p]
		if ch.noBuiltin {
			// The operator's allow patterns are the whole list for this platform.
			pl.allow = nil
		}
		pl.allow = append(pl.allow, ch.allow...)
		pl.deny = append(pl.deny, ch.deny...)
		pl.local = ch.noBuiltin || len(ch.allow) > 0 || len(ch.deny) > 0
	}
	return c, nil
}

// Check reports whether command may run on platform. command has already been through DeviceShowParams.Normalize. It
// returns nil when allowed, or a *protocol.Error with CodeNotAllowed saying why (the floor, a deny pattern, or no allow
// pattern), or CodeInvalidParams for an unknown platform.
//
// The order is fixed: the floor first (no list can override it), then the local deny patterns (deny always wins), then
// the allow patterns. Deny patterns are compiled to ignore case, because several CLIs accept keywords in any case and a
// keyword or argument typed in another case must not slip past a removal. Nothing else is canonicalised: a deny
// pattern must cover every spelling of its argument (Vlan10 and Vlan 10, Gi1/0/1 and GigabitEthernet1/0/1), as the
// local file's format notes.
func (c *Catalog) Check(platform, command string) *protocol.Error {
	pl, ok := c.platforms[platform]
	if !ok {
		return protocol.Errorf(protocol.CodeInvalidParams, "platform %q is not supported", platform)
	}
	if reason := floor(platform, command); reason != "" {
		return protocol.Errorf(protocol.CodeNotAllowed, "refused by the floor: %s", reason)
	}
	for _, d := range pl.deny {
		if d.re.MatchString(command) {
			return protocol.Errorf(protocol.CodeNotAllowed, "refused by local deny pattern %s", d.source)
		}
	}
	for _, a := range pl.allow {
		if a.re.MatchString(command) {
			return nil
		}
	}
	return protocol.Errorf(protocol.CodeNotAllowed,
		"not in the allow list for %s (commands are written out in full; device_commands lists the patterns)", platform)
}

// List returns the effective lists, for one platform or all (platform ""), in protocol.Platforms order. An unknown
// platform gives nil. The slices are copies.
func (c *Catalog) List(platform string) []protocol.PlatformCommands {
	var out []protocol.PlatformCommands
	for _, p := range protocol.Platforms {
		if platform != "" && platform != p {
			continue
		}
		pl := c.platforms[p]
		pc := protocol.PlatformCommands{Platform: p, Allow: sources(pl.allow), Local: pl.local}
		if len(pl.deny) > 0 {
			pc.Deny = sources(pl.deny)
		}
		out = append(out, pc)
	}
	return out
}

func sources(ps []pattern) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.source)
	}
	return out
}

// compilePattern checks that src is anchored (^...$), at most max characters, and compiles. The outer anchors are
// stripped and the inner expression is compiled as ^(?:inner)$: "^a|b$" would otherwise match any command containing
// b, and a final "\$" (a literal dollar, not an anchor) would otherwise pass as anchored. Wrapped, the first is
// anchored on both sides and the second fails to compile.
func compilePattern(src string, max int) (pattern, error) {
	if len(src) > max {
		return pattern{}, fmt.Errorf("pattern %q is longer than %d characters", src, max)
	}
	if len(src) < 2 || !strings.HasPrefix(src, "^") || !strings.HasSuffix(src, "$") {
		return pattern{}, fmt.Errorf("pattern %q must start with ^ and end with $", src)
	}
	inner := src[1 : len(src)-1]
	if inner == "" {
		return pattern{}, fmt.Errorf("pattern %q is empty", src)
	}
	re, err := regexp.Compile("^(?:" + inner + ")$")
	if err != nil {
		return pattern{}, fmt.Errorf("pattern %q does not compile: %v", src, err)
	}
	return pattern{source: src, re: re}, nil
}

// compileDenyPattern is compilePattern for a deny pattern: the same checks, compiled to ignore case.
func compileDenyPattern(src string, max int) (pattern, error) {
	p, err := compilePattern(src, max)
	if err != nil {
		return p, err
	}
	re, err := regexp.Compile("(?i)" + p.re.String())
	if err != nil {
		return pattern{}, fmt.Errorf("pattern %q does not compile: %v", src, err)
	}
	p.re = re
	return p, nil
}
