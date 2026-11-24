package devcmd

import (
	"fmt"
	"slices"
	"strings"

	"probetools/internal/protocol"
)

// The floor applies to every command on every platform, before any list is consulted, and no list (built-in or local)
// can override it. It keeps a command to one read-only line:
//
//   - 1 to protocol.MaxCommandLength bytes, already normalised: no leading, trailing or repeated spaces, no tabs or
//     newlines. Check never re-normalises, so "show version\nreload" is refused rather than repaired.
//   - only the characters in AllowedChars: letters, digits, space and . _ : / , = @ + -. This is the same set the
//     SSH runtime enforces (EdgeOS vbash and a Junos root login reach a POSIX shell), so device_commands never lists
//     a command that device_show would refuse. It shuts out every pipe, separator, redirection, substitution, glob,
//     quote, comment and help character, among them | ; > < ` $ [ ] { } \ & " ' # ! ? * ( ) ~ %.
//   - the platform's read verb first: show; on FortiOS get, or one of the fixed diagnose commands in fortiOSDiagnose
//     (no list can add another); on RouterOS a /menu path and print, or monitor ... once (floorRouterOS).
//   - no word that changes state, sends something, starts a long or streaming job, or leaves the box (commonRefused
//     and platformRefused), anywhere in the command. Each word, and each part of a word split at = @ + ,, is compared
//     case-insensitively (refusedToken).
//   - no abbreviation of such a word after the first word: most of these CLIs accept an unambiguous prefix of a
//     keyword (IOS "show tec" is show tech-support, EOS "show processes to" is show processes top, FortiOS "diagnose
//     deb" is diagnose debug), so a word that is a prefix of a refused word is refused once it is at least
//     minAbbrev characters long. The minimum is 3 by default, so that short keywords and interface types the lists use
//     (ha, up, in, Te, Po, Gi) survive; 2 for top; longer where a real keyword is itself a prefix of a refused word
//     (power and poweroff, down and download, tcp and tcpdump). On EdgeOS, whose operational mode expands prefixes,
//     any prefix of two letters or more of a streaming word (capture, tail, follow, monitor, top) is refused
//     (edgeOSStreaming). A word that starts with a refused stem (kick, as in kickmac) is refused too. A one-letter
//     abbreviation is never refused: that is a known limit.
//
// The refused words are a refusal list, not a parse of each CLI. The built-in lists are exact and need none of it; a
// broad local allow such as ^show .*$ trusts the platform's command tree, and the floor only takes the known-bad words
// out of it. A state-changing keyword that the list does not name, or a platform-specific spelling of one, can still
// pass under such a pattern: a local allow should be as narrow as the built-in ones.

// readVerbs is the first word each platform's commands must start with. RouterOS is handled by floorRouterOS, FortiOS
// diagnose by fortiOSDiagnose.
var readVerbs = map[string][]string{
	protocol.PlatformIOS:     {"show"},
	protocol.PlatformNXOS:    {"show"},
	protocol.PlatformJunos:   {"show"},
	protocol.PlatformEOS:     {"show"},
	protocol.PlatformPANOS:   {"show"},
	protocol.PlatformFortiOS: {"get", "diagnose"},
	protocol.PlatformEdgeOS:  {"show"},
}

// commonRefused are refused on every platform. The list follows the vendors' references for the words that start
// configuration, write, move or fetch files, install software, reload, clear or reset state, add or remove entries,
// bring things up or down, send messages, packets or probes (discover, wol), debug, run shells or scripts, open
// connections to other hosts, or stream (monitor, follow, tail, top, capture, sniffer). tech and tech-support are both here because the short form
// is how tech-support is usually typed.
var commonRefused = words(
	// configuration, files and software
	"configure", "config", "conf", "write", "copy", "delete", "erase", "format", "commit", "rollback", "revert", "set",
	"unset", "edit", "load", "merge", "replace", "save", "import", "export", "file", "archive", "rename", "move", "mkdir", "rmdir", "install", "uninstall", "upgrade", "downgrade", "update", "request", "append",
	"tee", "redirect", "upload", "download", "fetch", "push", "sync", "apply", "activate", "deactivate", "generate",
	// a counters baseline kept for the next command (PAN-OS show counter global filter delta yes)
	"delta",
	// reloads, state and entries
	"reload", "reboot", "shutdown", "shut", "halt", "poweroff", "restart", "reset", "reset-configuration",
	"reset-counters", "clear", "flush", "purge", "kill", "killall", "start", "stop", "enable", "disable", "suspend",
	"resume", "bounce", "failover", "add", "remove", "renew", "release", "refresh", "rotate", "recalculate",
	// debugging, tests and shells
	"debug", "undebug", "test", "execute", "exec", "run", "bash", "sh", "shell", "su", "sudo", "python", "tclsh",
	"guestshell", "tcpdump",
	// leaving the box, sending, probing others
	"send", "ping", "traceroute", "tracert", "ssh", "telnet", "rlogin", "scp", "sftp", "ftp", "tftp", "scan",
	"disconnect",
	// discover sends discovery probes (EdgeOS show ubnt discover); wol sends a wake-on-LAN packet (RouterOS /tool wol)
	"discover", "wol",
	// long jobs and streams
	"monitor", "follow", "tail", "top", "capture", "sniffer", "tech", "tech-support",
)

// platformRefused adds words that are only dangerous on one platform.
var platformRefused = map[string]map[string]bool{
	// FortiOS: "diagnose sys session filter" sets the CLI's session filter, "diagnose sys mpstat" streams (FortiOS 7.6
	// CLI troubleshooting cheat sheet); "diagnose sys ha reset-uptime" changes HA state (FortiOS CLI reference,
	// diagnose sys ha); "diagnose vpn tunnel up|down" brings an IPsec tunnel up or down. fortiOSDiagnose already
	// limits diagnose to fixed commands; these stay as a second line. up and down are FortiOS-only because they are
	// read filters elsewhere (NX-OS show interface status up).
	protocol.PlatformFortiOS: words("filter", "mpstat", "reset-uptime", "up", "down"),
	// PAN-OS: "less" pages log files (PAN-OS CLI quick start).
	protocol.PlatformPANOS: words("less"),
	// EdgeOS operational mode runs on bash.
	protocol.PlatformEdgeOS: words("vbash"),
}

// minAbbrev is the shortest abbreviation of a refused word that the floor refuses, where it is not
// defaultMinAbbrev. top is refused from "to" (show processes to), which no list uses. The longer ones keep real
// keywords and common names usable: power (show environment power, show power inline) is a prefix of poweroff, down
// (NX-OS show interface status down) of download and downgrade, tcp (IOS show tcp brief) of tcpdump; red, app, guest,
// tel, repl and com are common VRF, VLAN and zone names, and redirect, append, apply, guestshell, telnet, replace and
// commit only act as a command's first word or after a pipe, which the floor already refuses.
var minAbbrev = map[string]int{"top": 2, "poweroff": 6, "download": 5, "downgrade": 5, "tcpdump": 4, "redirect": 5,
	"append": 5, "apply": 4, "guestshell": 6, "telnet": 4, "replace": 5, "commit": 4}

const defaultMinAbbrev = 3

// edgeOSStreaming are refused on EdgeOS from two letters: its operational mode expands any unambiguous prefix of a
// keyword (show interfaces ethernet eth0 ca is capture, show log ta is tail), and none of the built-in EdgeOS commands
// has a two-letter word that begins one of these. One-letter abbreviations, here and on every platform, are not
// refused: a single letter is too often a real argument.
var edgeOSStreaming = words("capture", "tail", "follow", "monitor", "top")

// refusedStems are refused as the start of a word: kickmac, kick-client.
var refusedStems = []string{"kick"}

// refusedByPlatform is commonRefused plus platformRefused, sorted, per platform: refusal messages name the same word
// every time.
var refusedByPlatform = func() map[string][]string {
	m := make(map[string][]string, len(protocol.Platforms))
	for _, p := range protocol.Platforms {
		var l []string
		for w := range commonRefused {
			l = append(l, w)
		}
		for w := range platformRefused[p] {
			l = append(l, w)
		}
		slices.Sort(l)
		m[p] = l
	}
	return m
}()

// refusedAs returns the refused word that w (lower case) is, or abbreviates (when abbrev), or starts with (a stem), or
// "".
func refusedAs(platform, w string, abbrev bool) string {
	list := refusedByPlatform[platform]
	if _, ok := slices.BinarySearch(list, w); ok {
		return w
	}
	if !abbrev {
		return ""
	}
	for _, r := range list {
		least := minAbbrev[r]
		if least == 0 {
			least = defaultMinAbbrev
		}
		if platform == protocol.PlatformEdgeOS && edgeOSStreaming[r] {
			least = 2
		}
		if len(w) >= least && len(w) < len(r) && strings.HasPrefix(r, w) {
			return r
		}
	}
	for _, s := range refusedStems {
		if strings.HasPrefix(w, s) {
			return s
		}
	}
	return ""
}

// refusedToken returns why the floor refuses the command word tok, or "". first says tok is the command's first word,
// which is compared whole (it must be the read verb anyway); later words are also checked for abbreviations and
// stems. tok and each part of it split at = @ + , are checked, case-insensitively.
func refusedToken(platform, tok string, first bool) string {
	lt := strings.ToLower(tok)
	parts := strings.FieldsFunc(lt, func(r rune) bool {
		return r == '=' || r == '@' || r == '+' || r == ','
	})
	for _, w := range append(parts, lt) {
		if platform == protocol.PlatformRouterOS && w == "monitor" {
			continue // RouterOS monitor is checked by floorRouterOS: exactly <item> once
		}
		switch r := refusedAs(platform, w, !first); {
		case r == "":
		case r == w:
			return fmt.Sprintf("the word %q changes state, sends, streams or starts a long job", tok)
		default:
			return fmt.Sprintf("the word %q may abbreviate or extend %q, which changes state, sends, streams or "+
				"starts a long job (commands are written out in full)", tok, r)
		}
	}
	return ""
}

// fortiOSDiagnose are the only diagnose commands the floor admits on FortiOS. They are the same strings as the
// diagnose patterns in lists/fortios.yaml (a test holds the two together) and use its placeholders. FortiOS keeps
// display and action side by side in one diagnose sub-tree (diagnose ip arp list beside diagnose ip arp add, diagnose
// vpn tunnel list beside up and down, diagnose wireless-controller wlac with kickmac) and accepts abbreviations, so a
// refusal list cannot make diagnose safe: a local file cannot add diagnose commands, only remove these.
var fortiOSDiagnose = []string{
	`^diagnose sys session stat$`,
	`^diagnose hardware deviceinfo nic <NIF>$`,
	`^diagnose ip arp list$`,
	`^diagnose ip route list$`,
	`^diagnose (?:sys|system) ha status$`,
	`^diagnose netlink aggregate list$`,
	`^diagnose netlink aggregate name <NIF>(?: show)?$`,
	`^diagnose hardware sysinfo (?:memory|conserve)$`,
}

var fortiOSDiagnosePatterns = func() []pattern {
	out := make([]pattern, 0, len(fortiOSDiagnose))
	for _, src := range fortiOSDiagnose {
		exp, err := expand(src)
		if err != nil {
			panic(err)
		}
		p, err := compilePattern(exp, maxBuiltinPatternLength)
		if err != nil {
			panic(err)
		}
		out = append(out, p)
	}
	return out
}()

// RouterOS accepts any unambiguous prefix of a command or argument name (Console manual: "abbreviate command and
// argument names"), so the RouterOS floor works from exact, known-safe names rather than refusing known-bad ones:
//
//   - before where, print takes only the output-shaping arguments in routerOSPrintFlags and routerOSPrintKeys;
//     file=, append, follow, follow-only, follow-strict, interval=, on-event=, show-sensitive and every abbreviation of
//     them are therefore refused;
//   - monitor and monitor-traffic take exactly "<item> once";
//   - after where (a filter expression), any word that is a prefix of routerOSArgsRefused is still refused;
//   - a menu path word may not be a prefix of a refused word or of a RouterOS verb (routerOSVerbs), and no part of a
//     hyphenated path word may be one, so that a command such as "/system reb print" or "/system reset-configuration
//     print" cannot hide before the print: a command word in the path takes "print" as its argument;
//   - /log has no submenus: its other words (info, warning, error, debug) write a log entry, so "/log info print"
//     would log the word print. Only "/log print ..." passes.
//
// The menu path is still a refusal list: a RouterOS command that acts and that routerOSVerbs and the refused words do
// not name can stand before print under a broad local pattern such as ^/.*$.
var routerOSPrintFlags = words("detail", "terse", "brief", "count-only", "without-paging", "value-list", "show-ids",
	"as-value", "stats", "stats-detail", "oid")

var routerOSPrintKeys = words("from", "proplist")

var routerOSArgsRefused = []string{"file", "append", "follow", "follow-only", "follow-strict", "interval",
	"on-event", "do", "show-sensitive"}

// routerOSVerbs are RouterOS menu commands other than print and monitor (Command Line Interface manual, general
// commands) plus menu-specific and top-level ones that act, write or send.
var routerOSVerbs = []string{"add", "remove", "set", "unset", "move", "edit", "comment", "enable", "disable",
	"export", "import", "find", "get", "reset", "reset-counters", "reset-counters-all", "reset-mac-address",
	"reset-configuration", "blink", "cable-test", "refresh", "resend", "stop", "clear", "run", "reboot", "shutdown",
	"upgrade", "downgrade", "uninstall", "apply-changes", "check-for-updates", "install", "flush", "make-static",
	"release", "renew", "send", "scan", "sign", "sup-output", "force-update", "kill-connections", "password", "setup",
	"resolve", "beep", "delay", "quit", "undo", "redo"}

func words(ws ...string) map[string]bool {
	m := make(map[string]bool, len(ws))
	for _, w := range ws {
		m[w] = true
	}
	return m
}

// floor returns "" when command passes, or why it does not.
func floor(platform, command string) string {
	if command == "" || len(command) > protocol.MaxCommandLength {
		return fmt.Sprintf("a command is 1 to %d characters", protocol.MaxCommandLength)
	}
	for i := 0; i < len(command); i++ {
		if !allowedChar(command[i]) {
			c := command[i]
			if c < 0x20 || c > 0x7e {
				return fmt.Sprintf("character 0x%02x is not allowed (one line of printable ASCII)", c)
			}
			return fmt.Sprintf("character %q is not allowed (no pipes, separators, redirection, quotes or "+
				"substitution)", string(c))
		}
	}
	if command[0] == ' ' || command[len(command)-1] == ' ' || strings.Contains(command, "  ") {
		return "the command is not normalised (single spaces, none leading or trailing)"
	}
	toks := strings.Split(command, " ")
	for i, t := range toks {
		if reason := refusedToken(platform, t, i == 0); reason != "" {
			return reason
		}
	}
	if platform == protocol.PlatformRouterOS {
		return floorRouterOS(toks)
	}
	verbs := readVerbs[platform]
	if !slices.Contains(verbs, toks[0]) {
		return fmt.Sprintf("%s commands start with %s", platform, strings.Join(verbs, " or "))
	}
	if platform == protocol.PlatformFortiOS && toks[0] == "diagnose" {
		for _, p := range fortiOSDiagnosePatterns {
			if p.re.MatchString(command) {
				return ""
			}
		}
		return "on fortios, diagnose is limited to a fixed set of display commands (device_commands lists them); " +
			"other diagnose commands bring tunnels down, change ARP and routes, disconnect clients or debug"
	}
	return ""
}

// AllowedChars is every character a device command may contain.
const AllowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._:/,=@+-"

func allowedChar(c byte) bool {
	return c < 0x80 && strings.IndexByte(AllowedChars, c) >= 0
}

// floorRouterOS checks the RouterOS shape: "/menu [submenu ...] print [args]" or "/menu ... monitor[-traffic] <item>
// once". The menu path must be written with spaces (/ip route print, not /ip/route/print), so one command has one
// spelling and a deny pattern cannot be side-stepped by the other. The command word must be written in full.
func floorRouterOS(toks []string) string {
	if !strings.HasPrefix(toks[0], "/") || len(toks[0]) < 2 {
		return "routeros commands start with a /menu path"
	}
	path := []string{toks[0][1:]}
	i := 1
	for ; i < len(toks); i++ {
		if isRouterOSCommand(toks[i]) {
			break
		}
		path = append(path, toks[i])
	}
	if i == len(toks) {
		return "routeros commands are a menu path then print, or monitor ... once"
	}
	refused := refusedByPlatform[protocol.PlatformRouterOS]
	for _, w := range path {
		if !menuWord(w) {
			return fmt.Sprintf("menu path word %q is not a plain menu name (write the path with spaces: /ip route print)",
				w)
		}
		if r := prefixOf(w, routerOSVerbs, routerOSArgsRefused); r != "" {
			return fmt.Sprintf("menu path word %q may abbreviate %s", w, r)
		}
		for _, r := range refused {
			if strings.HasPrefix(r, w) && r != "monitor" {
				return fmt.Sprintf("menu path word %q may abbreviate %s", w, r)
			}
		}
		if parts := strings.Split(w, "-"); len(parts) > 1 {
			for _, part := range parts {
				if _, ok := slices.BinarySearch(refused, part); ok || slices.Contains(routerOSVerbs, part) {
					return fmt.Sprintf("menu path word %q holds %s, which acts", w, part)
				}
			}
		}
	}
	if len(path) > 1 && strings.HasPrefix("log", path[0]) {
		return "/log has no submenus: /log info, warning, error and debug write a log entry; only /log print is a read"
	}
	cmd, args := toks[i], toks[i+1:]
	if cmd != "print" {
		if len(args) != 2 || args[1] != "once" {
			return fmt.Sprintf("%s streams until stopped; only %s <item> once is allowed", cmd, cmd)
		}
		if r := prefixOf(args[0], routerOSArgsRefused); r != "" || strings.Contains(args[0], "=") {
			return fmt.Sprintf("%s item %q is not a plain name", cmd, args[0])
		}
		return ""
	}
	afterWhere := false
	for _, a := range args {
		if !afterWhere {
			if a == "where" {
				afterWhere = true
				continue
			}
			key, _, hasValue := strings.Cut(a, "=")
			if (!hasValue && !routerOSPrintFlags[a]) || (hasValue && !routerOSPrintKeys[key]) {
				return fmt.Sprintf("print argument %q is not one of the output-shaping arguments (detail, terse, "+
					"brief, count-only, without-paging, value-list, show-ids, as-value, stats, stats-detail, oid, "+
					"from=, proplist=, where); file=, follow, interval= and their abbreviations are refused", a)
			}
			continue
		}
		if a == "in" || a == "and" || a == "or" {
			continue // where-expression operators
		}
		key, _, _ := strings.Cut(a, "=")
		if key == "" {
			return fmt.Sprintf("where term %q has no name", a)
		}
		if r := prefixOf(strings.ToLower(key), routerOSArgsRefused); r != "" {
			return fmt.Sprintf("where term %q may abbreviate %s", a, r)
		}
	}
	return ""
}

// prefixOf returns the first word in lists of which w is a prefix, or "".
func prefixOf(w string, lists ...[]string) string {
	for _, l := range lists {
		for _, r := range l {
			if strings.HasPrefix(r, w) {
				return r
			}
		}
	}
	return ""
}

func isRouterOSCommand(t string) bool {
	return t == "print" || t == "monitor" || t == "monitor-traffic"
}

func menuWord(w string) bool {
	if w == "" || w[0] < 'a' || w[0] > 'z' {
		return false
	}
	for i := 0; i < len(w); i++ {
		c := w[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
