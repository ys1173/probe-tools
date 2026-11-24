package devssh

import (
	"bytes"
	"regexp"

	"probetools/internal/protocol"
)

// driver says how one platform runs a single operational command over SSH. Each row is the decision for that
// platform, with the sources it rests on; a correction from the field is a change to one row.
//
// Every driver sends the validated command and nothing else, except a shell driver's setup lines, which are
// documented session-only CLI settings (paging off). None changes the device's configuration. Exec drivers send no
// setup at all, since an exec channel carries exactly one command.
type driver struct {
	// shell runs the command in an interactive shell (PTY, prompt detection) instead of on the exec channel.
	shell bool
	// setup lines are sent, each waiting for the prompt, before the command (shell drivers only).
	setup []string
	// prompt matches the CLI prompt as the last line of output (shell drivers only).
	prompt *regexp.Regexp
	// pager matches a "more" prompt at the end of the output; the driver answers it with pagerKey. This is a fallback
	// for a device that pages despite the transport (it is never relied on for correctness).
	pager    *regexp.Regexp
	pagerKey string
	// errors match, at the start of a line within the first lines of output, the device's message for a command it
	// rejected. Exit statuses are not documented for these CLIs, so the text decides.
	errors *regexp.Regexp
	// userSuffix is appended to the user name at login (RouterOS console options), unless the name already has one.
	userSuffix string
}

var (
	ciscoPager = regexp.MustCompile(`(?i) ?-+ ?more ?-+ ?$`)
)

// drivers, one per platform in protocol.Platforms.
var drivers = map[string]driver{
	// Cisco IOS / IOS-XE: exec. Cisco: "Execution Shell, remote command execution, and SCP are the only applications
	// supported" by the SSH server.
	// https://www.cisco.com/en/US/docs/ios-xml/ios/sec_usr_ssh/configuration/15-1s/sec-secure-shell-v2.html
	// Paging on an exec channel without a PTY is not documented either way (unverified); the pager fallback answers
	// " --More-- " with a space, which pages on and changes nothing.
	// Error texts: "% Invalid input detected at '^' marker.", "% Ambiguous command", "% Incomplete command".
	protocol.PlatformIOS: {
		pager: ciscoPager, pagerKey: " ",
		errors: regexp.MustCompile(`^\s*(% ?(Invalid input detected|Ambiguous command|Incomplete command|Unknown command|Invalid command)|Command authorization failed|Command rejected)`),
	},
	// Cisco NX-OS: exec (vendor statement not found, unverified; widely used). `| no-more` exists per command
	// (https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/nx-os-software/200714-Nexus-NX-OS-tips-and-tricks.html)
	// but the driver does not add it: it would send something the catalog did not validate. Pager fallback as IOS.
	protocol.PlatformNXOS: {
		pager: ciscoPager, pagerKey: " ",
		errors: regexp.MustCompile(`^\s*(% ?(Invalid command|Invalid input|Ambiguous command|Incomplete command|Invalid parameter|Invalid number|Permission denied)|Syntax error while parsing)`),
	},
	// Juniper Junos: exec, for a login class whose shell is the CLI. A root login gets a FreeBSD shell instead, where
	// `show` is "Command not found": profiles must use a non-root user (the error marker below catches it).
	// https://www.juniper.net/documentation/us/en/software/junos-pyez/junos-pyez-developer/topics/task/junos-pyez-program-shell-accessing.html
	// Paging: `| no-more` / `set cli screen-length 0` exist but are not sent (exec takes one command, and the pipe
	// is not the validated command). Fallback answers "---(more)---" / "---(more 42%)---" with a space.
	// https://networkingdocs.hpe.com/documentation/us/en/software/junos/cli/topics/topic-map/cli-environment-settings.html
	protocol.PlatformJunos: {
		pager: regexp.MustCompile(`---\(more( \d+%)?\)--- ?$`), pagerKey: " ",
		errors: regexp.MustCompile(`^\s*(syntax error|unknown command|error: |.*: Command not found\.?$|.* is ambiguous\.)`),
	},
	// Arista EOS: exec (Arista doc not reachable, unverified; EOS's CLI runs commands given to sshd the same way as
	// IOS). Pager fallback as IOS.
	protocol.PlatformEOS: {
		pager: ciscoPager, pagerKey: " ",
		errors: regexp.MustCompile(`^\s*% ?(Invalid input|Ambiguous command|Incomplete command|Unavailable command|Authorization denied|Error)`),
	},
	// Palo Alto PAN-OS: interactive shell. Remote exec is reported to hang or fail (LIVEcommunity threads), and the
	// usual tooling (netmiko, scrapli) uses a shell. `set cli pager off` is an operational-mode command (it is in the
	// Ops command hierarchy, not the configure hierarchy) that only changes this CLI session:
	// https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/cli-command-hierarchy/pan-os-11-2-cli-ops-command-hierarchy
	// https://docs.paloaltonetworks.com/ngfw/pan-os-cli-quick-start/get-started-with-the-cli/customize-the-cli
	// That it lasts only for the session rests on a community answer (unverified in vendor docs); it does not touch the
	// configuration in any case. Decision: send it, and nothing else. Prompt: username@hostname> (operational mode).
	protocol.PlatformPANOS: {
		shell:  true,
		setup:  []string{"set cli pager off"},
		prompt: regexp.MustCompile(`^[\w.-]+@[\w.()-]+> ?$`),
		pager:  regexp.MustCompile(`(?i)(-+ ?more ?-+|lines \d+-\d+( \(END\))?) ?$`), pagerKey: " ",
		errors: regexp.MustCompile(`^\s*(Unknown command:|Invalid syntax\.|Server error|Validation Error:)`),
	},
	// Fortinet FortiOS: exec, one command. FortiOS has no session-only way to turn paging off: `config system console
	// / set output standard` is global configuration, so it is never sent.
	// https://community.fortinet.com/fortigate-3/technical-tip-cli-command-console-output-mode-93126
	// Whether exec output pages is unverified; the fallback answers "--More--" with a space. A login disclaimer that
	// waits for 'a' is reported as an error rather than accepted.
	// Errors: "Unknown action 0", "Command fail. Return code -61" (https://docs.fortinet.com/document/fortiweb/6.1.1/cli-reference/909750).
	protocol.PlatformFortiOS: {
		pager: ciscoPager, pagerKey: " ",
		errors: regexp.MustCompile(`^\s*(Unknown action \d+|Command fail\.|command parse error)`),
	},
	// Ubiquiti EdgeOS: interactive shell. The exec channel runs a non-login bash in which operational `show`
	// commands do not exist; the documented workaround (/opt/vyatta/bin/vyatta-op-cmd-wrapper) is reported to fail
	// for some commands without a TTY (`stty size`), and with a PTY it pages through less. A login shell (vbash) with
	// a PTY is what the operational CLI expects. `terminal length 0` is an operational-mode session setting (it sets
	// the session's pager); it is what netmiko's EdgeRouter driver sends.
	// https://help.uisp.com/hc/en-us/articles/22591243128215-EdgeRouter-Run-Operational-Mode-Command-from-Scripts
	// https://docs.vyos.io/en/1.4/automation/command-scripting.html
	// https://github.com/ktbyers/netmiko/blob/develop/netmiko/ubiquiti/edgerouter_ssh.py
	// Because the command is read by bash, the shell-safe character check below matters most here.
	protocol.PlatformEdgeOS: {
		shell:  true,
		setup:  []string{"terminal length 0"},
		prompt: regexp.MustCompile(`^[\w.-]+@[\w.-]+:\S*[$#] ?$`),
		errors: regexp.MustCompile(`^\s*(Invalid command|Ambiguous command|Incomplete command|Invalid value|-?vbash: .*: command not found)`),
	},
	// MikroTik RouterOS: exec. "To execute remote command it has to be supplied at the end of log-in line"; the SSH
	// server has no pseudo-terminal for multi-line input. Console login options are appended to the user name:
	// c = no colours, e = dumb terminal, t = no terminal auto-detection, 512w = width 512 (the set Ansible uses).
	// https://help.mikrotik.com/docs/spaces/ROS/pages/132350014/SSH
	// https://help.mikrotik.com/docs/spaces/ROS/pages/328134/Command+Line+Interface
	// https://docs.ansible.com/ansible/latest/collections/community/routeros/docsite/ssh-guide.html
	// Errors ("bad command name", "expected end of command", "syntax error") come from forum posts (unverified).
	protocol.PlatformRouterOS: {
		userSuffix: "+cet512w",
		pager:      regexp.MustCompile(`-- \[Q quit\|D dump\|[^\]]*\] ?$`), pagerKey: " ",
		errors: regexp.MustCompile(`^\s*(bad command name|expected end of command|syntax error|no such item|input does not match any value|failure: )`),
	},
}

// errorLines is how many lines from the start of the output are searched for an error marker: a device reports a
// rejected command at once, and later lines (logs, descriptions) may contain anything.
const errorLines = 6

// commandError returns the line that says the device rejected the command, or "".
func (d driver) commandError(out []byte) string {
	if d.errors == nil {
		return ""
	}
	n := 0
	for _, line := range bytes.Split(out, []byte("\n")) {
		t := bytes.TrimSpace(line)
		if len(t) == 0 {
			continue
		}
		if d.errors.Match(t) {
			if len(t) > 200 {
				t = t[:200]
			}
			return string(t)
		}
		n++
		if n == errorLines {
			break
		}
	}
	return ""
}

// shellSafe reports whether every byte of command is in the set a driver will send: letters, digits, space and
// . _ : / , = @ + -. Commands reach a device CLI, and on some platforms or logins (EdgeOS's vbash, a Junos root login,
// a Linux-based CLI) a POSIX shell; the characters that shell treats specially (& ( ) * ? ! ~ # % quotes and the rest)
// are refused here, before any connection, whatever the command list allows.
func shellSafe(command string) bool {
	for i := 0; i < len(command); i++ {
		c := command[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == ' ', c == '.', c == '_', c == ':', c == '/', c == ',', c == '=', c == '@', c == '+', c == '-':
		default:
			return false
		}
	}
	return true
}

var (
	ansiCSI   = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
	ansiOSC   = regexp.MustCompile(`\x1b\][^\x07\x1b]*(\x07|\x1b\\)`)
	ansiOther = regexp.MustCompile(`\x1b[()][0-9A-Za-z]|\x1b[=>78DEHMc]`)
)

// clean turns terminal output into plain text: escape sequences removed, backspaces applied, CRLF to LF, and a line
// rewritten with a bare CR reduced to what a terminal would show last.
func clean(b []byte) []byte {
	b = ansiOSC.ReplaceAll(b, nil)
	b = ansiCSI.ReplaceAll(b, nil)
	b = ansiOther.ReplaceAll(b, nil)
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == '\b' {
			if n := len(out); n > 0 && out[n-1] != '\n' {
				out = out[:n-1]
			}
			continue
		}
		out = append(out, c)
	}
	out = bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n"))
	if bytes.IndexByte(out, '\r') < 0 {
		return out
	}
	lines := bytes.Split(out, []byte("\n"))
	for i, line := range lines {
		if j := bytes.LastIndexByte(line, '\r'); j >= 0 {
			if rest := line[j+1:]; len(bytes.TrimSpace(rest)) > 0 {
				lines[i] = rest
			} else {
				lines[i] = bytes.TrimRight(line[:j], "\r")
				if k := bytes.LastIndexByte(lines[i], '\r'); k >= 0 {
					lines[i] = lines[i][k+1:]
				}
			}
		}
	}
	return bytes.Join(lines, []byte("\n"))
}

// stripPager removes pager prompts the driver answered that the device did not erase itself.
func (d driver) stripPager(b []byte) []byte {
	if d.pager == nil {
		return b
	}
	lines := bytes.Split(b, []byte("\n"))
	for i, line := range lines {
		if loc := d.pager.FindIndex(bytes.TrimRight(line, " ")); loc != nil {
			lines[i] = append(line[:loc[0]:loc[0]], line[min(loc[1], len(line)):]...)
		}
	}
	return bytes.Join(lines, []byte("\n"))
}

// atPager reports whether the output ends with a pager prompt.
func (d driver) atPager(tail []byte) bool {
	if d.pager == nil {
		return false
	}
	t := clean(tail)
	if i := bytes.LastIndexByte(t, '\n'); i >= 0 {
		t = t[i+1:]
	}
	return d.pager.Match(bytes.TrimRight(t, " "))
}

// lastLine is the text after the last newline of cleaned output.
func lastLine(b []byte) []byte {
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		return b[i+1:]
	}
	return b
}
