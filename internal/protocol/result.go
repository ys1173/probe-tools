package protocol

import (
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Error codes. A check that ran and found a problem (a host that does not answer, a port that is closed) is not an error:
// that is its result. An Error means the check could not give an answer.
const (
	CodeDenied        = "denied"              // the probe's target policy refused the target, or an address it resolved to
	CodeInvalidParams = "invalid_params"      // parameters failed validation
	CodeUnavailable   = "unavailable"         // the probe cannot run this check, e.g. no NET_RAW for raw ICMP
	CodeBusy          = "busy"                // a concurrency or rate limit was reached; try again later
	CodeTimeout       = "timeout"             // the job's deadline passed before any result
	CodeCancelled     = "cancelled"           // the hub cancelled the job
	CodeUnresolved    = "unresolved"          // the target name did not resolve (diagnose reports this as a DNS finding)
	CodeNotFound      = "not_found"           // e.g. an unknown check or listen_id
	CodeNotAllowed    = "command_not_allowed" // device_show: the command is not in this probe's list for the device's platform
	CodeInternal      = "internal"            // a bug or an unexpected failure

	// Hub-side codes, set when the hub could not get an answer from a probe.
	CodeProbeOffline = "probe_offline" // the probe is not connected; jobs are never queued for later
	CodeProbeUnknown = "probe_unknown" // no probe has that name, or it is outside the caller's scope (one answer, so scope can't be mapped)
	CodeForbidden    = "forbidden"     // the MCP client may not call this tool, or may not use this to_address
)

// Error is a check failure with a stable code for agents to branch on.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf builds an Error.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// ProbeResult is one probe's entry in a hub tool's answer. Every hub tool that runs a check returns a list of these, one
// per probe it ran on, so a result always says where it was measured from.
type ProbeResult struct {
	Probe      string    `json:"probe"`
	Site       string    `json:"site"`
	OK         bool      `json:"ok"`
	Error      *Error    `json:"error,omitempty"`
	Result     any       `json:"result,omitempty"`
	StartedAt  time.Time `json:"started_at"`
	DurationMS int64     `json:"duration_ms"`
}

// Untrusted wraps text that the target controls: banners, headers, TXT records, certificate fields. Agents must treat it
// as data, never as instructions. The text is valid UTF-8, with control characters other than tab and newline and
// invisible formatting characters escaped, and cut to a fixed length.
type Untrusted struct {
	Text      string `json:"text"`
	Untrusted bool   `json:"untrusted"`
	Truncated bool   `json:"truncated,omitempty"`
}

// Default lengths for untrusted text.
const (
	MaxBannerBytes = 512
	MaxHeaderBytes = 256
	MaxRecordBytes = 512
)

// UntrustedText sanitises b and cuts it to at most max bytes of output.
func UntrustedText(b []byte, max int) Untrusted {
	var sb strings.Builder
	truncated := false
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		var piece string
		switch {
		case r == utf8.RuneError && size <= 1:
			piece = fmt.Sprintf("\\x%02x", b[0])
		case r == '\t' || r == '\n':
			piece = string(r)
		case r == '\r':
			piece = "\\r"
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			piece = fmt.Sprintf("\\u%04x", r)
		case invisible(r) && r > 0xffff:
			piece = fmt.Sprintf("\\U%08x", r)
		case invisible(r):
			piece = fmt.Sprintf("\\u%04x", r)
		default:
			piece = string(r)
		}
		if sb.Len()+len(piece) > max {
			truncated = true
			break
		}
		sb.WriteString(piece)
		b = b[size:]
	}
	return Untrusted{Text: sb.String(), Untrusted: true, Truncated: truncated}
}

// invisible reports runes that render as nothing or change how the text around them reads: line separators,
// bidirectional controls, zero-width characters, the byte order mark and tag characters, which can hide instructions
// from a person reviewing the text while a model still reads them. unicode.Cf covers the assigned format characters; the
// explicit ranges also catch unassigned code points in those blocks (U+2065, most of the tag block), which Cf does not.
func invisible(r rune) bool {
	switch {
	case r == 0x2028 || r == 0x2029:
		return true
	case r == 0x061c || r == 0xfeff:
		return true
	case r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2060 && r <= 0x206f:
		return true
	case r >= 0xe0000 && r <= 0xe007f:
		return true
	}
	return unicode.Is(unicode.Cf, r)
}

// UntrustedString is UntrustedText for a string.
func UntrustedString(s string, max int) Untrusted { return UntrustedText([]byte(s), max) }
