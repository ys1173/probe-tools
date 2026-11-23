package mcpserver

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// auditRecord collects what one tool call did, for the single log line written when it ends. Handlers fill in what
// they learn; it never holds tokens or results.
type auditRecord struct {
	Client   string
	Tool     string
	Probes   []string
	Target   string
	Outcomes map[string]string // probe (or path_test step) -> "ok" or an error code
	Verdict  string
	Error    string // set when the call as a whole failed
}

type auditKey struct{}

func withAudit(ctx context.Context, rec *auditRecord) context.Context {
	return context.WithValue(ctx, auditKey{}, rec)
}

// auditFrom returns the call's record, or a throwaway one so handlers never need to check.
func auditFrom(ctx context.Context) *auditRecord {
	if rec, ok := ctx.Value(auditKey{}).(*auditRecord); ok {
		return rec
	}
	return &auditRecord{Outcomes: map[string]string{}}
}

func (h *hub) audit(ctx context.Context, rec *auditRecord, d time.Duration) {
	attrs := []slog.Attr{
		slog.String("event", "tool_call"),
		slog.String("client", rec.Client),
		slog.String("tool", rec.Tool),
		slog.Any("probes", rec.Probes),
		slog.String("target", rec.Target),
		slog.Any("outcomes", rec.Outcomes),
		slog.Int64("duration_ms", d.Milliseconds()),
	}
	if rec.Verdict != "" {
		attrs = append(attrs, slog.String("verdict", rec.Verdict))
	}
	level := slog.LevelInfo
	if rec.Error != "" {
		attrs = append(attrs, slog.String("error", truncate(rec.Error, 300)))
		level = slog.LevelWarn
	}
	h.logger.LogAttrs(ctx, level, "tool_call", attrs...)
}

// logTarget keeps a URL's scheme, host and path only: a query string may carry a token the agent was given.
func logTarget(s string) string {
	if !strings.Contains(s, "://") {
		return truncate(s, 256)
	}
	u, err := url.Parse(s)
	if err != nil {
		return "(unparseable url)"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return truncate(u.String(), 256)
}

func errorText(res *mcp.CallToolResult) string {
	for _, c := range res.Content {
		if t, ok := c.(*mcp.TextContent); ok {
			return t.Text
		}
	}
	return "tool error"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
