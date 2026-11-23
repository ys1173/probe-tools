// Command probe-hub is the hub: it serves probes (enrolment and the WebSocket link) and agents (MCP), and has local
// admin commands for tokens and probes. The work is in internal/hub; this file wires in the MCP server.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"probetools/internal/hub"
	"probetools/internal/hubapi"
	"probetools/internal/mcpserver"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cli := &hub.CLI{
		Stdout:    os.Stdout,
		Stderr:    os.Stderr,
		LookupEnv: os.LookupEnv,
		MCPHandler: func(router hubapi.Router, clients []hubapi.Client, logger *slog.Logger) (http.Handler, error) {
			h, err := mcpserver.New(router, clients, logger, os.LookupEnv)
			return h, err
		},
	}
	code := cli.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
