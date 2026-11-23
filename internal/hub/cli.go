package hub

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"probetools/internal/hubapi"
)

// MCPHandlerFunc builds the agent-facing MCP handler. The binary supplies it, so this package does not depend on the
// MCP server's package.
type MCPHandlerFunc func(router hubapi.Router, clients []hubapi.Client, logger *slog.Logger) (http.Handler, error)

// CLI runs the probe-hub command line.
type CLI struct {
	Stdout, Stderr io.Writer
	LookupEnv      func(string) (string, bool)
	MCPHandler     MCPHandlerFunc
	Now            func() time.Time // for tests; defaults to time.Now
}

const usage = `usage: probe-hub <command> [--config FILE]

commands:
  serve                                             run the hub (the default)
  token create --name N --site S [--ttl 24h] [--replace]
  token list
  token revoke <id>
  probes list
  probes revoke <name>
  check-config
  version

The config file is --config, else $HUB_CONFIG, else ` + DefaultConfigPath + `.
`

// Run executes one command and returns the process exit code.
func (c *CLI) Run(ctx context.Context, args []string) int {
	if c.LookupEnv == nil {
		c.LookupEnv = os.LookupEnv
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	cmd := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "serve":
		err = c.serve(ctx, args)
	case "token":
		err = c.token(ctx, args)
	case "probes":
		err = c.probes(ctx, args)
	case "check-config":
		err = c.checkConfig(args)
	case "version":
		fmt.Fprintln(c.Stdout, Version)
	case "help", "-h", "--help":
		fmt.Fprint(c.Stdout, usage)
	default:
		err = usageError("unknown command " + cmd)
	}
	var ue usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		fmt.Fprintf(c.Stderr, "probe-hub: %s\n\n%s", ue, usage)
		return 2
	case errors.Is(err, flag.ErrHelp):
		return 2
	default:
		fmt.Fprintf(c.Stderr, "probe-hub: %v\n", err)
		return 1
	}
}

type usageError string

func (e usageError) Error() string { return string(e) }

// parseFlags parses flags that may come before, after or between positional arguments (Go's flag package stops at
// the first positional, and `token revoke <id> --config x` should work).
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func (c *CLI) newFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.Stderr)
	cfg := fs.String("config", "", "config file")
	return fs, cfg
}

func (c *CLI) loadConfig(flagValue string) (*Config, error) {
	return LoadConfig(ResolveConfigPath(flagValue, c.LookupEnv))
}

func (c *CLI) openStore(cfg *Config) (*Store, error) {
	st, err := OpenStore(cfg.DataDir)
	if err != nil {
		return nil, err
	}
	st.Now = c.Now
	return st, nil
}

func (c *CLI) checkConfig(args []string) error {
	fs, cfgPath := c.newFlags("check-config")
	if pos, err := parseFlags(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usageError("check-config takes no arguments")
	}
	path := ResolveConfigPath(*cfgPath, c.LookupEnv)
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Stdout, "%s: ok\n", path)
	// Only a note: the variables may well be set only where `serve` runs.
	for _, cl := range cfg.Clients {
		if v, ok := c.LookupEnv(cl.TokenEnv); !ok || v == "" {
			fmt.Fprintf(c.Stdout, "note: client %q: $%s is not set in this environment\n", cl.Name, cl.TokenEnv)
		}
	}
	return nil
}

func (c *CLI) token(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("token needs a subcommand: create, list or revoke")
	}
	sub, args := args[0], args[1:]
	fs, cfgPath := c.newFlags("token " + sub)
	var name, site *string
	var ttl *time.Duration
	var replace *bool
	if sub == "create" {
		name = fs.String("name", "", "probe name")
		site = fs.String("site", "", "probe site")
		ttl = fs.Duration("ttl", 24*time.Hour, "how long the token stays valid")
		replace = fs.Bool("replace", false, "on enrolment, revoke the active probe with this name")
	}
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	cfg, err := c.loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	st, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	switch sub {
	case "create":
		if len(pos) > 0 {
			return usageError("token create takes no positional arguments")
		}
		if *name == "" || *site == "" {
			return usageError("token create needs --name and --site")
		}
		t, err := st.CreateToken(ctx, *name, *site, *ttl, *replace)
		if err != nil {
			return err
		}
		c.printToken(cfg, *name, *site, t, *replace)
		return nil
	case "list":
		if len(pos) > 0 {
			return usageError("token list takes no arguments")
		}
		toks, err := st.ListTokens(ctx)
		if err != nil {
			return err
		}
		now := c.Now()
		tw := tabwriter.NewWriter(c.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tSITE\tCREATED\tEXPIRES\tSTATE")
		for _, t := range toks {
			state := t.State(now)
			if t.Replace {
				state += " (replace)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Site, showTime(t.CreatedAt), showTime(t.ExpiresAt), state)
		}
		return tw.Flush()
	case "revoke":
		if len(pos) != 1 {
			return usageError("token revoke needs one token id")
		}
		if err := st.RevokeToken(ctx, pos[0]); err != nil {
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("no token with id %q", pos[0])
			}
			return err
		}
		fmt.Fprintf(c.Stdout, "token %s revoked\n", pos[0])
		return nil
	}
	return usageError("unknown token subcommand " + sub)
}

func (c *CLI) printToken(cfg *Config, name, site string, t NewToken, replace bool) {
	w := c.Stdout
	fmt.Fprintf(w, "Enrolment token for probe %q at site %q (id %s). It is shown only this once and works once.\n\n", name, site, t.ID)
	fmt.Fprintf(w, "  %s\n\n", t.Value)
	fmt.Fprintf(w, "Expires %s (in %s).\n", showTime(t.ExpiresAt), t.ExpiresAt.Sub(c.Now()).Round(time.Minute))
	if replace {
		fmt.Fprintf(w, "Enrolling with it revokes the probe currently named %q.\n", name)
	}
	hubURL := cfg.ProbeListener.PublicURL
	if hubURL == "" {
		hubURL = "wss://<this hub's address>"
	}
	fmt.Fprintf(w, "\nStart the probe with hub_url set to %s in its config and the token in its environment, e.g.:\n\n", hubURL)
	fmt.Fprintf(w, "  PROBE_ENROLL_TOKEN='%s' probe\n\n", t.Value)
	fmt.Fprintln(w, "The probe saves its identity on first start; the token is not needed after that.")
}

func (c *CLI) probes(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return usageError("probes needs a subcommand: list or revoke")
	}
	sub, args := args[0], args[1:]
	fs, cfgPath := c.newFlags("probes " + sub)
	pos, err := parseFlags(fs, args)
	if err != nil {
		return err
	}
	cfg, err := c.loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	st, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	switch sub {
	case "list":
		if len(pos) > 0 {
			return usageError("probes list takes no arguments")
		}
		ps, err := st.ListProbes(ctx, true)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(c.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSITE\tENROLLED\tLAST SEEN\tREVOKED")
		for _, p := range ps {
			revoked := "-"
			if p.Revoked() {
				revoked = showTime(p.RevokedAt)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Site, showTime(p.EnrolledAt), showTime(p.LastSeen), revoked)
		}
		return tw.Flush()
	case "revoke":
		if len(pos) != 1 {
			return usageError("probes revoke needs one probe name")
		}
		if _, err := st.RevokeProbe(ctx, pos[0]); err != nil {
			if errors.Is(err, ErrNotFound) {
				return fmt.Errorf("no active probe named %q", pos[0])
			}
			return err
		}
		fmt.Fprintf(c.Stdout, "probe %s revoked; a running hub closes its session within a few seconds\n", pos[0])
		return nil
	}
	return usageError("unknown probes subcommand " + sub)
}

func showTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func (c *CLI) serve(ctx context.Context, args []string) error {
	fs, cfgPath := c.newFlags("serve")
	if pos, err := parseFlags(fs, args); err != nil {
		return err
	} else if len(pos) > 0 {
		return usageError("serve takes no arguments")
	}
	cfg, err := c.loadConfig(*cfgPath)
	if err != nil {
		return err
	}
	logger := NewLogger(c.Stdout, cfg.LogLevel)
	slog.SetDefault(logger)

	st, err := c.openStore(cfg)
	if err != nil {
		return err
	}
	defer st.Close()

	h := New(st, logger, Options{})
	defer h.Close()

	if c.MCPHandler == nil {
		return errors.New("no MCP handler configured")
	}
	mcpHandler, err := c.MCPHandler(h, cfg.Clients, logger)
	if err != nil {
		return fmt.Errorf("mcp server: %w", err)
	}
	mcpMux := http.NewServeMux()
	mcpMux.Handle(cfg.MCP.Path, mcpHandler)
	mcpMux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write([]byte("ok"))
	})

	errLog := slog.NewLogLogger(logger.Handler(), slog.LevelWarn)
	// No ReadTimeout on the probe listener: it would also apply to hijacked WebSocket links and cut every probe off
	// after that long. Hub.Handler sets a read deadline on every request instead, /v1/connect lifts it just before the
	// upgrade, and the link has its own pings.
	probeSrv := &http.Server{
		Addr:              cfg.ProbeListener.Address,
		Handler:           h.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10, // a probe sends a few small headers; the 1 MiB default only helps a flood
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          errLog,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	mcpSrv := &http.Server{
		Addr:              cfg.MCP.Address,
		Handler:           mcpMux,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          errLog,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	// Listen first, so a busy port fails the start instead of a background goroutine.
	probeLn, err := net.Listen("tcp", probeSrv.Addr)
	if err != nil {
		return fmt.Errorf("probe listener: %w", err)
	}
	mcpLn, err := net.Listen("tcp", mcpSrv.Addr)
	if err != nil {
		probeLn.Close()
		return fmt.Errorf("mcp listener: %w", err)
	}

	errc := make(chan error, 2)
	go func() {
		var err error
		if cfg.ProbeListener.InsecurePlaintext {
			err = probeSrv.Serve(probeLn)
		} else {
			err = probeSrv.ServeTLS(probeLn, cfg.ProbeListener.TLSCertFile, cfg.ProbeListener.TLSKeyFile)
		}
		errc <- fmt.Errorf("probe listener: %w", err)
	}()
	go func() {
		var err error
		if cfg.MCP.TLSCertFile != "" {
			err = mcpSrv.ServeTLS(mcpLn, cfg.MCP.TLSCertFile, cfg.MCP.TLSKeyFile)
		} else {
			err = mcpSrv.Serve(mcpLn)
		}
		errc <- fmt.Errorf("mcp listener: %w", err)
	}()
	logger.Info("hub started", "version", Version, "probe_address", cfg.ProbeListener.Address,
		"probe_tls", !cfg.ProbeListener.InsecurePlaintext, "mcp_address", cfg.MCP.Address, "mcp_path", cfg.MCP.Path,
		"mcp_tls", cfg.MCP.TLSCertFile != "", "clients", len(cfg.Clients))

	var runErr error
	select {
	case <-ctx.Done():
		logger.Info("shutting down")
	case runErr = <-errc:
		logger.Error("listener failed", "err", runErr)
	}
	// Let calls in flight finish, within the 10 s a container runtime usually allows after SIGTERM.
	shutCtx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	mcpSrv.Shutdown(shutCtx)
	probeSrv.Shutdown(shutCtx)
	h.Close()
	logger.Info("hub stopped")
	return runErr
}
