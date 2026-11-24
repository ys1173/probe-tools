package probe

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"probetools/internal/check"
	"probetools/internal/policy"
	"probetools/internal/protocol"
	"probetools/internal/sshcfg"
)

// Version is the probe's version, set at build time with -ldflags "-X probetools/internal/probe.Version=...".
var Version = "dev"

// NewLogger returns a JSON logger on w at the given level ("debug", "info", "warn" or "error").
func NewLogger(w io.Writer, level string) *slog.Logger {
	lvl, err := ParseLogLevel(level)
	if err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: lvl}))
}

// Run enrols if needed, then keeps the link to the hub open and runs the jobs it sends until ctx ends. On shutdown it
// stops taking jobs, lets running ones finish for up to 5 s, and closes the link normally; it then returns nil. It
// returns an error only for problems that restarting would not fix, such as a refused enrolment token or a saved
// identity for another hub.
//
// reg holds the checks this probe runs and caps the capabilities found at start-up (e.g. "raw_icmp").
func Run(ctx context.Context, cfg Config, reg *check.Registry, caps map[string]bool, logger *slog.Logger) error {
	return run(ctx, cfg, reg, caps, logger, runOptions{getenv: os.Getenv, timers: realTimers()})
}

type runOptions struct {
	getenv func(string) string
	timers timers
	// Overrides for tests; zero means the default.
	welcomeTimeout time.Duration
	drainTimeout   time.Duration
	idleTimeout    time.Duration
}

func run(ctx context.Context, cfg Config, reg *check.Registry, caps map[string]bool, logger *slog.Logger, opts runOptions) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	pol, err := policy.New(cfg.Targets)
	if err != nil {
		return err
	}
	pol.Logger = logger
	pol.SetRateLimit(cfg.Limits.PerTargetPerMinute)
	client, err := newHubClient(cfg)
	if err != nil {
		return err
	}
	logger.Info("probe starting", "version", Version, "hub_url", cfg.HubURL, "policy_mode", pol.Summary().Mode,
		"listen_ports", cfg.ListenPorts, "checks", reg.Names(), "ssh", cfg.SSH.Enabled)
	id, err := loadOrEnroll(ctx, cfg, client, logger, opts.getenv, opts.timers)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	env := &check.Env{
		Policy:        pol,
		ProbeName:     id.Name,
		Site:          id.Site,
		Version:       Version,
		ListenPortMin: cfg.ListenPortMin,
		ListenPortMax: cfg.ListenPortMax,
		Capabilities:  caps,
	}
	if env.Capabilities == nil {
		env.Capabilities = map[string]bool{}
	}
	// The SSH profile summaries are read afresh for each hello, so a profile added with `probe ssh profile add` is
	// reported at the next connection.
	var sshStore *sshcfg.Store
	if cfg.SSH.Enabled {
		sshStore = sshcfg.New(cfg.StateDir)
	}
	disp := newDispatcher(reg, env, cfg.Limits, logger, opts.timers.now)
	l := &link{
		hubURL:    cfg.HubURL,
		stateDir:  cfg.StateDir,
		id:        id,
		client:    client,
		logger:    logger,
		disp:      disp,
		hello:     func() protocol.Hello { return buildHello(cfg, reg, caps, pol, sshStore) },
		t:         opts.timers,
		welcomeTO: orDefault(opts.welcomeTimeout, welcomeTimeout),
		idleTO:    orDefault(opts.idleTimeout, idleTimeout),
		drainTO:   orDefault(opts.drainTimeout, drainTimeout),
	}
	err = l.run(ctx)
	logger.Info("probe stopped")
	return err
}

func orDefault(v, def time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return def
}
