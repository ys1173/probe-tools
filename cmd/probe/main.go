// Command probe connects out to the hub and runs the fixed, read-only network checks it is asked for, within the
// target policy in its configuration file.
//
//	probe [run] [--config FILE]       connect to the hub and serve jobs (the default)
//	probe check-config [--config FILE] validate the configuration and show the policy
//	probe version
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"probetools/internal/check"
	"probetools/internal/checks/app"
	"probetools/internal/checks/diagnose"
	"probetools/internal/checks/icmp"
	"probetools/internal/checks/info"
	"probetools/internal/checks/pathtest"
	"probetools/internal/policy"
	"probetools/internal/probe"
)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(args []string, stdout, stderr io.Writer) int {
	cmd := "run"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "version":
		fmt.Fprintln(stdout, probe.Version)
		return 0
	case "run", "check-config":
	case "help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", cmd)
		usage(stderr)
		return 2
	}

	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	configFlag := fs.String("config", "", "configuration file (default $PROBE_CONFIG, else "+probe.DefaultConfigPath+")")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		return 2
	}
	path := probe.ConfigPath(*configFlag)
	cfg, err := probe.LoadConfig(path)
	if err != nil {
		fmt.Fprintf(stderr, "configuration is not valid:\n%v\n", err)
		return 1
	}
	if cmd == "check-config" {
		printSummary(stdout, path, cfg)
		return 0
	}

	logger := probe.NewLogger(stdout, cfg.LogLevel)
	reg := check.NewRegistry()
	app.Register(reg)
	diagnose.Register(reg)
	icmp.Register(reg)
	info.Register(reg)
	pathtest.Register(reg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := probe.Run(ctx, cfg, reg, icmp.Capabilities(), logger); err != nil {
		logger.Error("probe stopped with an error", "error", err.Error())
		return 1
	}
	return 0
}

func printSummary(w io.Writer, path string, cfg probe.Config) {
	fmt.Fprintf(w, "configuration %s is valid\n", path)
	fmt.Fprintf(w, "hub_url:       %s\n", cfg.HubURL)
	fmt.Fprintf(w, "state_dir:     %s\n", cfg.StateDir)
	// The compiled summary shows names as the policy will match them (lower case, no trailing dot).
	sum := cfg.Targets
	if pol, err := policy.New(cfg.Targets); err == nil {
		s := pol.Summary()
		sum = policy.Config{Mode: s.Mode, AllowCIDRs: s.AllowCIDRs, AllowHosts: s.AllowHosts, DenyCIDRs: s.DenyCIDRs}
	}
	fmt.Fprintf(w, "policy mode:   %s\n", sum.Mode)
	list := func(name string, v []string) {
		if len(v) == 0 {
			fmt.Fprintf(w, "%-14s (none)\n", name+":")
			return
		}
		fmt.Fprintf(w, "%-14s %s\n", name+":", strings.Join(v, ", "))
	}
	list("allow_cidrs", sum.AllowCIDRs)
	list("allow_hosts", sum.AllowHosts)
	list("deny_cidrs", sum.DenyCIDRs)
	if cfg.ListenPorts == "" {
		fmt.Fprintln(w, "listen_ports:  (none; this probe will not receive path tests)")
	} else {
		fmt.Fprintf(w, "listen_ports:  %d-%d\n", cfg.ListenPortMin, cfg.ListenPortMax)
	}
	fmt.Fprintf(w, "limits:        %d concurrent jobs, %d jobs per target address per minute\n",
		cfg.Limits.MaxConcurrent, cfg.Limits.PerTargetPerMinute)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage:
  probe [run] [--config FILE]         connect to the hub and serve jobs
  probe check-config [--config FILE]  validate the configuration and show the policy
  probe version                       print the version
`)
}
