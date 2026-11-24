// Command probe connects out to the hub and runs the fixed, read-only network checks it is asked for, within the
// target policy in its configuration file.
//
//	probe [run] [--config FILE]       connect to the hub and serve jobs (the default)
//	probe check-config [--config FILE] validate the configuration and show the policy
//	probe ssh ... [--config FILE]       manage this probe's SSH profiles, jump hosts and host keys (see probe ssh help)
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
	"time"

	"probetools/internal/check"
	"probetools/internal/checks/app"
	"probetools/internal/checks/devssh"
	"probetools/internal/checks/diagnose"
	"probetools/internal/checks/icmp"
	"probetools/internal/checks/info"
	"probetools/internal/checks/pathtest"
	"probetools/internal/devcmd"
	"probetools/internal/policy"
	"probetools/internal/probe"
	"probetools/internal/sshcfg"
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
	case "ssh":
		return newCLI(os.Stdin, stdout, stderr).run(args)
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
		// With SSH off the probe never loads ssh.commands_file, so Validate does not either; check-config still
		// reports a file that would not load, so it does not surprise the operator when SSH is turned on.
		if !cfg.SSH.Enabled && cfg.SSH.CommandsFile != "" {
			if _, err := devcmd.Load(cfg.SSH.CommandsFile); err != nil {
				fmt.Fprintf(stdout, "ssh.commands_file %s is not used (ssh.enabled is false), and it does not load:\n%v\n", cfg.SSH.CommandsFile, err)
				return 1
			}
			fmt.Fprintf(stdout, "ssh.commands_file %s loads, but is not used while ssh.enabled is false\n", cfg.SSH.CommandsFile)
		}
		return 0
	}

	logger := probe.NewLogger(stdout, cfg.LogLevel)
	reg := check.NewRegistry()
	app.Register(reg)
	diagnose.Register(reg)
	icmp.Register(reg)
	info.Register(reg)
	pathtest.Register(reg)
	if cfg.SSH.Enabled {
		cat, err := devcmd.Load(cfg.SSH.CommandsFile)
		if err != nil {
			fmt.Fprintf(stderr, "ssh.commands_file could not be loaded, so the probe will not start:\n%v\n", err)
			return 1
		}
		devssh.Register(reg, devssh.Config{
			Store:          sshcfg.New(cfg.StateDir),
			Commands:       cat,
			MaxOutputBytes: cfg.SSH.MaxOutputBytes,
			ConnectTimeout: time.Duration(cfg.SSH.ConnectTimeoutMS) * time.Millisecond,
			Logger:         logger,

			AuthFailureCooldown: cfg.SSH.AuthFailureCooldown(),
		})
	}

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
		sum = policy.Config{Mode: s.Mode, AllowCIDRs: s.AllowCIDRs, AllowHosts: s.AllowHosts, DenyCIDRs: s.DenyCIDRs,
			DenyHosts: s.DenyHosts}
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
	list("deny_hosts", sum.DenyHosts)
	if cfg.ListenPorts == "" {
		fmt.Fprintln(w, "listen_ports:  (none; this probe will not receive path tests)")
	} else {
		fmt.Fprintf(w, "listen_ports:  %d-%d\n", cfg.ListenPortMin, cfg.ListenPortMax)
	}
	fmt.Fprintf(w, "limits:        %d concurrent jobs, %d jobs per target address per minute\n",
		cfg.Limits.MaxConcurrent, cfg.Limits.PerTargetPerMinute)
	if !cfg.SSH.Enabled {
		fmt.Fprintln(w, "ssh:           disabled (device_show and device_commands are not offered)")
		return
	}
	cmds := cfg.SSH.CommandsFile
	if cmds == "" {
		cmds = "built-in lists"
	}
	fmt.Fprintf(w, "ssh:           enabled; commands %s; max_output_bytes %d; connect_timeout_ms %d; auth_failure_cooldown_s %d\n",
		cmds, cfg.SSH.MaxOutputBytes, cfg.SSH.ConnectTimeoutMS, int(cfg.SSH.AuthFailureCooldown()/time.Second))
	if cat, err := devcmd.Load(cfg.SSH.CommandsFile); err == nil {
		var parts []string
		for _, pc := range cat.List("") {
			part := fmt.Sprintf("%s %d", pc.Platform, len(pc.Allow))
			if pc.Local {
				part += " (changed locally)"
			}
			parts = append(parts, part)
		}
		fmt.Fprintf(w, "allowed:       %s\n", strings.Join(parts, ", "))
	}
	if c, err := sshcfg.New(cfg.StateDir).Load(); err != nil {
		fmt.Fprintf(w, "ssh store:     cannot be read here: %v\n", err)
	} else {
		fmt.Fprintf(w, "ssh store:     %d profiles, %d jump hosts (probe ssh profile list)\n", len(c.Profiles), len(c.Jumps))
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage:
  probe [run] [--config FILE]         connect to the hub and serve jobs
  probe check-config [--config FILE]  validate the configuration and show the policy
  probe ssh ... [--config FILE]       SSH profiles, jump hosts and host keys for device_show (probe ssh help)
  probe version                       print the version
`)
}
