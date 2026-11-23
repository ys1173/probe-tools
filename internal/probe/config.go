// Package probe is the probe's runtime: its configuration, enrolment and saved identity, the link to the hub, and the
// dispatch of jobs to checks under the probe's limits. It does not import the check packages, so it can be tested with
// fake checks; cmd/probe builds the registry and calls Run.
package probe

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"probetools/internal/policy"
)

// Defaults for settings the file may leave out.
const (
	DefaultConfigPath      = "/etc/probe/probe.yaml"
	DefaultStateDir        = "/var/lib/probe"
	DefaultEnrollTokenEnv  = "PROBE_ENROLL_TOKEN"
	DefaultMaxConcurrent   = 4
	DefaultPerTargetPerMin = 30
)

// Upper bounds on the limits, so a typo cannot turn the probe into a load generator.
const (
	maxMaxConcurrent   = 64
	maxPerTargetPerMin = 600
)

// Config is the probe's configuration file, after environment overrides.
type Config struct {
	HubURL            string        `yaml:"hub_url"`
	EnrollTokenEnv    string        `yaml:"enroll_token_env"`
	StateDir          string        `yaml:"state_dir"`
	CAFile            string        `yaml:"ca_file"`
	InsecurePlaintext bool          `yaml:"insecure_plaintext"`
	Targets           policy.Config `yaml:"targets"`
	ListenPorts       string        `yaml:"listen_ports"`
	Limits            Limits        `yaml:"limits"`
	LogLevel          string        `yaml:"log_level"`

	// Set by Validate from ListenPorts; both zero when listening is off.
	ListenPortMin int `yaml:"-"`
	ListenPortMax int `yaml:"-"`
}

// Limits bound how much work the hub can ask of this probe at once.
type Limits struct {
	MaxConcurrent int `yaml:"max_concurrent"`
	// PerTargetPerMinute is how many jobs may contact one address per minute. The policy counts it on resolved
	// addresses, once per job, so other spellings of a target share its limit.
	PerTargetPerMinute int `yaml:"per_target_per_minute"`
}

// ConfigPath picks the configuration file: the --config flag, else PROBE_CONFIG, else the default path.
func ConfigPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if p := os.Getenv("PROBE_CONFIG"); p != "" {
		return p
	}
	return DefaultConfigPath
}

// LoadConfig reads, overrides from the environment and validates the configuration file at path.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("reading config: %w", err)
	}
	cfg, err := ParseConfig(data, os.Getenv)
	if err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// ParseConfig parses YAML, applies the PROBE_HUB_URL, PROBE_STATE_DIR and PROBE_LOG_LEVEL overrides read through
// getenv, fills defaults and validates. Unknown keys are refused, since a misspelt key would otherwise be silently
// ignored and could leave the policy wider than the operator meant.
func ParseConfig(data []byte, getenv func(string) string) (Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parsing config: %w", err)
	}
	if getenv != nil {
		if v := getenv("PROBE_HUB_URL"); v != "" {
			cfg.HubURL = v
		}
		if v := getenv("PROBE_STATE_DIR"); v != "" {
			cfg.StateDir = v
		}
		if v := getenv("PROBE_LOG_LEVEL"); v != "" {
			cfg.LogLevel = v
		}
	}
	if cfg.EnrollTokenEnv == "" {
		cfg.EnrollTokenEnv = DefaultEnrollTokenEnv
	}
	if cfg.StateDir == "" {
		cfg.StateDir = DefaultStateDir
	}
	if cfg.Limits.MaxConcurrent == 0 {
		cfg.Limits.MaxConcurrent = DefaultMaxConcurrent
	}
	if cfg.Limits.PerTargetPerMinute == 0 {
		cfg.Limits.PerTargetPerMinute = DefaultPerTargetPerMin
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks every setting and fills ListenPortMin and ListenPortMax. It returns all problems found, not just the
// first, so an operator can fix the file in one pass.
func (c *Config) Validate() error {
	var errs []error
	if err := validateHubURL(c.HubURL, c.InsecurePlaintext); err != nil {
		errs = append(errs, err)
	}
	if c.EnrollTokenEnv == "" {
		errs = append(errs, errors.New("enroll_token_env must name an environment variable"))
	}
	if c.StateDir == "" {
		errs = append(errs, errors.New("state_dir is required"))
	}
	if c.CAFile != "" {
		if _, err := loadCAFile(c.CAFile); err != nil {
			errs = append(errs, err)
		}
	}
	if _, err := policy.New(c.Targets); err != nil {
		errs = append(errs, err)
	}
	lo, hi, err := ParsePortRange(c.ListenPorts)
	if err != nil {
		errs = append(errs, fmt.Errorf("listen_ports: %w", err))
	} else {
		c.ListenPortMin, c.ListenPortMax = lo, hi
	}
	if c.Limits.MaxConcurrent < 1 || c.Limits.MaxConcurrent > maxMaxConcurrent {
		errs = append(errs, fmt.Errorf("limits.max_concurrent must be 1 to %d, got %d", maxMaxConcurrent, c.Limits.MaxConcurrent))
	}
	if c.Limits.PerTargetPerMinute < 1 || c.Limits.PerTargetPerMinute > maxPerTargetPerMin {
		errs = append(errs, fmt.Errorf("limits.per_target_per_minute must be 1 to %d, got %d", maxPerTargetPerMin, c.Limits.PerTargetPerMinute))
	}
	if _, err := ParseLogLevel(c.LogLevel); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func validateHubURL(raw string, insecure bool) error {
	if raw == "" {
		return errors.New("hub_url is required, e.g. wss://hub.example.com:8443")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("hub_url: %v", err)
	}
	switch u.Scheme {
	case "wss":
	case "ws":
		if !insecure {
			return errors.New("hub_url uses ws://, which sends the probe's secret in clear; use wss:// or set insecure_plaintext: true")
		}
	default:
		return fmt.Errorf("hub_url must start with wss:// (or ws:// with insecure_plaintext: true), got scheme %q", u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("hub_url has no host")
	}
	// Credentials in the URL would end up in logs and in the saved identity; the probe has its own secret.
	if u.User != nil {
		return errors.New("hub_url must not contain a user name or password")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("hub_url must not have a query or fragment")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("hub_url port %q must be 1 to 65535", p)
		}
	}
	return nil
}

// ParsePortRange parses "lo-hi" or a single port. "" means no range and returns zeros.
func ParsePortRange(s string) (lo, hi int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, 0, nil
	}
	a, b, isRange := strings.Cut(s, "-")
	if lo, err = parsePort(a); err != nil {
		return 0, 0, err
	}
	hi = lo
	if isRange {
		if hi, err = parsePort(b); err != nil {
			return 0, 0, err
		}
	}
	if lo > hi {
		return 0, 0, fmt.Errorf("range %q starts above where it ends", s)
	}
	return lo, hi, nil
}

func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number (want e.g. 40000-40100)", s)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Errorf("port %d is outside 1 to 65535", n)
	}
	return n, nil
}

// ParseLogLevel maps debug, info, warn or error to a slog level.
func ParseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("log_level %q must be debug, info, warn or error", s)
}

func loadCAFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ca_file %s: %v", path, err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("ca_file %s holds no PEM certificates", path)
	}
	return certs, nil
}
