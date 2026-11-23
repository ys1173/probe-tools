package hub

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"probetools/internal/hubapi"
)

// Version is the hub's version, set at build time with -ldflags "-X probetools/internal/hub.Version=...".
var Version = "dev"

// DefaultConfigPath is used when neither --config nor HUB_CONFIG names a file.
const DefaultConfigPath = "/etc/probe-hub/hub.yaml"

// Config is the hub's configuration file.
type Config struct {
	DataDir       string              `yaml:"data_dir"`
	ProbeListener ProbeListenerConfig `yaml:"probe_listener"`
	MCP           MCPConfig           `yaml:"mcp"`
	Clients       []hubapi.Client     `yaml:"clients"`
	LogLevel      string              `yaml:"log_level"`
}

// ProbeListenerConfig is the listener probes connect to: enrolment, the WebSocket link and /healthz.
type ProbeListenerConfig struct {
	Address     string `yaml:"address"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
	// InsecurePlaintext serves plain HTTP, for when a TLS-terminating proxy sits in front of the hub. Probe secrets
	// cross this listener, so it must never face a network directly without TLS.
	InsecurePlaintext bool `yaml:"insecure_plaintext"`
	// PublicURL is the address probes use to reach the hub. It is only printed by `token create`.
	PublicURL string `yaml:"public_url"`
}

// MCPConfig is the listener agents call. It is meant for the central site's internal network, so TLS is optional.
type MCPConfig struct {
	Address     string `yaml:"address"`
	Path        string `yaml:"path"`
	TLSCertFile string `yaml:"tls_cert_file"`
	TLSKeyFile  string `yaml:"tls_key_file"`
}

// ResolveConfigPath picks the configuration file: the flag, then HUB_CONFIG, then the default.
func ResolveConfigPath(flagValue string, lookupEnv func(string) (string, bool)) string {
	if flagValue != "" {
		return flagValue
	}
	if v, ok := lookupEnv("HUB_CONFIG"); ok && v != "" {
		return v
	}
	return DefaultConfigPath
}

// LoadConfig reads, defaults and validates a configuration file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return ParseConfig(b)
}

// ParseConfig decodes a configuration, refusing unknown keys so a misspelt setting is not silently ignored.
func ParseConfig(b []byte) (*Config, error) {
	var cfg Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// A second document would be ignored by a single Decode; refuse it rather than surprise the operator.
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("parse config: more than one YAML document")
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.DataDir == "" {
		c.DataDir = "/data"
	}
	if c.ProbeListener.Address == "" {
		c.ProbeListener.Address = ":8443"
	}
	if c.MCP.Address == "" {
		c.MCP.Address = ":8080"
	}
	if c.MCP.Path == "" {
		c.MCP.Path = "/mcp"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
}

// Validate checks the configuration. It does not look up the clients' token variables: the MCP server does that when
// it starts, and admin commands must work without them.
func (c *Config) Validate() error {
	var errs []error
	pl := c.ProbeListener
	if !pl.InsecurePlaintext && (pl.TLSCertFile == "" || pl.TLSKeyFile == "") {
		errs = append(errs, errors.New("probe_listener: tls_cert_file and tls_key_file are required unless insecure_plaintext is true"))
	}
	if pl.InsecurePlaintext && (pl.TLSCertFile != "" || pl.TLSKeyFile != "") {
		errs = append(errs, errors.New("probe_listener: tls files are set but insecure_plaintext is true; choose one"))
	}
	if pl.PublicURL != "" {
		u, err := url.Parse(pl.PublicURL)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("probe_listener.public_url: %v", err))
		case u.Scheme != "wss" && u.Scheme != "ws":
			// It is printed as the probe's hub_url, which the probe only accepts as wss:// (or ws://).
			errs = append(errs, errors.New("probe_listener.public_url: scheme must be wss (or ws)"))
		case u.Host == "":
			errs = append(errs, errors.New("probe_listener.public_url: no host"))
		case u.User != nil:
			errs = append(errs, errors.New("probe_listener.public_url: must not contain credentials"))
		case u.RawQuery != "" || u.Fragment != "":
			errs = append(errs, errors.New("probe_listener.public_url: must not have a query or fragment"))
		}
	}
	if (c.MCP.TLSCertFile == "") != (c.MCP.TLSKeyFile == "") {
		errs = append(errs, errors.New("mcp: set both tls_cert_file and tls_key_file, or neither"))
	}
	if !strings.HasPrefix(c.MCP.Path, "/") || c.MCP.Path == "/healthz" {
		errs = append(errs, errors.New("mcp.path: must start with / and must not be /healthz"))
	}
	if c.MCP.Address == c.ProbeListener.Address {
		errs = append(errs, errors.New("mcp.address and probe_listener.address must differ"))
	}
	if _, err := parseLogLevel(c.LogLevel); err != nil {
		errs = append(errs, err)
	}
	seen := map[string]bool{}
	for i, cl := range c.Clients {
		if cl.Name == "" {
			errs = append(errs, fmt.Errorf("clients[%d]: name is required", i))
		} else if seen[cl.Name] {
			errs = append(errs, fmt.Errorf("clients[%d]: duplicate name %q", i, cl.Name))
		}
		seen[cl.Name] = true
		if cl.TokenEnv == "" {
			errs = append(errs, fmt.Errorf("clients[%d]: token_env is required", i))
		}
	}
	return errors.Join(errs...)
}

func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return slog.LevelDebug, nil
	case "info", "":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("log_level: %q is not one of debug, info, warn, error", s)
}

// NewLogger builds the hub's JSON logger at the configured level.
func NewLogger(w io.Writer, level string) *slog.Logger {
	l, err := parseLogLevel(level)
	if err != nil {
		l = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l}))
}
