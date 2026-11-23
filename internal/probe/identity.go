package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"probetools/internal/protocol"
)

// IdentityFile is the name of the saved identity inside state_dir.
const IdentityFile = "identity.json"

// Identity is what enrolment gives the probe, saved so it survives restarts. The secret is the probe's only credential.
type Identity struct {
	HubURL  string `json:"hub_url"`
	ProbeID string `json:"probe_id"`
	Name    string `json:"name"`
	Site    string `json:"site"`
	Secret  string `json:"secret"`
}

// LogValue keeps the secret out of logs even if an Identity is logged whole by mistake.
func (id Identity) LogValue() slog.Value {
	return slog.GroupValue(slog.String("probe_id", id.ProbeID), slog.String("name", id.Name), slog.String("site", id.Site))
}

// String keeps the secret out of fmt output for the same reason.
func (id Identity) String() string {
	return fmt.Sprintf("probe %s (%s, site %s)", id.ProbeID, id.Name, id.Site)
}

// IdentityPath is where the identity is saved.
func IdentityPath(stateDir string) string { return filepath.Join(stateDir, IdentityFile) }

// LoadIdentity reads a saved identity. It returns (nil, nil) when there is none, so the caller enrols.
func LoadIdentity(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading identity: %w", err)
	}
	var id Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("identity file %s is damaged (%v); delete it and re-enrol with a new token", path, err)
	}
	if id.ProbeID == "" || id.Secret == "" || id.HubURL == "" {
		return nil, fmt.Errorf("identity file %s is incomplete; delete it and re-enrol with a new token", path)
	}
	return &id, nil
}

// SaveIdentity writes the identity to stateDir atomically with mode 0600: a crash mid-write leaves either the old file
// or none, never half a secret.
func SaveIdentity(stateDir string, id Identity) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("creating state_dir: %w", err)
	}
	data, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, ".identity-*.tmp")
	if err != nil {
		return fmt.Errorf("saving identity: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("saving identity: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("saving identity: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("saving identity: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("saving identity: %w", err)
	}
	if err := os.Rename(tmpName, IdentityPath(stateDir)); err != nil {
		return fmt.Errorf("saving identity: %w", err)
	}
	// Make the rename itself durable; failure here is not worth refusing to start over.
	if d, err := os.Open(stateDir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// sameHub compares hub URLs ignoring case in the scheme and host and a trailing slash.
func sameHub(a, b string) bool { return normalizeHubURL(a) == normalizeHubURL(b) }

func normalizeHubURL(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return s
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String()
}

// hubEndpoint joins the hub URL and a path, with the scheme swapped to http(s) for plain requests or kept as ws(s).
func hubEndpoint(hubURL, path string, plainHTTP bool) (string, error) {
	u, err := url.Parse(hubURL)
	if err != nil {
		return "", err
	}
	if plainHTTP {
		switch u.Scheme {
		case "wss":
			u.Scheme = "https"
		case "ws":
			u.Scheme = "http"
		}
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	return u.String(), nil
}

// enrollError says whether retrying could help. A refused token will be refused again, so the probe stops.
type enrollError struct {
	permanent bool
	err       error
}

func (e *enrollError) Error() string { return e.err.Error() }
func (e *enrollError) Unwrap() error { return e.err }

// Enroll exchanges the one-time token for an identity.
func Enroll(ctx context.Context, client *http.Client, hubURL, token, hostname string) (Identity, error) {
	endpoint, err := hubEndpoint(hubURL, protocol.PathEnroll, true)
	if err != nil {
		return Identity{}, &enrollError{permanent: true, err: err}
	}
	body, _ := json.Marshal(protocol.EnrollRequest{Token: token, Hostname: hostname, Version: Version})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return Identity{}, &enrollError{permanent: true, err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		// Strip the URL wrapper; the error text stays useful without repeating the endpoint.
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err
		}
		return Identity{}, &enrollError{err: fmt.Errorf("enrolment request failed: %w", err)}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The hub's message is shown sanitised and short; it explains e.g. an expired or used token.
		msg := protocol.UntrustedText(bytes.TrimSpace(data), 200).Text
		e := fmt.Errorf("hub refused enrolment: HTTP %d: %s", resp.StatusCode, msg)
		permanent := resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests &&
			resp.StatusCode != http.StatusRequestTimeout
		return Identity{}, &enrollError{permanent: permanent, err: e}
	}
	var er protocol.EnrollResponse
	if err := json.Unmarshal(data, &er); err != nil {
		return Identity{}, &enrollError{err: fmt.Errorf("enrolment answer is not valid JSON: %v", err)}
	}
	if er.ProbeID == "" || er.Secret == "" {
		return Identity{}, &enrollError{err: errors.New("enrolment answer lacks probe_id or secret")}
	}
	return Identity{HubURL: hubURL, ProbeID: er.ProbeID, Name: er.Name, Site: er.Site, Secret: er.Secret}, nil
}

// loadOrEnroll returns the saved identity, or enrols and saves one. Network failures during enrolment are retried with
// backoff, since a probe often starts before its network is up; a refusal from the hub is final.
func loadOrEnroll(ctx context.Context, cfg Config, client *http.Client, logger *slog.Logger, getenv func(string) string,
	t timers) (Identity, error) {
	path := IdentityPath(cfg.StateDir)
	saved, err := LoadIdentity(path)
	if err != nil {
		return Identity{}, err
	}
	if saved != nil {
		if !sameHub(saved.HubURL, cfg.HubURL) {
			return Identity{}, fmt.Errorf("the identity in %s was enrolled with hub %s but hub_url is now %s; "+
				"to move this probe to the new hub, delete %s and start it with a new enrolment token", path, saved.HubURL, cfg.HubURL, path)
		}
		if fi, err := os.Stat(path); err == nil && fi.Mode().Perm()&0o077 != 0 {
			logger.Warn("identity file is readable by others; tightening it to 0600", "path", path)
			_ = os.Chmod(path, 0o600)
		}
		logger.Info("using saved identity", "identity", *saved)
		return *saved, nil
	}

	token := strings.TrimSpace(getenv(cfg.EnrollTokenEnv))
	if token == "" {
		return Identity{}, fmt.Errorf("no saved identity in %s and the enrolment token variable %s is empty; "+
			"create a token on the hub and set %s", path, cfg.EnrollTokenEnv, cfg.EnrollTokenEnv)
	}
	hostname, _ := os.Hostname()
	b := newBackoff(t)
	for {
		logger.Info("enrolling with hub", "hub_url", cfg.HubURL)
		id, err := Enroll(ctx, client, cfg.HubURL, token, hostname)
		if err == nil {
			if err := SaveIdentity(cfg.StateDir, id); err != nil {
				return Identity{}, fmt.Errorf("enrolled as %s but could not save the identity, so the token is now spent: %w", id.Name, err)
			}
			logger.Info("enrolled", "identity", id, "path", path)
			return id, nil
		}
		var ee *enrollError
		if errors.As(err, &ee) && ee.permanent {
			return Identity{}, err
		}
		d := b.next()
		logger.Warn("enrolment failed; will retry", "error", err.Error(), "retry_in_ms", d.Milliseconds())
		if err := t.sleep(ctx, d); err != nil {
			return Identity{}, err
		}
	}
}
