package hub

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"probetools/internal/protocol"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func enrollReason(err error) string {
	var ee *EnrollError
	if errors.As(err, &ee) {
		return ee.Reason
	}
	return ""
}

func TestStoreFileMode(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	fi, err := os.Stat(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("hub.db mode %v, want 0600", fi.Mode().Perm())
	}
	var mode string
	if err := st.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("journal_mode %q, %v; want wal", mode, err)
	}
}

func TestTokenSingleUse(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	tok, err := st.CreateToken(ctx, "syd-1", "sydney", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Value) < 43 {
		t.Fatalf("token too short: %d chars", len(tok.Value))
	}
	enr, err := st.Enroll(ctx, tok.Value)
	if err != nil {
		t.Fatal(err)
	}
	if enr.Name != "syd-1" || enr.Site != "sydney" || enr.ProbeID == "" || len(enr.Secret) < 43 {
		t.Fatalf("bad enrolment %+v", enr.EnrollResponse)
	}
	if _, err := st.Enroll(ctx, tok.Value); enrollReason(err) != ReasonTokenUsed {
		t.Fatalf("reuse: %v, want token_used", err)
	}
	if _, err := st.Enroll(ctx, "not-a-token"); enrollReason(err) != ReasonTokenUnknown {
		t.Fatalf("unknown: %v", err)
	}

	p, err := st.Authenticate(ctx, enr.ProbeID, enr.Secret)
	if err != nil || p.Name != "syd-1" {
		t.Fatalf("authenticate: %+v %v", p, err)
	}
	if _, err := st.Authenticate(ctx, enr.ProbeID, "wrong"); enrollReason(err) != ReasonBadSecret {
		t.Fatalf("bad secret: %v", err)
	}
	if _, err := st.Authenticate(ctx, "nope", enr.Secret); enrollReason(err) != ReasonProbeUnknown {
		t.Fatalf("unknown probe: %v", err)
	}

	// Neither the token nor the secret is stored, only their hashes.
	var n int
	st.db.QueryRow(`SELECT COUNT(*) FROM enroll_tokens WHERE token_hash = ? OR CAST(token_hash AS TEXT) = ?`, tok.Value, tok.Value).Scan(&n)
	if n != 0 {
		t.Fatal("token value stored")
	}
	var h []byte
	st.db.QueryRow(`SELECT secret_hash FROM probes WHERE id = ?`, enr.ProbeID).Scan(&h)
	if bytes.Contains(h, []byte(enr.Secret)) || len(h) != 32 {
		t.Fatalf("secret_hash is not a SHA-256: %d bytes", len(h))
	}

	toks, _ := st.ListTokens(ctx)
	if len(toks) != 1 || toks[0].State(time.Now()) != "used" {
		t.Fatalf("tokens %+v", toks)
	}
}

func TestTokenExpiryAndRevoke(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	st.Now = func() time.Time { return now }

	exp, _ := st.CreateToken(ctx, "a", "s", time.Hour, false)
	rev, _ := st.CreateToken(ctx, "b", "s", time.Hour, false)
	if err := st.RevokeToken(ctx, rev.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeToken(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoke missing: %v", err)
	}
	if _, err := st.Enroll(ctx, rev.Value); enrollReason(err) != ReasonTokenRevoked {
		t.Fatalf("revoked: %v", err)
	}
	now = now.Add(time.Hour)
	if _, err := st.Enroll(ctx, exp.Value); enrollReason(err) != ReasonTokenExpired {
		t.Fatalf("expired: %v", err)
	}
	toks, _ := st.ListTokens(ctx)
	states := map[string]string{}
	for _, tk := range toks {
		states[tk.Name] = tk.State(now)
	}
	if states["a"] != "expired" || states["b"] != "revoked" {
		t.Fatalf("states %v", states)
	}
}

func TestTokenNameRules(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	for _, bad := range []string{"", "Upper", "has space", "under_score", string(make([]byte, 64))} {
		if _, err := st.CreateToken(ctx, bad, "s", time.Hour, false); err == nil {
			t.Errorf("name %q accepted", bad)
		}
		if _, err := st.CreateToken(ctx, "ok", bad, time.Hour, false); err == nil {
			t.Errorf("site %q accepted", bad)
		}
	}
	if _, err := st.CreateToken(ctx, "ok", "s", 0, false); err == nil {
		t.Error("zero ttl accepted")
	}
}

func TestTokenNameClashAndReplace(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	t1, _ := st.CreateToken(ctx, "edge", "s", time.Hour, false)
	// A second token for the same name is allowed while no probe holds the name...
	t2, err := st.CreateToken(ctx, "edge", "s", time.Hour, false)
	if err != nil {
		t.Fatal(err)
	}
	first, err := st.Enroll(ctx, t1.Value)
	if err != nil {
		t.Fatal(err)
	}
	// ...but once one does, creating another is refused, and enrolling the earlier one is too, leaving it unused.
	if _, err := st.CreateToken(ctx, "edge", "s", time.Hour, false); !errors.Is(err, ErrNameTaken) {
		t.Fatalf("create clash: %v", err)
	}
	if _, err := st.Enroll(ctx, t2.Value); enrollReason(err) != ReasonNameTaken {
		t.Fatalf("enrol clash: %v", err)
	}
	toks, _ := st.ListTokens(ctx)
	for _, tk := range toks {
		if tk.ID == t2.ID && tk.State(time.Now()) != "valid" {
			t.Fatalf("refused token state %s, want valid", tk.State(time.Now()))
		}
	}

	rep, err := st.CreateToken(ctx, "edge", "s2", time.Hour, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := st.Enroll(ctx, rep.Value)
	if err != nil {
		t.Fatal(err)
	}
	if second.ReplacedID != first.ProbeID {
		t.Fatalf("replaced %q, want %q", second.ReplacedID, first.ProbeID)
	}
	if _, err := st.Authenticate(ctx, first.ProbeID, first.Secret); enrollReason(err) != ReasonProbeRevoked {
		t.Fatalf("old probe: %v", err)
	}
	p, err := st.ActiveProbe(ctx, "edge")
	if err != nil || p.ID != second.ProbeID || p.Site != "s2" {
		t.Fatalf("active %+v %v", p, err)
	}
	all, _ := st.ListProbes(ctx, true)
	active, _ := st.ListProbes(ctx, false)
	if len(all) != 2 || len(active) != 1 {
		t.Fatalf("all %d active %d", len(all), len(active))
	}
	ids, _ := st.ActiveIDs(ctx, []string{first.ProbeID, second.ProbeID})
	if ids[first.ProbeID] || !ids[second.ProbeID] {
		t.Fatalf("active ids %v", ids)
	}
}

func TestProbeRevokeAndHello(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	tok, _ := st.CreateToken(ctx, "p", "s", time.Hour, false)
	enr, _ := st.Enroll(ctx, tok.Value)
	seen := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	if err := st.SetHello(ctx, enr.ProbeID, protocol.Hello{Type: "hello", Version: "1.2", Hostname: "h"}, seen); err != nil {
		t.Fatal(err)
	}
	p, _ := st.ActiveProbe(ctx, "p")
	if p.LastHello == nil || p.LastHello.Version != "1.2" || !p.LastSeen.Equal(seen) {
		t.Fatalf("probe %+v", p)
	}
	if _, err := st.RevokeProbe(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.RevokeProbe(ctx, "p"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
	if _, err := st.ActiveProbe(ctx, "p"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("active after revoke: %v", err)
	}
	// The name is free again.
	if _, err := st.CreateToken(ctx, "p", "s", time.Hour, false); err != nil {
		t.Fatal(err)
	}
}

// Two stores on one file stand in for `serve` and an admin command running side by side.
func TestStoreConcurrentProcesses(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	a, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	tok, _ := b.CreateToken(ctx, "x", "s", time.Hour, false)
	enr, err := a.Enroll(ctx, tok.Value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.RevokeProbe(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	ids, err := a.ActiveIDs(ctx, []string{enr.ProbeID})
	if err != nil || ids[enr.ProbeID] {
		t.Fatalf("revocation not visible: %v %v", ids, err)
	}
}
