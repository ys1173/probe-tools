package hub

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go, so the hub builds without cgo

	"probetools/internal/protocol"
)

// Store keeps enrolled probes and enrolment tokens in SQLite. It holds hashes of tokens and secrets, never the values.
// WAL mode and a busy timeout let the admin commands write to the database while `serve` runs.
type Store struct {
	db   *sql.DB
	file string
	// Now is the clock, replaceable in tests.
	Now func() time.Time
}

// ProbeRecord is one enrolled probe as stored.
type ProbeRecord struct {
	ID         string
	Name       string
	Site       string
	EnrolledAt time.Time
	RevokedAt  time.Time // zero while the probe is active
	LastSeen   time.Time
	LastHello  *protocol.Hello
}

// Revoked reports whether the probe has been revoked.
func (p ProbeRecord) Revoked() bool { return !p.RevokedAt.IsZero() }

// TokenRecord is one enrolment token as stored, without its value.
type TokenRecord struct {
	ID        string
	Name      string
	Site      string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time
	RevokedAt time.Time
	Replace   bool
}

// State is the token's state at time now: used, revoked, expired or valid.
func (t TokenRecord) State(now time.Time) string {
	switch {
	case !t.UsedAt.IsZero():
		return "used"
	case !t.RevokedAt.IsZero():
		return "revoked"
	case !now.Before(t.ExpiresAt):
		return "expired"
	}
	return "valid"
}

// Errors the admin commands show to the operator.
var (
	ErrNotFound  = errors.New("not found")
	ErrNameTaken = errors.New("an active probe already has this name; revoke it first or use --replace")
)

// EnrollError is why an enrolment failed. The reason is logged but never sent to the caller, so a guesser learns
// nothing about which part was wrong.
type EnrollError struct{ Reason string }

func (e *EnrollError) Error() string { return "enrolment refused: " + e.Reason }

// Reason codes for refused enrolments and connections, logged by the hub.
const (
	ReasonTokenUnknown  = "token_unknown"
	ReasonTokenUsed     = "token_used"
	ReasonTokenRevoked  = "token_revoked"
	ReasonTokenExpired  = "token_expired"
	ReasonNameTaken     = "name_taken"
	ReasonProbeUnknown  = "probe_unknown"
	ReasonBadSecret     = "bad_secret"
	ReasonProbeRevoked  = "probe_revoked"
	ReasonMalformedAuth = "malformed_auth"
)

const schema = `
CREATE TABLE IF NOT EXISTS probes (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL,
	site        TEXT NOT NULL,
	secret_hash BLOB NOT NULL,
	enrolled_at TEXT NOT NULL,
	revoked_at  TEXT,
	last_seen   TEXT,
	last_hello  TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS probes_active_name ON probes(name) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS enroll_tokens (
	id         TEXT PRIMARY KEY,
	token_hash BLOB NOT NULL UNIQUE,
	name       TEXT NOT NULL,
	site       TEXT NOT NULL,
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	used_at    TEXT,
	revoked_at TEXT,
	"replace"  INTEGER NOT NULL DEFAULT 0
);
`

// OpenStore opens (creating if needed) dataDir/hub.db.
func OpenStore(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	return OpenStorePath(filepath.Join(dataDir, "hub.db"))
}

// OpenStorePath opens (creating if needed) the database at path.
func OpenStorePath(path string) (*Store, error) {
	// Create the file ourselves so it starts as 0600; SQLite gives the WAL and shared-memory files the same mode.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("create database: %w", err)
	}
	f.Close()
	// Immediate transactions take the write lock at BEGIN, so a read-then-write transaction waits on busy_timeout
	// instead of failing when another process (an admin command) writes at the same moment.
	dsn := "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &Store{db: db, file: path, Now: time.Now}, nil
}

// path is the database file.
func (s *Store) path() string { return s.file }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) now() time.Time { return s.Now().UTC() }

// Times are stored as RFC 3339 text in UTC, so the database is readable with the sqlite3 tool.
func fmtTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return fmtTime(t)
}

func parseTime(ns sql.NullString) time.Time {
	if !ns.Valid {
		return time.Time{}
	}
	t, _ := time.Parse(time.RFC3339Nano, ns.String)
	return t
}

// randomValue returns n random bytes, base64url-encoded without padding.
func randomValue(n int) string {
	b := make([]byte, n)
	rand.Read(b) // never fails; see crypto/rand
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomID(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func hashSecret(v string) []byte {
	h := sha256.Sum256([]byte(v))
	return h[:]
}

var nameRE = regexp.MustCompile(`^[a-z0-9-]{1,63}$`)

// ValidName reports whether s is a valid probe name or site: 1 to 63 characters of a-z, 0-9 and '-'.
func ValidName(s string) bool { return nameRE.MatchString(s) }

// NewToken is a freshly created enrolment token. Value is shown to the operator once and never stored.
type NewToken struct {
	ID        string
	Value     string
	ExpiresAt time.Time
}

// CreateToken makes a single-use enrolment token that fixes the probe's name and site. Unless replace is set, the name
// must not belong to an active probe; with replace, enrolling revokes that probe.
func (s *Store) CreateToken(ctx context.Context, name, site string, ttl time.Duration, replace bool) (NewToken, error) {
	if !ValidName(name) {
		return NewToken{}, fmt.Errorf("name %q: use 1 to 63 characters of a-z, 0-9 and -", name)
	}
	if !ValidName(site) {
		return NewToken{}, fmt.Errorf("site %q: use 1 to 63 characters of a-z, 0-9 and -", site)
	}
	if ttl <= 0 {
		return NewToken{}, errors.New("ttl must be positive")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return NewToken{}, err
	}
	defer tx.Rollback()
	if !replace {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM probes WHERE name = ? AND revoked_at IS NULL`, name).Scan(&n); err != nil {
			return NewToken{}, err
		}
		if n > 0 {
			return NewToken{}, ErrNameTaken
		}
	}
	now := s.now()
	t := NewToken{ID: randomID(8), Value: randomValue(32), ExpiresAt: now.Add(ttl)}
	_, err = tx.ExecContext(ctx, `INSERT INTO enroll_tokens (id, token_hash, name, site, created_at, expires_at, "replace")
		VALUES (?, ?, ?, ?, ?, ?, ?)`, t.ID, hashSecret(t.Value), name, site, fmtTime(now), fmtTime(t.ExpiresAt), replace)
	if err != nil {
		return NewToken{}, err
	}
	return t, tx.Commit()
}

// ListTokens returns every token, newest first.
func (s *Store) ListTokens(ctx context.Context) ([]TokenRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, site, created_at, expires_at, used_at, revoked_at, "replace"
		FROM enroll_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TokenRecord
	for rows.Next() {
		var t TokenRecord
		var created, expires, used, revoked sql.NullString
		if err := rows.Scan(&t.ID, &t.Name, &t.Site, &created, &expires, &used, &revoked, &t.Replace); err != nil {
			return nil, err
		}
		t.CreatedAt, t.ExpiresAt, t.UsedAt, t.RevokedAt = parseTime(created), parseTime(expires), parseTime(used), parseTime(revoked)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken makes an unused token unusable. Revoking an already revoked token is not an error.
func (s *Store) RevokeToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE enroll_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?`, fmtTime(s.now()), id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Enrollment is the outcome of a successful enrolment.
type Enrollment struct {
	protocol.EnrollResponse
	ReplacedID string // the probe revoked because the token had replace set, if any
}

// Enroll exchanges a token for a new probe identity. In one transaction it marks the token used, refuses a name that
// an active probe holds (unless the token allows replacing it, in which case the old probe is revoked) and creates the
// probe. A refusal returns *EnrollError and leaves the token as it was.
func (s *Store) Enroll(ctx context.Context, token string) (Enrollment, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Enrollment{}, err
	}
	defer tx.Rollback()

	h := hashSecret(token)
	var (
		id, name, site string
		storedHash     []byte
		expires        string
		used, revoked  sql.NullString
		replace        bool
	)
	err = tx.QueryRowContext(ctx, `SELECT id, token_hash, name, site, expires_at, used_at, revoked_at, "replace"
		FROM enroll_tokens WHERE token_hash = ?`, h).Scan(&id, &storedHash, &name, &site, &expires, &used, &revoked, &replace)
	if errors.Is(err, sql.ErrNoRows) {
		return Enrollment{}, &EnrollError{ReasonTokenUnknown}
	}
	if err != nil {
		return Enrollment{}, err
	}
	// The lookup was by hash already; the constant-time comparison is a second check that costs nothing.
	if subtle.ConstantTimeCompare(storedHash, h) != 1 {
		return Enrollment{}, &EnrollError{ReasonTokenUnknown}
	}
	now := s.now()
	switch {
	case used.Valid:
		return Enrollment{}, &EnrollError{ReasonTokenUsed}
	case revoked.Valid:
		return Enrollment{}, &EnrollError{ReasonTokenRevoked}
	case !now.Before(parseTime(sql.NullString{String: expires, Valid: true})):
		return Enrollment{}, &EnrollError{ReasonTokenExpired}
	}
	res, err := tx.ExecContext(ctx, `UPDATE enroll_tokens SET used_at = ? WHERE id = ? AND used_at IS NULL AND revoked_at IS NULL`, fmtTime(now), id)
	if err != nil {
		return Enrollment{}, err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return Enrollment{}, &EnrollError{ReasonTokenUsed}
	}

	var out Enrollment
	var oldID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM probes WHERE name = ? AND revoked_at IS NULL`, name).Scan(&oldID)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return Enrollment{}, err
	case !replace:
		return Enrollment{}, &EnrollError{ReasonNameTaken}
	default:
		if _, err := tx.ExecContext(ctx, `UPDATE probes SET revoked_at = ? WHERE id = ?`, fmtTime(now), oldID); err != nil {
			return Enrollment{}, err
		}
		out.ReplacedID = oldID
	}

	out.ProbeID = randomID(16)
	out.Name = name
	out.Site = site
	out.Secret = randomValue(32)
	_, err = tx.ExecContext(ctx, `INSERT INTO probes (id, name, site, secret_hash, enrolled_at) VALUES (?, ?, ?, ?, ?)`,
		out.ProbeID, name, site, hashSecret(out.Secret), fmtTime(now))
	if err != nil {
		return Enrollment{}, err
	}
	if err := tx.Commit(); err != nil {
		return Enrollment{}, err
	}
	return out, nil
}

// dummyHash is compared against when a probe id is unknown, so unknown ids and wrong secrets take the same time.
var dummyHash = hashSecret("no such probe")

// Authenticate checks a probe's id and secret. It returns the probe, or *EnrollError with a reason to log.
func (s *Store) Authenticate(ctx context.Context, id, secret string) (ProbeRecord, error) {
	p, storedHash, err := s.probeByID(ctx, id)
	if errors.Is(err, ErrNotFound) {
		subtle.ConstantTimeCompare(dummyHash, hashSecret(secret))
		return ProbeRecord{}, &EnrollError{ReasonProbeUnknown}
	}
	if err != nil {
		return ProbeRecord{}, err
	}
	if subtle.ConstantTimeCompare(storedHash, hashSecret(secret)) != 1 {
		return ProbeRecord{}, &EnrollError{ReasonBadSecret}
	}
	if p.Revoked() {
		return ProbeRecord{}, &EnrollError{ReasonProbeRevoked}
	}
	return p, nil
}

const probeColumns = `id, name, site, secret_hash, enrolled_at, revoked_at, last_seen, last_hello`

func scanProbe(sc interface{ Scan(...any) error }) (ProbeRecord, []byte, error) {
	var p ProbeRecord
	var hash []byte
	var enrolled string
	var revoked, seen, hello sql.NullString
	if err := sc.Scan(&p.ID, &p.Name, &p.Site, &hash, &enrolled, &revoked, &seen, &hello); err != nil {
		return p, nil, err
	}
	p.EnrolledAt = parseTime(sql.NullString{String: enrolled, Valid: true})
	p.RevokedAt = parseTime(revoked)
	p.LastSeen = parseTime(seen)
	if hello.Valid && hello.String != "" {
		var h protocol.Hello
		if json.Unmarshal([]byte(hello.String), &h) == nil {
			p.LastHello = &h
		}
	}
	return p, hash, nil
}

func (s *Store) probeByID(ctx context.Context, id string) (ProbeRecord, []byte, error) {
	p, h, err := scanProbe(s.db.QueryRowContext(ctx, `SELECT `+probeColumns+` FROM probes WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil, ErrNotFound
	}
	return p, h, err
}

// ProbeByID returns a probe, revoked or not.
func (s *Store) ProbeByID(ctx context.Context, id string) (ProbeRecord, error) {
	p, _, err := s.probeByID(ctx, id)
	return p, err
}

// ActiveProbe returns the unrevoked probe with this name.
func (s *Store) ActiveProbe(ctx context.Context, name string) (ProbeRecord, error) {
	p, _, err := scanProbe(s.db.QueryRowContext(ctx, `SELECT `+probeColumns+` FROM probes WHERE name = ? AND revoked_at IS NULL`, name))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// ListProbes returns probes sorted by name, then newest first; revoked ones only if includeRevoked.
func (s *Store) ListProbes(ctx context.Context, includeRevoked bool) ([]ProbeRecord, error) {
	q := `SELECT ` + probeColumns + ` FROM probes`
	if !includeRevoked {
		q += ` WHERE revoked_at IS NULL`
	}
	q += ` ORDER BY name, enrolled_at DESC`
	rows, err := s.db.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ProbeRecord
	for rows.Next() {
		p, _, err := scanProbe(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// RevokeProbe revokes the active probe with this name. A running hub closes its session within a few seconds.
func (s *Store) RevokeProbe(ctx context.Context, name string) (string, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `UPDATE probes SET revoked_at = ? WHERE name = ? AND revoked_at IS NULL RETURNING id`,
		fmtTime(s.now()), name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return id, err
}

// ActiveIDs reports which of ids belong to unrevoked probes.
func (s *Store) ActiveIDs(ctx context.Context, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	q := `SELECT id FROM probes WHERE revoked_at IS NULL AND id IN (?` + strings.Repeat(",?", len(ids)-1) + `)`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// SetHello records the probe's latest hello, so its details are shown while it is offline.
func (s *Store) SetHello(ctx context.Context, id string, h protocol.Hello, seen time.Time) error {
	b, err := json.Marshal(h)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE probes SET last_hello = ?, last_seen = ? WHERE id = ?`, string(b), nullTime(seen), id)
	return err
}

// SetLastSeen records when the probe was last heard from.
func (s *Store) SetLastSeen(ctx context.Context, id string, seen time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE probes SET last_seen = ? WHERE id = ?`, nullTime(seen), id)
	return err
}
