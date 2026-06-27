// auth helpers — roles, role_bindings, sessions, 2FA, recovery
// codes. These records back the path-based RBAC engine in internal/auth.
//
// Existing users / tokens helpers stay in users.go for now; they get
// extended with the new realm and scope columns at their call sites.
package corrosion

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// ────────────────────────────── ROLES ──────────────────────────────

// RoleRecord is one named permission bundle. Verbs are a JSON array of
// dotted paths like "vm.start" or "lb.*"; "*" alone means "any verb".
type RoleRecord struct {
	Name        string
	Verbs       []string
	Description string
	BuiltIn     bool
	UpdatedAt   string
}

// InsertRole stores a role. Built-in roles set BuiltIn=true so RPC handlers
// can refuse to modify or delete them.
func InsertRole(ctx context.Context, c *Client, r RoleRecord) error {
	now := c.NowTS()
	verbsJSON, err := json.Marshal(r.Verbs)
	if err != nil {
		return fmt.Errorf("marshal verbs: %w", err)
	}
	builtIn := 0
	if r.BuiltIn {
		builtIn = 1
	}
	return c.Execute(ctx,
		`INSERT INTO roles (name, verbs, description, built_in, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE
		   SET verbs = excluded.verbs,
		       description = excluded.description,
		       built_in = excluded.built_in,
		       updated_at = excluded.updated_at`,
		r.Name, string(verbsJSON), r.Description, builtIn, now)
}

// GetRole returns a role by name, or nil if not found.
func GetRole(ctx context.Context, c *Client, name string) (*RoleRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, verbs, description, built_in, updated_at
		 FROM roles WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return scanRole(r), nil
}

// ListRoles returns every active role.
func ListRoles(ctx context.Context, c *Client) ([]RoleRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, verbs, description, built_in, updated_at
		 FROM roles WHERE deleted_at IS NULL ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := make([]RoleRecord, len(rows))
	for i, r := range rows {
		out[i] = *scanRole(r)
	}
	return out, nil
}

// DeleteRole soft-deletes a role. Refuses to touch built-in roles.
func DeleteRole(ctx context.Context, c *Client, name string) error {
	role, err := GetRole(ctx, c, name)
	if err != nil {
		return err
	}
	if role == nil {
		return fmt.Errorf("role %q not found", name)
	}
	if role.BuiltIn {
		return fmt.Errorf("role %q is built-in and cannot be deleted", name)
	}
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE roles SET deleted_at = ?, updated_at = ? WHERE name = ?`,
		nowRFC3339(), now, name)
}

func scanRole(r Row) *RoleRecord {
	verbs := []string{}
	_ = json.Unmarshal([]byte(r.String("verbs")), &verbs)
	return &RoleRecord{
		Name:        r.String("name"),
		Verbs:       verbs,
		Description: r.String("description"),
		BuiltIn:     r.Int("built_in") == 1,
		UpdatedAt:   r.String("updated_at"),
	}
}

// ────────────────────────────── ROLE BINDINGS ──────────────────────────────

// RoleBindingRecord assigns a role to a principal at a path. Principals are:
//
//	user:<username>            — direct user binding
//	group:<group>@<realm>      — group from a realm (e.g. group:platform-team@oidc)
type RoleBindingRecord struct {
	ID        string
	Path      string
	Role      string
	Principal string
	Propagate bool
	UpdatedAt string
}

// InsertRoleBinding creates a (path, role, principal) binding.
func InsertRoleBinding(ctx context.Context, c *Client, b RoleBindingRecord) error {
	now := c.NowTS()
	prop := 1
	if !b.Propagate {
		prop = 0
	}
	return c.Execute(ctx,
		`INSERT INTO role_bindings (id, path, role, principal, propagate, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		b.ID, b.Path, b.Role, b.Principal, prop, now)
}

// DeleteRoleBinding soft-deletes a binding by id.
func DeleteRoleBinding(ctx context.Context, c *Client, id string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE role_bindings SET deleted_at = ?, updated_at = ? WHERE id = ?`,
		nowRFC3339(), now, id)
}

// ListRoleBindings returns all active bindings. Used by the permission
// engine on every RPC; volume is small (hundreds in typical clusters)
// and the index on `principal` keeps lookups fast.
func ListRoleBindings(ctx context.Context, c *Client) ([]RoleBindingRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, path, role, principal, propagate, updated_at
		 FROM role_bindings WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	out := make([]RoleBindingRecord, len(rows))
	for i, r := range rows {
		out[i] = RoleBindingRecord{
			ID:        r.String("id"),
			Path:      r.String("path"),
			Role:      r.String("role"),
			Principal: r.String("principal"),
			Propagate: r.Int("propagate") == 1,
			UpdatedAt: r.String("updated_at"),
		}
	}
	return out, nil
}

// ListBindingsForPrincipal returns bindings that apply to a single
// principal. Used at login/permission-check time.
func ListBindingsForPrincipal(ctx context.Context, c *Client, principal string) ([]RoleBindingRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, path, role, principal, propagate, updated_at
		 FROM role_bindings WHERE principal = ? AND deleted_at IS NULL`, principal)
	if err != nil {
		return nil, err
	}
	out := make([]RoleBindingRecord, len(rows))
	for i, r := range rows {
		out[i] = RoleBindingRecord{
			ID:        r.String("id"),
			Path:      r.String("path"),
			Role:      r.String("role"),
			Principal: r.String("principal"),
			Propagate: r.Int("propagate") == 1,
			UpdatedAt: r.String("updated_at"),
		}
	}
	return out, nil
}

// ────────────────────────────── SESSIONS ──────────────────────────────

// SessionRecord is one active session for a logged-in user.
type SessionRecord struct {
	ID         string
	Username   string
	Realm      string
	IP         string
	UserAgent  string
	CreatedAt  string
	LastUsedAt string
	ExpiresAt  string
	RevokedAt  string
}

// InsertSession creates a session row.
func InsertSession(ctx context.Context, c *Client, s SessionRecord) error {
	return c.Execute(ctx,
		`INSERT INTO sessions
		 (id, username, realm, ip, user_agent, created_at, last_used_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		s.ID, s.Username, s.Realm, s.IP, s.UserAgent,
		s.CreatedAt, s.LastUsedAt, s.ExpiresAt)
}

// GetSession returns a session by id, including revoked rows so the auth
// interceptor can reject them with the right error.
func GetSession(ctx context.Context, c *Client, id string) (*SessionRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, username, realm, ip, user_agent, created_at, last_used_at,
		        expires_at, COALESCE(revoked_at, '') AS revoked_at
		 FROM sessions WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &SessionRecord{
		ID: r.String("id"), Username: r.String("username"), Realm: r.String("realm"),
		IP: r.String("ip"), UserAgent: r.String("user_agent"),
		CreatedAt: r.String("created_at"), LastUsedAt: r.String("last_used_at"),
		ExpiresAt: r.String("expires_at"), RevokedAt: r.String("revoked_at"),
	}, nil
}

// TouchSession bumps last_used_at on every authenticated request so
// idle-timeout calculations are accurate.
func TouchSession(ctx context.Context, c *Client, id string) error {
	return c.Execute(ctx,
		`UPDATE sessions SET last_used_at = ? WHERE id = ? AND revoked_at IS NULL`,
		nowRFC3339(), id) // bare marker (parsed for idle checks; not an LWW key)
}

// RevokeSession marks a session as terminated immediately.
func RevokeSession(ctx context.Context, c *Client, id string) error {
	return c.Execute(ctx,
		`UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`,
		nowRFC3339(), id) // bare marker
}

// ListSessionsForUser returns active sessions for a username.
func ListSessionsForUser(ctx context.Context, c *Client, username string) ([]SessionRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT id, realm, ip, user_agent, created_at, last_used_at, expires_at
		 FROM sessions WHERE username = ? AND revoked_at IS NULL
		 ORDER BY last_used_at DESC`, username)
	if err != nil {
		return nil, err
	}
	out := make([]SessionRecord, len(rows))
	for i, r := range rows {
		out[i] = SessionRecord{
			ID: r.String("id"), Username: username, Realm: r.String("realm"),
			IP: r.String("ip"), UserAgent: r.String("user_agent"),
			CreatedAt: r.String("created_at"), LastUsedAt: r.String("last_used_at"),
			ExpiresAt: r.String("expires_at"),
		}
	}
	return out, nil
}

// ────────────────────────────── 2FA ──────────────────────────────

// User2FARecord is one enrolled second factor.
type User2FARecord struct {
	Username   string
	Method     string // "totp" | "webauthn"
	Secret     string // bcrypt(secret) for TOTP-shared-secret model; opaque blob for WebAuthn
	Label      string
	EnrolledAt string
	LastUsedAt string
	LastStep   int64 // highest consumed TOTP time-step (replay guard); 0 = none yet
}

// InsertUser2FA records an enrolled factor. Re-enrolling a previously
// soft-deleted (username, method, label) reactivates it: deleted_at is cleared
// and the TOTP replay ratchet is reset (mirrors UpsertLBConfig/InsertUser).
// label is a Go string (never NULL), so the composite PK never carries a NULL.
func InsertUser2FA(ctx context.Context, c *Client, r User2FARecord) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO user_2fa (username, method, secret, label, enrolled_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)
		 ON CONFLICT(username, method, label) DO UPDATE
		   SET secret = excluded.secret, updated_at = excluded.updated_at,
		       deleted_at = NULL, last_step = 0`,
		r.Username, r.Method, r.Secret, r.Label, nowRFC3339(), now)
}

// ListUser2FA returns the user's enrolled (non-deleted) factors. Empty slice = no 2FA.
func ListUser2FA(ctx context.Context, c *Client, username string) ([]User2FARecord, error) {
	rows, err := c.Query(ctx,
		`SELECT username, method, secret, COALESCE(label, '') AS label,
		        enrolled_at, COALESCE(last_used_at, '') AS last_used_at,
		        COALESCE(last_step, 0) AS last_step
		 FROM user_2fa WHERE username = ? AND deleted_at IS NULL`, username)
	if err != nil {
		return nil, err
	}
	out := make([]User2FARecord, len(rows))
	for i, r := range rows {
		out[i] = User2FARecord{
			Username: r.String("username"), Method: r.String("method"),
			Secret: r.String("secret"), Label: r.String("label"),
			EnrolledAt: r.String("enrolled_at"), LastUsedAt: r.String("last_used_at"),
			LastStep: r.Int64("last_step"),
		}
	}
	return out, nil
}

// TouchUser2FA bumps last_used_at after a successful verification.
func TouchUser2FA(ctx context.Context, c *Client, username, method, label string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE user_2fa SET last_used_at = ?, updated_at = ?
		 WHERE username = ? AND method = ? AND COALESCE(label,'') = ? AND deleted_at IS NULL`,
		nowRFC3339(), now, username, method, label)
}

// RecordTOTPStep ratchets last_step forward (and bumps last_used_at) after a
// successful TOTP verification. The `last_step < ?` guard means a concurrent
// double-submit of the same code on this node can't move the ratchet twice,
// and replicates the new high-water step to peers so the same code can't be
// replayed on a different node either. The caller still performs a Go-level
// `step <= LastStep` pre-check; this is the persistence + concurrency backstop.
func RecordTOTPStep(ctx context.Context, c *Client, username, method, label string, step int64) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE user_2fa SET last_step = ?, last_used_at = ?, updated_at = ?
		 WHERE username = ? AND method = ? AND COALESCE(label,'') = ? AND last_step < ? AND deleted_at IS NULL`,
		step, nowRFC3339(), now, username, method, label, step)
}

// DeleteUser2FA un-enrolls a single factor. It SOFT-deletes (sets deleted_at +
// bumps updated_at) rather than hard-deleting: anti-entropy is a union merge that
// can't propagate a hard delete, so a peer that missed it would resurrect the
// factor. The newer updated_at carries the tombstone under the sensitive lane.
func DeleteUser2FA(ctx context.Context, c *Client, username, method, label string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE user_2fa SET deleted_at = ?, updated_at = ?
		 WHERE username = ? AND method = ? AND COALESCE(label,'') = ?`,
		nowRFC3339(), now, username, method, label)
}

// ────────────────────────────── RECOVERY CODES ──────────────────────────────

// randomSetID mints an opaque 16-byte hex token naming a recovery-code
// enrollment set. It is an identity match only (no ordering), so per-node clock
// skew is irrelevant — unlike a numeric/MAX generation, which NowTS()'s per-node
// (not cluster) monotonicity would make unsafe for selecting the active set.
func randomSetID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("recovery set id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// InsertRecoveryCodes stores N bcrypt-hashed single-use codes as a new
// enrollment set and points the user at it. Validity comes from the active-set
// pointer (recovery_code_sets), NOT from deletion: a code is accepted only when
// its set_id equals the pointer's active_set_id, so a stale old-set code a peer
// resurrects can never validate even if its tombstone was missed. One atomic
// batch (a single NowTS for the LWW keys):
//
//	(a) LWW-upsert the pointer to a freshly-minted random set_id;
//	(b) best-effort soft-delete locally-known old unused codes (cleanup only —
//	    validity already comes from the pointer);
//	(c) insert the new set's codes carrying that set_id.
func InsertRecoveryCodes(ctx context.Context, c *Client, username string, codeHashes []string) error {
	setID, err := randomSetID()
	if err != nil {
		return err
	}
	now := c.NowTS()       // LWW key for the pointer + code rows
	marker := nowRFC3339() // bare created_at/deleted_at markers (non-LWW)
	stmts := make([]Statement, 0, len(codeHashes)+2)
	// (a) Point the user at the new set (LWW on updated_at).
	stmts = append(stmts, Statement{
		SQL: `INSERT INTO recovery_code_sets (username, active_set_id, updated_at)
			 VALUES (?, ?, ?)
			 ON CONFLICT(username) DO UPDATE SET
			   active_set_id = excluded.active_set_id,
			   updated_at = excluded.updated_at,
			   deleted_at = NULL`,
		Params: []interface{}{username, setID, now},
	})
	// (b) Cleanup: soft-delete this node's old unused codes from prior sets.
	stmts = append(stmts, Statement{
		SQL: `UPDATE recovery_codes SET deleted_at = ?, updated_at = ?
			 WHERE username = ? AND used_at IS NULL AND set_id != ?`,
		Params: []interface{}{marker, now, username, setID},
	})
	// (c) Insert the new codes. ON CONFLICT re-homes a recurring hash into the new
	//     set (bcrypt salting makes recurrence practically impossible; defensive).
	for _, h := range codeHashes {
		stmts = append(stmts, Statement{
			SQL: `INSERT INTO recovery_codes (username, code_hash, created_at, set_id, updated_at)
			 VALUES (?, ?, ?, ?, ?)
			 ON CONFLICT(username, code_hash) DO UPDATE SET
			   set_id = excluded.set_id, used_at = NULL,
			   deleted_at = NULL, updated_at = excluded.updated_at`,
			Params: []interface{}{username, h, marker, setID, now},
		})
	}
	return c.ExecuteBatch(ctx, stmts)
}

// ListUnusedRecoveryCodes returns the bcrypt hashes the verifier should try
// against a presented code: unused, not tombstoned, and belonging to the user's
// CURRENT active set. An old-set code (a resurrected peer row) is excluded even
// if its tombstone was missed, because its set_id no longer matches the pointer.
func ListUnusedRecoveryCodes(ctx context.Context, c *Client, username string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT code_hash FROM recovery_codes
		 WHERE username = ? AND used_at IS NULL AND deleted_at IS NULL
		   AND set_id = (SELECT active_set_id FROM recovery_code_sets
		                 WHERE username = ? AND deleted_at IS NULL)`,
		username, username)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.String("code_hash")
	}
	return out, nil
}

// MarkRecoveryCodeUsed sets used_at on a hash so it can't be reused, and bumps
// updated_at so "used" beats a peer's stale "unused" under LWW. The defensive
// WHERE (active-set match, unused, not tombstoned) means a re-enroll landing
// between list-and-mark can't flip an old-set row.
func MarkRecoveryCodeUsed(ctx context.Context, c *Client, username, codeHash string) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`UPDATE recovery_codes SET used_at = ?, updated_at = ?
		 WHERE username = ? AND code_hash = ? AND used_at IS NULL AND deleted_at IS NULL
		   AND set_id = (SELECT active_set_id FROM recovery_code_sets
		                 WHERE username = ? AND deleted_at IS NULL)`,
		nowRFC3339(), now, username, codeHash, username)
}
