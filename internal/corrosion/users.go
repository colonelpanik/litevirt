package corrosion

import (
	"context"
	"encoding/json"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// UserRecord represents a litevirt user.
type UserRecord struct {
	Username     string
	Role         string
	PasswordHash string
	CreatedAt    string
	// ScopePaths is non-nil only when ValidateToken populates it from the
	// matched API token. Empty slice = no scoping (inherit user's full
	// perms). A scoped token may only operate on paths that are under one
	// of these prefixes.
	ScopePaths []string
}

// TokenRecord represents an API token.
type TokenRecord struct {
	ID         string
	Username   string
	Name       string
	TokenHash  string
	ExpiresAt  string
	CreatedAt  string
	ScopePaths []string // empty/nil = no scoping
}

// InsertUser creates a new user. If the username was previously soft-deleted,
// it reactivates the row with the new role and password.
func InsertUser(ctx context.Context, c *Client, username, role, passwordHash string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	// Try reactivating a soft-deleted user first.
	rows, err := c.Query(ctx,
		`SELECT username FROM users WHERE username = ? AND deleted_at IS NOT NULL`, username)
	if err == nil && len(rows) > 0 {
		return c.Execute(ctx,
			`UPDATE users SET role = ?, password_hash = ?, deleted_at = NULL, updated_at = ? WHERE username = ?`,
			role, passwordHash, now, username,
		)
	}
	return c.Execute(ctx,
		`INSERT INTO users (username, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
		username, role, passwordHash, now, now,
	)
}

// GetUser returns a user by username, or nil if not found.
func GetUser(ctx context.Context, c *Client, username string) (*UserRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT username, role, password_hash, created_at FROM users WHERE username = ? AND deleted_at IS NULL`,
		username)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &UserRecord{
		Username:     r.String("username"),
		Role:         r.String("role"),
		PasswordHash: r.String("password_hash"),
		CreatedAt:    r.String("created_at"),
	}, nil
}

// ListUsers returns all active users.
func ListUsers(ctx context.Context, c *Client) ([]UserRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT username, role, created_at FROM users WHERE deleted_at IS NULL ORDER BY username`)
	if err != nil {
		return nil, err
	}
	users := make([]UserRecord, len(rows))
	for i, r := range rows {
		users[i] = UserRecord{
			Username:  r.String("username"),
			Role:      r.String("role"),
			CreatedAt: r.String("created_at"),
		}
	}
	return users, nil
}

// UpdateUserPassword updates the password hash for a user.
func UpdateUserPassword(ctx context.Context, c *Client, username, passwordHash string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ? AND deleted_at IS NULL`,
		passwordHash, now, username,
	)
}

// DeleteUser tombstones a user.
func DeleteUser(ctx context.Context, c *Client, username string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE users SET deleted_at = ?, updated_at = ? WHERE username = ?`,
		now, now, username,
	)
}

// InsertToken stores a new API token. scope_paths, when non-empty, is
// JSON-encoded and stored verbatim.
func InsertToken(ctx context.Context, c *Client, t TokenRecord) error {
	now := time.Now().UTC().Format(time.RFC3339)
	var scope string
	if len(t.ScopePaths) > 0 {
		b, err := json.Marshal(t.ScopePaths)
		if err != nil {
			return err
		}
		scope = string(b)
	}
	return c.Execute(ctx,
		`INSERT INTO tokens (id, username, name, token_hash, expires_at, scope_paths, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Username, t.Name, t.TokenHash, t.ExpiresAt, scope, now, now,
	)
}

// RevokeToken tombstones a token. updated_at is bumped alongside deleted_at so the
// revocation wins LWW over a stale peer's still-live copy under anti-entropy.
// (last_used_at bumps in ValidateToken deliberately do NOT touch updated_at, so a
// high-frequency token use can't out-timestamp a revoke.)
func RevokeToken(ctx context.Context, c *Client, id string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.Execute(ctx,
		`UPDATE tokens SET deleted_at = ?, updated_at = ? WHERE id = ?`,
		now, now, id,
	)
}

// ValidateToken checks a raw token string against stored bcrypt hashes.
// Returns the associated UserRecord on success (with ScopePaths populated
// if the matched token is scoped), or nil if no token matches.
func ValidateToken(ctx context.Context, c *Client, rawToken string) (*UserRecord, error) {
	// Fast-reject anything that isn't shaped like one of our tokens BEFORE
	// touching the bcrypt sweep below. CreateToken always emits exactly 64
	// lowercase hex chars (hex of 32 random bytes), so a bearer that doesn't
	// match can't be valid — and rejecting it here means a flood of garbage
	// bearers can't force an O(N) run of (expensive) bcrypt comparisons per
	// request. A correctly-shaped but wrong token still falls through to the
	// sweep; eliminating that O(N) entirely needs an indexed lookup selector
	// (separate, schema-bumping change).
	if !looksLikeAPIToken(rawToken) {
		return nil, nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	rows, err := c.Query(ctx,
		`SELECT t.id, t.username, t.token_hash, t.scope_paths, u.role
		 FROM tokens t
		 JOIN users u ON u.username = t.username
		 WHERE t.deleted_at IS NULL AND u.deleted_at IS NULL
		   AND (t.expires_at IS NULL OR t.expires_at = '' OR t.expires_at > ?)`,
		now)
	if err != nil {
		return nil, err
	}

	for _, r := range rows {
		hash := r.String("token_hash")
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(rawToken)) == nil {
			_ = c.Execute(ctx, `UPDATE tokens SET last_used_at = ? WHERE id = ?`,
				time.Now().UTC().Format(time.RFC3339), r.String("id"))
			rec := &UserRecord{
				Username: r.String("username"),
				Role:     r.String("role"),
			}
			if raw := r.String("scope_paths"); raw != "" {
				var paths []string
				if err := json.Unmarshal([]byte(raw), &paths); err == nil {
					rec.ScopePaths = paths
				}
			}
			return rec, nil
		}
	}
	return nil, nil
}

// looksLikeAPIToken reports whether s has the exact shape CreateToken emits:
// 64 lowercase hex characters. Used to cheaply discard malformed bearers
// before the bcrypt comparison sweep.
func looksLikeAPIToken(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
