package corrosion

import (
	"context"
	"time"
)

// RegistryCredential is one stored OCI/Docker registry login (schema v23).
// A row is either per-user (Scope="user", Owner=<username>) or global
// (Scope="global", Owner=""). Secret is the raw password/token — List paths
// must redact it before it leaves the daemon (see grpcapi.toPbRegistryCredential).
type RegistryCredential struct {
	ID        string
	Scope     string // "user" | "global"
	Owner     string // username for user scope; "" for global
	Registry  string // normalized registry host
	Username  string
	Secret    string
	CreatedAt string
	UpdatedAt string
}

const (
	RegistryScopeUser   = "user"
	RegistryScopeGlobal = "global"
)

// UpsertRegistryCredential replaces the live credential for (scope, owner,
// registry). It soft-deletes any existing live row for that triple then inserts
// a fresh id, both in one batch so the partial unique index never collides.
// The caller supplies a pre-generated ID.
func UpsertRegistryCredential(ctx context.Context, c *Client, rc RegistryCredential) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return c.ExecuteBatch(ctx, []Statement{
		{
			SQL: `UPDATE registry_credentials SET deleted_at = ?, updated_at = ?
			       WHERE scope = ? AND owner = ? AND registry = ? AND deleted_at IS NULL`,
			Params: []interface{}{now, now, rc.Scope, rc.Owner, rc.Registry},
		},
		{
			SQL: `INSERT INTO registry_credentials
			       (id, scope, owner, registry, username, secret, created_at, updated_at, deleted_at)
			       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			Params: []interface{}{rc.ID, rc.Scope, rc.Owner, rc.Registry, rc.Username, rc.Secret, now, now},
		},
	})
}

func scanRegistryCredentials(rows []Row) []RegistryCredential {
	out := make([]RegistryCredential, 0, len(rows))
	for _, r := range rows {
		out = append(out, RegistryCredential{
			ID: r.String("id"), Scope: r.String("scope"), Owner: r.String("owner"),
			Registry: r.String("registry"), Username: r.String("username"), Secret: r.String("secret"),
			CreatedAt: r.String("created_at"), UpdatedAt: r.String("updated_at"),
		})
	}
	return out
}

// ListRegistryCredentials returns the live rows owned by `owner` and,
// optionally, the global rows. Secret IS included (ResolveRegistryCredential
// needs it); redaction happens at the gRPC layer.
func ListRegistryCredentials(ctx context.Context, c *Client, owner string, includeGlobal bool) ([]RegistryCredential, error) {
	q := `SELECT id, scope, owner, registry, username, secret, created_at, updated_at
	       FROM registry_credentials
	       WHERE deleted_at IS NULL AND ((scope = 'user' AND owner = ?)`
	if includeGlobal {
		q += ` OR scope = 'global'`
	}
	q += `) ORDER BY scope, registry`
	rows, err := c.Query(ctx, q, owner)
	if err != nil {
		return nil, err
	}
	return scanRegistryCredentials(rows), nil
}

// ListAllRegistryCredentials returns every live row across all owners plus the
// global rows. Used by the operator `lv registry ls --all`.
func ListAllRegistryCredentials(ctx context.Context, c *Client) ([]RegistryCredential, error) {
	rows, err := c.Query(ctx,
		`SELECT id, scope, owner, registry, username, secret, created_at, updated_at
		 FROM registry_credentials WHERE deleted_at IS NULL ORDER BY scope, owner, registry`)
	if err != nil {
		return nil, err
	}
	return scanRegistryCredentials(rows), nil
}

// DeleteRegistryCredential soft-deletes the live row for (scope, owner,
// registry). The bool reports whether a live row existed (so the handler can
// return NotFound).
func DeleteRegistryCredential(ctx context.Context, c *Client, scope, owner, registry string) (bool, error) {
	existing, err := c.Query(ctx,
		`SELECT id FROM registry_credentials
		 WHERE scope = ? AND owner = ? AND registry = ? AND deleted_at IS NULL`,
		scope, owner, registry)
	if err != nil {
		return false, err
	}
	if len(existing) == 0 {
		return false, nil
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if err := c.Execute(ctx,
		`UPDATE registry_credentials SET deleted_at = ?, updated_at = ?
		 WHERE scope = ? AND owner = ? AND registry = ? AND deleted_at IS NULL`,
		now, now, scope, owner, registry); err != nil {
		return false, err
	}
	return true, nil
}

// ResolveRegistryCredential implements the pull-time precedence rule: the
// caller's per-user row for `registry` wins, else the global row, else
// (nil, nil) for an anonymous pull.
func ResolveRegistryCredential(ctx context.Context, c *Client, username, registry string) (*RegistryCredential, error) {
	rows, err := c.Query(ctx,
		`SELECT id, scope, owner, registry, username, secret, created_at, updated_at
		 FROM registry_credentials
		 WHERE registry = ? AND deleted_at IS NULL
		   AND ((scope = 'user' AND owner = ?) OR scope = 'global')
		 ORDER BY CASE scope WHEN 'user' THEN 0 ELSE 1 END
		 LIMIT 1`,
		registry, username)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	rc := scanRegistryCredentials(rows)[0]
	return &rc, nil
}
