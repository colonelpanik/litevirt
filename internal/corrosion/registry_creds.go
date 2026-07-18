package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/binary"

	"github.com/google/uuid"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// capCanonicalRegistryV1 is the capability token gating the Part H2 canonical registry writer +
// its capability-gated ledger disposition. Aliased from the capabilities package (single source of
// truth) so the ledger policy and the runtime activation check can't drift.
const capCanonicalRegistryV1 = capabilities.CanonicalRegistryV1

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

// RegistryCredentialID derives the DETERMINISTIC, cluster-stable primary-key id for one logical
// credential (scope, owner, registry) — the Part H2 canonical model. Because every node computes
// the SAME id for a triple, two nodes creating/rotating the same credential target the SAME
// physical PK, so a replication conflict resolves by normal LWW on that PK instead of minting two
// random ids that collide on the partial UNIQUE index.
//
// The encoding is a FROZEN contract (a change ⇒ a new domain tag "credential/v2" + a migration):
// a domain tag followed by each field LENGTH-PREFIXED (big-endian uint32) so no two distinct
// triples can frame to the same bytes, hashed with SHA-256; the first 16 bytes become a v8
// (custom, RFC 9562) UUID. Inputs are the STORED canonical values — `registry` is already
// normalized by lxc.NormalizeRegistry at write time, and this function applies NO further
// normalization (notably NO lowercasing: NormalizeRegistry preserves case beyond folding the
// Docker Hub aliases, so re-casing here would split a credential from its own pulls).
func RegistryCredentialID(scope, owner, registry string) string {
	b := make([]byte, 0, 64)
	b = append(b, "credential/v1"...)
	for _, f := range []string{scope, owner, registry} {
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(f)))
		b = append(b, l[:]...)
		b = append(b, f...)
	}
	sum := sha256.Sum256(b)
	var id uuid.UUID
	copy(id[:], sum[:16])
	id[6] = (id[6] & 0x0f) | 0x80 // version 8 (custom / hash-derived)
	id[8] = (id[8] & 0x3f) | 0x80 // RFC 4122 variant
	return id.String()
}

// UpsertRegistryCredential replaces the live credential for (scope, owner,
// registry). It soft-deletes any existing live row for that triple then inserts
// a fresh id, both in one batch so the partial unique index never collides.
// The caller supplies a pre-generated ID.
func UpsertRegistryCredential(ctx context.Context, c *Client, rc RegistryCredential) error {
	now := c.NowTS()
	return c.ExecuteBatch(ctx, []Statement{
		{
			SQL: `UPDATE registry_credentials SET deleted_at = ?, updated_at = ?
			       WHERE scope = ? AND owner = ? AND registry = ? AND deleted_at IS NULL`,
			Params: []interface{}{nowRFC3339(), now, rc.Scope, rc.Owner, rc.Registry},
		},
		{
			SQL: `INSERT INTO registry_credentials
			       (id, scope, owner, registry, username, secret, created_at, updated_at, deleted_at)
			       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			Params: []interface{}{rc.ID, rc.Scope, rc.Owner, rc.Registry, rc.Username, rc.Secret, nowRFC3339(), now},
		},
	})
}

// UpsertRegistryCredentialCanonical writes the credential for (scope, owner, registry) as ONE
// stable row keyed on its deterministic id (Part H2). Create / rotate / revive all funnel through
// a single PK-keyed upsert: it inserts the row live, or ON CONFLICT updates the credential material
// and CLEARS deleted_at (a revive), always stamping a fresh HLC updated_at. scope/owner/registry
// and created_at are never reassigned (the id pins the triple; created_at is set once). No
// tombstone+insert and no minted id, so two nodes writing the same triple converge by LWW on the
// PK rather than colliding on the partial UNIQUE. rc.ID is ignored (recomputed).
// registryCanonicalUpsertSQL is the single frozen statement the canonical writer emits (exported
// to tests so they can't drift from the ledger-registered shape). The ON CONFLICT SET is a FULL
// image of the row's mutable content — including created_at = excluded.created_at — so a
// replicated write CONVERGES the whole row on the winning value: two nodes that independently
// created this deterministic id (with different wall-clock created_at) otherwise keep different
// created_at forever and read as a permanent equal-timestamp content fault. scope/owner/registry
// are not reassigned (the id pins them); deleted_at is always cleared (a write is a revive).
const registryCanonicalUpsertSQL = `INSERT INTO registry_credentials
		   (id, scope, owner, registry, username, secret, created_at, updated_at, deleted_at)
		   VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(id) DO UPDATE SET
		   username = excluded.username,
		   secret = excluded.secret,
		   created_at = excluded.created_at,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`

func UpsertRegistryCredentialCanonical(ctx context.Context, c *Client, rc RegistryCredential) error {
	now := c.NowTS()
	id := RegistryCredentialID(rc.Scope, rc.Owner, rc.Registry)
	// PRESERVE an existing row's created_at (a rotate/revive keeps the original creation time),
	// then propagate that selected value through the full-image upsert so every node converges on
	// it. A create (no row yet) stamps a fresh created_at.
	createdAt := nowRFC3339()
	if existing, err := c.Query(ctx, "SELECT created_at FROM registry_credentials WHERE id = ?", id); err != nil {
		return err
	} else if len(existing) == 1 {
		createdAt = existing[0].String("created_at")
	}
	return c.Execute(ctx, registryCanonicalUpsertSQL,
		id, rc.Scope, rc.Owner, rc.Registry, rc.Username, rc.Secret, createdAt, now)
}

// UpsertRegistryCredentialAuto selects the canonical (deterministic-id) writer when the H2
// activation predicate is on, else the legacy mint-new-id tombstone+insert writer — so a login is
// behavior-neutral until the fleet has converged and the writer is activated.
func UpsertRegistryCredentialAuto(ctx context.Context, c *Client, rc RegistryCredential) error {
	if c.canonicalRegistryOn() {
		return UpsertRegistryCredentialCanonical(ctx, c, rc)
	}
	return UpsertRegistryCredential(ctx, c, rc)
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
	now := c.NowTS()
	if err := c.Execute(ctx,
		`UPDATE registry_credentials SET deleted_at = ?, updated_at = ?
		 WHERE scope = ? AND owner = ? AND registry = ? AND deleted_at IS NULL`,
		nowRFC3339(), now, scope, owner, registry); err != nil {
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
