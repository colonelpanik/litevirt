package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// capCanonicalRegistryV1 is the capability token gating the Part H2 canonical registry writer +
// its capability-gated ledger disposition. Aliased from the capabilities package (single source of
// truth) so the ledger policy and the runtime activation check can't drift.
const capCanonicalRegistryV1 = capabilities.CanonicalRegistryV1

// PART H2 STATUS — preparatory infrastructure only. The canonical deterministic-id model exists as
// building blocks (RegistryCredentialID, UpsertRegistryCredentialCanonical, ConsolidateRegistry-
// Credentials, the readiness diagnostics) plus ONE runtime behavior: once canonical_registry_v1 is
// durably latched cluster-wide, replicated canonical upserts are ACCEPTED on apply. Nothing switches
// the WRITER — every local API write still uses the legacy mint-new-id writer, so the concurrent-
// login collision (two nodes minting different ids for one triple → a legacy batch loses LWW on its
// tombstone and its INSERT back-pressures the peer stream) is NOT resolved here; it remains OPEN
// until the deferred operator-run activation contract (writer switch + durable barrier/watermark
// proof + convergence proof + node admission/reseed + legacy-shape rejection + index contract, done
// as one atomic operation). See docs/diagnostics.md.

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

// registryTombstoneByTripleSQL soft-deletes the LIVE row for a triple (the legacy writer's first
// statement; also reused by consolidation to retire a legacy live row). Registered shape.
const registryTombstoneByTripleSQL = `UPDATE registry_credentials SET deleted_at = ?, updated_at = ?
			       WHERE scope = ? AND owner = ? AND registry = ? AND deleted_at IS NULL`

// registryLegacyInsertSQL mints a new random-id credential row (the legacy writer's second
// statement). It auto-derives to DispPlainInsert and is always accepted — rejecting the legacy shape
// is part of the deferred operator-run writer-activation contract, not this reversible core.
const registryLegacyInsertSQL = `INSERT INTO registry_credentials
			       (id, scope, owner, registry, username, secret, created_at, updated_at, deleted_at)
			       VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)`

// UpsertRegistryCredential replaces the live credential for (scope, owner,
// registry). It soft-deletes any existing live row for that triple then inserts
// a fresh id, both in one batch so the partial unique index never collides.
// The caller supplies a pre-generated ID.
func UpsertRegistryCredential(ctx context.Context, c *Client, rc RegistryCredential) error {
	now := c.NowTS()
	return c.ExecuteBatch(ctx, []Statement{
		{
			SQL:    registryTombstoneByTripleSQL,
			Params: []interface{}{nowRFC3339(), now, rc.Scope, rc.Owner, rc.Registry},
		},
		{
			SQL:    registryLegacyInsertSQL,
			Params: []interface{}{rc.ID, rc.Scope, rc.Owner, rc.Registry, rc.Username, rc.Secret, nowRFC3339(), now},
		},
	})
}

// registryCanonicalUpsertSQL is the single frozen statement the canonical writer + consolidation
// emit (also referenced by tests so they can't drift from the ledger-registered shape). The ON
// CONFLICT SET is a FULL image of the row's mutable content — including created_at =
// excluded.created_at — so a replicated write CONVERGES the whole row on the winning value: two
// nodes that independently created this deterministic id (with different wall-clock created_at)
// otherwise keep different created_at forever and read as a permanent equal-timestamp content
// fault. scope/owner/registry are not reassigned (the id pins them); deleted_at is always cleared
// (a write is a revive).
const registryCanonicalUpsertSQL = `INSERT INTO registry_credentials
		   (id, scope, owner, registry, username, secret, created_at, updated_at, deleted_at)
		   VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
		 ON CONFLICT(id) DO UPDATE SET
		   username = excluded.username,
		   secret = excluded.secret,
		   created_at = excluded.created_at,
		   updated_at = excluded.updated_at,
		   deleted_at = NULL`

// registryTombstoneByIDSQL soft-deletes a SPECIFIC legacy row, CAS-guarded on its COMPLETE
// expected content — id, triple, username, secret, created_at, updated_at, and still-live. Used by
// consolidation to retire the exact legacy row. The full-content CAS is what keeps an
// equal-timestamp/different-content conflict fail-closed: on a peer that holds the same legacy id
// and updated_at but DIFFERENT content, this tombstone affects ZERO rows, so the following canonical
// insert collides with the still-live legacy row on the partial UNIQUE and the whole mutation entry
// rolls back / back-pressures — the migration never silently picks one credential. (A guard on only
// id + updated_at would retire the peer's differing row and let the sender's canonical row win.)
// Registered shape (full-PK LWW).
const registryTombstoneByIDSQL = `UPDATE registry_credentials SET deleted_at = ?, updated_at = ? WHERE id = ? AND scope = ? AND owner = ? AND registry = ? AND username = ? AND secret = ? AND created_at = ? AND updated_at = ? AND deleted_at IS NULL`

// registryWriteRetries bounds the read-modify-write CAS retries for a contended row.
const registryWriteRetries = 8

// UpsertRegistryCredentialCanonical writes the credential for (scope, owner, registry) as ONE
// stable row keyed on its deterministic id (Part H2). Create / rotate / revive all funnel through a
// single PK-keyed upsert. The whole operation is a LWW-guarded read-modify-write under one lock: it
// reads the current row, mints a fresh updated_at, and applies ONLY IF that is strictly newer than
// the current row (never overwriting/reviving a concurrently-committed newer op — the local
// lost-update the plain Query+Execute allowed), preserving the existing created_at so a rotate keeps
// the original creation time. On an equal/newer current row it is a no-op (the LWW loser). rc.ID is
// ignored (recomputed).
func UpsertRegistryCredentialCanonical(ctx context.Context, c *Client, rc RegistryCredential) error {
	id := RegistryCredentialID(rc.Scope, rc.Owner, rc.Registry)
	for attempt := 0; attempt < registryWriteRetries; attempt++ {
		now := c.NowTS()
		cur, err := c.Query(ctx, "SELECT created_at, updated_at FROM registry_credentials WHERE id = ?", id)
		if err != nil {
			return err
		}
		createdAt := nowRFC3339()
		preExists := len(cur) == 1
		if preExists {
			if lwwOrder(cur[0].String("updated_at"), now) >= 0 {
				return nil // current is newer-or-equal ⇒ our write is the LWW loser: a no-op success
			}
			createdAt = cur[0].String("created_at") // preserve
		}
		applied, err := c.ExecuteBatchGuarded(ctx,
			func(tx *sql.Tx) (bool, error) {
				var cc, cu sql.NullString
				e := tx.QueryRowContext(ctx, "SELECT created_at, updated_at FROM registry_credentials WHERE id = ?", id).Scan(&cc, &cu)
				if errors.Is(e, sql.ErrNoRows) {
					return !preExists, nil // apply the create only if we still expect no row
				}
				if e != nil {
					return false, e
				}
				// Row exists: apply only if still strictly newer AND created_at consistent with our stmt.
				return cc.String == createdAt && lwwOrder(cu.String, now) < 0, nil
			},
			[]Statement{{SQL: registryCanonicalUpsertSQL, Params: []interface{}{id, rc.Scope, rc.Owner, rc.Registry, rc.Username, rc.Secret, createdAt, now}}})
		if err != nil {
			return err
		}
		if applied {
			return nil
		}
		// The guard declined (the row changed since the pre-read) ⇒ retry with a fresh read.
	}
	return fmt.Errorf("registry credential upsert on %s: too much contention", id)
}

// ConsolidateRegistryCredentials rewrites legacy random-id LIVE rows to their canonical
// deterministic-id row — the Part H2 one-time "converge" data migration. IDEMPOTENT. It REQUIRES
// canonical_registry_v1 latched (else the emitted canonical writes would be rejected by peers). For
// each triple with a live, non-canonical row it does a LWW-guarded read-modify-write per triple:
// tombstone the EXACT legacy row by primary key (CAS-guarded on its updated_at + still-live, so
// exchanging migration entries never deletes an already-canonical row), and — only when the
// canonical row is absent or older — upsert it with the legacy content (username/secret AND
// created_at preserved, the legacy updated_at carried, so two nodes consolidating the same converged
// row emit byte-identical canonical rows). The guard revalidates the exact legacy id/updated_at
// inside the transaction, so a concurrent legacy login can't be silently overwritten with stale
// content; on a CAS miss it retries from a fresh row.
//
// An equal-timestamp/different-content conflict is inherently CROSS-NODE (the partial UNIQUE keeps
// each node's local state to one live row); it surfaces fail-closed at the canonical upsert's LWW
// apply (an exact tie keeps local), not by silently picking a winner. Retired legacy rows are left
// tombstoned for the watermark-gated GC — a local hard delete of a replicated row is union-unsafe,
// the rule ReapSpentProofs follows.
func ConsolidateRegistryCredentials(ctx context.Context, c *Client) (migrated int, err error) {
	if !c.canonicalRegistryAcceptOn() {
		return 0, fmt.Errorf("registry consolidation requires canonical_registry_v1 latched (peers would reject the canonical writes)")
	}
	triples, err := c.Query(ctx,
		`SELECT DISTINCT scope, owner, registry FROM registry_credentials WHERE deleted_at IS NULL`)
	if err != nil {
		return 0, err
	}
	for _, t := range triples {
		scope, owner, registry := t.String("scope"), t.String("owner"), t.String("registry")
		did, mErr := c.migrateRegistryTriple(ctx, scope, owner, registry)
		if mErr != nil {
			return migrated, mErr
		}
		if did {
			migrated++
		}
	}
	return migrated, nil
}

// migrateRegistryTriple consolidates one triple's live legacy row (see ConsolidateRegistryCredentials).
func (c *Client) migrateRegistryTriple(ctx context.Context, scope, owner, registry string) (bool, error) {
	detID := RegistryCredentialID(scope, owner, registry)
	for attempt := 0; attempt < registryWriteRetries; attempt++ {
		live, err := c.Query(ctx,
			"SELECT id, username, secret, created_at, updated_at FROM registry_credentials WHERE scope=? AND owner=? AND registry=? AND deleted_at IS NULL",
			scope, owner, registry)
		if err != nil {
			return false, err
		}
		if len(live) == 0 {
			return false, nil // nothing live (revoked / consolidated concurrently)
		}
		legacyID := live[0].String("id")
		if legacyID == detID {
			return false, nil // already canonical
		}
		legacyTS := live[0].String("updated_at")
		username, secret, createdAt := live[0].String("username"), live[0].String("secret"), live[0].String("created_at")

		// The canonical row's current state decides whether we (re)write it — never clobber a newer
		// canonical row (e.g. a peer's revoke that arrived before its tombstone of this legacy row).
		det, err := c.Query(ctx, "SELECT updated_at FROM registry_credentials WHERE id = ?", detID)
		if err != nil {
			return false, err
		}
		detTS := ""
		if len(det) == 1 {
			detTS = det[0].String("updated_at")
		}
		writeCanonical := detTS == "" || lwwOrder(detTS, legacyTS) < 0

		// Full-content CAS: id, triple, username, secret, created_at, updated_at, still-live.
		stmts := []Statement{{SQL: registryTombstoneByIDSQL, Params: []interface{}{
			nowRFC3339(), c.NowTS(), legacyID, scope, owner, registry, username, secret, createdAt, legacyTS}}}
		if writeCanonical {
			stmts = append(stmts, Statement{SQL: registryCanonicalUpsertSQL,
				Params: []interface{}{detID, scope, owner, registry, username, secret, createdAt, legacyTS}})
		}
		applied, err := c.ExecuteBatchGuarded(ctx,
			func(tx *sql.Tx) (bool, error) {
				// The legacy row must still be live at the expected updated_at ...
				var n int
				if e := tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM registry_credentials WHERE id=? AND updated_at=? AND deleted_at IS NULL", legacyID, legacyTS).Scan(&n); e != nil {
					return false, e
				}
				if n != 1 {
					return false, nil
				}
				// ... and the canonical row unchanged since the pre-read (so writeCanonical is valid).
				var cu sql.NullString
				e := tx.QueryRowContext(ctx, "SELECT updated_at FROM registry_credentials WHERE id=?", detID).Scan(&cu)
				if errors.Is(e, sql.ErrNoRows) {
					return detTS == "", nil
				}
				if e != nil {
					return false, e
				}
				return cu.String == detTS, nil
			},
			stmts)
		if err != nil {
			return false, err
		}
		if applied {
			return true, nil
		}
		// declined (raced) ⇒ retry from a fresh read
	}
	return false, nil // gave up after retries; the idempotent next run picks it up
}

// RegistryWriterReady reports whether NO legacy (non-canonical) LIVE row remains locally — the
// precondition for switching the WRITER to canonical (a legacy live row would collide with a
// canonical write on the partial UNIQUE). It ignores tombstones (a soft-deleted legacy row is inert
// under the partial index).
func RegistryWriterReady(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx,
		`SELECT id, scope, owner, registry FROM registry_credentials WHERE deleted_at IS NULL`)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if row.String("id") != RegistryCredentialID(row.String("scope"), row.String("owner"), row.String("registry")) {
			return false, nil
		}
	}
	return true, nil
}

// RegistryContractReady reports whether NO non-canonical PHYSICAL row remains locally — live OR
// tombstoned. This is the precondition for the CONTRACT (replacing the partial UNIQUE with a
// non-partial UNIQUE(scope,owner,registry)): the non-partial index would reject the leftover legacy
// tombstones, so they must first be reclaimed by the watermark-safe GC. Strictly stronger than
// RegistryWriterReady. The cross-node component (peer barriers, no legacy shape in any mutation/relay
// log, AE convergence) is evaluated by the daemon-level contract orchestrator.
func RegistryContractReady(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx, `SELECT id, scope, owner, registry FROM registry_credentials`)
	if err != nil {
		return false, err
	}
	for _, row := range rows {
		if row.String("id") != RegistryCredentialID(row.String("scope"), row.String("owner"), row.String("registry")) {
			return false, nil
		}
	}
	return true, nil
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
