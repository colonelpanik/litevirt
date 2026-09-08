package corrosion

import (
	"context"
	"fmt"
	"time"
)

// mintLeaseTermSQL records one lease incarnation.
//
// The term is a BOUND PARAMETER, computed by a separate read, rather than a
// subselect in the VALUES tuple. That is not a style choice: a subselect there is
// structurally invalid for replication —
//
//	stmtshapecheck: unsupported value sqlTok in INSERT VALUES: "("
//
// — so the obvious `VALUES (?, (SELECT COALESCE(MAX(term),0)+1 ...), ...)` never
// reaches a peer. audit_chain_heads has exactly this shape for exactly this
// reason: currentAuditEpoch runs its own SELECT MAX(epoch) and audit_heads.go
// binds the result.
//
// INSERT OR IGNORE absorbs the one conflict this can produce. Since the term is
// read then bound, two goroutines on the SAME node can read the same MAX and
// compute the same term (rebalancer.go: "two loops on the leader renewing
// concurrently is safe"). Same node, same holder, same term: the loser skipping
// silently is correct. A cross-node conflict is not this statement's problem —
// two partitioned nodes minting one term is the two-leaders case, resolved by the
// append-only registration and the content chain.
const mintLeaseTermSQL = `INSERT OR IGNORE INTO leader_lease_terms
	   (key, term, holder, acquired_at, created_at, updated_at)
	 VALUES (?, ?, ?, ?, ?, ?)`

// mintLeaseTermStmt builds the mint as a Statement so the WAL apply path can be
// driven with the SAME shape the writer emits — a test that hand-rolled
// equivalent SQL would exercise a shape the cluster never sends.
//
// It deliberately does NOT call Execute: it is not an emitter, and the writer
// above passes mintLeaseTermSQL directly for the reason noted there.
func mintLeaseTermStmt(key string, term int64, holder, ts string) Statement {
	return Statement{
		SQL:    mintLeaseTermSQL,
		Params: []interface{}{key, term, holder, ts, ts, ts},
	}
}

// MintLeaseTerm records a NEW lease incarnation for key, held by holder, and
// returns its term.
//
// Call it only on an ACQUISITION, never on a renewal. A renewal that minted would
// make the number useless as a fencing token, because the holder would invalidate
// its own in-flight work every renewal interval.
//
// Terms start at 1. Term 0 is the column default, so it must stay distinguishable
// from a real acquisition — otherwise a row written by a binary that knows
// nothing of terms reads as a legitimate term 0 and passes any threshold check.
//
// It CAN return 0 with no error, and a caller must handle that as "no term
// recorded" rather than as success. CurrentLeaseTerm skips tombstoned rows, so a
// tombstoned term leaves a gap: with term 1 live and term 2 tombstoned, the
// threshold reads 1, this computes 2, and the INSERT collides with the
// tombstoned row and is dropped by OR IGNORE. The read-back then correctly
// reports that this holder owns nothing. That is why the read-back is
// OwnLeaseTerm and not CurrentLeaseTerm: the latter would hand back term 1,
// which belongs to another node.
func MintLeaseTerm(ctx context.Context, c *Client, key, holder string, now time.Time) (int64, error) {
	cur, err := CurrentLeaseTerm(ctx, c, key)
	if err != nil {
		return 0, err
	}
	ts := now.UTC().Format(time.RFC3339)
	// The SQL constant is passed DIRECTLY, not via a Statement field.
	// stmtshapecheck resolves a replicated statement's SQL statically and rejects
	// `c.Execute(ctx, stmt.SQL, stmt.Params...)` as "dynamically-built replicated
	// SQL", because it cannot see through the struct field to a fixed shape.
	if err := c.Execute(ctx, mintLeaseTermSQL,
		key, cur+1, holder, ts, ts, ts); err != nil {
		return 0, fmt.Errorf("mint lease term for %q: %w", key, err)
	}
	// Read back this HOLDER's own highest term, not MAX(term): a peer's higher
	// term may have arrived between the write and this read, and adopting it here
	// would be the escalation OwnLeaseTerm exists to prevent.
	return OwnLeaseTerm(ctx, c, key, holder)
}

// CurrentLeaseTerm is the highest term any node has minted for key — the
// REJECTION THRESHOLD.
//
// This is the only thing MAX(term) may be used for. It must never become a
// holder's own token; see OwnLeaseTerm.
func CurrentLeaseTerm(ctx context.Context, c *Client, key string) (int64, error) {
	rows, err := c.Query(ctx,
		`SELECT COALESCE(MAX(term), 0) AS max_term FROM leader_lease_terms
		 WHERE key = ? AND deleted_at IS NULL`, key)
	if err != nil {
		return 0, fmt.Errorf("read current lease term for %q: %w", key, err)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int64("max_term"), nil
}

// OwnLeaseTerm is the highest term THIS holder has minted for key — the token a
// renewal returns.
//
// Deliberately distinct from CurrentLeaseTerm, and the distinction is a security
// boundary rather than a naming preference. leader_lease_terms and
// leader_election replicate independently, so a displaced holder A can receive
// winner B's higher term row while A's leader_election row still names A. Because
// holdLease renews by calling acquireLease (coordinator.go), renewal and
// acquisition are the same code path, so that window is reached on the ordinary
// renewal tick. A renewal reading MAX(term) there would hand A a term it never
// acquired, letting it stamp work that passes the stale-term check.
//
// Reading from the ledger rather than process state also means the term survives
// a restart with no extra bookkeeping: a coordinator that comes back still
// holding the lease recovers its own term, and one that re-acquires mints a new
// higher one.
func OwnLeaseTerm(ctx context.Context, c *Client, key, holder string) (int64, error) {
	rows, err := c.Query(ctx,
		`SELECT COALESCE(MAX(term), 0) AS max_term FROM leader_lease_terms
		 WHERE key = ? AND holder = ? AND deleted_at IS NULL`, key, holder)
	if err != nil {
		return 0, fmt.Errorf("read own lease term for %q/%q: %w", key, holder, err)
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int64("max_term"), nil
}
