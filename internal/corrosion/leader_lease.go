package corrosion

import (
	"context"
	"fmt"
)

// LeaseKeyFailover is the failover coordinator's lease key. It lives here, not
// in internal/failover, because an enforcement path in internal/grpcapi must ask
// about the SAME key the coordinator acquires — and a second copy of the string
// in a second package is a divergence nothing would catch: the executor would
// check a ledger the coordinator never writes and pass every proof.
const LeaseKeyFailover = "failover"

// The other two lease keys, here for the same reason: an enforcement or
// diagnostic path outside their packages must ask about the SAME key its
// consumer acquires, and a second copy of the string in a second package is a
// divergence nothing would catch.
const (
	LeaseKeyRebalancer = "rebalancer"
	LeaseKeyDualRun    = "dual_run_detector"
)

// leaseKeys is the closed set of real lease keys.
var leaseKeys = map[string]bool{
	LeaseKeyFailover:   true,
	LeaseKeyRebalancer: true,
	LeaseKeyDualRun:    true,
}

// ValidLeaseKey reports whether key names one of the three real leases.
//
// EXACT match only — no trimming, no case folding. A near-miss is a bug or an
// attack and normalising it would hide both. An unknown key must never be
// treated as valid: a reader would find an empty ledger for it, MAX(term) = 0,
// and conclude that anything naming it is current.
func ValidLeaseKey(key string) bool { return leaseKeys[key] }

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
// A plain INSERT, not INSERT OR IGNORE. The receiver applies it as OR IGNORE
// anyway (leader_lease_terms is in customMergeTables, and the WAL branch for a
// custom-merge INSERT calls setInsertOrIgnore), so writing OR IGNORE here bought
// nothing on the receive side and cost the LOCAL writer its error: OR IGNORE
// skips rows violating NOT NULL and CHECK exactly as it skips a PK conflict, so
// a malformed row was dropped with a nil error. Locally the term slot is already
// proven free inside the guard, so a conflict here is a bug that should surface.
//
// NOTE on column sources: updated_at is the LWW conflict key and MUST come from
// Client.NowTS() (monotonic, persisted, HLC-ready); acquired_at and created_at
// are wall-clock facts about the tenure and come from the caller's clock, which
// is what keeps the fleet harness's virtual time working. They must not share a
// source — see the same warning on audit_heads.go's epoch insert.
const mintLeaseTermSQL = `INSERT INTO leader_lease_terms
	   (key, term, holder, acquired_at, created_at, updated_at)
	 VALUES (?, ?, ?, ?, ?, ?)`

// mintLeaseTermStmt builds the mint as a Statement so the WAL apply path can be
// driven with the SAME shape the writer emits — a test that hand-rolled
// equivalent SQL would exercise a shape the cluster never sends.
func mintLeaseTermStmt(key string, term int64, holder, acquiredAt, updatedAt string) Statement {
	return Statement{
		SQL:    mintLeaseTermSQL,
		Params: []interface{}{key, term, holder, acquiredAt, acquiredAt, updatedAt},
	}
}

// leaseTerm is one incarnation record: which holder claimed a given term.
type leaseTerm struct {
	Term   int64
	Holder string
}

// newestLeaseTerm is the highest LIVE term recorded for key, together with the
// holder that claimed it. Term 0 with an empty holder means no term exists.
//
// This — not "the highest term this holder ever recorded" — is how a caller
// learns whether it still owns the current incarnation. An earlier version asked
// for MAX(term) WHERE holder = ?, which excluded other nodes' terms but NOT this
// node's terms from incarnations it no longer holds: a host that had once held
// term 6 got 6 back on a tenure it acquired as term 1, and a reimaged host
// reusing a hostname inherited its predecessor's highest term. Reading the
// newest row and checking WHOSE it is answers the actual question.
func newestLeaseTerm(ctx context.Context, c *Client, key string) (leaseTerm, error) {
	rows, err := c.Query(ctx,
		`SELECT term, holder FROM leader_lease_terms
		 WHERE key = ? AND deleted_at IS NULL
		 ORDER BY term DESC LIMIT 1`, key)
	if err != nil {
		return leaseTerm{}, fmt.Errorf("read newest lease term for %q: %w", key, err)
	}
	if len(rows) == 0 {
		return leaseTerm{}, nil
	}
	return leaseTerm{Term: rows[0].Int64("term"), Holder: rows[0].String("holder")}, nil
}

// nextLeaseTerm is the term a new incarnation should claim: one above every
// retained term for this key, TOMBSTONES INCLUDED.
//
// The asymmetry with the live-only reads above is deliberate and was a bug when
// it was absent. Allocating from a tombstone-filtered maximum meant a tombstoned
// term left a GAP that allocation walked straight into: with term 1 live and
// term 2 tombstoned, the next term computed as 2 and collided forever.
//
// DO NOT ADD GC FOR THIS TABLE without reading both constraints. Term rows are
// retained indefinitely by design, and that is load-bearing twice over:
//
//  1. Retention is what stops a term number being reused. This function
//     allocates above every retained row precisely so a deleted term cannot be
//     handed out again to a different incarnation. leader_lease_terms is in
//     reseedKeepTables for the same reason — a reseed would otherwise regress
//     MAX(term) to whatever the source peer happened to have.
//  2. A GC horizon would have to sit above the highest term any node might still
//     present in a proof, which is not locally knowable.
//
// (Tombstone dominance itself is no longer part of this argument: the custom
// merge runs tombstoneDominates first on both replication paths, so a tombstone
// can no longer be overwritten by a peer's older live copy.)
func nextLeaseTerm(ctx context.Context, c *Client, key string) (int64, error) {
	rows, err := c.Query(ctx,
		`SELECT COALESCE(MAX(term), 0) AS max_term FROM leader_lease_terms WHERE key = ?`, key)
	if err != nil {
		return 0, fmt.Errorf("allocate lease term for %q: %w", key, err)
	}
	if len(rows) == 0 {
		return 1, nil
	}
	return rows[0].Int64("max_term") + 1, nil
}

// CurrentLeaseTerm is the highest term any node has minted for key — the
// REJECTION THRESHOLD a Phase-2 enforcement path compares against.
//
// It must never be used as a holder's own token; see newestLeaseTerm.
func CurrentLeaseTerm(ctx context.Context, c *Client, key string) (int64, error) {
	t, err := newestLeaseTerm(ctx, c, key)
	if err != nil {
		return 0, err
	}
	return t.Term, nil
}

// LeaseTermHolder returns the holder recorded for (key, term), and whether such
// a LIVE row exists on this node.
//
// found=false means "this node has not seen that term". It is NOT evidence the
// term is unheld, and a caller must never read it that way: leader_lease_terms
// replicates independently of the direct RPC that carries a proof, so a fresh,
// entirely valid proof routinely arrives before its own term row does. An
// enforcement path is safe to proceed on found=false only because a quorum
// threshold check already ran; on its own this answer authorizes nothing.
//
// Tombstones are excluded, matching newestLeaseTerm: a deleted incarnation is
// not a tenure anyone holds. nextLeaseTerm's inclusion of tombstones is about
// ALLOCATION never reusing a number and does not apply to this read.
//
// READ err FIRST. err != nil means the answer is UNKNOWN, and found is
// MEANINGLESS then — not false-meaning-unseen. The two are otherwise
// indistinguishable, because a query failure and a genuinely unseen term both
// return ("", false, ...), while the doc above tells an enforcement path that
// found == false is a normal answer it may proceed on. So an enforcement path
// must fail closed on an error and may proceed only on
// (found == false, err == nil). Written while this function still has no
// caller, which is the cheapest moment to fix a contract.
func LeaseTermHolder(ctx context.Context, c *Client, key string, term int64) (string, bool, error) {
	rows, err := c.Query(ctx,
		`SELECT holder FROM leader_lease_terms
		  WHERE key = ? AND term = ? AND deleted_at IS NULL`, key, term)
	if err != nil {
		return "", false, fmt.Errorf("read lease term %d holder for %q: %w", term, key, err)
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	return rows[0].String("holder"), true, nil
}
