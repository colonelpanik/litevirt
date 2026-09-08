package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// leaseUpsertSQL takes or renews a leader lease.
//
// The expiry compare uses the bound RFC3339 `now`, NOT datetime('now'):
// expires_at is stored RFC3339 ("…T…Z") and datetime('now') yields
// space-separated text, so a string compare breaks once the date matches
// ('T' > ' ') — a same-day lease NEVER looked expired, so a dead leader's lease
// could not transfer and failover stalled cluster-wide until the UTC date rolled
// over. All three original call sites carried their own copy of that fix and
// their own comment about it, which is what triplicated code looks like just
// before it diverges.
//
// The key is a BOUND parameter. The failover coordinator's copy used a literal
// ('failover'), giving it a different registered statement shape from the other
// two; one bound form means one shape for all three consumers.
const leaseUpsertSQL = `INSERT INTO leader_election (key, holder, expires_at, updated_at)
	 VALUES (?, ?, ?, ?)
	 ON CONFLICT(key) DO UPDATE
	   SET holder = excluded.holder,
	       expires_at = excluded.expires_at,
	       updated_at = excluded.updated_at
	   WHERE leader_election.expires_at < ?
	      OR leader_election.holder = excluded.holder`

// maxLeaseTermAttempts bounds the acquisition retry. A retry happens only when
// the guard declines because another claimant took the allocated term between
// the allocation read and the transaction — genuine contention, which resolves
// in one or two rounds. An unbounded loop here would spin a failover cycle.
const maxLeaseTermAttempts = 3

// AcquireLeaseWithTerm takes or renews the leader lease for key and returns the
// caller's fencing term.
//
// It replaces three copy-pasted implementations (grpcapi/dualrun.go,
// failover/coordinator.go, scheduler/rebalancer.go) that ran the identical
// guarded upsert and read-back. They are merged because a term acquired by one
// path and checked by another must come from the same code.
//
// held=false always comes with term 0. A term is only meaningful to its holder,
// and handing one to a loser invites it to be used.
func AcquireLeaseWithTerm(ctx context.Context, c *Client, key, holder string, ttl time.Duration, now time.Time) (bool, int64, error) {
	nowRFC := now.UTC().Format(time.RFC3339)
	expires := now.Add(ttl).UTC().Format(time.RFC3339)

	// The prior holder is read BEFORE any write, because it is the only thing
	// that distinguishes a renewal from an acquisition — and it cannot be
	// recovered afterwards. Both arms of the upsert's
	// `WHERE expires_at < ? OR holder = excluded.holder` affect exactly one row,
	// so rows-affected cannot tell them apart, and the upsert has already
	// overwritten the previous value.
	//
	// This must NOT be inferred from the term ledger instead. A displaced holder
	// whose own term is below the cluster maximum looks identical to a
	// re-acquiring one, and treating it as an acquisition would let it mint a
	// FRESH HIGHER term — promoting a stale leader above the legitimate holder,
	// which is worse than the problem this design fixes.
	prior, err := leaseHolder(ctx, c, key)
	if err != nil {
		return false, 0, err
	}

	if prior == holder {
		held, term, err := renewLeaseWithTerm(ctx, c, key, holder, expires, nowRFC)
		if err != nil {
			return false, 0, err
		}
		if held && term > 0 {
			return true, term, nil
		}
		if !held {
			return false, 0, nil
		}
		// Held with no term recorded. Fall through and acquire properly. This is
		// not an error path: it is the ordinary state after a rolling upgrade
		// from a binary with no term ledger, where the node restarts still
		// holding its lease. Nothing failed, so no write atomicity covers it.
	}

	return acquireLeaseWithTerm(ctx, c, key, holder, expires, nowRFC, now)
}

// renewLeaseWithTerm extends a lease this node already holds. It mints nothing:
// a renewal that bumped the term would make the holder invalidate its own
// in-flight work every renewal interval.
//
// COVERAGE NOTE, stated rather than implied. Two defensive branches in this file
// are RACE-ONLY and are not covered by the test suite:
//
//   - the `cur != holder` loss check below. Reaching it needs the lease to move
//     between AcquireLeaseWithTerm's pre-read and this read-back; a test that
//     moves the lease first takes the acquisition path instead.
//   - the guard's termSlotFreeTx check in acquireLeaseWithTerm. nextLeaseTerm
//     returns MAX+1 over every retained term, so the slot it allocates is free
//     by construction — it can only be occupied by a write landing between that
//     read and the guarded transaction.
//
// Both are correct and cheap, and the concurrent tests may hit them, but neither
// is deterministically reachable without a hook between two statements. Mutating
// either one leaves the suite green. That is a real gap, not a claim of
// coverage; closing it would need a test seam in the client.
func renewLeaseWithTerm(ctx context.Context, c *Client, key, holder, expires, nowRFC string) (bool, int64, error) {
	if err := c.Execute(ctx, leaseUpsertSQL,
		key, holder, expires, nowRFC, nowRFC); err != nil {
		return false, 0, fmt.Errorf("renew lease for %q: %w", key, err)
	}
	cur, err := leaseHolder(ctx, c, key)
	if err != nil {
		return false, 0, err
	}
	if cur != holder {
		return false, 0, nil
	}
	// This holder's OWN term, never MAX(term). A peer's higher term may have
	// arrived while we still hold the local leader_election row, and adopting it
	// here would hand a stale leader a term it never acquired.
	term, err := OwnLeaseTerm(ctx, c, key, holder)
	if err != nil {
		return false, 0, err
	}
	return true, term, nil
}

// acquireLeaseWithTerm takes a lease and records a new incarnation ATOMICALLY.
//
// The two writes share one transaction via ExecuteBatchGuarded, whose guard runs
// inside that transaction against a consistent snapshot. Without atomicity a
// crash between them leaves the durable state as holder-recorded-with-no-term,
// and the next call classifies that as a renewal.
//
// The guard checks BOTH preconditions, which is why this cannot be done in SQL:
// a replicated INSERT must be `INSERT ... VALUES` (an `INSERT ... SELECT ... WHERE`
// is refused with `expected "VALUES", got "SELECT"`), so the term-slot check has
// nowhere to live in the statement. And dropping the check is worse than having
// no atomicity: losing the race while still minting leaves an orphan term row
// that raises MAX(term) above the real holder's own term, actively fencing the
// legitimate leader.
//
// No MutationGuard is needed for peers. Its fields are workload/operation
// protocol specific (Protocol, ResourceKind, OperationID, OwnerEpoch,
// SpecGeneration…) and cannot express a lease precondition — but they do not
// need to. The guard governs whether THIS node writes; the replicated row is an
// append-only historical assertion ("this holder claimed term N"), not a
// mutation of shared current state, and a receiver applies it as INSERT OR
// IGNORE because leader_lease_terms is registered append-only. A peer's own
// leader_election is irrelevant to recording that fact.
func acquireLeaseWithTerm(ctx context.Context, c *Client, key, holder, expires, nowRFC string, now time.Time) (bool, int64, error) {
	ts := now.UTC().Format(time.RFC3339)

	for attempt := 0; attempt < maxLeaseTermAttempts; attempt++ {
		next, err := nextLeaseTerm(ctx, c, key)
		if err != nil {
			return false, 0, err
		}

		applied, err := c.ExecuteBatchGuarded(ctx,
			func(tx *sql.Tx) (bool, error) {
				free, gerr := leaseTakeableTx(ctx, tx, key, holder, nowRFC)
				if gerr != nil || !free {
					return false, gerr
				}
				return termSlotFreeTx(ctx, tx, key, next)
			},
			[]Statement{
				{SQL: leaseUpsertSQL, Params: []interface{}{key, holder, expires, nowRFC, nowRFC}},
				{SQL: mintLeaseTermSQL, Params: []interface{}{key, next, holder, ts, ts, ts}},
			})
		if err != nil {
			return false, 0, fmt.Errorf("acquire lease %q with term: %w", key, err)
		}
		if applied {
			// The guard held the client lock across the whole transaction and
			// confirmed the slot was free, so the mint cannot have been dropped.
			return true, next, nil
		}

		// Declined. Distinguish "someone else holds the lease" — terminal — from
		// "the term I allocated was taken" — retryable with a fresh allocation.
		cur, err := leaseHolder(ctx, c, key)
		if err != nil {
			return false, 0, err
		}
		if cur != "" && cur != holder {
			return false, 0, nil
		}
	}
	return false, 0, fmt.Errorf("acquire lease %q: term contention did not settle in %d attempts",
		key, maxLeaseTermAttempts)
}

// leaseHolder is the current holder of key, "" when the lease row is absent.
func leaseHolder(ctx context.Context, c *Client, key string) (string, error) {
	rows, err := c.Query(ctx, `SELECT holder FROM leader_election WHERE key = ?`, key)
	if err != nil {
		return "", fmt.Errorf("read lease holder for %q: %w", key, err)
	}
	if len(rows) == 0 {
		return "", nil
	}
	return rows[0].String("holder"), nil
}

// leaseTakeableTx reports whether key's lease can be taken or renewed by holder,
// evaluated inside the caller's transaction. It mirrors leaseUpsertSQL's WHERE
// exactly — absent, expired, or already ours — so the guard and the statement
// cannot disagree about who may write.
func leaseTakeableTx(ctx context.Context, tx *sql.Tx, key, holder, nowRFC string) (bool, error) {
	var curHolder, expiresAt string
	err := tx.QueryRowContext(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, key).Scan(&curHolder, &expiresAt)
	if err == sql.ErrNoRows {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return expiresAt < nowRFC || curHolder == holder, nil
}

// termSlotFreeTx reports whether (key, term) is unclaimed, evaluated inside the
// caller's transaction. Tombstoned rows count as claimed: a term number is never
// reused, so an INSERT OR IGNORE against a tombstone would be silently dropped.
func termSlotFreeTx(ctx context.Context, tx *sql.Tx, key string, term int64) (bool, error) {
	var n int
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM leader_lease_terms WHERE key = ? AND term = ?`, key, term).Scan(&n); err != nil {
		return false, err
	}
	return n == 0, nil
}
