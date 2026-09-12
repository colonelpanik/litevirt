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
//
// updated_at is bound separately from the expiry-compare `now` because it is the
// LWW conflict key and comes from Client.NowTS(); see mintLeaseTermSQL.
const leaseUpsertSQL = `INSERT INTO leader_election (key, holder, expires_at, updated_at)
	 VALUES (?, ?, ?, ?)
	 ON CONFLICT(key) DO UPDATE
	   SET holder = excluded.holder,
	       expires_at = excluded.expires_at,
	       updated_at = excluded.updated_at
	   WHERE leader_election.expires_at < ?
	      OR leader_election.holder = excluded.holder`

// maxLeaseAttempts bounds the classify-then-commit loop. An iteration is spent
// only when the state changed under us — another claimant took the lease or the
// term we allocated — which resolves in one or two rounds.
const maxLeaseAttempts = 3

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
//
// Contention is NOT an error. Every other ExecuteBatchGuarded caller returns
// applied=false when its guard declines, and the callers here map an error onto
// a paged store-error metric and onto aborting an in-progress fence as "lease
// lost" — so returning one for transient contention paged with a wrong cause and
// abandoned fences of genuinely dead hosts. Exhausting the attempts reports
// "not held", which is the same shape as losing the race and is what the callers
// already handle.
func AcquireLeaseWithTerm(ctx context.Context, c *Client, key, holder string, ttl time.Duration, now time.Time) (bool, int64, error) {
	nowRFC := now.UTC().Format(time.RFC3339)
	expires := now.Add(ttl).UTC().Format(time.RFC3339)

	for attempt := 0; attempt < maxLeaseAttempts; attempt++ {
		// Classification is re-derived on every iteration. It cannot be hoisted:
		// a declined guard means the state it described has changed, and the most
		// common change is a sibling caller on THIS node having just acquired the
		// lease — in which case this call is now a renewal, not a retryable
		// acquisition.
		curHolder, curExpires, err := leaseRow(ctx, c, key)
		if err != nil {
			return false, 0, err
		}

		// The ledger is not writable yet: hold the lease the pre-ledger way and
		// report no term. This is the mid-rolling-upgrade state — a peer on the
		// previous release cannot resolve the mint's statement shape, and an
		// unregistered shape back-pressures its entire replication stream — so the
		// mint waits for DurablyLatched(lease_term_ledger_v1). See
		// SetLeaseTermLedgerGate.
		//
		// This runs BEFORE any ledger classification, and that ordering is the
		// whole point. The classification below fails closed on a term belonging
		// to another holder, which is right when we can mint — it stops this node
		// promoting itself above the term race's winner — but a node that mints
		// NOTHING has no escalation to prevent, and refusing there returned
		// held=false while our own leader_election row still named us and still
		// blocked every peer's guarded upsert. The lease stopped being renewed and
		// could not transfer, so failover, rebalancing and dual-run detection all
		// stood down for most of every TTL, indefinitely, on a path whose contract
		// is that availability is unaffected.
		if !c.MayMintLeaseTerm() {
			return holdLeaseWithoutTerm(ctx, c, key, holder, expires, nowRFC, curHolder, curExpires)
		}

		newest, err := newestLeaseTerm(ctx, c, key)
		if err != nil {
			return false, 0, err
		}

		// Both sides are RFC3339 UTC, so a lexical compare is a time compare.
		// Expiry is consulted deliberately: holder identity alone does NOT prove
		// an uninterrupted tenure. A lease that fully lapsed — a GC pause, a
		// SIGSTOP, an IO stall longer than the TTL — and was then re-taken by its
		// own prior holder is a NEW tenure, because the lapse is exactly the
		// window in which other nodes were entitled to act. Treating it as a
		// renewal kept the old term and made work from before the lapse
		// indistinguishable from work after it.
		ourTenure := curHolder == holder && curExpires >= nowRFC

		if ourTenure {
			switch {
			case newest.Term > 0 && newest.Holder == holder:
				// Same tenure, term already recorded: renew, mint nothing. A
				// renewal that bumped the term would make the holder invalidate
				// its own in-flight work every renewal interval.
				held, err := renewLease(ctx, c, key, holder, expires, nowRFC)
				if err != nil {
					return false, 0, err
				}
				if !held {
					continue // lost it mid-renewal; re-classify rather than guess
				}
				return true, newest.Term, nil

			case newest.Term > 0 && newest.Holder != holder:
				// A peer's claim is newer than ours while our own
				// leader_election row still names us. FAIL CLOSED: return no
				// term rather than minting a fresh higher one.
				//
				// Minting here is the escalation this design exists to prevent —
				// it would promote whichever node lost the term race ABOVE the
				// winner, inverting fencing. leader_election is anti-entropy
				// excluded while leader_lease_terms is replicated, so this skew
				// is reachable in ordinary operation and must not be read as
				// "no term yet".
				return false, 0, nil
			}
			// newest.Term == 0: no term exists for this key at all. Fall through
			// and acquire one. This is the rolling-upgrade case — a node that
			// restarts still holding a lease minted by a binary with no term
			// ledger — and it is now provably ONLY that case: the custom merge
			// keeps the local row, so a peer can no longer overwrite our term,
			// and reseedKeepTables stops a reseed from deleting it.
		}

		held, term, err := takeLeaseAndMintTerm(ctx, c, key, holder, expires, nowRFC, now)
		if err != nil {
			return false, 0, err
		}
		if held {
			return true, term, nil
		}
		if term == leaseContended {
			continue // the term we allocated was taken; re-classify and retry
		}
		return false, 0, nil
	}
	// Contention never settled. Reported as "not held", never as an error.
	return false, 0, nil
}

// holdLeaseWithoutTerm is the entire lease path while the term ledger is not
// writable — the pre-ledger behaviour, reproduced exactly.
//
// The term is ALWAYS 0 here, including when this key's ledger already holds a
// row naming us. A term is a claim about one unbroken tenure, and only the mint
// re-establishes that correspondence: with the gate open, a lease that lapsed
// and was re-taken by its own prior holder classifies as a new tenure and mints
// a fresh term, so the ledger row and the tenure stay in step. A node that
// cannot mint cannot do that, so a surviving row says only "this node held some
// earlier tenure" — reporting its term would hand out the PRE-LAPSE number for
// work done after the lapse, which is the staleness AcquireLeaseWithTerm's
// expiry check exists to prevent. Withholding it costs nothing that is not
// already withheld: enforcement refuses on term 0 by design, and
// LeaseTermReadiness withholds lease_term_v1 for exactly this reason.
//
// A peer's live lease short-circuits before the upsert. The statement would be
// a zero-row no-op — its ON CONFLICT ... WHERE takes the row only when the
// lease is expired or already ours — but a no-op still writes a mutation_log
// row and wakes the replicator, because both write paths log the statements they
// were GIVEN rather than the ones that changed anything. Every non-holder
// polling three lease keys would then emit sustained replicated no-ops onto the
// stream this gate exists to keep quiet, for as long as the gate stays closed.
func holdLeaseWithoutTerm(ctx context.Context, c *Client, key, holder, expires, nowRFC, curHolder, curExpires string) (bool, int64, error) {
	if curHolder != "" && curHolder != holder && curExpires >= nowRFC {
		return false, 0, nil
	}
	held, err := renewLease(ctx, c, key, holder, expires, nowRFC)
	if err != nil {
		return false, 0, err
	}
	return held, 0, nil
}

// leaseContended is the sentinel takeLeaseAndMintTerm returns alongside
// held=false when the guard declined for a retryable reason (the allocated term
// slot was taken) rather than a terminal one (someone else holds the lease).
const leaseContended int64 = -1

// renewLease runs the guarded upsert alone — no term — and reports whether this
// node holds the lease afterwards.
//
// Named for its common caller, but the statement takes an EXPIRED lease from
// another holder just as it renews our own (see leaseUpsertSQL's WHERE), which
// is what makes it the whole pre-ledger acquisition path as well: it is what
// AcquireLeaseWithTerm falls back to while the term ledger is not yet writable.
func renewLease(ctx context.Context, c *Client, key, holder, expires, nowRFC string) (bool, error) {
	if err := c.Execute(ctx, leaseUpsertSQL,
		key, holder, expires, c.NowTS(), nowRFC); err != nil {
		return false, fmt.Errorf("renew lease for %q: %w", key, err)
	}
	cur, _, err := leaseRow(ctx, c, key)
	if err != nil {
		return false, err
	}
	return cur == holder, nil
}

// takeLeaseAndMintTerm takes a lease and records a new incarnation ATOMICALLY.
//
// The two writes share one transaction via ExecuteBatchGuarded, whose guard runs
// inside that transaction against a consistent snapshot. Without atomicity a
// crash between them leaves the durable state as holder-recorded-with-no-term,
// which the next call would classify as the rolling-upgrade self-heal.
//
// The guard checks all three preconditions, which is why this cannot be done in
// SQL: a replicated INSERT must be `INSERT ... VALUES` (an
// `INSERT ... SELECT ... WHERE` is refused with `expected "VALUES", got
// "SELECT"`), so the term checks have nowhere to live in the statement. And
// dropping them is worse than having no atomicity: losing the race while still
// minting leaves an orphan term row that raises MAX(term) above the real
// holder's own term, actively fencing the legitimate leader.
func takeLeaseAndMintTerm(ctx context.Context, c *Client, key, holder, expires, nowRFC string, now time.Time) (bool, int64, error) {
	acquiredAt := now.UTC().Format(time.RFC3339)

	next, err := nextLeaseTerm(ctx, c, key)
	if err != nil {
		return false, 0, err
	}

	applied, err := c.ExecuteBatchGuarded(ctx,
		func(tx *sql.Tx) (bool, error) {
			return leaseAcquirableTx(ctx, tx, key, holder, nowRFC, next)
		},
		[]Statement{
			{SQL: leaseUpsertSQL, Params: []interface{}{key, holder, expires, c.NowTS(), nowRFC}},
			// Built inline rather than via mintLeaseTermStmt so this function is
			// the statement's resolvable emitter: stmtshapecheck's reachability
			// guard refuses a registered shape whose builder it cannot tie to a
			// live caller, and routing the only production mint through a helper
			// hid it. mintLeaseTermStmt stays for the WAL-apply test, which needs
			// the same shape as a Statement value.
			{SQL: mintLeaseTermSQL, Params: []interface{}{key, next, holder, acquiredAt, acquiredAt, c.NowTS()}},
		})
	if err != nil {
		return false, 0, fmt.Errorf("acquire lease %q with term: %w", key, err)
	}
	if applied {
		// The guard held the client lock across the whole transaction and
		// confirmed both the lease and the term slot, so neither write was
		// dropped.
		return true, next, nil
	}

	// Declined. Distinguish "someone else holds the lease" — terminal — from
	// "the state moved under us" — retryable with a fresh classification.
	cur, _, err := leaseRow(ctx, c, key)
	if err != nil {
		return false, 0, err
	}
	if cur != "" && cur != holder {
		return false, 0, nil
	}
	return false, leaseContended, nil
}

// leaseRow reads key's current holder and expiry. holder is "" when the row is
// absent.
func leaseRow(ctx context.Context, c *Client, key string) (holder, expiresAt string, err error) {
	rows, err := c.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, key)
	if err != nil {
		return "", "", fmt.Errorf("read lease row for %q: %w", key, err)
	}
	if len(rows) == 0 {
		return "", "", nil
	}
	return rows[0].String("holder"), rows[0].String("expires_at"), nil
}

// leaseAcquirableTx is the ACQUISITION precondition, evaluated as a whole inside
// the caller's transaction. All of it has to be one guard: each clause below
// closes a hole that checking the others alone left open.
//
//  1. The lease must be takeable — absent, expired, or already ours. This
//     mirrors leaseUpsertSQL's WHERE exactly, so the guard and the statement
//     cannot disagree about who may write.
//
//  2. If it is already ours and still live, a term must NOT already exist for
//     this key. Without this clause a same-holder caller that should have
//     RENEWED instead minted: production runs three distinct *Rebalancer values
//     against one key (the proposing loop, the executor loop, and the
//     RunRebalance RPC), so several callers with the same holder race the first
//     acquisition and every takeover. One committed term 1; another, classified
//     from a read taken before that commit, found slot 2 free and minted it.
//     Two rows for one unbroken tenure, and the caller left holding the lower
//     term sits below the rejection threshold — fenced by its own ledger.
//     Re-classifying on retry is not enough on its own, because the losing
//     caller's guard has to REJECT before the retry can reclassify.
//
//  3. term must be above every retained term. nextLeaseTerm runs outside the
//     transaction, so a peer's replicated term N+5 can arrive in the window
//     between the allocation read and this transaction, leaving slot N+1 free
//     while the cluster's rejection threshold has moved to N+5. Checking only
//     that the SLOT was unclaimed let the legitimate new holder record a term
//     below that threshold — the same inversion as an orphan term, arriving on
//     the success path. Comparing against MAX rather than existence also covers
//     the slot check, since tombstoned rows keep their number reserved.
func leaseAcquirableTx(ctx context.Context, tx *sql.Tx, key, holder, nowRFC string, term int64) (bool, error) {
	var curHolder, expiresAt string
	err := tx.QueryRowContext(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, key).Scan(&curHolder, &expiresAt)
	switch {
	case err == sql.ErrNoRows:
		// Absent: acquirable.
	case err != nil:
		return false, err
	default:
		expired := expiresAt < nowRFC
		if !expired && curHolder != holder {
			return false, nil // someone else holds it
		}
		if !expired && curHolder == holder {
			// Our own live tenure. Only an acquisition if it has no term yet
			// (the rolling-upgrade self-heal).
			var n int
			if err := tx.QueryRowContext(ctx,
				`SELECT COUNT(*) FROM leader_lease_terms WHERE key = ? AND deleted_at IS NULL`,
				key).Scan(&n); err != nil {
				return false, err
			}
			if n > 0 {
				return false, nil // a term exists: this is a renewal, not an acquisition
			}
		}
	}

	var maxTerm int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(term), 0) FROM leader_lease_terms WHERE key = ?`, key).Scan(&maxTerm); err != nil {
		return false, err
	}
	return maxTerm < term, nil
}
