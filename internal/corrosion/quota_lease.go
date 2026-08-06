package corrosion

import (
	"context"
	"strings"
	"time"
)

// Project-quota admission lease.
//
// Quota is a cluster-wide limit, so exactly one node may serialize a project's
// admissions. A DERIVED holder (rendezvous hash over the replicated host set) cannot
// deliver that: ListHosts is replicated asynchronously, so two nodes with different
// views compute different winners and both serve as authority. Nothing converges them
// while the views differ, and each admits against its own snapshot.
//
// So the holder is a LEASE — one replicated fact — taken with the same mechanism
// failover uses for "exactly one node decides": a conditional upsert that only wins
// on an expired lease (or a renewal by the current holder), followed by a READ-BACK
// to confirm we actually hold it. Peers route to the recorded holder rather than
// deriving their own answer, so once the row replicates every node agrees.
//
// Reuses leader_election rather than adding a table: it already is a per-key lease
// (keys "failover", "rebalancer", …), already replicates, and already has the merge
// behaviour and statement shapes this needs.
//
// HONEST LIMIT, same as every other lease here: this is not linearizable across a
// partition. Two nodes can both win their local conditional write before replication
// resolves it, and LWW then picks one — so a brief two-serializer window exists. It is
// bounded by the read-back plus TTL re-validation, and callers additionally gate on
// quorum so a minority side cannot acquire at all. That is the standard this codebase
// already holds its most safety-critical operation (fencing) to; quota is a soft
// tenancy limit, so it is proportionate here.

// quotaLeaseTTL is how long an acquired admission lease stays valid without renewal;
// QuotaLeaseRenewInterval is how often a holder with outstanding charges refreshes it.
//
// The TTL is SHORTER than the lifetime of the charges it protects, which is only safe
// because the holder actively renews. Without renewal the lease would lapse under a
// long-running create while its reservation was still outstanding, and the next node
// would acquire it with an EMPTY ledger and hand out quota that is still owed — the
// TTL would turn a rare handoff into a routine one. So: renew while anything is
// charged, and stop serving the moment renewal fails.
const (
	quotaLeaseTTL           = 30 * time.Second
	QuotaLeaseRenewInterval = 10 * time.Second
)

// QuotaLeaseKey is the leader_election key namespace for project-quota authority.
func QuotaLeaseKey(project string) string {
	return "quota-authority/" + projectOrDefault(project)
}

// ProjectFromQuotaLeaseKey is the inverse, for diagnostics.
func ProjectFromQuotaLeaseKey(key string) (string, bool) {
	const p = "quota-authority/"
	if !strings.HasPrefix(key, p) {
		return "", false
	}
	return strings.TrimPrefix(key, p), true
}

// AcquireProjectQuotaLease takes or renews the project's admission lease.
//
// held is true ONLY when the read-back confirms this holder — never merely because
// the write returned without error. The conditional upsert can legitimately no-op
// (someone else holds an unexpired lease), and treating that as success is exactly
// how two nodes would both believe they are the authority.
//
// currentHolder is who the lease says holds it after the attempt, so a loser can
// route there instead of guessing.
// AcquireProjectQuotaLease also reports prevHolder: whoever the lease row named
// IMMEDIATELY BEFORE this write.
//
// That is what distinguishes a fresh acquisition from a renewal, and a prefix on the
// holder name is not: if A reconciles, loses authority to B, and later reacquires, the
// name is still A, so a name-based check reads the takeover as a renewal and skips the
// drain — missing every reservation B granted. prevHolder != self means someone else (or
// nobody) held it in between, which is exactly the condition that invalidates a previous
// reconciliation.
//
// prevHolder == self across a LAPSE is safe to treat as continuation: another node could
// only have granted reservations by holding the lease, and holding it would have left its
// name here.
func AcquireProjectQuotaLease(ctx context.Context, c *Client, project, holder string) (held bool, currentHolder, prevHolder string, err error) {
	key := QuotaLeaseKey(project)
	// Read BEFORE the upsert. A missing row reports "" — also a takeover.
	if prev, perr := c.Query(ctx, `SELECT holder FROM leader_election WHERE key = ?`, key); perr == nil && len(prev) > 0 {
		prevHolder = prev[0].String("holder")
	}
	now := time.Now().UTC()
	nowRFC := now.Format(time.RFC3339)
	expiresAt := now.Add(quotaLeaseTTL).Format(time.RFC3339)

	// Both sides of the comparison are RFC3339. Using datetime('now') here would
	// break the string compare once the date digits align ('T' > ' '), so a lease
	// would never look expired — the same bug the failover lease carries a comment
	// about.
	if err := c.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at
		   WHERE leader_election.expires_at < ?
		      OR leader_election.holder = excluded.holder`,
		key, holder, expiresAt, nowRFC, nowRFC); err != nil {
		return false, "", prevHolder, err
	}

	cur, ok, err := ProjectQuotaLeaseHolder(ctx, c, project)
	if err != nil {
		return false, "", prevHolder, err
	}
	if !ok {
		return false, "", prevHolder, nil
	}
	return cur == holder, cur, prevHolder, nil
}

// ProjectQuotaLeaseHolder returns the current UNEXPIRED lease holder, if any. An
// expired lease reports ok=false: a holder that stopped renewing has stopped being
// the authority, and its projects must become servable again.
func ProjectQuotaLeaseHolder(ctx context.Context, c *Client, project string) (holder string, ok bool, err error) {
	rows, err := c.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, QuotaLeaseKey(project))
	if err != nil {
		return "", false, err
	}
	if len(rows) == 0 {
		return "", false, nil
	}
	h := rows[0].String("holder")
	exp := rows[0].String("expires_at")
	if h == "" || exp == "" {
		return "", false, nil
	}
	t, perr := time.Parse(time.RFC3339, exp)
	if perr != nil {
		// An unparseable expiry is not a licence to serve. Treat it as no lease.
		return "", false, nil
	}
	if !time.Now().UTC().Before(t) {
		return "", false, nil // expired
	}
	return h, true, nil
}
