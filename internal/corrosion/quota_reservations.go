package corrosion

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

// Durable project-quota reservations.
//
// The reservation has to outlive the authority that granted it. An in-memory ledger
// did not: a lease handoff left the successor with nothing, so it re-admitted the same
// quota while the previous holder's in-flight request went on to commit. Point-in-time
// validation cannot close that — the validating RPC fails exactly when authority is
// being lost, and even a successful answer leaves a gap between the answer and the
// caller's durable write. So the reservation is a replicated row, and EVERY node's
// quota arithmetic counts it.
//
// That also removes the need for a commit fence in the first place: an in-flight
// request may commit safely, because its charge was never lost.
//
// Durability alone is NOT sufficient, and the earlier version of this comment hand-waved
// that away. A reservation that exists only on the granting node is invisible to a
// successor: once the lease expires, a successor whose replica lacks the row admits the
// same quota while the original request can still commit. "The lease TTL exceeds normal
// replication delivery" is a timing hope, not an argument.
//
// So admission does not succeed until the row has been REPLICATED — see
// Client.ReplicateReservationBarrier. Two obligations, both required:
//
//   - a QUORUM of voting peers must have it, so any node that can later win the lease
//     (winning requires quorum) necessarily has it too;
//   - the REQUESTING node must have it, so its local commit fence can see it instead of
//     racing replication and aborting a valid request.
//
// If either cannot be met the reservation is tombstoned and admission is REFUSED. Fail
// closed: an un-replicated charge is indistinguishable from no charge at all.

const (
	// QuotaReservationTTL bounds a caller that dies mid-request. Same bound the
	// in-memory version already had, so durability costs nothing here.
	QuotaReservationTTL = 15 * time.Minute
	// QuotaCommittedGraceTTL bounds a committed reservation whose workload never
	// becomes visible (the create failed after its durable write, or the workload was
	// deleted immediately).
	QuotaCommittedGraceTTL = 5 * time.Minute

	QuotaReservationPending   = "pending"
	QuotaReservationCommitted = "committed"
)

// QuotaReservation is one live reservation.
type QuotaReservation struct {
	ID       string
	Project  string
	Holder   string
	CPU      int
	MemMiB   int
	State    string
	Workload string
	Kind     string
	Host     string
	WantCPU  int
	WantMem  int
}

// SumLiveQuotaReservations totals the reservations still charged against a project.
//
// A 'pending' row counts unconditionally. A 'committed' row counts only while this
// node cannot yet SEE its workload at the size it was admitted for — that is the
// replication gap, and it is measured by direct observation of THAT workload, never by
// aggregate usage movement (any unrelated increase would otherwise retire it early).
//
// Expired rows are ignored here and swept separately, so a stuck reaper cannot freeze
// a project's quota.
func SumLiveQuotaReservations(ctx context.Context, c *Client, project string) (cpu, memMiB int, err error) {
	project = projectOrDefault(project)
	now := nowRFC3339()
	rows, err := c.Query(ctx,
		`SELECT id, holder, cpu, mem_mib, state, workload, kind, host, want_cpu, want_mem
		   FROM quota_reservations
		  WHERE project = ? AND deleted_at IS NULL AND expires_at > ?`, project, now)
	if err != nil {
		return 0, 0, err
	}
	for _, r := range rows {
		state := r.String("state")
		if state == QuotaReservationCommitted {
			obsCPU, obsMem, found, oerr := WorkloadQuotaContribution(ctx, c, project,
				r.String("kind"), r.String("host"), r.String("workload"))
			if oerr != nil {
				return 0, 0, oerr
			}
			// Already visible at (or above) the admitted size: committed usage now
			// accounts for it, so charging the reservation too would double-count.
			if found && obsCPU >= r.Int("want_cpu") && obsMem >= r.Int("want_mem") {
				continue
			}
		}
		cpu += r.Int("cpu")
		memMiB += r.Int("mem_mib")
	}
	return cpu, memMiB, nil
}

// ReserveProjectQuota atomically re-checks the project's quota and, if the grow fits,
// writes a durable reservation.
//
// The guard runs INSIDE the transaction that inserts the row, so check-then-reserve
// cannot interleave with another reservation on this node. applied=false means the
// grow did not fit (detail says which dimension); the caller must not proceed.
//
// This is not cluster-wide serialization on its own — the guard sees only the local
// replica — which is why admission is still routed to one leased authority. What the
// durable row adds is that the charge SURVIVES that authority changing.
func ReserveProjectQuota(ctx context.Context, c *Client, id, project, holder string, cpu, memMiB int) (applied bool, detail string, err error) {
	project = projectOrDefault(project)
	now, wall := c.NowTS(), nowRFC3339()
	expires := time.Now().UTC().Add(QuotaReservationTTL).Format(time.RFC3339)

	q, err := GetProjectQuota(ctx, c, project)
	if err != nil {
		return false, "", err
	}
	if q == nil {
		return false, "", nil // unbounded: caller treats this as "nothing to reserve"
	}

	guard := func(tx *sql.Tx) (bool, error) {
		// Committed usage, re-read inside the transaction.
		var usedCPU, usedMem int
		if qerr := tx.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(json_extract(spec,'$.cpu')),0),
			        COALESCE(SUM(json_extract(spec,'$.memory_mib')),0)
			   FROM vms WHERE project = ? AND deleted_at IS NULL`, project).Scan(&usedCPU, &usedMem); qerr != nil {
			return false, qerr
		}
		var ctCPU, ctMem int
		if qerr := tx.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(cpu_limit),0), COALESCE(SUM(memory_mib),0)
			   FROM containers WHERE project = ? AND deleted_at IS NULL`, project).Scan(&ctCPU, &ctMem); qerr != nil {
			return false, qerr
		}
		// Existing live reservations, applying the SAME retirement rule
		// SumLiveQuotaReservations does: a committed row whose workload is already
		// visible is redundant, because the usage sums above now include it. Counting
		// both would double-charge that workload and refuse legal requests until the
		// sweeper caught up, so the rule is expressed in SQL rather than skipped.
		var resCPU, resMem int
		if qerr := tx.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(r.cpu),0), COALESCE(SUM(r.mem_mib),0)
			   FROM quota_reservations r
			  WHERE r.project = ? AND r.deleted_at IS NULL AND r.expires_at > ?
			    AND NOT (
			      r.state = 'committed' AND (
			        -- r.kind is REQUIRED on each branch. Without it a VM named "web"
			        -- retires a still-owed CONTAINER reservation for "web" (and vice
			        -- versa), releasing quota before the container row replicates. This
			        -- mirrors WorkloadQuotaContribution, which keys on (kind, host, name)
			        -- for the same reason.
			        (r.kind = 'vm' AND EXISTS (SELECT 1 FROM vms v
			                 WHERE v.name = r.workload AND v.project = r.project
			                   AND v.deleted_at IS NULL
			                   AND COALESCE(json_extract(v.spec,'$.cpu'),0)        >= r.want_cpu
			                   AND COALESCE(json_extract(v.spec,'$.memory_mib'),0) >= r.want_mem))
			        OR (r.kind = 'container' AND EXISTS (SELECT 1 FROM containers ct
			                 WHERE ct.name = r.workload AND ct.host_name = r.host
			                   AND ct.project = r.project AND ct.deleted_at IS NULL
			                   AND COALESCE(ct.cpu_limit,0)  >= r.want_cpu
			                   AND COALESCE(ct.memory_mib,0) >= r.want_mem))
			      )
			    )`, project, wall).Scan(&resCPU, &resMem); qerr != nil {
			return false, qerr
		}
		if q.VCPULimit > 0 && usedCPU+ctCPU+resCPU+cpu > q.VCPULimit {
			detail = fmt.Sprintf("vCPU quota exceeded (used %d + reserved %d + new %d > limit %d)",
				usedCPU+ctCPU, resCPU, cpu, q.VCPULimit)
			return false, nil
		}
		if q.MemMiBLimit > 0 && usedMem+ctMem+resMem+memMiB > q.MemMiBLimit {
			detail = fmt.Sprintf("memory quota exceeded (used %d + reserved %d + new %d > limit %d)",
				usedMem+ctMem, resMem, memMiB, q.MemMiBLimit)
			return false, nil
		}
		return true, nil
	}

	stmts := []Statement{{
		SQL: `INSERT OR IGNORE INTO quota_reservations
		      (id, project, holder, cpu, mem_mib, state, workload, kind, host,
		       want_cpu, want_mem, expires_at, created_at, updated_at, deleted_at)
		      VALUES (?, ?, ?, ?, ?, 'pending', '', '', '', 0, 0, ?, ?, ?, NULL)`,
		Params: []interface{}{id, project, holder, cpu, memMiB, expires, wall, now},
	}}
	applied, err = c.ExecuteBatchGuarded(ctx, guard, stmts)
	return applied, detail, err
}

// CommitProjectQuotaReservation records that the reservation's workload was durably
// written, with the identity its charge is retired against. The row stays charged until
// this node observes that workload — which is what covers the replication gap, and what
// makes the charge safe to hand to a successor.
func CommitProjectQuotaReservation(ctx context.Context, c *Client, id, workload, kind, host string, wantCPU, wantMem int) error {
	return c.Execute(ctx,
		`UPDATE quota_reservations
		    SET state = ?, workload = ?, kind = ?, host = ?, want_cpu = ?, want_mem = ?,
		        expires_at = ?, updated_at = ?
		  WHERE id = ? AND deleted_at IS NULL`,
		QuotaReservationCommitted, workload, kind, host, wantCPU, wantMem,
		time.Now().UTC().Add(QuotaCommittedGraceTTL).Format(time.RFC3339), c.NowTS(), id)
}

// ReleaseProjectQuotaReservationRow tombstones a reservation whose operation did NOT
// commit. Releasing a committed one would drop a charge the project still owes.
func ReleaseProjectQuotaReservationRow(ctx context.Context, c *Client, id string) error {
	return c.Execute(ctx,
		`UPDATE quota_reservations SET deleted_at = ?, updated_at = ?
		  WHERE id = ? AND state = ? AND deleted_at IS NULL`,
		nowRFC3339(), c.NowTS(), id, QuotaReservationPending)
}

// SweepQuotaReservations tombstones reservations that are done with: committed ones
// whose workload is now visible (committed usage accounts for them), and any past
// their expiry.
//
// Idempotent and safe to run on any node — it only ever tombstones rows that are no
// longer charged, so two nodes sweeping concurrently cannot lose a live charge.
func SweepQuotaReservations(ctx context.Context, c *Client) error {
	now := nowRFC3339()
	rows, err := c.Query(ctx,
		`SELECT id, project, state, workload, kind, host, want_cpu, want_mem, expires_at
		   FROM quota_reservations WHERE deleted_at IS NULL`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		id := r.String("id")
		if r.String("expires_at") <= now {
			slog.Warn("quota reservation expired; sweeping",
				"id", id, "project", r.String("project"), "state", r.String("state"),
				"workload", r.String("workload"))
			if derr := c.Execute(ctx,
				`UPDATE quota_reservations SET deleted_at = ?, updated_at = ? WHERE id = ?`,
				now, c.NowTS(), id); derr != nil {
				return derr
			}
			continue
		}
		if r.String("state") != QuotaReservationCommitted {
			continue
		}
		obsCPU, obsMem, found, oerr := WorkloadQuotaContribution(ctx, c, r.String("project"),
			r.String("kind"), r.String("host"), r.String("workload"))
		if oerr != nil {
			return oerr
		}
		if found && obsCPU >= r.Int("want_cpu") && obsMem >= r.Int("want_mem") {
			// Committed usage now accounts for this workload, so the reservation is
			// redundant. Tombstone it or the project stays double-charged.
			if derr := c.Execute(ctx,
				`UPDATE quota_reservations SET deleted_at = ?, updated_at = ? WHERE id = ?`,
				now, c.NowTS(), id); derr != nil {
				return derr
			}
		}
	}
	return nil
}

// QuotaReservationLive reports whether a reservation row is still present and unexpired
// on THIS node's replica.
//
// This is the commit fence, and it is a LOCAL read on purpose. The previous fence asked
// the authority over the network and fell open when it could not answer — which is
// exactly when authority is being lost, so it was defeated in the only case it existed
// for. A durable row is visible here through replication, so no RPC is needed and a
// partition cannot defeat the check. The caller fails CLOSED on a read error.
func QuotaReservationLive(ctx context.Context, c *Client, id string) (bool, error) {
	if id == "" {
		return true, nil // nothing was reserved (unbounded project); nothing to confirm
	}
	rows, err := c.Query(ctx,
		`SELECT 1 AS ok FROM quota_reservations
		  WHERE id = ? AND deleted_at IS NULL AND expires_at > ?`, id, nowRFC3339())
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// ProjectsWithLiveQuotaReservations lists the projects a holder still has live
// reservations for. The authority renews its lease for exactly these: a charge can
// outlive one lease period, and an unrenewed lease would let a successor start serving
// while the original request is still running.
func ProjectsWithLiveQuotaReservations(ctx context.Context, c *Client, holder string) ([]string, error) {
	rows, err := c.Query(ctx,
		`SELECT DISTINCT project FROM quota_reservations
		  WHERE holder = ? AND deleted_at IS NULL AND expires_at > ?`, holder, nowRFC3339())
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.String("project"))
	}
	return out, nil
}

// ReservationBarrier is what a reservation must clear before admission may succeed.
// Implemented by the replicator; injected so corrosion does not depend on it directly.
type ReservationBarrier interface {
	ReplicateNowTo(ctx context.Context, peerName string) error
}

// ReplicateReservationBarrier makes a freshly-written reservation VISIBLE before its
// admission is allowed to succeed.
//
// requester is the node that asked for the reservation (empty when the holder is
// admitting for itself). It must receive the row so its own commit fence reads a present
// reservation instead of racing replication and aborting a valid request.
//
// A QUORUM of voting peers must also receive it. That is the property that makes
// handoff safe rather than hopeful: acquiring the lease requires quorum, so any node that
// can later become the authority is necessarily in some quorum that has this row. Without
// it a reservation could live only on the granting node, and a successor on the far side
// of a partition would admit the same quota.
//
// Returns an error when either obligation is unmet. The caller MUST then tombstone the
// reservation and refuse the admission — an un-replicated charge is indistinguishable
// from no charge.
func ReplicateReservationBarrier(ctx context.Context, c *Client, b ReservationBarrier, self, requester string) error {
	if b == nil {
		// No replicator wired (single-node, or a test harness sharing one store): there
		// are no peers to be invisible to.
		return nil
	}
	hosts, err := ListHosts(ctx, c)
	if err != nil {
		return fmt.Errorf("list hosts for the reservation barrier: %w", err)
	}
	// Voting peers = everything active except ourselves. Witnesses vote, so they count
	// toward a quorum that could later elect an authority, and they can hold the row.
	var voters []string
	for _, h := range hosts {
		if h.State != "active" || h.Name == self {
			continue
		}
		voters = append(voters, h.Name)
	}
	total := len(voters) + 1 // including ourselves, who already has the row
	need := total/2 + 1

	acked := 1 // self
	var lastErr error
	requesterOK := requester == "" || requester == self
	for _, peer := range voters {
		if perr := b.ReplicateNowTo(ctx, peer); perr != nil {
			lastErr = perr
			continue
		}
		acked++
		if peer == requester {
			requesterOK = true
		}
	}
	if !requesterOK {
		return fmt.Errorf("reservation not delivered to the requesting node %q: %v", requester, lastErr)
	}
	if acked < need {
		return fmt.Errorf("reservation reached %d/%d nodes, need %d for quorum: %v",
			acked, total, need, lastErr)
	}
	return nil
}
