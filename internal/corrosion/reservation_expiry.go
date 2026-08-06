package corrosion

import (
	"context"
	"time"
)

// CapacityResourceKind marks an operation that exists ONLY to hold a provisional
// admission reservation (reserve-then-verify), as opposed to one backing a real
// persisted spec or runtime change.
//
// The distinction is what makes expiry safe. These leases live for the duration of
// a single RPC — seconds — so anything materially older is orphaned. A resize or
// migration operation, by contrast, legitimately stays nonterminal for a long time
// and MUST never be expired: its reservation is backed by a spec that has already
// been committed, and freeing it would let the cluster admit capacity that is
// genuinely spoken for.
const CapacityResourceKind = "capacity"

// TransferCapacityLeaseMaxAge bounds a capacity lease held ACROSS A TRANSFER:
// the destination-held (or local-target) admission lease of MigrateVM,
// MigrateContainer, and DrainHost, which legitimately stays nonterminal for as
// long as the data takes to move. A --with-storage migration of a large disk
// routinely outlives the RPC-scoped TTL, and cancelling its lease mid-flight
// releases headroom the incoming workload is about to consume — a concurrent
// create is then admitted against memory already spoken for, the exact
// overpack the lease exists to prevent. The trade is deliberate: a transfer
// lease leaked by a crashed source strands capacity until THIS ceiling
// collects it, bounded and fail-closed, instead of a live transfer being
// silently overpacked. Sized for multi-terabyte storage copies on modest
// links.
const TransferCapacityLeaseMaxAge = 6 * time.Hour

// transferLeaseMethods are the originating RPCs whose capacity leases span a
// whole data transfer rather than one admission RPC.
var transferLeaseMethods = map[string]bool{
	"MigrateVM":        true,
	"MigrateContainer": true,
	"DrainHost":        true,
}

// ExpireStaleCapacityReservations cancels admission leases older than maxAge.
//
// Reserve-then-verify made a crash between "reserve" and "release" leak capacity
// permanently: the reaper only tombstones TERMINAL operations, and an abandoned
// lease never becomes terminal, so it consumed headroom forever with no workload
// behind it. That failure mode did not exist before create began reserving, which
// is exactly why it needs closing alongside it.
//
// Deliberately scoped to resource_kind='capacity'. A blanket "cancel old
// nonterminal operations" sweep would eventually cancel a legitimately long resize
// or migration and free capacity that IS backed by a persisted spec — the precise
// thing the F2 item warns expiry must never do.
//
// Local-deterministic and idempotent: appending a terminal step converges under the
// same immutable-merge discipline as the terminal reaper, so every node may run it.
func ExpireStaleCapacityReservations(ctx context.Context, c *Client, maxAge time.Duration) (int, error) {
	now := time.Now()
	cutoff := now.Add(-maxAge).UTC().Format(time.RFC3339)
	// Transfer-method leases (see transferLeaseMethods) age against the
	// transfer ceiling instead: they legitimately span the whole data move.
	transferCutoff := now.Add(-TransferCapacityLeaseMaxAge).UTC().Format(time.RFC3339)

	rows, err := c.Query(ctx,
		`SELECT id, operation_kind, method, created_at FROM operations
		  WHERE deleted_at IS NULL
		    AND resource_kind = ?
		    AND reservation_json != ''
		    AND created_at < ?`,
		CapacityResourceKind, cutoff)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}

	steps, err := c.Query(ctx, `SELECT operation_id, step_name FROM operation_steps WHERE deleted_at IS NULL`)
	if err != nil {
		return 0, err
	}
	byOp := make(map[string][]string, len(rows))
	for _, r := range steps {
		id := r.String("operation_id")
		byOp[id] = append(byOp[id], r.String("step_name"))
	}

	expired := 0
	for _, r := range rows {
		id := r.String("id")
		if transferLeaseMethods[r.String("method")] && r.String("created_at") >= transferCutoff {
			continue // an in-flight transfer's lease — not orphaned, just long
		}
		state, _ := ReduceOperationState(OperationKind(r.String("operation_kind")), byOp[id])
		if IsOperationTerminal(state) {
			continue // already released
		}
		if err := AppendOperationStep(ctx, c, OperationStepRecord{
			OperationID: id, StepName: OpStepCancelled, Facts: "capacity lease expired",
		}); err != nil {
			return expired, err
		}
		expired++
	}
	return expired, nil
}
