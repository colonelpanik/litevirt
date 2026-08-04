package corrosion

import (
	"context"
	"strings"
	"time"
)

// Delegated project-quota admission counting (F2 second half).
//
// Routing every project admission through one decider closes the race between two
// IN-FLIGHT reservations: the holder's own replica necessarily contains every grant
// it has made, so a second request cannot miss the first.
//
// It does NOT, by itself, close the window that opens once a grant is released. The
// winner commits its VM row on ITS node and only then releases the lease; the holder
// learns of that row when replication delivers it. Between those two moments the
// holder's committed-usage sum is short by exactly one admission — so a second
// request arriving in that gap sees quota that is already spent.
//
// So a released lease keeps counting until the resource it admitted is actually
// VISIBLE here. Each lease records what it was about to create, and the check is
// simply "can I see that row yet?" — if yes, committed usage already counts it and
// the lease must not be counted again; if no, the lease stands in for it.
//
// That self-cancelling condition matters more than it looks. A blind timer instead of
// a visibility check double-counts every admission for the length of the timer, which
// makes ordinary SEQUENTIAL creates on the holder fail — the first version of this did
// exactly that, and a fleet scenario caught it.
//
// The grace remains only as a BACKSTOP, for a lease whose resource never appears at
// all (the admission was granted but the create failed downstream). Those hold quota
// briefly and then stop.

// stampedStep is an operation step with the wall-clock time it was appended — the
// step reducer needs only names, but the settle grace needs to know how long ago a
// lease was released.
type stampedStep struct {
	name string
	at   string
}

// ProjectReservedSettling sums the project-quota reservation deltas this admission
// must yield to:
//
//   - NONTERMINAL reservations from operations sorting strictly BEFORE opID — earlier
//     claimants, exactly as ReservedBefore counts them (later ones yield to us, and
//     our own must not be subtracted from the headroom we compare against).
//   - CAPACITY leases that reached a terminal step within `grace` AND whose admitted
//     resource is not yet visible here, at ANY id — winners that are committing right
//     now. Id order is irrelevant for these: they are no longer racing us, they are a
//     decided fact this node cannot see yet.
//
// grace ≤ 0 disables the settle term, leaving pure earlier-claimant counting.
func ProjectReservedSettling(ctx context.Context, c *Client, project, opID string, grace time.Duration, now time.Time) (cpu, memMiB int, err error) {
	project = projectOrDefault(project)

	orows, err := c.Query(ctx,
		`SELECT id, operation_kind, resource_kind, resource_id, reservation_json FROM operations
		  WHERE deleted_at IS NULL AND reservation_json != ''`)
	if err != nil {
		return 0, 0, err
	}
	if len(orows) == 0 {
		return 0, 0, nil
	}

	srows, err := c.Query(ctx,
		`SELECT operation_id, step_name, created_at FROM operation_steps WHERE deleted_at IS NULL`)
	if err != nil {
		return 0, 0, err
	}
	stepsByOp := make(map[string][]stampedStep, len(orows))
	for _, r := range srows {
		id := r.String("operation_id")
		stepsByOp[id] = append(stepsByOp[id], stampedStep{name: r.String("step_name"), at: r.String("created_at")})
	}

	cutoff := now.Add(-grace)
	for _, r := range orows {
		id := r.String("id")
		rv, derr := DecodeReservation(r.String("reservation_json"))
		if derr != nil {
			return 0, 0, derr
		}
		if projectOrDefault(rv.Project) != project || (rv.ProjectCPU == 0 && rv.ProjectMemMiB == 0) {
			continue
		}
		if id == opID {
			continue // our own provisional reservation
		}

		steps := stepsByOp[id]
		names := make([]string, 0, len(steps))
		for _, s := range steps {
			names = append(names, s.name)
		}
		state, _ := ReduceOperationState(OperationKind(r.String("operation_kind")), names)

		if !IsOperationTerminal(state) {
			if id < opID { // an earlier claimant; later ones yield to us
				cpu += rv.ProjectCPU
				memMiB += rv.ProjectMemMiB
			}
			continue
		}
		// Terminal. Only a capacity LEASE settles — a spec-backed operation's
		// reservation ends when the operation does, because the spec it wrote is the
		// thing usage will count, and holding it open would double-charge the project
		// for its own committed resize.
		if grace <= 0 || r.String("resource_kind") != CapacityResourceKind {
			continue
		}
		if !terminalStepWithin(steps, cutoff) {
			continue // released long enough ago to have settled either way
		}
		// The whole point of the settle term: count it only while the thing it
		// admitted is still invisible here. Once the row lands, committed usage
		// counts it and counting the lease too would charge the project twice.
		visible, verr := resourceVisible(ctx, c, r.String("resource_id"))
		if verr != nil {
			return 0, 0, verr
		}
		if !visible {
			cpu += rv.ProjectCPU
			memMiB += rv.ProjectMemMiB
		}
	}
	return cpu, memMiB, nil
}

// resourceVisible reports whether the resource a lease admitted ("vm:<name>" or
// "ct:<name>") is present in this node's replica.
//
// An id that is empty or in an unrecognised form reports NOT visible, so the lease
// keeps its capacity for the remainder of the grace. That is the safe reading: an
// admission whose subject cannot be identified must not be assumed already accounted
// for.
func resourceVisible(ctx context.Context, c *Client, resourceID string) (bool, error) {
	kind, name, ok := strings.Cut(resourceID, ":")
	if !ok || name == "" {
		return false, nil
	}
	var q string
	switch kind {
	case "vm":
		q = `SELECT name FROM vms WHERE name = ? AND deleted_at IS NULL LIMIT 1`
	case "ct":
		q = `SELECT name FROM containers WHERE name = ? AND deleted_at IS NULL LIMIT 1`
	default:
		return false, nil
	}
	rows, err := c.Query(ctx, q, name)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// terminalStepWithin reports whether any of an operation's terminal steps was
// appended at or after cutoff. A step whose timestamp will not parse is treated as
// RECENT: an unreadable release time must not silently free quota.
func terminalStepWithin(steps []stampedStep, cutoff time.Time) bool {
	for _, s := range steps {
		switch s.name {
		case OpStepCompleted, OpStepFailed, OpStepCancelled:
		default:
			continue
		}
		t, err := time.Parse(time.RFC3339, s.at)
		if err != nil || !t.Before(cutoff) {
			return true
		}
	}
	return false
}
