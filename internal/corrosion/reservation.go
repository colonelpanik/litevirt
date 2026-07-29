package corrosion

import (
	"context"
	"encoding/json"
)

// ReservationVector is the capacity an in-flight operation has reserved, persisted
// as operations.reservation_json. It is the F2 admission SOURCE OF TRUTH: the
// replicated operation record IS the reservation, so admission needs no separate
// reservation table or renewable lease — a nonterminal operation holds its
// reservation until it terminates (completed/failed/cancelled/superseded).
//
// Deltas are ADDITIVE over committed state (running-VM actuals) so summing running
// actuals + nonterminal reservations never double-counts: a create/start reserves
// the FULL VM size (the VM isn't in the running-actuals sum yet); a resize-grow
// reserves only the POSITIVE delta (the VM's current actuals are already counted).
// SourceHost capacity is released at COMMIT (migration), so it is not a reserve.
type ReservationVector struct {
	Project       string `json:"project,omitempty"`
	ProjectCPU    int    `json:"project_cpu,omitempty"`
	ProjectMemMiB int    `json:"project_mem_mib,omitempty"`
	TargetHost    string `json:"target_host,omitempty"`
	TargetCPU     int    `json:"target_cpu,omitempty"`
	TargetMemMiB  int    `json:"target_mem_mib,omitempty"`
	SourceHost    string `json:"source_host,omitempty"`
}

// Encode serializes the vector for the operations.reservation_json column. A zero
// vector encodes to "" (no reservation).
func (r ReservationVector) Encode() (string, error) {
	if r == (ReservationVector{}) {
		return "", nil
	}
	b, err := json.Marshal(r)
	return string(b), err
}

// DecodeReservation parses a reservation_json value; an empty string is the zero
// vector (no capacity reserved).
func DecodeReservation(s string) (ReservationVector, error) {
	var r ReservationVector
	if s == "" {
		return r, nil
	}
	err := json.Unmarshal([]byte(s), &r)
	return r, err
}

// nonterminalReservations returns the reservation vector of every operation whose
// reduced state is NOT terminal — the in-flight capacity claims admission must
// count on top of committed running-VM actuals.
func nonterminalReservations(ctx context.Context, c *Client) ([]ReservationVector, error) {
	orows, err := c.Query(ctx,
		`SELECT id, operation_kind, reservation_json FROM operations WHERE deleted_at IS NULL AND reservation_json != ''`)
	if err != nil {
		return nil, err
	}
	if len(orows) == 0 {
		return nil, nil
	}

	// Bulk-load steps once, grouped by operation id (arbitrary owner epoch — the
	// reducer only needs the set of step names to decide terminality).
	srows, err := c.Query(ctx, `SELECT operation_id, step_name FROM operation_steps WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	stepsByOp := make(map[string][]string, len(orows))
	for _, r := range srows {
		id := r.String("operation_id")
		stepsByOp[id] = append(stepsByOp[id], r.String("step_name"))
	}

	var out []ReservationVector
	for _, r := range orows {
		id := r.String("id")
		kind := OperationKind(r.String("operation_kind"))
		state, _ := ReduceOperationState(kind, stepsByOp[id])
		if IsOperationTerminal(state) {
			continue
		}
		rv, err := DecodeReservation(r.String("reservation_json"))
		if err != nil {
			return nil, err
		}
		out = append(out, rv)
	}
	return out, nil
}

// ReservedBefore sums the NONTERMINAL reservation deltas of operations whose id
// sorts strictly BEFORE opID — the claimants this admission must yield to.
//
// Operation ids are globally unique, so ordering them lexically is a TOTAL order
// every node computes identically. Reserve-then-verify counts only these: our own
// reservation must not be subtracted from the headroom we are about to compare our
// own request against (that double-counts), and later claimants yield to us, which
// is what makes exactly one racer win instead of both refusing.
//
// Counting earlier-only rather than crediting back is deliberate. Headroom clamps
// at zero, so "subtract everything then add ours back" silently over-credits once
// the host is oversubscribed — a bug this shape had until a test caught it.
func ReservedBefore(ctx context.Context, c *Client, host, project, opID string) (hostCPU, hostMem, projCPU, projMem int, err error) {
	rvs, err := nonterminalReservationsWithIDs(ctx, c)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	for id, rv := range rvs {
		if id >= opID {
			continue // ourselves, or a LATER claimant that yields to us
		}
		if host != "" && rv.TargetHost == host {
			hostCPU += rv.TargetCPU
			hostMem += rv.TargetMemMiB
		}
		if project != "" && rv.Project == project {
			projCPU += rv.ProjectCPU
			projMem += rv.ProjectMemMiB
		}
	}
	return hostCPU, hostMem, projCPU, projMem, nil
}

// nonterminalReservationsWithIDs is nonterminalReservations keyed by operation id,
// for the orderings reserve-then-verify needs.
func nonterminalReservationsWithIDs(ctx context.Context, c *Client) (map[string]ReservationVector, error) {
	orows, err := c.Query(ctx,
		`SELECT id, operation_kind, reservation_json FROM operations WHERE deleted_at IS NULL AND reservation_json != ''`)
	if err != nil {
		return nil, err
	}
	if len(orows) == 0 {
		return nil, nil
	}
	srows, err := c.Query(ctx, `SELECT operation_id, step_name FROM operation_steps WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	stepsByOp := make(map[string][]string, len(orows))
	for _, r := range srows {
		id := r.String("operation_id")
		stepsByOp[id] = append(stepsByOp[id], r.String("step_name"))
	}
	out := make(map[string]ReservationVector, len(orows))
	for _, r := range orows {
		id := r.String("id")
		state, _ := ReduceOperationState(OperationKind(r.String("operation_kind")), stepsByOp[id])
		if IsOperationTerminal(state) {
			continue
		}
		rv, derr := DecodeReservation(r.String("reservation_json"))
		if derr != nil {
			return nil, derr
		}
		out[id] = rv
	}
	return out, nil
}

// HostReserved sums the target-host reservation deltas of all NONTERMINAL operations
// targeting host — the in-flight capacity not yet reflected in running-VM actuals.
func HostReserved(ctx context.Context, c *Client, host string) (cpu, memMiB int, err error) {
	rvs, err := nonterminalReservations(ctx, c)
	if err != nil {
		return 0, 0, err
	}
	for _, rv := range rvs {
		if rv.TargetHost == host {
			cpu += rv.TargetCPU
			memMiB += rv.TargetMemMiB
		}
	}
	return cpu, memMiB, nil
}

// ProjectReserved sums the project-quota reservation deltas of all NONTERMINAL
// operations in project (normalized).
func ProjectReserved(ctx context.Context, c *Client, project string) (cpu, memMiB int, err error) {
	project = projectOrDefault(project)
	rvs, err := nonterminalReservations(ctx, c)
	if err != nil {
		return 0, 0, err
	}
	for _, rv := range rvs {
		if projectOrDefault(rv.Project) == project {
			cpu += rv.ProjectCPU
			memMiB += rv.ProjectMemMiB
		}
	}
	return cpu, memMiB, nil
}

// HostFreeCapacity reports a host's free CPU and memory (MiB): ALLOCATABLE (see
// HostAllocatable — physical, adjusted by overcommit ratios and host reserves)
// minus committed running-VM actuals, running-container memory, per-VM qemu
// overhead, and in-flight nonterminal reservations. Negative values are
// clamped to 0 (an overcommitted
// host has no free capacity). Returns ok=false when the host is unknown.
//
// Uses the DEFAULT cluster policy. Callers that carry a configured one should use
// HostFreeCapacityWithPolicy so a cluster's configuration is actually honoured.
func HostFreeCapacity(ctx context.Context, c *Client, host string) (freeCPU, freeMemMiB int, ok bool, err error) {
	return HostFreeCapacityWithPolicy(ctx, c, host, DefaultCapacityPolicy())
}

// HostFreeCapacityBefore is HostFreeCapacityWithPolicy counting only reservations
// from operations that sort BEFORE opID. Used by reserve-then-verify so an
// admission compares its request against headroom that excludes its own
// provisional reservation.
func HostFreeCapacityBefore(ctx context.Context, c *Client, host string, policy CapacityPolicy, opID string) (freeCPU, freeMemMiB int, ok bool, err error) {
	resCPU, resMem, _, _, err := ReservedBefore(ctx, c, host, "", opID)
	if err != nil {
		return 0, 0, false, err
	}
	return hostFreeWithReserved(ctx, c, host, policy, resCPU, resMem)
}

// HostFreeCapacityWithPolicy is HostFreeCapacity under an explicit cluster policy.
func HostFreeCapacityWithPolicy(ctx context.Context, c *Client, host string, policy CapacityPolicy) (freeCPU, freeMemMiB int, ok bool, err error) {
	resCPU, resMem, err := HostReserved(ctx, c, host)
	if err != nil {
		return 0, 0, false, err
	}
	return hostFreeWithReserved(ctx, c, host, policy, resCPU, resMem)
}

// hostFreeWithReserved is the shared tail of the host-headroom calculation, taking
// the reservation totals to subtract. Split out so reserve-then-verify can supply a
// FILTERED total (earlier claimants only) instead of re-deriving the arithmetic —
// and so the clamp below lives in exactly one place.
func hostFreeWithReserved(ctx context.Context, c *Client, host string, policy CapacityPolicy, resCPU, resMem int) (freeCPU, freeMemMiB int, ok bool, err error) {
	h, err := GetHost(ctx, c, host)
	if err != nil || h == nil {
		return 0, 0, false, err
	}
	usage, err := SumVMResourcesByHost(ctx, c)
	if err != nil {
		return 0, 0, false, err
	}
	// Containers consume host memory too, and were absent from this sum entirely.
	ctMem, err := SumContainerMemoryByHost(ctx, c)
	if err != nil {
		return 0, 0, false, err
	}
	allocCPU, allocMem := HostAllocatable(*h, policy)
	u := usage[host]
	freeCPU = allocCPU - u.CpuUsed - resCPU
	freeMemMiB = allocMem - u.MemUsedMiB - ctMem[host] - resMem - policy.MemOverheadFor(u.VMCount)
	if freeCPU < 0 {
		freeCPU = 0
	}
	if freeMemMiB < 0 {
		freeMemMiB = 0
	}
	return freeCPU, freeMemMiB, true, nil
}
