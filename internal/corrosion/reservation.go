package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
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

// ReservationFacts is persisted on the reserved operation step. It is kept
// separate from the requested capacity vector because it proves who authorized
// that request, and therefore participates in authority-epoch validation.
type ReservationFacts struct {
	Project        string `json:"project"`
	AuthorityEpoch int64  `json:"authority_epoch"`
	AuthorityHost  string `json:"authority_host"`
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

func reservationStepFacts(facts *ReservationFacts, project string) (string, error) {
	if facts == nil {
		return "", nil // backward-compatible pre-authority reservation
	}
	if facts.AuthorityEpoch <= 0 || facts.AuthorityHost == "" {
		return "", fmt.Errorf("invalid reservation authority facts")
	}
	if projectOrDefault(facts.Project) != projectOrDefault(project) {
		return "", fmt.Errorf("reservation project does not match operation project")
	}
	normalized := ReservationFacts{
		Project:        projectOrDefault(project),
		AuthorityEpoch: facts.AuthorityEpoch,
		AuthorityHost:  facts.AuthorityHost,
	}
	b, err := json.Marshal(normalized)
	return string(b), err
}

// nonterminalReservations returns the reservation vector of every operation whose
// reduced state is NOT terminal — the in-flight capacity claims admission must
// count on top of committed running-VM actuals.
func nonterminalReservations(ctx context.Context, c *Client) ([]ReservationVector, error) {
	orows, err := c.Query(ctx,
		`SELECT id, project, operation_kind, reservation_json, vm_owner_epoch
		 FROM operations WHERE deleted_at IS NULL AND reservation_json != ''`)
	if err != nil {
		return nil, err
	}
	if len(orows) == 0 {
		return nil, nil
	}

	// Bulk-load steps once, grouped by operation id + the immutable header's
	// owner epoch. A terminal written by a stale owner must not release the
	// current owner's reservation.
	srows, err := c.Query(ctx,
		`SELECT operation_id, owner_epoch, step_name, facts
		 FROM operation_steps WHERE deleted_at IS NULL`)
	if err != nil {
		return nil, err
	}
	stepsByOpEpoch := make(map[string][]string, len(orows))
	reservationFactsByOpEpoch := make(map[string]string, len(orows))
	for _, r := range srows {
		id := r.String("operation_id")
		key := fmt.Sprintf("%s\x00%d", id, r.Int64("owner_epoch"))
		stepsByOpEpoch[key] = append(stepsByOpEpoch[key], r.String("step_name"))
		if r.String("step_name") == OpStepReserved {
			reservationFactsByOpEpoch[key] = r.String("facts")
		}
	}

	var out []ReservationVector
	for _, r := range orows {
		id := r.String("id")
		kind := OperationKind(r.String("operation_kind"))
		key := fmt.Sprintf("%s\x00%d", id, r.Int64("vm_owner_epoch"))
		state, _ := ReduceOperationState(kind, stepsByOpEpoch[key])
		if IsOperationTerminal(state) {
			continue
		}
		rv, err := DecodeReservation(r.String("reservation_json"))
		if err != nil {
			return nil, err
		}
		authority, ok, err := CurrentProjectAuthority(ctx, c, r.String("project"))
		if err != nil {
			return nil, err
		}
		if ok {
			rawFacts := reservationFactsByOpEpoch[key]
			if rawFacts == "" {
				// A pre-authority reservation cannot be attributed to the
				// current authority. It remains journal-visible but does not
				// consume capacity after an authority epoch is established.
				continue
			}
			var facts ReservationFacts
			if err := json.Unmarshal([]byte(rawFacts), &facts); err != nil {
				return nil, fmt.Errorf("reservation %s has malformed authority facts: %w", id, err)
			}
			if facts.Project == "" || facts.AuthorityEpoch <= 0 || facts.AuthorityHost == "" {
				return nil, fmt.Errorf("reservation %s has malformed authority facts", id)
			}
			if facts.AuthorityEpoch != authority.Epoch {
				continue // reservation minted by a fenced/stale authority
			}
			if projectOrDefault(facts.Project) != authority.Project ||
				facts.AuthorityHost != authority.Holder {
				return nil, fmt.Errorf("reservation %s has invalid current-authority facts", id)
			}
		}
		out = append(out, rv)
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

// HostFreeCapacityWithPolicy is HostFreeCapacity under an explicit cluster policy.
func HostFreeCapacityWithPolicy(ctx context.Context, c *Client, host string, policy CapacityPolicy) (freeCPU, freeMemMiB int, ok bool, err error) {
	h, err := GetHost(ctx, c, host)
	if err != nil {
		return 0, 0, false, err
	}
	if h == nil {
		return 0, 0, false, nil
	}
	usage, err := SumVMResourcesByHost(ctx, c)
	if err != nil {
		return 0, 0, false, err
	}
	resCPU, resMem, err := HostReserved(ctx, c, host)
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
