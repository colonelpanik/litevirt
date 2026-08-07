package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
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

	// The other two dimensions a project quota bounds. They are reserved on the
	// SAME lease as cpu/mem rather than checked by a read the moment before the
	// insert: an unserialized glance cannot see a concurrent request's in-flight
	// claim, so two creates that each fit the remaining disk (or NIC) budget both
	// passed and both committed. Host capacity has no disk/NIC dimension — these
	// are tenancy limits only, so they appear on the project half alone.
	ProjectDiskGiB int `json:"project_disk_gib,omitempty"`
	ProjectNIC     int `json:"project_nic,omitempty"`

	TargetHost   string `json:"target_host,omitempty"`
	TargetCPU    int    `json:"target_cpu,omitempty"`
	TargetMemMiB int    `json:"target_mem_mib,omitempty"`
	SourceHost   string `json:"source_host,omitempty"`

	// Workload identity plus the ABSOLUTE size the admission is growing it to.
	//
	// The settle rule holds a released project lease until the thing it admitted is
	// visible here — and for a GROW, "visible" cannot mean mere presence: the row
	// already exists at its old size, so a presence check frees the lease instantly
	// while the holder's usage still reflects the smaller workload, under-counting
	// exactly the amount being added. Recording the post-commit target lets the
	// settle retire the lease only once the workload CONTRIBUTES that much.
	//
	// Identity is (kind, host, name), never name alone: a VM and a container may
	// share a name, and container names are unique only per host, so an ambiguous
	// match could retire a charge that is still owed.
	Workload     string `json:"workload,omitempty"`
	WorkloadKind string `json:"workload_kind,omitempty"` // WorkloadVM | WorkloadContainer
	WorkloadHost string `json:"workload_host,omitempty"` // disambiguates containers
	WantCPU      int    `json:"want_cpu,omitempty"`
	WantMemMiB   int    `json:"want_mem_mib,omitempty"`
	WantDiskGiB  int    `json:"want_disk_gib,omitempty"`
	WantNIC      int    `json:"want_nic,omitempty"`
}

// ProjectAmount is the project-quota half of the vector as a QuotaAmount.
func (r ReservationVector) ProjectAmount() QuotaAmount {
	return QuotaAmount{VCPU: r.ProjectCPU, MemMiB: r.ProjectMemMiB, DiskGiB: r.ProjectDiskGiB, NIC: r.ProjectNIC}
}

// ReservesProjectQuota reports whether the vector claims any project quota at
// all — the predicate the project sums use to skip rows that reserve only host
// capacity.
func (r ReservationVector) ReservesProjectQuota() bool {
	return r.ProjectCPU != 0 || r.ProjectMemMiB != 0 || r.ProjectDiskGiB != 0 || r.ProjectNIC != 0
}

// ReservationFacts is persisted on the reserved operation step. It is kept
// separate from the requested capacity vector because it proves who authorized
// that request, and therefore participates in authority-epoch validation.
type ReservationFacts struct {
	Project        string `json:"project"`
	AuthorityEpoch int64  `json:"authority_epoch"`
	AuthorityHost  string `json:"authority_host"`
}

// Validate rejects reservation vectors that could reduce capacity accounting or
// cannot be attributed to a host. Empty project names remain the canonical
// default-project representation for compatibility with legacy reservations.
func (r ReservationVector) Validate() error {
	values := []struct {
		field string
		value int
	}{
		{field: "project_cpu", value: r.ProjectCPU},
		{field: "project_mem_mib", value: r.ProjectMemMiB},
		{field: "project_disk_gib", value: r.ProjectDiskGiB},
		{field: "project_nic", value: r.ProjectNIC},
		{field: "target_cpu", value: r.TargetCPU},
		{field: "target_mem_mib", value: r.TargetMemMiB},
		{field: "want_cpu", value: r.WantCPU},
		{field: "want_mem_mib", value: r.WantMemMiB},
		{field: "want_disk_gib", value: r.WantDiskGiB},
		{field: "want_nic", value: r.WantNIC},
	}
	for _, value := range values {
		if value.value < 0 {
			return fmt.Errorf("reservation %s must be non-negative", value.field)
		}
	}
	if r.TargetHost == "" && (r.TargetCPU != 0 || r.TargetMemMiB != 0) {
		return fmt.Errorf("reservation target_host is required for target capacity")
	}
	return nil
}

// Encode serializes the vector for the operations.reservation_json column. A zero
// vector encodes to "" (no reservation).
func (r ReservationVector) Encode() (string, error) {
	if err := r.Validate(); err != nil {
		return "", err
	}
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
	var decoded *ReservationVector
	if err := json.Unmarshal([]byte(s), &decoded); err != nil {
		return ReservationVector{}, err
	}
	if decoded == nil {
		return ReservationVector{}, fmt.Errorf("reservation must be a JSON object")
	}
	r = *decoded
	if err := r.Validate(); err != nil {
		return ReservationVector{}, err
	}
	return r, nil
}

func checkedReservationAdd(total, delta int) (int, error) {
	if total < 0 || delta < 0 {
		return 0, fmt.Errorf("reservation total cannot be negative")
	}
	if delta > math.MaxInt-total {
		return 0, fmt.Errorf("reservation total overflow")
	}
	return total + delta, nil
}

func remainingCapacity(allocatable int, consumed ...int) (int, error) {
	if allocatable < 0 {
		return 0, fmt.Errorf("allocatable capacity cannot be negative")
	}
	remaining := allocatable
	for _, amount := range consumed {
		if amount < 0 {
			return 0, fmt.Errorf("consumed capacity cannot be negative")
		}
		if amount >= remaining {
			return 0, nil
		}
		remaining -= amount
	}
	return remaining, nil
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
	byID, err := nonterminalReservationsByID(ctx, c)
	if err != nil {
		return nil, err
	}
	out := make([]ReservationVector, 0, len(byID))
	for _, rv := range byID {
		out = append(out, rv)
	}
	return out, nil
}

// nonterminalReservationsByID is the single validated scan behind every capacity
// aggregate, keyed by operation id for the orderings reserve-then-verify needs.
//
// Keeping ONE scan matters more than it looks: an unvalidated id-keyed duplicate
// used to sit beside this, so ReservedBefore counted claims that HostReserved had
// already fenced as stale, and admission could disagree with itself about the same
// reservation depending on which aggregate asked.
func nonterminalReservationsByID(ctx context.Context, c *Client) (map[string]ReservationVector, error) {
	orows, err := c.Query(ctx,
		`SELECT id, project, resource_kind, resource_id, operation_kind,
		        reservation_json, desired_ref, vm_owner_epoch
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

	out := make(map[string]ReservationVector, len(orows))
	for _, r := range orows {
		id := r.String("id")
		kind := OperationKind(r.String("operation_kind"))
		if kind == OpWorkloadCreate && r.Int64("vm_owner_epoch") != 0 {
			current, err := operationOwnsCurrentWorkload(ctx, c,
				id, r.String("resource_kind"), r.String("resource_id"),
				r.String("desired_ref"), r.Int64("vm_owner_epoch"))
			if err != nil {
				return nil, err
			}
			if !current {
				// The immutable header remains journal-visible, but a superseded
				// v44 workload owner must not make it an authoritative capacity
				// claim. Epoch-zero legacy journals retain their old behavior.
				continue
			}
		}
		key := fmt.Sprintf("%s\x00%d", id, r.Int64("vm_owner_epoch"))
		state, _ := ReduceOperationState(kind, stepsByOpEpoch[key])
		if IsOperationTerminal(state) {
			continue
		}
		rv, err := DecodeReservation(r.String("reservation_json"))
		if err != nil {
			return nil, err
		}
		if operationProject := r.String("project"); operationProject != "" && rv != (ReservationVector{}) {
			if rv.Project != operationProject {
				return nil, fmt.Errorf(
					"reservation %s project %q does not match operation project %q",
					id, rv.Project, operationProject)
			}
			if err := validateReservationProject(r.String("reservation_json"), operationProject); err != nil {
				return nil, fmt.Errorf("reservation %s has invalid project binding: %w", id, err)
			}
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
		out[id] = rv
	}
	return out, nil
}

func operationOwnsCurrentWorkload(ctx context.Context, c *Client, operationID, resourceKind, resourceID, desiredRef string, ownerEpoch int64) (bool, error) {
	var rows []Row
	var err error
	switch resourceKind {
	case "vm":
		rows, err = c.Query(ctx,
			`SELECT 1 FROM vms
			 WHERE name = ? AND vm_owner_epoch = ? AND active_operation_id = ?
			   AND deleted_at IS NULL`,
			resourceID, ownerEpoch, operationID)
	case "container":
		host, name, ok := parseContainerCreateDesiredRef(desiredRef)
		if !ok || name != resourceID {
			return false, nil
		}
		rows, err = c.Query(ctx,
			`SELECT 1 FROM containers
			 WHERE host_name = ? AND name = ? AND owner_epoch = ?
			   AND active_operation_id = ? AND deleted_at IS NULL`,
			host, name, ownerEpoch, operationID)
	default:
		// Reservations are currently defined only for workload operations.
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(rows) != 0, nil
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
	hostCPU, hostMem, proj, err := reservedBefore(ctx, c, host, project, opID)
	return hostCPU, hostMem, proj.VCPU, proj.MemMiB, err
}

// ProjectReservedBefore is ReservedBefore's project half in ALL FOUR quota
// dimensions. The serialized quota check uses this one: reserving disk and NIC
// but summing only cpu/mem would leave those dimensions claimed and never
// counted, which is the same unenforced limit as not reserving them at all.
func ProjectReservedBefore(ctx context.Context, c *Client, project, opID string) (QuotaAmount, error) {
	_, _, proj, err := reservedBefore(ctx, c, "", project, opID)
	return proj, err
}

func reservedBefore(ctx context.Context, c *Client, host, project, opID string) (hostCPU, hostMem int, proj QuotaAmount, err error) {
	rvs, err := nonterminalReservationsByID(ctx, c)
	if err != nil {
		return 0, 0, QuotaAmount{}, err
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
			proj = proj.Add(rv.ProjectAmount())
		}
	}
	return hostCPU, hostMem, proj, nil
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
			cpu, err = checkedReservationAdd(cpu, rv.TargetCPU)
			if err != nil {
				return 0, 0, fmt.Errorf("sum host %q CPU reservations: %w", host, err)
			}
			memMiB, err = checkedReservationAdd(memMiB, rv.TargetMemMiB)
			if err != nil {
				return 0, 0, fmt.Errorf("sum host %q memory reservations: %w", host, err)
			}
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
			cpu, err = checkedReservationAdd(cpu, rv.ProjectCPU)
			if err != nil {
				return 0, 0, fmt.Errorf("sum project %q CPU reservations: %w", project, err)
			}
			memMiB, err = checkedReservationAdd(memMiB, rv.ProjectMemMiB)
			if err != nil {
				return 0, 0, fmt.Errorf("sum project %q memory reservations: %w", project, err)
			}
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
	freeCPU, err = remainingCapacity(allocCPU, u.CpuUsed, resCPU)
	if err != nil {
		return 0, 0, false, fmt.Errorf("calculate host %q free CPU: %w", host, err)
	}
	freeMemMiB, err = remainingCapacity(
		allocMem, u.MemUsedMiB, ctMem[host], resMem, policy.MemOverheadFor(u.VMCount))
	if err != nil {
		return 0, 0, false, fmt.Errorf("calculate host %q free memory: %w", host, err)
	}
	return freeCPU, freeMemMiB, true, nil
}

// AppendReservationFacts records the `reserved` step proving WHICH authority epoch
// admitted a reservation.
//
// This is not optional bookkeeping. Once a project has an authority epoch, the
// aggregation above refuses to count a reservation that cannot be attributed to the
// CURRENT one — so a mint that skips this step silently stops consuming capacity and
// the same headroom gets handed out twice. Every live reservation writer must call it.
//
// facts==nil is the genuine pre-authority case (no epoch exists yet): the step is
// written empty, and aggregation keeps counting the claim as a legacy one.
func AppendReservationFacts(ctx context.Context, c *Client, opID string, ownerEpoch int64, project string, facts *ReservationFacts) error {
	encoded, err := reservationStepFacts(facts, project)
	if err != nil {
		return err
	}
	return AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: opID, OwnerEpoch: ownerEpoch, StepName: OpStepReserved, Facts: encoded,
	})
}

// ReservationFactsFor builds the authority facts for a reservation minted under the
// project's current authority, or nil when the project has none yet.
func ReservationFactsFor(project string, epoch int64, holder string) *ReservationFacts {
	if epoch <= 0 || holder == "" {
		return nil
	}
	return &ReservationFacts{Project: projectOrDefault(project), AuthorityEpoch: epoch, AuthorityHost: holder}
}
