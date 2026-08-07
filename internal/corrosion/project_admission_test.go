package corrosion

import (
	"context"
	"testing"
	"time"
)

// insertProjectLease writes a project-quota reservation for a delegated admission.
func insertProjectLease(t *testing.T, db *Client, id, project, resourceKind string, cpu, mem int) {
	t.Helper()
	insertProjectLeaseFor(t, db, id, project, resourceKind, "", cpu, mem)
}

// insertProjectLeaseFor is insertProjectLease naming the resource the admission is
// about to create, which is how a settled lease knows when to stop counting.
func insertProjectLeaseFor(t *testing.T, db *Client, id, project, resourceKind, resourceID string, cpu, mem int) {
	t.Helper()
	rv := ReservationVector{Project: project, ProjectCPU: cpu, ProjectMemMiB: mem}
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := InsertOperation(context.Background(), db, OperationRecord{
		ID: id, Method: "CreateVM", Project: project, ResourceKind: resourceKind,
		ResourceID:    resourceID,
		OperationKind: string(OpResourceUpdateRunning), ReservationJSON: enc,
	}); err != nil {
		t.Fatalf("InsertOperation %s: %v", id, err)
	}
}

// settleLease marks a lease terminal and backdates the terminal step, so the settle
// grace can be exercised without sleeping.
func settleLease(t *testing.T, db *Client, id string, ago time.Duration) {
	t.Helper()
	ctx := context.Background()
	if err := AppendOperationStep(ctx, db, OperationStepRecord{
		OperationID: id, StepName: OpStepCompleted,
	}); err != nil {
		t.Fatalf("AppendOperationStep %s: %v", id, err)
	}
	when := time.Now().Add(-ago).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`UPDATE operation_steps SET created_at = ? WHERE operation_id = ? AND step_name = ?`,
		when, id, OpStepCompleted); err != nil {
		t.Fatalf("backdate %s: %v", id, err)
	}
}

// TestProjectReservedSettling_YieldsToEarlierClaimantsOnly pins the tie-break the
// whole scheme rests on: an admission counts claims that sort BEFORE it and ignores
// later ones, so exactly one racer proceeds instead of both refusing.
func TestProjectReservedSettling_YieldsToEarlierClaimantsOnly(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertProjectLease(t, db, "op-a", "proj", CapacityResourceKind, 4, 4096)
	insertProjectLease(t, db, "op-b", "proj", CapacityResourceKind, 2, 2048)
	insertProjectLease(t, db, "op-c", "proj", CapacityResourceKind, 8, 8192)

	// op-b yields to op-a only: op-c sorts after it, and its own claim must not be
	// counted against the request it is about to make.
	cpu, mem, err := ProjectReservedSettling(ctx, db, "proj", "op-b", 0, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 4 || mem != 4096 {
		t.Errorf("op-b sees %d vCPU/%d MiB reserved, want 4/4096 (op-a only)", cpu, mem)
	}

	// The earliest claimant yields to nobody — otherwise no one ever gets in.
	cpu, _, err = ProjectReservedSettling(ctx, db, "proj", "op-a", 0, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 0 {
		t.Errorf("op-a (earliest) sees %d vCPU reserved, want 0", cpu)
	}
}

// TestProjectReservedSettling_CountsAWinnerStillCommitting is the reason the settle
// grace exists. A delegated admission that WON releases its lease only after writing
// its VM on its OWN node; the holder learns of that row when replication delivers it.
// Counting the released lease as free in that gap hands the same quota out twice.
func TestProjectReservedSettling_CountsAWinnerStillCommitting(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertProjectLease(t, db, "op-winner", "proj", CapacityResourceKind, 4, 4096)
	settleLease(t, db, "op-winner", time.Second) // released a moment ago

	// A LATER request must still see the winner's capacity as spent, even though the
	// lease is terminal and the winner's VM row has not arrived here yet.
	cpu, mem, err := ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 4 || mem != 4096 {
		t.Fatalf("settling winner counted as %d vCPU/%d MiB, want 4/4096 — a released lease whose commit has not replicated must stay spent", cpu, mem)
	}

	// Sorting BEFORE the winner does not exempt a request from it: a settled lease is
	// a decided fact, not a racer to be ordered against.
	cpu, _, err = ProjectReservedSettling(ctx, db, "proj", "op-aaa", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 4 {
		t.Errorf("earlier-sorting request sees %d vCPU from a settled winner, want 4", cpu)
	}
}

// TestProjectReservedSettling_StopsCountingOnceTheResourceIsVisible is the other half
// of the settle rule, and the one that is easy to get wrong.
//
// A settled lease stands in for a commit this node cannot see yet. The moment the row
// DOES land, committed usage counts it — so continuing to count the lease charges the
// project twice. An earlier version settled on a blind timer and did exactly that,
// which made ordinary SEQUENTIAL creates on the holder fail for the length of the
// timer; a fleet scenario caught it.
func TestProjectReservedSettling_StopsCountingOnceTheResourceIsVisible(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertProjectLeaseFor(t, db, "op-winner", "proj", CapacityResourceKind, "vm:vm-a", 4, 4096)
	settleLease(t, db, "op-winner", time.Second) // released a moment ago, well inside the grace

	// Not visible yet: the lease holds the capacity.
	cpu, _, err := ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 4 {
		t.Fatalf("before the row lands the lease counts %d vCPU, want 4", cpu)
	}

	// The committed row arrives. Usage now counts it, so the lease must not.
	if err := InsertVM(ctx, db, VMRecord{
		Name: "vm-a", HostName: "h1", Project: "proj", Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	cpu, mem, err := ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("lease still counts %d vCPU/%d MiB after its VM became visible, want 0/0 — "+
			"committed usage already counts that VM, so this is a double charge", cpu, mem)
	}
}

// TestProjectReservedSettling_ReleasesOnceTheGraceElapses: the grace must expire, or
// every admission would permanently consume quota twice — once as a settled lease and
// again as the committed row it became.
func TestProjectReservedSettling_ReleasesOnceTheGraceElapses(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertProjectLease(t, db, "op-old", "proj", CapacityResourceKind, 4, 4096)
	settleLease(t, db, "op-old", time.Hour)

	cpu, mem, err := ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("lease settled an hour ago still counted as %d vCPU/%d MiB, want 0/0", cpu, mem)
	}
}

// TestProjectReservedSettling_NeverSettlesASpecBackedOperation. The grace is a
// stand-in for "the committed row has not arrived yet", which is true only for a
// provisional capacity lease. A resize/migration that has COMPLETED already wrote the
// spec its project usage counts, so holding its reservation open past completion
// would charge the project twice for its own committed change.
func TestProjectReservedSettling_NeverSettlesASpecBackedOperation(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertProjectLease(t, db, "op-resize", "proj", "vm", 4, 4096) // spec-backed, not a lease
	settleLease(t, db, "op-resize", time.Second)

	cpu, mem, err := ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("completed spec-backed operation counted as %d vCPU/%d MiB, want 0/0", cpu, mem)
	}
}

// TestProjectReservedSettling_IgnoresOtherProjects guards the obvious way a quota
// check goes wrong globally: one project's admissions must not consume another's.
func TestProjectReservedSettling_IgnoresOtherProjects(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertProjectLease(t, db, "op-a", "other", CapacityResourceKind, 8, 8192)
	insertProjectLease(t, db, "op-b", "proj", CapacityResourceKind, 2, 2048)

	cpu, mem, err := ProjectReservedSettling(ctx, db, "proj", "op-z", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 2 || mem != 2048 {
		t.Errorf("cross-project leakage: %d vCPU/%d MiB, want 2/2048", cpu, mem)
	}
}

// insertIdentityLease is insertProjectLeaseFor carrying the full workload identity
// and the ABSOLUTE size the admission grows it to — the settle inputs for a grow.
func insertIdentityLease(t *testing.T, db *Client, id, project, kind, host, name string, deltaCPU, deltaMem, wantCPU, wantMem int) {
	t.Helper()
	rv := ReservationVector{
		Project: project, ProjectCPU: deltaCPU, ProjectMemMiB: deltaMem,
		Workload: name, WorkloadKind: kind, WorkloadHost: host,
		WantCPU: wantCPU, WantMemMiB: wantMem,
	}
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := InsertOperation(context.Background(), db, OperationRecord{
		ID: id, Method: "UpdateVM", Project: project, ResourceKind: CapacityResourceKind,
		ResourceID:    kind + ":" + name,
		OperationKind: string(OpResourceUpdateRunning), ReservationJSON: enc,
	}); err != nil {
		t.Fatalf("InsertOperation %s: %v", id, err)
	}
}

// TestProjectReservedSettling_HoldsAGrowUntilTheGrownSizeIsVisible is the regression
// the identity-keyed want exists for. A grow's row is ALREADY present at its old
// size, so a presence-only settle freed the lease the instant it was released — while
// the holder's committed usage still counted the smaller spec, under-counting exactly
// the growth and handing it to the next request.
func TestProjectReservedSettling_HoldsAGrowUntilTheGrownSizeIsVisible(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertVM(ctx, db, VMRecord{
		Name: "vm-g", HostName: "h1", Project: "proj",
		Spec: `{"cpu":4,"memory_mib":4096}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	insertIdentityLease(t, db, "op-grow", "proj", WorkloadVM, "h1", "vm-g", 2, 2048, 6, 6144)
	settleLease(t, db, "op-grow", time.Second)

	// The VM is visible — but only at its OLD size, so the lease must keep counting.
	cpu, mem, err := ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 2 || mem != 2048 {
		t.Fatalf("grow lease counts %d vCPU/%d MiB while the row still shows the old size, want 2/2048 — "+
			"presence alone must not settle a grow", cpu, mem)
	}

	// The grown spec lands. Usage now counts the larger size, so the lease must stop.
	if err := db.Execute(ctx,
		`UPDATE vms SET spec = ? WHERE name = ?`, `{"cpu":6,"memory_mib":6144}`, "vm-g"); err != nil {
		t.Fatalf("update spec: %v", err)
	}
	cpu, mem, err = ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("grow lease still counts %d vCPU/%d MiB after the grown size became visible, want 0/0", cpu, mem)
	}
}

// TestProjectReservedSettling_SumsConcurrentGrows: two grows that both committed
// before either replicated owe BOTH deltas. Each lease settles against its own
// absolute target, so the intermediate size retires only the smaller one — a max()
// or shared-target scheme would silently release half the owed quota.
func TestProjectReservedSettling_SumsConcurrentGrows(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	if err := InsertVM(ctx, db, VMRecord{
		Name: "vm-s", HostName: "h1", Project: "proj",
		Spec: `{"cpu":4,"memory_mib":4096}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	insertIdentityLease(t, db, "op-g1", "proj", WorkloadVM, "h1", "vm-s", 2, 0, 6, 4096)
	insertIdentityLease(t, db, "op-g2", "proj", WorkloadVM, "h1", "vm-s", 2, 0, 8, 4096)
	settleLease(t, db, "op-g1", time.Second)
	settleLease(t, db, "op-g2", time.Second)

	cpu, _, err := ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 4 {
		t.Fatalf("two settling +2 grows count %d vCPU, want 4 — both deltas are owed until seen", cpu)
	}

	// The first grow's size lands; only its lease retires.
	if err := db.Execute(ctx,
		`UPDATE vms SET spec = ? WHERE name = ?`, `{"cpu":6,"memory_mib":4096}`, "vm-s"); err != nil {
		t.Fatalf("update spec: %v", err)
	}
	cpu, _, err = ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 2 {
		t.Errorf("after the intermediate size lands, %d vCPU still settling, want 2 (the second grow only)", cpu)
	}
}

// TestProjectReservedSettling_AnUnrelatedWorkloadCannotRetireACharge pins the
// identity property itself: only the workload a charge was taken FOR may retire it.
// An aggregate usage-growth heuristic is fooled by any unrelated increase — a
// workload that replicated late, or one admitted through a fail-open path.
func TestProjectReservedSettling_AnUnrelatedWorkloadCannotRetireACharge(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertIdentityLease(t, db, "op-create", "proj", WorkloadVM, "h1", "vm-mine", 4, 4096, 4, 4096)
	settleLease(t, db, "op-create", time.Second)

	// A DIFFERENT, larger VM appears. Aggregate usage grew past the want — but not
	// because of this admission, so the charge must stand.
	if err := InsertVM(ctx, db, VMRecord{
		Name: "vm-other", HostName: "h1", Project: "proj",
		Spec: `{"cpu":8,"memory_mib":8192}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	cpu, _, err := ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 4 {
		t.Fatalf("an unrelated VM retired the charge (%d vCPU counted, want 4)", cpu)
	}

	// The right workload arrives at its admitted size: now it retires.
	if err := InsertVM(ctx, db, VMRecord{
		Name: "vm-mine", HostName: "h1", Project: "proj",
		Spec: `{"cpu":4,"memory_mib":4096}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	cpu, _, err = ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 0 {
		t.Errorf("charge still counted (%d vCPU) after its own workload became visible, want 0", cpu)
	}
}

// TestProjectReservedSettling_ContainerChargeIsHostKeyed: container names are unique
// only per HOST, so a same-named container elsewhere must not retire the charge.
func TestProjectReservedSettling_ContainerChargeIsHostKeyed(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	insertIdentityLease(t, db, "op-ct", "proj", WorkloadContainer, "h1", "web", 2, 1024, 2, 1024)
	settleLease(t, db, "op-ct", time.Second)

	// Same name, same size — WRONG host.
	if err := UpsertContainer(ctx, db, ContainerRecord{
		HostName: "h2", Name: "web", Project: "proj", State: "running",
		CPULimit: 2, MemMiB: 1024,
	}); err != nil {
		t.Fatalf("UpsertContainer h2: %v", err)
	}
	cpu, _, err := ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 2 {
		t.Fatalf("a same-named container on another host retired the charge (%d vCPU counted, want 2)", cpu)
	}

	// The container the charge was taken for lands on ITS host: retire.
	if err := UpsertContainer(ctx, db, ContainerRecord{
		HostName: "h1", Name: "web", Project: "proj", State: "running",
		CPULimit: 2, MemMiB: 1024,
	}); err != nil {
		t.Fatalf("UpsertContainer h1: %v", err)
	}
	cpu, _, err = ProjectReservedSettling(ctx, db, "proj", "op-zzz", 5*time.Second, time.Now())
	if err != nil {
		t.Fatalf("ProjectReservedSettling: %v", err)
	}
	if cpu != 0 {
		t.Errorf("charge still counted (%d vCPU) after its container became visible on its host, want 0", cpu)
	}
}
