package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The tie-break, pinned DETERMINISTICALLY rather than by racing two goroutines.
//
// A concurrency test that fires two creates and counts winners is only as good as
// its timing: once the window narrows, it passes whether or not the mechanism
// works (it did exactly that here — a check-then-write mutation survived it). So
// the ordering guarantee is asserted directly, by planting a competing reservation
// with a known id and observing which way the decision goes.
//
// Operation ids are globally unique, giving a TOTAL order every node computes
// identically. An admission yields to reservations sorting BEFORE it and ignores
// those sorting after — which is what produces exactly one winner instead of two
// refusals.

// plantReservation inserts a nonterminal operation holding a capacity reservation
// under a chosen id, standing in for a concurrent admission on another node.
func plantReservation(t *testing.T, s *Server, id, host, project string, cpu, mem int) {
	t.Helper()
	rv := corrosion.ReservationVector{
		Project: project, ProjectCPU: cpu, ProjectMemMiB: mem,
		TargetHost: host, TargetCPU: cpu, TargetMemMiB: mem,
	}
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode reservation: %v", err)
	}
	if err := corrosion.InsertOperation(context.Background(), s.db, corrosion.OperationRecord{
		ID: id, Method: "CreateVM", Project: project, ResourceKind: "capacity",
		OperationKind: string(corrosion.OpResourceUpdateRunning), ReservationJSON: enc,
	}); err != nil {
		t.Fatalf("plant reservation %s: %v", id, err)
	}
}

// admissionHost seeds a host with exactly enough headroom for ONE of two competing
// 1024 MiB admissions.
func admissionHost(t *testing.T, s *Server) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.9", State: "active", CPUTotal: 16, MemTotal: 2560,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	// Allocatable = 2560 - 1024 reserve = 1536 → room for ONE 1024, not two.
}

// TestAdmitWithReservation_YieldsToAnEarlierClaimant: a competing reservation that
// sorts BEFORE ours holds the capacity, so we must stand down.
func TestAdmitWithReservation_YieldsToAnEarlierClaimant(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	admissionHost(t, s)

	// "0000…" sorts before any minted id.
	plantReservation(t, s, "00000000-earlier", "test-host", "_default", 1, 1024)

	lease, err := s.admitWithReservation(ctx, "CreateVM", "test-host", "_default", "vm:probe", 1, 1024, false)
	if status.Code(err) != codes.ResourceExhausted {
		if lease != nil {
			lease.release(ctx)
		}
		t.Fatalf("admission against an EARLIER claimant: got %v, want ResourceExhausted", err)
	}
}

// TestAdmitWithReservation_IgnoresALaterClaimant: a competing reservation that
// sorts AFTER ours will yield to us, so we proceed. Without this the two racers
// would both refuse and nobody would get in.
func TestAdmitWithReservation_IgnoresALaterClaimant(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	admissionHost(t, s)

	// "zzzz…" sorts after any minted id.
	plantReservation(t, s, "zzzzzzzz-later", "test-host", "_default", 1, 1024)

	lease, err := s.admitWithReservation(ctx, "CreateVM", "test-host", "_default", "vm:probe", 1, 1024, false)
	if err != nil {
		t.Fatalf("admission against a LATER claimant was refused: %v — later racers yield, or both sides deadlock and nobody is admitted", err)
	}
	lease.release(ctx)
}

// TestAdmitWithReservation_ReleaseFreesTheCapacity: a lease that is not released
// permanently consumes capacity no workload is using, so release is as
// load-bearing as reserve.
//
// Asserted on HostReserved directly rather than by attempting a second admission.
// That indirect version was 50/50: ids come from newID(), so whether a leaked
// reservation is even VISIBLE to the next admission depends on which id sorts
// first — and a mutation that never released survived it half the time.
func TestAdmitWithReservation_ReleaseFreesTheCapacity(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	admissionHost(t, s)

	before, _, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}

	lease, err := s.admitWithReservation(ctx, "CreateVM", "test-host", "_default", "vm:probe", 1, 1024, false)
	if err != nil {
		t.Fatalf("admission: %v", err)
	}
	held, _, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if held != before+1 {
		t.Fatalf("reserved vCPU = %d while the lease is held, want %d — the reservation is not visible to anyone else", held, before+1)
	}

	lease.release(ctx)

	after, _, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if after != before {
		t.Errorf("reserved vCPU = %d after release, want %d — the reservation leaked and permanently consumes capacity", after, before)
	}
}

// TestAdmitHostWithReservation_DoesNotChargeProjectQuota: the start paths reserve
// HOST capacity only.
//
// A project allocation counts whether the workload is running or stopped, so a
// start grows nothing at the project level. Reserving against the project too
// would make two concurrent starts look like they were each consuming quota
// neither is growing — and would refuse a plain stop/start of any workload sized
// over half its quota, which is the regression the split exists to prevent.
func TestAdmitHostWithReservation_DoesNotChargeProjectQuota(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	admissionHost(t, s)

	beforeCPU, beforeMem, err := corrosion.ProjectReserved(ctx, s.db, "_default")
	if err != nil {
		t.Fatalf("ProjectReserved: %v", err)
	}

	lease, err := s.admitHostWithReservation(ctx, "StartVM", "test-host", "_default", "vm:res-test", 1, 1024, false)
	if err != nil {
		t.Fatalf("host-only admission: %v", err)
	}
	defer lease.release(ctx)

	// The HOST reservation must be visible…
	hostCPU, _, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if hostCPU != 1 {
		t.Errorf("host reserved vCPU = %d, want 1 — a concurrent start cannot see this demand", hostCPU)
	}

	// …while the PROJECT reservation must not move.
	afterCPU, afterMem, err := corrosion.ProjectReserved(ctx, s.db, "_default")
	if err != nil {
		t.Fatalf("ProjectReserved: %v", err)
	}
	if afterCPU != beforeCPU || afterMem != beforeMem {
		t.Errorf("project reserved moved to (%d,%d) from (%d,%d) — a start grows no project allocation and must not charge quota",
			afterCPU, afterMem, beforeCPU, beforeMem)
	}
}

// readReservationVector decodes the reservation an operation row is holding.
func readReservationVector(t *testing.T, s *Server, opID string) corrosion.ReservationVector {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT reservation_json FROM operations WHERE id = ?`, opID)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read operation %s: err=%v rows=%d", opID, err, len(rows))
	}
	rv, err := corrosion.DecodeReservation(rows[0].String("reservation_json"))
	if err != nil {
		t.Fatalf("decode reservation: %v", err)
	}
	return rv
}

// TestAdmitGrowWithReservation_RecordsIdentityAndAbsoluteTarget: a grow's
// reservation must name the workload it grows and the ABSOLUTE size it grows it
// to. Without those the settle rule sees the (already-present) row and frees the
// lease instantly, while the quota check still counts the old size — the
// under-count that let concurrent resizes over-admit.
func TestAdmitGrowWithReservation_RecordsIdentityAndAbsoluteTarget(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)

	lease, err := s.admitGrowWithReservation(context.Background(), "UpdateVM", "test-host", "proj",
		corrosion.WorkloadVM, "vm-g", 2, 512, 6, 4608)
	if err != nil {
		t.Fatalf("admitGrowWithReservation: %v", err)
	}
	defer lease.release(context.Background())
	if lease.id == "" {
		t.Fatal("grow admission produced no reservation operation")
	}

	rv := readReservationVector(t, s, lease.id)
	if rv.Workload != "vm-g" || rv.WorkloadKind != corrosion.WorkloadVM || rv.WorkloadHost != "test-host" {
		t.Errorf("grow reservation identity = (%q,%q,%q), want (vm-g,%s,test-host)",
			rv.Workload, rv.WorkloadKind, rv.WorkloadHost, corrosion.WorkloadVM)
	}
	if rv.WantCPU != 6 || rv.WantMemMiB != 4608 {
		t.Errorf("grow reservation want = %d vCPU/%d MiB, want the ABSOLUTE target 6/4608 — "+
			"the delta alone cannot tell the settle when the grow has landed", rv.WantCPU, rv.WantMemMiB)
	}
	if rv.ProjectCPU != 2 || rv.ProjectMemMiB != 512 {
		t.Errorf("grow reservation charges %d vCPU/%d MiB, want the DELTA 2/512 — "+
			"charging the absolute size would double-count the part already in usage", rv.ProjectCPU, rv.ProjectMemMiB)
	}
}

// TestAdmitWithReservation_ACreateRecordsItsOwnSizeAsTheTarget: for a create the
// workload does not exist yet, so its absolute target IS its delta, and the
// identity must still be recorded — a created-but-unreplicated workload may only
// retire its own charge.
func TestAdmitWithReservation_ACreateRecordsItsOwnSizeAsTheTarget(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)

	lease, err := s.admitWithReservation(context.Background(), "CreateContainer", "test-host", "proj",
		"ct:web", 2, 1024, false)
	if err != nil {
		t.Fatalf("admitWithReservation: %v", err)
	}
	defer lease.release(context.Background())

	rv := readReservationVector(t, s, lease.id)
	if rv.Workload != "web" || rv.WorkloadKind != corrosion.WorkloadContainer || rv.WorkloadHost != "test-host" {
		t.Errorf("create reservation identity = (%q,%q,%q), want (web,%s,test-host)",
			rv.Workload, rv.WorkloadKind, rv.WorkloadHost, corrosion.WorkloadContainer)
	}
	if rv.WantCPU != 2 || rv.WantMemMiB != 1024 {
		t.Errorf("create reservation want = %d/%d, want 2/1024 (a create's target is its own size)",
			rv.WantCPU, rv.WantMemMiB)
	}
}

// TestReservationLease_FenceAbortsWhenAuthorityMoves: a grant made under epoch N
// must not commit once the authority has moved to N+1. The successor's view cannot
// contain this (possibly un-replicated) lease, so it may already have admitted the
// same quota — the only sound resolution is aborting before the durable write.
func TestReservationLease_FenceAbortsWhenAuthorityMoves(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	applied, err := corrosion.ClaimInitialProjectAuthority(ctx, s.db, "proj", "test-host")
	if err != nil || !applied {
		t.Fatalf("ClaimInitialProjectAuthority: applied=%v err=%v", applied, err)
	}
	lease := &reservationLease{s: s, quotaProject: "proj", quotaHolder: "test-host", quotaEpoch: 1}

	// Authority unchanged: the grant may commit.
	if err := lease.allowCommit(ctx); err != nil {
		t.Fatalf("fence refused while the granting authority is still current: %v", err)
	}

	// A planned takeover mints epoch 2. The epoch-1 grant is now uncovered.
	if _, ok, terr := corrosion.TakeoverProjectAuthority(ctx, s.db, "proj", "other-host", "planned", "", 1); terr != nil || !ok {
		t.Fatalf("TakeoverProjectAuthority: ok=%v err=%v", ok, terr)
	}
	err = lease.allowCommit(ctx)
	if err == nil {
		t.Fatal("fence allowed a commit under a superseded authority epoch — the successor may have admitted the same quota")
	}
	if status.Code(err) != codes.Aborted {
		t.Errorf("fence refusal code = %v, want Aborted (a retry-able, nothing-committed refusal)", status.Code(err))
	}
}

// TestReservationLease_FenceZeroValueAllows: an admission that reserved no quota
// (unbounded project, delegation inactive, host-only) has no authority to lose.
// Blocking it would fail every create on a quota-less project.
func TestReservationLease_FenceZeroValueAllows(t *testing.T) {
	ctx := context.Background()
	var nilLease *reservationLease
	if err := nilLease.allowCommit(ctx); err != nil {
		t.Errorf("nil lease fence refused: %v", err)
	}
	if err := (&reservationLease{}).allowCommit(ctx); err != nil {
		t.Errorf("zero lease fence refused: %v", err)
	}
	s := testServer(t)
	if err := (&reservationLease{s: s, quotaProject: "proj"}).allowCommit(ctx); err != nil {
		t.Errorf("epoch-0 lease fence refused: %v — no epoch-bearing authority backed this grant", err)
	}
}
