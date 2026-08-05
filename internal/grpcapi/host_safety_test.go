package grpcapi

import (
	"context"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// seedOwnershipCondition plants an ACTIVE ownership condition, the input the
// admission gate reads.
func seedOwnershipCondition(t *testing.T, s *Server, code, subjectKind, subject string, hosts ...string) {
	t.Helper()
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: code, SubjectKind: subjectKind, SubjectID: subject,
		Lifecycle: corrosion.ConditionObserved, Severity: corrosion.SeverityWarning,
		Hosts: hosts, FirstSeen: "2026-08-04T10:00:00Z", LastSeen: "2026-08-04T10:00:00Z",
	}); err != nil {
		t.Fatalf("seed condition: %v", err)
	}
}

// TestHostSafety_OwnershipConditionBlocksInvolvedHost: an active dual-run
// blocks capacity-growing admission to EVERY involved host — even while still
// OBSERVED, before the second scan confirms it. Growing into a possibly-
// corrupting host is not a risk admission gets to take.
func TestHostSafety_OwnershipConditionBlocksInvolvedHost(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	seedOwnershipCondition(t, s, "vm_dual_run", "vm", "web-1", "test-host", "other-host")

	_, err := s.admitWithReservation(context.Background(), "CreateVM", "test-host", "proj",
		"vm:new-vm", 1, 512, true)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("admission to an involved host: got %v, want FailedPrecondition", err)
	}

	// An UNINVOLVED host still admits — the condition scopes to its hosts.
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "clean-host", Address: "10.0.0.7", State: "active", CPUTotal: 16, MemTotal: 8192,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	s2 := testServer(t)
	_ = s2 // placeholder: admission is host-scoped on s; reuse s with the clean host
	lease, err := s.admitWithReservation(context.Background(), "CreateVM", "clean-host", "proj",
		"vm:new-vm", 1, 512, true)
	if err != nil {
		t.Fatalf("admission to an uninvolved host refused: %v", err)
	}
	lease.release(context.Background())
}

// TestHostSafety_AffectedWorkloadBlockedEverywhere: a runtime-changing action
// on the workload NAMED by the condition refuses on any host.
func TestHostSafety_AffectedWorkloadBlockedEverywhere(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	seedOwnershipCondition(t, s, "runtime_owner_mismatch", "vm", "drifted", "elsewhere-1", "elsewhere-2")

	_, err := s.admitGrowWithReservation(context.Background(), "UpdateVM", "test-host", "proj",
		corrosion.WorkloadVM, "drifted", 1, 512, 2, 1024)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("grow of a disputed workload: got %v, want FailedPrecondition", err)
	}
}

// TestHostSafety_OvercommitCannotBypass: --allow-overcommit bypasses numeric
// headroom only. The overcommit draw path consults the same gate.
func TestHostSafety_OvercommitCannotBypass(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	seedOwnershipCondition(t, s, "ct_dual_run", "container", "web", "test-host")

	_, err := s.reserveWithoutCheck(context.Background(), "CreateVM", "test-host", "proj",
		"vm:dense", 64, 65536)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("overcommit reserve on an involved host: got %v, want FailedPrecondition — "+
			"--allow-overcommit bypasses the numeric check only", err)
	}
}

// TestHostSafety_IncompleteInventoryBlocksNewWorkloads: a host that cannot
// account for its own runtime refuses NEW workloads, but a grow of an existing
// one (no new residency) still admits.
func TestHostSafety_IncompleteInventoryBlocksNewWorkloads(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	s.virt = &recordingVirt{listErr: fmt.Errorf("libvirt down")}
	s.invalidateInventoryCache()

	_, err := s.admitWithReservation(context.Background(), "CreateVM", "test-host", "proj",
		"vm:new-vm", 1, 512, true)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("new workload on a blind host: got %v, want FailedPrecondition", err)
	}

	// A grow of an existing workload is not new residency — quota/host checks
	// still run, safety inventory does not block it.
	lease, err := s.admitGrowWithReservation(context.Background(), "UpdateVM", "test-host", "proj",
		corrosion.WorkloadVM, "existing", 1, 512, 2, 1024)
	if err != nil {
		t.Fatalf("grow on a blind host refused: %v — incomplete inventory blocks NEW residency only", err)
	}
	lease.release(context.Background())
}

// TestVIPSafety_DualRunFreezesLBChange_NotPlacement: a VIP dual-holder blocks
// the VIP's LB reconfiguration but must not block unrelated VM placement.
func TestVIPSafety_DualRunFreezesLBChange_NotPlacement(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: "dual_run", Code: "vip_dual_run", SubjectKind: "vip", SubjectID: "10.0.0.100",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
		Hosts: []string{"test-host", "other-host"},
		FirstSeen: "2026-08-04T10:00:00Z", LastSeen: "2026-08-04T10:00:00Z",
	}); err != nil {
		t.Fatalf("seed VIP condition: %v", err)
	}

	if err := s.checkVIPSafety(context.Background(), "10.0.0.100"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("VIP change under a dual-holder: got %v, want FailedPrecondition", err)
	}
	if err := s.checkVIPSafety(context.Background(), "10.0.0.200"); err != nil {
		t.Fatalf("unrelated VIP refused: %v", err)
	}
	// Unrelated VM placement on an involved host is NOT blocked by a VIP condition.
	lease, err := s.admitWithReservation(context.Background(), "CreateVM", "test-host", "proj",
		"vm:unrelated", 1, 512, true)
	if err != nil {
		t.Fatalf("VM placement blocked by a VIP condition: %v — VIP dual-run freezes VIP moves only", err)
	}
	lease.release(context.Background())
}

// TestPlacement_RefusesUnknownCapacity: an incomplete or stale capacity
// observation disqualifies the host as a placement target; a missing one does
// not (bootstrap), and extra runtime-only usage counts against headroom.
func TestPlacement_RefusesUnknownCapacity(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	hosts := []corrosion.HostRecord{
		{Name: "h-fresh", State: "active", CPUTotal: 16, MemTotal: 16384},
		{Name: "h-stale", State: "active", CPUTotal: 16, MemTotal: 16384},
		{Name: "h-incomplete", State: "active", CPUTotal: 16, MemTotal: 16384},
		{Name: "h-virgin", State: "active", CPUTotal: 16, MemTotal: 16384},
	}
	snap := placement.BuildSnapshotFrom(hosts, nil)
	snap.AddCapacityObservations([]corrosion.HostCapacityObservation{
		{HostName: "h-fresh", Complete: true, ExtraCPU: 2, ExtraMemMiB: 2048,
			SampledAt: now.Add(-time.Minute).Format(time.RFC3339)},
		{HostName: "h-stale", Complete: true,
			SampledAt: now.Add(-time.Hour).Format(time.RFC3339)},
		{HostName: "h-incomplete", Complete: false, Detail: "uncapped rogue",
			SampledAt: now.Add(-time.Minute).Format(time.RFC3339)},
	}, now)

	if !snap.CapacityUnknown["h-stale"] {
		t.Error("a stale observation must mark the host unknown")
	}
	if !snap.CapacityUnknown["h-incomplete"] {
		t.Error("an incomplete observation must mark the host unknown")
	}
	if snap.CapacityUnknown["h-fresh"] || snap.CapacityUnknown["h-virgin"] {
		t.Error("fresh and never-sampled hosts must remain eligible")
	}
	if snap.CPUUsed["h-fresh"] != 2 || snap.MemUsed["h-fresh"] != 2048 {
		t.Errorf("runtime-only extra not counted: cpu=%d mem=%d, want 2/2048",
			snap.CPUUsed["h-fresh"], snap.MemUsed["h-fresh"])
	}
}

// TestHostSafety_UncappedRogueBlocksNewResidency: an uncapped RUNTIME-ONLY
// container makes the host's consumption unattributable, so a pinned create
// must refuse exactly like the placement filter does — while a DB-known
// uncapped container (deliberately unlimited, accounted) does not block.
func TestHostSafety_UncappedRogueBlocksNewResidency(t *testing.T) {
	origCap := lxcCapable
	lxcCapable = func() bool { return true }
	defer func() { lxcCapable = origCap }()

	s := testServer(t)
	admissionHost(t, s)
	s.SetContainerRuntime(&fakeCT{
		names:  []string{"rogue"},
		states: map[string]string{"rogue": "running"},
	})
	s.invalidateInventoryCache()

	_, err := s.admitWithReservation(context.Background(), "CreateVM", "test-host", "proj",
		"vm:new-vm", 1, 512, true)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("new workload beside an uncapped rogue: got %v, want FailedPrecondition", err)
	}

	// Account the container in the DB: no longer a rogue, admission opens.
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "test-host", Name: "rogue", State: "running",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	s.invalidateInventoryCache()
	lease, err := s.admitWithReservation(context.Background(), "CreateVM", "test-host", "proj",
		"vm:new-vm", 1, 512, true)
	if err != nil {
		t.Fatalf("DB-accounted uncapped container still blocks: %v", err)
	}
	lease.release(context.Background())
}
