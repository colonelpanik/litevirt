package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// admitServer builds a server owning "test-host" with the given total memory.
// Allocatable = total - 1024 MiB default reserve (see DefaultCapacityPolicy).
func admitServer(t *testing.T, memTotal int) (*Server, context.Context) {
	t.Helper()
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.9", State: "active", CPUTotal: 64, MemTotal: memTotal,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	return s, ctx
}

// TestStartVM_HostAndVMShareAName_NoDeadlock is the case that a single
// name-keyed lock map would have hung: StartVM takes lockVM("web") and then
// admits capacity for the host, which is ALSO named "web". With one map and one
// non-reentrant mutex that self-deadlocks. Separate maps make it safe.
//
// The deadline is the assertion: on a deadlock the test times out rather than
// failing an equality check.
func TestStartVM_HostAndVMShareAName_NoDeadlock(t *testing.T) {
	s := testServerR2(t)
	s.hostName = "web"
	s.virt = libvirtfake.New()
	ctx, cancel := context.WithTimeout(adminCtx(), 10*time.Second)
	defer cancel()

	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "web", Address: "10.0.0.9", State: "active", CPUTotal: 16, MemTotal: 16384,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web", HostName: "web", State: "stopped", CPUActual: 1, MemActual: 1024,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 1024}),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>web</name><devices></devices></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.StartVM(ctx, &pb.StartVMRequest{Name: "web"})
	}()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("StartVM deadlocked when the host and the VM share a name — the host-admission " +
			"ledger must not share vmLocks' key space")
	}
}

// TestStartVM_AlreadyRunningReservesNothing guards the hoist: the release func is
// declared outside `if vm.State != "running"` so it can span startVMLocked, and it
// must stay a no-op when admission is skipped. Asserted against the REPLICATED
// reservation store — the only in-flight ledger since reserve-then-verify.
func TestStartVM_AlreadyRunningReservesNothing(t *testing.T) {
	s, ctx := admitServer(t, 16384)

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "up", HostName: "test-host", State: "running", CPUActual: 1, MemActual: 1024,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "up", Cpu: 1, MemoryMib: 1024}),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>up</name><devices></devices></domain>`); err != nil {
		t.Fatalf("DefineDomain: %v", err)
	}

	_, _ = s.StartVM(ctx, &pb.StartVMRequest{Name: "up"})

	cpu, mem, err := corrosion.HostReserved(ctx, s.db, "test-host")
	if err != nil {
		t.Fatalf("HostReserved: %v", err)
	}
	if cpu != 0 || mem != 0 {
		t.Errorf("reserved %d vCPU/%d MiB after starting an ALREADY-RUNNING VM, want 0/0 — "+
			"a no-op start adds nothing and must reserve nothing (a leak here would slowly "+
			"starve the host of admissions)", cpu, mem)
	}
}

// TestAdmission_IncomingVMPaysItsOwnOverhead pins the P2 asymmetry on the LIVE
// primitives (the in-process ledger that first pinned it is gone):
//
// Free capacity is computed net of one qemu overhead per VM ALREADY on the host,
// so an incoming VM compared as bare guest memory disagrees by exactly one
// overhead. 4096 total → 3072 allocatable: a 3072 MiB VM "fits exactly" and must
// be refused; 2944 (3072 − 128) is the largest that genuinely fits. And a GROW of
// a running VM must NOT pay the overhead again — its own is already subtracted —
// so growing by exactly the remaining free memory is legal.
func TestAdmission_IncomingVMPaysItsOwnOverhead(t *testing.T) {
	s, ctx := admitServer(t, 4096) // 3072 allocatable

	if _, err := s.admitHostWithReservation(ctx, "StartVM", "test-host", "_default",
		"vm:dense", 1, 3072, intentVMResident); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("a 3072 MiB VM on 3072 allocatable: got %v, want ResourceExhausted — "+
			"the incoming domain draws guest memory plus its own overhead", err)
	}
	lease, err := s.admitHostWithReservation(ctx, "StartVM", "test-host", "_default",
		"vm:fits", 1, 2944, intentVMResident)
	if err != nil {
		t.Fatalf("a 2944 MiB VM (3072 − overhead) was refused: %v", err)
	}
	lease.release(ctx)

	// A running VM at 1024 → free = 3072 − 1024 − 128 = 1920. Growing by exactly
	// that must be allowed (overhead already counted), and the same figures as a
	// NEW resident VM must be refused — the asymmetry the intent encodes.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "grow", HostName: "test-host", State: "running", CPUActual: 1, MemActual: 1024,
		Spec: seedSpecJSON(t, &pb.VMSpec{Name: "grow", Cpu: 1, MemoryMib: 1024}),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	glease, err := s.admitGrowWithReservation(ctx, "UpdateVM", "test-host", "_default",
		corrosion.WorkloadVM, "grow", 0, 1920, 1, 2944)
	if err != nil {
		t.Fatalf("growing a RUNNING VM by exactly the free memory was refused (%v) — its "+
			"overhead is already subtracted and must not be charged twice", err)
	}
	glease.release(ctx)
	if _, err := s.admitHostWithReservation(ctx, "StartVM", "test-host", "_default",
		"vm:newbie", 0, 1920, intentVMResident); status.Code(err) != codes.ResourceExhausted {
		t.Errorf("a NEW 1920 MiB VM with only 1920 free: got %v, want ResourceExhausted", err)
	}
}
