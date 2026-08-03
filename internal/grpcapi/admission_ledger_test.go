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

// TestAdmitHostCapacity_ReservationBlocksSecondAdmit is the core of the fix.
//
// A lock held only across the CHECK would not close the race: on the create path
// the commit happens minutes later (image pull, disk creation, DefineDomain), so
// two callers would both check, both pass, and both commit. What makes admission
// safe is the RESERVATION spanning the commit. This test therefore holds the first
// release func — simulating a create still in flight — and requires the second
// admit to be refused.
func TestAdmitHostCapacity_ReservationBlocksSecondAdmit(t *testing.T) {
	// 3072 allocatable: room for exactly two 1536 MiB admissions.
	s, ctx := admitServer(t, 4096)

	release1, err := s.admitHostCapacity(ctx, "test-host", 1, 1536)
	if err != nil {
		t.Fatalf("first admit: %v", err)
	}
	release2, err := s.admitHostCapacity(ctx, "test-host", 1, 1536)
	if err != nil {
		t.Fatalf("second admit (still fits): %v", err)
	}

	// Third must be refused: nothing has committed yet, but 3072 MiB is already
	// promised to the two in-flight requests.
	if _, err := s.admitHostCapacity(ctx, "test-host", 1, 1536); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("third admit with the host fully reserved: got %v, want ResourceExhausted — "+
			"an admitted-but-uncommitted request must still count", err)
	}

	// Releasing one frees exactly one slot.
	release1()
	release3, err := s.admitHostCapacity(ctx, "test-host", 1, 1536)
	if err != nil {
		t.Fatalf("admit after releasing one reservation: %v", err)
	}
	release2()
	release3()

	st := s.hostAdmitStateFor("test-host")
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pendingCPU != 0 || st.pendingMem != 0 {
		t.Errorf("ledger after releasing everything = %d vCPU/%d MiB, want 0/0",
			st.pendingCPU, st.pendingMem)
	}
}

// TestAdmitHostCapacity_ReleaseIsIdempotent: a caller may both defer release and
// release early. A double release must not hand the same capacity out twice.
func TestAdmitHostCapacity_ReleaseIsIdempotent(t *testing.T) {
	s, ctx := admitServer(t, 4096)

	release, err := s.admitHostCapacity(ctx, "test-host", 2, 1024)
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	release()
	release()
	release()

	st := s.hostAdmitStateFor("test-host")
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pendingCPU != 0 || st.pendingMem != 0 {
		t.Errorf("ledger after a triple release = %d vCPU/%d MiB, want 0/0 — a repeated "+
			"release must not credit the ledger more than once", st.pendingCPU, st.pendingMem)
	}
}

// TestAdmitHostCapacity_RemoteHostDoesNotReserve: we only reserve what we will
// commit. Reserving on a host we are merely fail-fast checking would leak a
// phantom draw on that host's ledger that nothing ever releases against reality.
func TestAdmitHostCapacity_RemoteHostDoesNotReserve(t *testing.T) {
	s, ctx := admitServer(t, 16384)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "other-host", Address: "10.0.0.10", State: "active", CPUTotal: 64, MemTotal: 16384,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	release, err := s.admitHostCapacity(ctx, "other-host", 1, 1024)
	if err != nil {
		t.Fatalf("admit on a remote host: %v", err)
	}
	defer release()

	s.hostAdmitMu.Lock()
	st, ok := s.hostAdmit["other-host"]
	s.hostAdmitMu.Unlock()
	if ok && st != nil {
		st.mu.Lock()
		pending := st.pendingMem
		st.mu.Unlock()
		if pending != 0 {
			t.Errorf("remote host ledger = %d MiB pending, want 0 — the owner reserves, not us", pending)
		}
	}
}

// TestAdmitHostCapacity_ShrinkAndNoopReserveNothing: only growth consumes
// capacity. A shrink that reserved would refuse the very operation that frees
// memory.
func TestAdmitHostCapacity_ShrinkAndNoopReserveNothing(t *testing.T) {
	s, ctx := admitServer(t, 4096)

	for _, c := range []struct{ cpu, mem int }{{0, 0}, {-1, -512}, {0, -512}} {
		release, err := s.admitHostCapacity(ctx, "test-host", c.cpu, c.mem)
		if err != nil {
			t.Fatalf("admit(%d,%d): %v", c.cpu, c.mem, err)
		}
		release()
	}
	st := s.hostAdmitStateFor("test-host")
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pendingCPU != 0 || st.pendingMem != 0 {
		t.Errorf("ledger = %d/%d after shrinks and no-ops, want 0/0", st.pendingCPU, st.pendingMem)
	}
}

// TestAdmitHostCapacity_OvercommitReserveIsVisible: --allow-overcommit skips the
// CHECK, but hiding its DRAW would let the very next normal admission overcommit
// again on top of it.
func TestAdmitHostCapacity_OvercommitReserveIsVisible(t *testing.T) {
	s, ctx := admitServer(t, 4096) // 3072 allocatable

	release := s.reserveHostCapacity("test-host", 1, 3072)
	defer release()

	if _, err := s.admitHostCapacity(ctx, "test-host", 1, 1024); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("normal admit after an overcommit reservation consumed the host: got %v, "+
			"want ResourceExhausted — an overcommit draw must be visible to the next admission", err)
	}
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
// must stay a no-op when admission is skipped. It also guards the closure form —
// `defer release()` instead of `defer func(){ release() }()` would capture the
// no-op and silently never release a real reservation.
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

	st := s.hostAdmitStateFor("test-host")
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.pendingMem != 0 || st.pendingCPU != 0 {
		t.Errorf("ledger = %d vCPU/%d MiB after starting an ALREADY-RUNNING VM, want 0/0 — "+
			"a no-op start adds nothing and must reserve nothing (a leak here would slowly "+
			"starve the host of admissions)", st.pendingCPU, st.pendingMem)
	}
}
