package grpcapi

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// coordResizeServer latches BOTH live_resize and operation_protocol, so resizes take
// the post-latch F1 durability path.
func coordResizeServer(t *testing.T) *Server {
	t.Helper()
	s := reconfigServer(t)
	s.SetLiveResize(true)
	s.SetOperationProtocol(true)
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{
		capabilities.LiveResizeV1:        true,
		capabilities.OperationProtocolV1: true,
	}})
	return s
}

func seedRunningVM(t *testing.T, s *Server, name string, spec *pb.VMSpec, cpuActual, memActual int) {
	t.Helper()
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: name, HostName: "test-host", State: "running",
		CPUActual: cpuActual, MemActual: memActual, Spec: seedSpecJSON(t, spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
	if err := s.virt.DefineDomain(`<domain type='kvm'><name>` + name + `</name><memory unit='KiB'>2097152</memory><vcpu current='2'>8</vcpu></domain>`); err != nil {
		t.Fatalf("seed domain: %v", err)
	}
}

// A combined cpu+mem live resize under both latches applies both dimensions, persists
// the desired spec + actuals, and clears the mutation barrier on completion.
func TestResizeVMLive_CombinedLive_Coordinated(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	seedRunningVM(t, s, "co", &pb.VMSpec{Name: "co", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, MinMemoryMib: 1024, MaxMemoryMib: 8192}, 2, 2048)

	if err := s.resizeVMLive(ctx, "co", &pb.VMSpec{Cpu: 4, MemoryMib: 3072}, "k1"); err != nil {
		t.Fatalf("combined live resize: %v", err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "co")
	if vm.CPUActual != 4 || vm.MemActual != 3072 {
		t.Errorf("actuals = %d/%d, want 4/3072", vm.CPUActual, vm.MemActual)
	}
	if vm.ActiveOperationID != "" {
		t.Errorf("mutation barrier not cleared: %q", vm.ActiveOperationID)
	}
	if spec := loadStoredSpec(t, s, "co"); spec.Cpu != 4 || spec.MemoryMib != 3072 {
		t.Errorf("desired spec = %d/%d, want 4/3072", spec.Cpu, spec.MemoryMib)
	}
}

// Preflight rejects an out-of-band memory target BEFORE touching the domain — no
// vcpu/memory libvirt call is made.
func TestResizeVMLive_PreflightOutOfBand_NoMutation(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	seedRunningVM(t, s, "ob", &pb.VMSpec{Name: "ob", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, MaxMemoryMib: 4096}, 2, 2048)

	// mem 8192 exceeds the 4096 ceiling; the cpu grow is fine, but preflight must
	// reject the whole resize before applying either dimension.
	err := s.resizeVMLive(ctx, "ob", &pb.VMSpec{Cpu: 4, MemoryMib: 8192}, "k1")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("out-of-band mem: want FailedPrecondition, got %v", err)
	}
	f := s.virt.(*libvirtfake.Fake)
	for _, e := range f.EventLog() {
		if e.Op == "set-vcpus" || e.Op == "set-memory" {
			t.Errorf("preflight rejection still mutated the domain: %s %s", e.Op, e.Note)
		}
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "ob")
	if vm.ActiveOperationID != "" {
		t.Errorf("barrier claimed despite preflight rejection: %q", vm.ActiveOperationID)
	}
}

// A persistent/live apply failure on one dimension (mem) leaves the operation
// NONTERMINAL and RECOVERABLE — the desired spec is committed, the barrier is NOT
// aborted — and a subsequent recovery pass converges it to the committed target.
func TestResizeVMLive_PartialFailure_RecoverableThenConverges(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	seedRunningVM(t, s, "pf", &pb.VMSpec{Name: "pf", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, MinMemoryMib: 1024, MaxMemoryMib: 8192}, 2, 2048)

	f := s.virt.(*libvirtfake.Fake)
	f.FailSetMemory = func(string, int) error { return errors.New("inject balloon failure") }

	// cpu applies, mem fails → partial-success error.
	if err := s.resizeVMLive(ctx, "pf", &pb.VMSpec{Cpu: 4, MemoryMib: 3072}, "k1"); err == nil {
		t.Fatal("expected a partial-success error when the mem apply fails")
	}

	// The op is left nonterminal + recoverable: barrier still held, desired spec
	// committed, NOT aborted/cancelled.
	vm, _ := corrosion.GetVM(ctx, s.db, "pf")
	if vm.ActiveOperationID == "" {
		t.Fatal("barrier cleared on partial failure — must remain for recovery")
	}
	view, ok, _ := corrosion.GetVMActiveOperation(ctx, s.db, "pf")
	if !ok || corrosion.IsOperationTerminal(view.State) {
		t.Fatalf("operation is terminal on partial failure (state=%q) — must stay recoverable", view.State)
	}
	if view.State == corrosion.OpStepCancelled || view.State == corrosion.OpStepFailed {
		t.Errorf("operation was aborted/failed (state=%q) — plan forbids abort on a committed desired", view.State)
	}
	if spec := loadStoredSpec(t, s, "pf"); spec.Cpu != 4 || spec.MemoryMib != 3072 {
		t.Errorf("desired spec not committed at Begin: %d/%d, want 4/3072", spec.Cpu, spec.MemoryMib)
	}

	// Recovery with the fault cleared converges to the committed target + clears the barrier.
	f.FailSetMemory = nil
	s.RecoverResourceOperations(ctx)

	vm, _ = corrosion.GetVM(ctx, s.db, "pf")
	if vm.ActiveOperationID != "" {
		t.Errorf("recovery did not clear the barrier: %q", vm.ActiveOperationID)
	}
	if vm.CPUActual != 4 || vm.MemActual != 3072 {
		t.Errorf("recovery did not converge actuals: %d/%d, want 4/3072", vm.CPUActual, vm.MemActual)
	}
}

// SetVMMemory post-latch routes through the F1 path and updates the DESIRED memory_mib
// (not just the observed actual) while clearing the barrier.
func TestSetVMMemory_PostLatch_UpdatesDesiredSpec(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	seedRunningVM(t, s, "bm", &pb.VMSpec{Name: "bm", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, MinMemoryMib: 1024, MaxMemoryMib: 8192}, 2, 2048)

	if _, err := s.SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "bm", TargetMib: 4096, IdempotencyKey: "m1"}); err != nil {
		t.Fatalf("SetVMMemory post-latch: %v", err)
	}
	if spec := loadStoredSpec(t, s, "bm"); spec.MemoryMib != 4096 {
		t.Errorf("desired memory_mib not updated: %d, want 4096", spec.MemoryMib)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "bm")
	if vm.MemActual != 4096 {
		t.Errorf("mem_actual = %d, want 4096", vm.MemActual)
	}
	if vm.ActiveOperationID != "" {
		t.Errorf("barrier not cleared: %q", vm.ActiveOperationID)
	}
}
