package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestCreateVM_ZeroSpecIsAdmittedAtItsDefaultSize is the regression test for
// admission running BEFORE the 0 → 2 vCPU / 4096 MiB defaults.
//
// A direct API client sending cpu=0/memory=0 — which the implementation documents
// as "use defaults" — was admitted as a ZERO-sized VM: the admission helpers
// early-return on non-positive deltas, placement skips its fit filter behind
// `if req.CPUNeeded > 0`, and a quota check cannot be violated by adding 0. The
// VM was then persisted at 2/4096. Repeating it bypassed project quota and host
// capacity entirely.
//
// The host here has 4096 MiB total, so allocatable is 3072 (default 1024 MiB
// reserve) — less than the 4096 MiB default VM. A zero spec must therefore be
// REFUSED. Before the fix it was accepted.
func TestCreateVM_ZeroSpecIsAdmittedAtItsDefaultSize(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()

	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.9", State: "active", CPUTotal: 8, MemTotal: 4096,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	req := &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "zero", Image: "noimage"}}
	_, err := s.CreateVM(ctx, req)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("CreateVM with cpu=0/memory=0 on a host too small for the DEFAULT size: got %v, "+
			"want ResourceExhausted — a zero spec must be admitted at what it will actually cost", err)
	}

	// The refusal above IS the assertion that admission saw the real numbers: a
	// spec still carrying 0/0 costs nothing, fits anywhere, and would have been
	// ADMITTED on this deliberately-too-small host. It holds regardless of which
	// admission layer (placement or capacity) does the refusing.
	//
	// Deliberately NOT asserted on the caller's req: createVM clones the whole
	// request before touching it, so the caller's object is never mutated — that
	// clone is what stops a caller steering the server-owned UUID. Normalization
	// is applied to the clone that actually gets forwarded (vm.go), which is the
	// copy the owning host re-admits from. Asserting in-place mutation here would
	// pin an implementation detail the design specifically rejects, not the safety
	// property.

	// No partial state from a refused create.
	if rec, gerr := corrosion.GetVM(ctx, s.db, "zero"); gerr == nil && rec != nil {
		t.Errorf("VM row exists after a refused create (state=%q); a rejected admission must "+
			"leave nothing behind", rec.State)
	}
}

// TestCreateVM_ZeroSpecFitsWhenHostIsBigEnough is the other half: normalizing
// must not turn every zero spec into a refusal. On a host with room for the
// default size, a zero spec passes admission — it must fail LATER (no such image)
// and never with ResourceExhausted.
func TestCreateVM_ZeroSpecFitsWhenHostIsBigEnough(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()

	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.9", State: "active", CPUTotal: 16, MemTotal: 16384,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "fits", Image: "noimage"}})
	if status.Code(err) == codes.ResourceExhausted {
		t.Fatalf("CreateVM with cpu=0/memory=0 on a 16 GiB host was refused for capacity (%v); "+
			"the default 2 vCPU/4096 MiB fits and must be admitted", err)
	}
}
