package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/health"
)

// TestServerSatisfiesStackCleaner pins the interface wiring. If someone renames the
// cleanup method back to DeleteVM, the reconciler starts calling the RBAC-gated RPC again
// and the 30s failure loop returns — so the compile-time assertion IS the guard.
func TestServerSatisfiesStackCleaner(t *testing.T) {
	var _ health.StackCleaner = (*Server)(nil)
}

// TestDeleteVMForStackCleanup_AttachesASystemPrincipal is the regression test for the
// 2026-08-06 production incident.
//
// The stack reconciler is a background loop with no identity, and DeleteVM is RBAC-gated,
// so the reconciler's call failed "no authenticated principal" EVERY time. Because a
// failure is treated as retryable it looped every 30s indefinitely: the stack never
// finished deleting, and the VM could not be removed from the UI either.
//
// The assertion is deliberately "not Unauthenticated" rather than "succeeds": a bare
// server has no libvirt or VM, so the call fails later for unrelated reasons. What must
// never happen again is failing at the AUTH gate.
func TestDeleteVMForStackCleanup_AttachesASystemPrincipal(t *testing.T) {
	s := testServer(t)

	// Background context — exactly what the reconciler passes.
	_, err := s.DeleteVMForStackCleanup(context.Background(), &pb.DeleteVMRequest{Name: "gone"})
	if status.Code(err) == codes.Unauthenticated {
		t.Fatalf("stack cleanup was rejected at the auth gate (%v) — a background loop has no "+
			"identity, so the cleanup wrapper must attach a system principal or the stack "+
			"deletion retries forever", err)
	}

	// And the un-wrapped handler must still REJECT an identity-less context, or the test
	// above would pass for the wrong reason (i.e. because the gate stopped working).
	if _, err := s.DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "gone"}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("DeleteVM with no principal returned %v, want Unauthenticated — the RBAC gate "+
			"itself must stay intact; the wrapper is what supplies identity", err)
	}
}
