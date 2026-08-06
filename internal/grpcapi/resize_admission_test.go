package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestResizeAdmission_DisputedWorkloadRefused: the coordinated live-resize
// admission passes the same host-safety gate as the equivalent UpdateVM grow —
// a VM under an active ownership condition must not be live-grown through the
// one admission path that skipped the gate.
func TestResizeAdmission_DisputedWorkloadRefused(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	ctx := context.Background()
	seedOwnershipCondition(t, s, "vm_dual_run", "vm", "drifted", "elsewhere-1", "elsewhere-2")

	vm := &corrosion.VMRecord{Name: "drifted", HostName: "test-host", Project: "proj", State: "running"}
	_, err := s.admitResizeReservation(ctx, newID(), "ResizeVMLive", "op@local", vm, 1, 512, 2, 1024)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("live-resize grow of a disputed workload: got %v, want FailedPrecondition — "+
			"UpdateVM refuses this same grow, and resize must not be the side door", err)
	}

	// An undisputed workload on the same host still admits.
	clean := &corrosion.VMRecord{Name: "clean-vm", HostName: "test-host", Project: "proj", State: "running"}
	lease, err := s.admitResizeReservation(ctx, newID(), "ResizeVMLive", "op@local", clean, 1, 512, 2, 1024)
	if err != nil {
		t.Fatalf("live-resize of an undisputed workload refused: %v", err)
	}
	lease.release(ctx)
}
