package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestUpdateVM_MaxCPU_GatedOnLatch: setting a vCPU hotplug ceiling is refused until
// live_resize is enabled AND latched; once it is, max_cpu persists and the redefined
// domain carries the <vcpu current=…> hotplug headroom.
func TestUpdateVM_MaxCPU_GatedOnLatch(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "hp", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "hp", Cpu: 2, MemoryMib: 2048}))

	// Not latched → refused.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", MaxCpu: proto.Int32(8)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("max_cpu without latch: want FailedPrecondition, got %v", err)
	}

	// Enable + latch live_resize.
	s.SetLiveResize(true)
	s.SetGate(fakeServerGate{enforcedTok: map[string]bool{capabilities.LiveResizeV1: true}})

	// max_cpu below cpu is rejected.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", MaxCpu: proto.Int32(1)}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("max_cpu < cpu: want InvalidArgument, got %v", err)
	}

	// Valid ceiling → stored + XML headroom.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "hp", MaxCpu: proto.Int32(8)}); err != nil {
		t.Fatalf("latched max_cpu: %v", err)
	}
	spec := loadStoredSpec(t, s, "hp")
	if spec.MaxCpu != 8 {
		t.Errorf("max_cpu not persisted: got %d, want 8", spec.MaxCpu)
	}
	got, err := s.virt.DumpXML("hp")
	if err != nil {
		t.Fatalf("DumpXML: %v", err)
	}
	if !strings.Contains(got, `current="2"`) || !strings.Contains(got, ">8</vcpu>") {
		t.Errorf("redefined domain missing vCPU hotplug headroom:\n%s", got)
	}
}
