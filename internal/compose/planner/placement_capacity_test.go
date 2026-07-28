package planner

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Compose planning must place under the cluster's configured capacity policy —
// not the built-in defaults — or the plan targets hosts that admission
// (which uses the configured policy) then refuses at deploy time.
func TestBuildPlacementRequest_CarriesCapacityPolicy(t *testing.T) {
	pol := corrosion.CapacityPolicy{
		CPUOvercommit: 2.0, MemOvercommit: 1.0,
		CPUReserve: 2, MemReserveMiB: 8192, MemReservePct: 10, VMMemOverheadMiB: 256,
	}
	spec := &pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 2048}

	req := buildPlacementRequest(spec, pol)

	if req.Capacity != pol {
		t.Errorf("req.Capacity = %+v, want configured policy %+v", req.Capacity, pol)
	}
	if req.VMName != "vm1" || req.CPUNeeded != 2 || req.MemMiBNeeded != 2048 {
		t.Errorf("basic fields wrong: %+v", req)
	}
}
