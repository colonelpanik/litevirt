package planner

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
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

// Running containers in the snapshot must count against host memory during
// plan-time batch placement, exactly as they do at deploy-time admission —
// otherwise the plan succeeds and CreateVM then refuses.
func TestResolve_ContainerMemoryCountsAgainstHosts(t *testing.T) {
	f := makeFile("mystack", map[string]compose.VMDef{
		// Default policy: allocatable = 4096 - max(1024, 5%) = 3072 MiB.
		// The 2800 MiB running container leaves 272 — this VM must not place.
		"web": {Image: "ubuntu", CPU: 1, Memory: 2048},
	})
	state := makeState(
		[]corrosion.HostRecord{makeHost("h1", 8, 4096)},
		nil, nil,
	)
	state.Containers = []corrosion.ContainerRecord{
		{Name: "hog", HostName: "h1", State: "running", MemMiB: 2800},
	}

	if _, err := Resolve(context.Background(), f, state); err == nil {
		t.Fatal("expected placement failure: container memory must count against the host at plan time")
	}
}
