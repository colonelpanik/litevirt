package grpcapi

import (
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestGetClusterStatus_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	cs, err := s.GetClusterStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	if cs.HostsTotal != 0 {
		t.Errorf("HostsTotal = %d, want 0", cs.HostsTotal)
	}
	if cs.VmsTotal != 0 {
		t.Errorf("VmsTotal = %d, want 0", cs.VmsTotal)
	}
}

func TestGetClusterStatus_WithData(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestHost(t, ctx, s.db, "node-1", "active")
	insertTestHost(t, ctx, s.db, "node-2", "offline")

	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-1", HostName: "node-1", State: "running",
	}, nil, nil)
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-2", HostName: "node-1", State: "error",
	}, nil, nil)
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-3", HostName: "node-2", State: "stopped",
	}, nil, nil)

	cs, err := s.GetClusterStatus(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetClusterStatus: %v", err)
	}
	if cs.HostsTotal != 2 {
		t.Errorf("HostsTotal = %d, want 2", cs.HostsTotal)
	}
	if cs.HostsActive != 1 {
		t.Errorf("HostsActive = %d, want 1", cs.HostsActive)
	}
	if cs.VmsTotal != 3 {
		t.Errorf("VmsTotal = %d, want 3", cs.VmsTotal)
	}
	if cs.VmsRunning != 1 {
		t.Errorf("VmsRunning = %d, want 1", cs.VmsRunning)
	}
	if cs.VmsError != 1 {
		t.Errorf("VmsError = %d, want 1", cs.VmsError)
	}
	if len(cs.Hosts) != 2 {
		t.Errorf("Hosts count = %d, want 2", len(cs.Hosts))
	}
}
