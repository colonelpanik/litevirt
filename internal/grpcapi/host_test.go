package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestHostStateToPB_NeverMasqueradesAsActive guards the host-state display
// mapping: "fenced", "upgrading", and unknown future states must not report
// as HOST_ACTIVE, which would show a dead or transitioning host as healthy in
// `lv host ls` / UI / REST.
func TestHostStateToPB_NeverMasqueradesAsActive(t *testing.T) {
	cases := []struct {
		in   string
		want pb.HostState
	}{
		{"active", pb.HostState_HOST_ACTIVE},
		{"draining", pb.HostState_HOST_DRAINING},
		{"maintenance", pb.HostState_HOST_MAINTENANCE},
		{"suspect", pb.HostState_HOST_SUSPECT},
		{"offline", pb.HostState_HOST_OFFLINE},
		{"fenced", pb.HostState_HOST_OFFLINE},            // fenced ⇒ down, not active
		{"upgrading", pb.HostState_HOST_DRAINING},        // transient, not steady-active
		{"some-future-state", pb.HostState_HOST_OFFLINE}, // fail safe: unknown ≠ active
	}
	for _, c := range cases {
		if got := hostStateToPB(c.in); got != c.want {
			t.Errorf("hostStateToPB(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func insertTestHost(t *testing.T, ctx context.Context, db *corrosion.Client, name, state string) {
	t.Helper()
	err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name:     name,
		Address:  "10.0.0.1",
		SSHUser:  "root",
		SSHPort:  22,
		GRPCPort: 7443,
		State:    state,
		CPUTotal: 8,
		MemTotal: 16384,
	})
	if err != nil {
		t.Fatalf("InsertHost(%s): %v", name, err)
	}
}

func TestListHosts_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(resp.Hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(resp.Hosts))
	}
}

func TestListHosts_WithHosts(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestHost(t, ctx, s.db, "node-1", "active")
	insertTestHost(t, ctx, s.db, "node-2", "draining")

	resp, err := s.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(resp.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(resp.Hosts))
	}

	// Verify states are mapped correctly.
	stateMap := map[string]pb.HostState{}
	for _, h := range resp.Hosts {
		stateMap[h.Name] = h.State
	}
	if stateMap["node-1"] != pb.HostState_HOST_ACTIVE {
		t.Errorf("node-1 state = %v, want ACTIVE", stateMap["node-1"])
	}
	if stateMap["node-2"] != pb.HostState_HOST_DRAINING {
		t.Errorf("node-2 state = %v, want DRAINING", stateMap["node-2"])
	}
}

func TestListHosts_IncludesVMCount(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestHost(t, ctx, s.db, "node-1", "active")
	// Insert a VM on node-1.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:     "vm-1",
		HostName: "node-1",
		State:    "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	resp, err := s.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(resp.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(resp.Hosts))
	}
	if resp.Hosts[0].VmCount != 1 {
		t.Errorf("VmCount = %d, want 1", resp.Hosts[0].VmCount)
	}
}

func TestInspectHost_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "no-such-host"})
	if err == nil {
		t.Fatal("expected error for non-existent host")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestInspectHost_Found(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestHost(t, ctx, s.db, "my-host", "active")

	h, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "my-host"})
	if err != nil {
		t.Fatalf("InspectHost: %v", err)
	}
	if h.Name != "my-host" {
		t.Errorf("Name = %q, want my-host", h.Name)
	}
	if h.CpuTotal != 8 {
		t.Errorf("CpuTotal = %d, want 8", h.CpuTotal)
	}
	if h.State != pb.HostState_HOST_ACTIVE {
		t.Errorf("State = %v, want ACTIVE", h.State)
	}
}

func TestGetHostHealth_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.GetHostHealth(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetHostHealth: %v", err)
	}
	if len(resp.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(resp.Entries))
	}
}

func TestPing(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.Ping(ctx, &pb.PingRequest{})
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if resp.HostName != "test-host" {
		t.Errorf("HostName = %q, want test-host", resp.HostName)
	}
}

func TestSetHostLabels_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
		Name:   "missing",
		Labels: map[string]string{"gpu": "true"},
	})
	if err == nil {
		t.Fatal("expected error for non-existent host")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestSetHostLabels_AddAndRemove(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestHost(t, ctx, s.db, "labelled-host", "active")

	// Add labels.
	h, err := s.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
		Name:   "labelled-host",
		Labels: map[string]string{"gpu": "nvidia", "zone": "us-east"},
	})
	if err != nil {
		t.Fatalf("SetHostLabels add: %v", err)
	}
	if h.Name != "labelled-host" {
		t.Errorf("Name = %q, want labelled-host", h.Name)
	}

	// Remove one label.
	h, err = s.SetHostLabels(ctx, &pb.SetHostLabelsRequest{
		Name:   "labelled-host",
		Remove: []string{"zone"},
	})
	if err != nil {
		t.Fatalf("SetHostLabels remove: %v", err)
	}
	_ = h
}

func TestUndrainHost_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.UndrainHost(ctx, &pb.UndrainHostRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestUndrainHost_Success(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestHost(t, ctx, s.db, "drain-me", "draining")

	h, err := s.UndrainHost(ctx, &pb.UndrainHostRequest{Name: "drain-me"})
	if err != nil {
		t.Fatalf("UndrainHost: %v", err)
	}
	if h.State != pb.HostState_HOST_ACTIVE {
		t.Errorf("State = %v, want ACTIVE", h.State)
	}
}

func TestFenceHost_NotConfirmed(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.FenceHost(ctx, &pb.FenceHostRequest{Name: "h1", Confirmed: false})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestFenceHost_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.FenceHost(ctx, &pb.FenceHostRequest{Name: "missing", Confirmed: true})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestRemoveHost_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.RemoveHost(ctx, &pb.RemoveHostRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestRemoveHost_HasVMs_NoForce(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestHost(t, ctx, s.db, "busy-host", "active")
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:     "vm-on-busy",
		HostName: "busy-host",
		State:    "running",
	}, nil, nil)

	_, err := s.RemoveHost(ctx, &pb.RemoveHostRequest{Name: "busy-host", Force: false})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestRemoveHost_HasVMs_Force(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestHost(t, ctx, s.db, "busy-host2", "active")
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:     "vm-on-busy2",
		HostName: "busy-host2",
		State:    "running",
	}, nil, nil)

	_, err := s.RemoveHost(ctx, &pb.RemoveHostRequest{Name: "busy-host2", Force: true})
	if err != nil {
		t.Fatalf("RemoveHost force: %v", err)
	}
}

func TestRemoveHost_NoVMs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestHost(t, ctx, s.db, "empty-host", "active")

	_, err := s.RemoveHost(ctx, &pb.RemoveHostRequest{Name: "empty-host"})
	if err != nil {
		t.Fatalf("RemoveHost: %v", err)
	}
}

func TestNewID_UniqueAndLength(t *testing.T) {
	id1 := newID()
	id2 := newID()
	if id1 == id2 {
		t.Error("newID returned same value twice")
	}
	if len(id1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("newID length = %d, want 16", len(id1))
	}
}

func TestLiveHostStats_NoVMs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	cpu, mem, _ := s.hostAllocatedResources(ctx, s.hostName)
	if cpu != 0 || mem != 0 {
		t.Errorf("hostAllocatedResources with no VMs: cpu=%d mem=%d, want 0,0", cpu, mem)
	}
}

func TestLiveHostStats_WithRunningVMs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Insert VMs on this host (hostName = "test-host").
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "vm-a",
		HostName:  "test-host",
		State:     "running",
		CPUActual: 2,
		MemActual: 2048,
	}, nil, nil)
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "vm-b",
		HostName:  "test-host",
		State:     "stopped", // should not count
		CPUActual: 4,
		MemActual: 8192,
	}, nil, nil)

	cpu, mem, _ := s.hostAllocatedResources(ctx, s.hostName)
	if cpu != 2 {
		t.Errorf("cpu = %d, want 2", cpu)
	}
	if mem != 2048 {
		t.Errorf("mem = %d, want 2048", mem)
	}
}
