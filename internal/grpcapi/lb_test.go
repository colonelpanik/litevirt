package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestInspectLoadBalancer_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestRefreshLBForStack_EmptyStack(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Should not panic with empty stack name.
	s.refreshLBForStack(ctx, "")
}

// --- ListLoadBalancers ---

func TestLBListEmpty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.ListLoadBalancers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListLoadBalancers: %v", err)
	}
	if len(resp.Lbs) != 0 {
		t.Errorf("expected 0 LBs, got %d", len(resp.Lbs))
	}
}

func TestLBListWithRecords(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Insert two LB config records.
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "web-lb", VIP: "10.0.0.50/24", Algorithm: "roundrobin", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "api-lb", VIP: "10.0.0.51/24", Algorithm: "leastconn", Enabled: false,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	resp, err := s.ListLoadBalancers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListLoadBalancers: %v", err)
	}
	if len(resp.Lbs) != 2 {
		t.Fatalf("expected 2 LBs, got %d", len(resp.Lbs))
	}

	// Build a map for easier assertions.
	byName := map[string]*pb.LoadBalancer{}
	for _, lb := range resp.Lbs {
		byName[lb.Name] = lb
	}

	web := byName["web-lb"]
	if web == nil {
		t.Fatal("web-lb not found")
	}
	if web.Vip != "10.0.0.50/24" {
		t.Errorf("web-lb vip = %q, want 10.0.0.50/24", web.Vip)
	}
	if web.Algorithm != "roundrobin" {
		t.Errorf("web-lb algorithm = %q, want roundrobin", web.Algorithm)
	}
	if web.State != "active" {
		t.Errorf("web-lb state = %q, want active", web.State)
	}

	api := byName["api-lb"]
	if api == nil {
		t.Fatal("api-lb not found")
	}
	if api.State != "disabled" {
		t.Errorf("api-lb state = %q, want disabled", api.State)
	}
	if api.Algorithm != "leastconn" {
		t.Errorf("api-lb algorithm = %q, want leastconn", api.Algorithm)
	}
}

func TestLBListDefaultAlgorithm(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Insert with empty algorithm to test the default.
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "noalgo-lb", VIP: "10.0.0.60/24", Algorithm: "", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	resp, err := s.ListLoadBalancers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListLoadBalancers: %v", err)
	}
	if len(resp.Lbs) != 1 {
		t.Fatalf("expected 1 LB, got %d", len(resp.Lbs))
	}
	if resp.Lbs[0].Algorithm != "roundrobin" {
		t.Errorf("algorithm = %q, want roundrobin", resp.Lbs[0].Algorithm)
	}
}

func TestLBListUnauthorized(t *testing.T) {
	s := testServer(t)
	// No role in context => should fail RequireRole("viewer").
	ctx := context.Background()

	_, err := s.ListLoadBalancers(ctx, &emptypb.Empty{})
	if err == nil {
		t.Fatal("expected permission error")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

// --- InspectLoadBalancer ---

func TestLBInspectFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "myapp-lb", VIP: "10.0.0.100/24", Algorithm: "source", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	lb, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "myapp-lb"})
	if err != nil {
		t.Fatalf("InspectLoadBalancer: %v", err)
	}
	if lb.Name != "myapp-lb" {
		t.Errorf("name = %q, want myapp-lb", lb.Name)
	}
	if lb.Vip != "10.0.0.100/24" {
		t.Errorf("vip = %q, want 10.0.0.100/24", lb.Vip)
	}
	if lb.Algorithm != "source" {
		t.Errorf("algorithm = %q, want source", lb.Algorithm)
	}
	if lb.State != "active" {
		t.Errorf("state = %q, want active", lb.State)
	}
	if lb.ActiveHost != "test-host" {
		t.Errorf("active_host = %q, want test-host", lb.ActiveHost)
	}
}

func TestLBInspectDisabled(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "off-lb", VIP: "10.0.0.200/24", Algorithm: "roundrobin", Enabled: false,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	lb, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "off-lb"})
	if err != nil {
		t.Fatalf("InspectLoadBalancer: %v", err)
	}
	if lb.State != "disabled" {
		t.Errorf("state = %q, want disabled", lb.State)
	}
}

// --- ApplyLB ---

func TestApplyLB_MissingName(t *testing.T) {
	s := newPeerAuthServer(t)
	ctx := mtlsCtx("peer-1")

	_, err := s.ApplyLB(ctx, &pb.ApplyLBRequest{})
	if err == nil {
		t.Fatal("expected error for empty lb_name")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestApplyLB_InvalidVIP(t *testing.T) {
	s := newPeerAuthServer(t)
	ctx := mtlsCtx("peer-1")

	_, err := s.ApplyLB(ctx, &pb.ApplyLBRequest{
		LbName: "test-lb",
		Vip:    "not-an-ip/abc",
	})
	if err == nil {
		t.Fatal("expected error for invalid VIP")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestApplyLB_DefaultAlgorithm(t *testing.T) {
	s := newPeerAuthServer(t)
	ctx := mtlsCtx("peer-1")

	// ApplyLB with valid VIP but no algorithm — should default to "roundrobin".
	// The actual Apply call will fail (no haproxy binary) but the error
	// should be Internal (from lb.Manager.Apply), not InvalidArgument.
	_, err := s.ApplyLB(ctx, &pb.ApplyLBRequest{
		LbName: "test-lb",
		Vip:    "10.0.0.50/24",
		Backends: []*pb.LBBackend{
			{VmName: "web-1", Address: "10.0.0.10"},
		},
		Ports: []*pb.LBPort{
			{Listen: 80, Target: 8080, Protocol: "tcp"},
		},
	})
	if err == nil {
		return // Apply somehow succeeded, that's fine
	}
	if c := status.Code(err); c != codes.Internal {
		t.Errorf("code = %v, want Internal (from lb.Manager.Apply)", c)
	}
}

// ApplyLB is peer-only: a non-peer (bearer) caller — even admin — must be rejected before
// any VIP work, so an authenticated client can't drive an arbitrary VIP bring-up.
func TestApplyLB_RejectsNonPeer(t *testing.T) {
	s := newPeerAuthServer(t)
	_, err := s.ApplyLB(adminCtx(), &pb.ApplyLBRequest{LbName: "x", Vip: "10.0.0.50/24"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-peer ApplyLB must be PermissionDenied; got %v", status.Code(err))
	}
}

// --- RemoveLB ---

func TestRemoveLB_MissingName(t *testing.T) {
	s := newPeerAuthServer(t) // hostName "self", knows host "peer-1"
	ctx := mtlsCtx("peer-1")  // RemoveLB is peer-only

	_, err := s.RemoveLB(ctx, &pb.RemoveLBRequest{})
	if err == nil {
		t.Fatal("expected error for empty lb_name")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

// RemoveLB is a peer-only RPC: a non-peer (operator) caller is refused.
func TestRemoveLB_RejectsNonPeer(t *testing.T) {
	s := newPeerAuthServer(t)
	if _, err := s.RemoveLB(adminCtx(), &pb.RemoveLBRequest{LbName: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("code = %v, want PermissionDenied (peer-only)", status.Code(err))
	}
}

func TestRemoveLB_NonExistent(t *testing.T) {
	s := newPeerAuthServer(t)
	ctx := mtlsCtx("peer-1")

	// RemoveLB for a name that was never applied should still succeed
	// (lb.Manager.Remove is idempotent).
	resp, err := s.RemoveLB(ctx, &pb.RemoveLBRequest{LbName: "ghost-lb"})
	if err != nil {
		t.Fatalf("RemoveLB: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// --- RefreshLB RPC ---

func TestRefreshLB_EmptyStackName(t *testing.T) {
	s := testServer(t)
	ctx := peerCtxFor(t, s, "peer-1")

	resp, err := s.RefreshLB(ctx, &pb.RefreshLBRequest{StackName: ""})
	if err != nil {
		t.Fatalf("RefreshLB: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestRefreshLB_NoVMs(t *testing.T) {
	s := testServer(t)
	ctx := peerCtxFor(t, s, "peer-1")

	resp, err := s.RefreshLB(ctx, &pb.RefreshLBRequest{StackName: "nonexistent"})
	if err != nil {
		t.Fatalf("RefreshLB: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestRefreshLB_VMsWithoutLBSpec(t *testing.T) {
	s := testServer(t)
	ctx := peerCtxFor(t, s, "peer-1")

	spec := &pb.VMSpec{
		Name:      "web-1",
		StackName: "myapp",
		Cpu:       1,
		MemoryMib: 512,
	}
	specJSON, _ := json.Marshal(spec)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "web-1",
		StackName: "myapp",
		HostName:  "test-host",
		Spec:      string(specJSON),
		State:     "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	resp, err := s.RefreshLB(ctx, &pb.RefreshLBRequest{StackName: "myapp"})
	if err != nil {
		t.Fatalf("RefreshLB: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

func TestRefreshLB_VMsWithDisabledLB(t *testing.T) {
	s := testServer(t)
	ctx := peerCtxFor(t, s, "peer-1")

	spec := &pb.VMSpec{
		Name:      "web-1",
		StackName: "myapp",
		Cpu:       1,
		MemoryMib: 512,
		Loadbalancer: &pb.LBSpec{
			Enabled: false,
			Vip:     "10.0.0.50/24",
		},
	}
	specJSON, _ := json.Marshal(spec)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "web-1",
		StackName: "myapp",
		HostName:  "test-host",
		Spec:      string(specJSON),
		State:     "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	resp, err := s.RefreshLB(ctx, &pb.RefreshLBRequest{StackName: "myapp"})
	if err != nil {
		t.Fatalf("RefreshLB: %v", err)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
}

// --- RefreshLBForStack (exported wrapper) ---

func TestRefreshLBForStack_MissingStack(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Should not panic when no VMs exist.
	s.RefreshLBForStack(ctx, "no-such-stack")
}

func TestRefreshLBForStack_VMsWithoutSpec(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// VM with empty spec — should be skipped gracefully.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "bare-1",
		StackName: "bare",
		HostName:  "test-host",
		Spec:      "",
		State:     "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	s.RefreshLBForStack(ctx, "bare")
}

func TestRefreshLBForStack_VMsWithBadJSON(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "bad-1",
		StackName: "badstack",
		HostName:  "test-host",
		Spec:      "{{{invalid json",
		State:     "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	s.RefreshLBForStack(ctx, "badstack")
}

// --- lbBackends ---

func TestLBBackends_NoSuffix(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// lbBackends derives stack name by stripping "-lb" suffix.
	// If the name doesn't end in "-lb", it returns nil.
	backends := s.lbBackends(ctx, "notsuffixed")
	if backends != nil {
		t.Errorf("expected nil for name without -lb suffix, got %v", backends)
	}
}

func TestLBBackends_NoVMs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	backends := s.lbBackends(ctx, "myapp-lb")
	if len(backends) != 0 {
		t.Errorf("expected 0 backends, got %d", len(backends))
	}
}

func TestLBBackends_WithRunningVMs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "app-1",
		StackName: "app",
		HostName:  "other-host",
		Spec:      "{}",
		State:     "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "app-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	backends := s.lbBackends(ctx, "app-lb")
	if len(backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(backends))
	}
	if backends[0].VmName != "app-1" {
		t.Errorf("backend vm_name = %q, want app-1", backends[0].VmName)
	}
	if backends[0].Address != "10.0.0.10" {
		t.Errorf("backend address = %q, want 10.0.0.10", backends[0].Address)
	}
	if backends[0].Status != "active" {
		t.Errorf("backend status = %q, want active", backends[0].Status)
	}
}

func TestLBBackends_StoppedVM(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "app-1",
		StackName: "app",
		HostName:  "other-host",
		Spec:      "{}",
		State:     "stopped",
	}, []corrosion.InterfaceRecord{
		{VMName: "app-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	backends := s.lbBackends(ctx, "app-lb")
	if len(backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(backends))
	}
	if backends[0].Status != "down" {
		t.Errorf("backend status = %q, want down", backends[0].Status)
	}
}

func TestLBBackends_VMWithNoIP(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "app-1",
		StackName: "app",
		HostName:  "other-host",
		Spec:      "{}",
		State:     "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "app-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: ""},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	backends := s.lbBackends(ctx, "app-lb")
	if len(backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(backends))
	}
	if backends[0].Address != "" {
		t.Errorf("backend address = %q, want empty", backends[0].Address)
	}
}

func TestLBBackends_MultipleVMs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	ips := []string{"10.0.0.10", "10.0.0.11", ""}
	for i, name := range []string{"app-1", "app-2", "app-3"} {
		mac := "52:54:00:aa:bb:0" + string(rune('1'+i))
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
			Name: name, StackName: "app", HostName: "other-host", Spec: "{}", State: "running",
		}, []corrosion.InterfaceRecord{
			{VMName: name, NetworkName: "default", Ordinal: 0, MAC: mac, IP: ips[i]},
		}, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}

	backends := s.lbBackends(ctx, "app-lb")
	if len(backends) != 3 {
		t.Fatalf("expected 3 backends, got %d", len(backends))
	}
}

// --- collectLBBackends ---

func TestCollectLBBackends_NoVMs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	lbSpec := &pb.LBSpec{
		Enabled: true,
		Vip:     "10.0.0.50/24",
		Ports:   []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	backends := s.collectLBBackends(ctx, "empty-stack", lbSpec)
	if len(backends) != 0 {
		t.Errorf("expected 0 backends, got %d", len(backends))
	}
}

func TestCollectLBBackends_SkipsStoppedVMs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web-1", StackName: "web", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "web-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:00:00:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web-2", StackName: "web", HostName: "other-host", Spec: "{}", State: "stopped",
	}, []corrosion.InterfaceRecord{
		{VMName: "web-2", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:00:00:02", IP: "10.0.0.11"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	lbSpec := &pb.LBSpec{
		Enabled: true,
		Vip:     "10.0.0.50/24",
		Ports:   []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	backends := s.collectLBBackends(ctx, "web", lbSpec)
	if len(backends) != 1 {
		t.Fatalf("expected 1 backend (running only), got %d", len(backends))
	}
	if backends[0].Name != "web-1" {
		t.Errorf("backend name = %q, want web-1", backends[0].Name)
	}
	if backends[0].Port != 8080 {
		t.Errorf("backend port = %d, want 8080", backends[0].Port)
	}
}

func TestCollectLBBackends_DefaultPort(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web-1", StackName: "web", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "web-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:00:00:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// No ports in the LB spec — should default to port 80.
	lbSpec := &pb.LBSpec{
		Enabled: true,
		Vip:     "10.0.0.50/24",
	}
	backends := s.collectLBBackends(ctx, "web", lbSpec)
	if len(backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(backends))
	}
	if backends[0].Port != 80 {
		t.Errorf("backend port = %d, want 80 (default)", backends[0].Port)
	}
}

func TestCollectLBBackends_SkipsVMsWithNoIP(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "web-1", StackName: "web", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "web-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:00:00:01", IP: ""},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	lbSpec := &pb.LBSpec{
		Enabled: true,
		Vip:     "10.0.0.50/24",
		Ports:   []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}
	backends := s.collectLBBackends(ctx, "web", lbSpec)
	if len(backends) != 0 {
		t.Errorf("expected 0 backends (no IPs available), got %d", len(backends))
	}
}

// --- applyLBForStack ---

func TestApplyLBForStack_NotLBHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Server's hostName is "test-host". If lbHosts is ["other-host"],
	// applyLBForStack should skip and return nil.
	err := s.applyLBForStack(ctx, "myapp-lb", "10.0.0.50/24", "roundrobin", nil, nil, []string{"other-host"}, nil, false)
	if err != nil {
		t.Errorf("expected nil error when not an LB host, got %v", err)
	}
}

func TestApplyLBForStack_VIPConflict(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Pre-insert an existing LB config with the same VIP.
	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "existing-lb", VIP: "10.0.0.50/24", Algorithm: "roundrobin", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	// Try to apply a different LB with the same VIP.
	// Pass this host in lbHosts so the function doesn't skip.
	err := s.applyLBForStack(ctx, "new-lb", "10.0.0.50/24", "roundrobin", nil, nil, []string{s.hostName}, nil, false)
	if err == nil {
		t.Fatal("expected VIP conflict error")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("error = %q, want to contain 'already in use'", err.Error())
	}
}

func TestApplyLBForStack_SameNameNoConflict(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "myapp-lb", VIP: "10.0.0.50/24", Algorithm: "roundrobin", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	// Applying the same name with the same VIP should NOT trigger VIP conflict.
	err := s.applyLBForStack(ctx, "myapp-lb", "10.0.0.50/24", "roundrobin", nil, nil, []string{s.hostName}, nil, false)
	if err != nil && strings.Contains(err.Error(), "already in use") {
		t.Errorf("same-name LB should not trigger VIP conflict: %v", err)
	}
	// Any other error (from mgr.Apply) is expected and acceptable.
}

// --- applyLBFromSpec ---

func TestLBApplyFromSpec_NilLBSpec(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.applyLBFromSpec(ctx, &pb.VMSpec{
		Name:      "web-1",
		StackName: "myapp",
	})
}

func TestLBApplyFromSpec_DisabledLB(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.applyLBFromSpec(ctx, &pb.VMSpec{
		Name:      "web-1",
		StackName: "myapp",
		Loadbalancer: &pb.LBSpec{
			Enabled: false,
		},
	})
}

// --- removeLBForStack ---

func TestRemoveLBForStack_EmptyStackName(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.removeLBForStack(ctx, "", nil)
}

func TestRemoveLBForStack_NoLBRecord(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	vms := []corrosion.VMRecord{
		{Name: "web-1", StackName: "myapp", Spec: "{}"},
	}
	s.removeLBForStack(ctx, "myapp", vms)
}

func TestRemoveLBForStack_WithLBRecord(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "myapp-lb", VIP: "10.0.0.50/24", Algorithm: "roundrobin", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	vms := []corrosion.VMRecord{
		{Name: "web-1", StackName: "myapp", Spec: "{}"},
	}
	s.removeLBForStack(ctx, "myapp", vms)

	// Verify the LB record was soft-deleted: the tombstone row persists (so the
	// delete survives anti-entropy) with deleted_at set (gone from active listings).
	rows, err := s.db.Query(ctx, `SELECT deleted_at FROM lb_configs WHERE name = 'myapp-lb'`)
	if err != nil {
		t.Fatalf("query lb_configs: %v", err)
	}
	if len(rows) != 1 || rows[0].String("deleted_at") == "" {
		t.Errorf("expected myapp-lb tombstoned (deleted_at set), got %+v", rows)
	}
}

func TestRemoveLBForStack_WithVMSpecLB(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{
		Name:      "web-1",
		StackName: "myapp",
		Loadbalancer: &pb.LBSpec{
			Enabled: true,
			Vip:     "10.0.0.50/24",
			Hosts:   []string{"test-host"},
		},
	}
	specJSON, _ := json.Marshal(spec)
	vms := []corrosion.VMRecord{
		{Name: "web-1", StackName: "myapp", Spec: string(specJSON)},
	}
	s.removeLBForStack(ctx, "myapp", vms)
}

// --- refreshLBLocal ---

func TestRefreshLBLocal_EmptyStack(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	result := s.refreshLBLocal(ctx, "")
	if result != nil {
		t.Errorf("expected nil for empty stack, got %+v", result)
	}
}

func TestRefreshLBLocal_NoVMs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	result := s.refreshLBLocal(ctx, "ghost-stack")
	if result != nil {
		t.Errorf("expected nil when no VMs, got %+v", result)
	}
}

func TestRefreshLBLocal_VMWithEnabledLB(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	spec := &pb.VMSpec{
		Name:      "web-1",
		StackName: "webstack",
		Cpu:       1,
		MemoryMib: 512,
		Loadbalancer: &pb.LBSpec{
			Enabled:   true,
			Vip:       "10.0.0.50/24",
			Algorithm: "roundrobin",
			Hosts:     []string{"test-host"},
			Ports:     []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		},
	}
	specJSON, _ := json.Marshal(spec)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "web-1",
		StackName: "webstack",
		HostName:  "test-host",
		Spec:      string(specJSON),
		State:     "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// refreshLBLocal guards against re-applying during teardown by checking lb_configs.
	corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "webstack-lb", VIP: "10.0.0.50/24", Algorithm: "roundrobin",
		Hosts: "[]", Ports: "[]", Enabled: true,
	})

	result := s.refreshLBLocal(ctx, "webstack")
	if result == nil {
		t.Fatal("expected non-nil spec")
	}
	if result.Loadbalancer == nil || !result.Loadbalancer.Enabled {
		t.Error("expected enabled LB spec")
	}
}

// --- applyLBFromSpecWithRetry ---

func TestLBApplyFromSpecWithRetry_NilSpec(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.applyLBFromSpecWithRetry(ctx, &pb.VMSpec{
		Name:      "web-1",
		StackName: "myapp",
	})
}

func TestLBApplyFromSpecWithRetry_DisabledLB(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.applyLBFromSpecWithRetry(ctx, &pb.VMSpec{
		Name:      "web-1",
		StackName: "myapp",
		Loadbalancer: &pb.LBSpec{
			Enabled: false,
		},
	})
}

// --- InspectLoadBalancer with backends ---

func TestLBInspectWithBackends(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name: "svc-lb", VIP: "10.0.0.50/24", Algorithm: "roundrobin", Enabled: true,
	}); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "svc-1", StackName: "svc", HostName: "other-host", Spec: "{}", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "svc-1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:00:00:01", IP: "10.0.0.10"},
	}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	lb, err := s.InspectLoadBalancer(ctx, &pb.InspectLBRequest{Name: "svc-lb"})
	if err != nil {
		t.Fatalf("InspectLoadBalancer: %v", err)
	}
	if len(lb.Backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(lb.Backends))
	}
	if lb.Backends[0].VmName != "svc-1" {
		t.Errorf("backend vm_name = %q, want svc-1", lb.Backends[0].VmName)
	}
	if lb.Backends[0].Address != "10.0.0.10" {
		t.Errorf("backend address = %q, want 10.0.0.10", lb.Backends[0].Address)
	}
}
