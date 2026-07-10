package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestCreateNetwork_Validation(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// CreateNetwork with actual provisioning requires root for bridge creation.
	// Test the validation/DB path: duplicate detection, missing name, etc.
	// The provisioning itself is tested by network package tests.

	// Default type should be bridge.
	_, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "sriov-net", Type: "sriov", Pf: "ens1f0",
	})
	// SR-IOV provisioning returns PF name directly (no syscall needed).
	if err != nil {
		t.Fatalf("CreateNetwork sriov: %v", err)
	}

	// Verify it was persisted.
	ni, err := s.GetNetwork(ctx, &pb.GetNetworkRequest{Name: "sriov-net"})
	if err != nil {
		t.Fatalf("GetNetwork after create: %v", err)
	}
	if ni.Type != "sriov" {
		t.Errorf("Type = %q, want sriov", ni.Type)
	}
}

func TestCreateNetwork_Duplicate(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Seed a network record directly.
	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "dup-net", Type: "bridge", Config: `{"interface":"br0"}`,
	})

	_, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "dup-net", Type: "bridge", Iface: "br0",
	})
	if err == nil {
		t.Fatal("expected error for duplicate, got nil")
	}
	if c := status.Code(err); c != codes.AlreadyExists {
		t.Errorf("code = %v, want AlreadyExists", c)
	}
}

func TestCreateNetwork_MissingName(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{Type: "bridge"})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestGetNetwork_OK(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "get-net", Type: "vxlan",
		Config: `{"interface":"br-vni100","vni":100,"subnet":"10.50.0.0/24"}`,
	})

	ni, err := s.GetNetwork(ctx, &pb.GetNetworkRequest{Name: "get-net"})
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if ni.Name != "get-net" {
		t.Errorf("Name = %q, want get-net", ni.Name)
	}
	if ni.Type != "vxlan" {
		t.Errorf("Type = %q, want vxlan", ni.Type)
	}
	if ni.Vni != 100 {
		t.Errorf("VNI = %d, want 100", ni.Vni)
	}
	if ni.Subnet != "10.50.0.0/24" {
		t.Errorf("Subnet = %q, want 10.50.0.0/24", ni.Subnet)
	}
}

func TestGetNetwork_NotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.GetNetwork(ctx, &pb.GetNetworkRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected not found error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestDeleteNetwork_OK(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "del-net", Type: "bridge", Config: `{"interface":"br-del"}`,
	})

	_, err := s.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "del-net"})
	if err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}

	// Verify it's gone.
	_, err = s.GetNetwork(ctx, &pb.GetNetworkRequest{Name: "del-net"})
	if err == nil {
		t.Fatal("expected not found after delete")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestDeleteNetwork_NotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected not found error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestDeleteNetwork_InUse(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "busy-net", Type: "bridge", Config: `{"interface":"br-busy"}`,
	})

	// Insert a host so the VM insert succeeds.
	corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active",
	})

	// Insert a VM with an interface on this network.
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "h1", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "vm1", NetworkName: "busy-net", Ordinal: 0, MAC: "52:54:00:00:00:01"},
	}, nil)

	// Delete without force should fail.
	_, err := s.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "busy-net"})
	if err == nil {
		t.Fatal("expected FailedPrecondition")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}

	// Delete with force should succeed.
	_, err = s.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "busy-net", Force: true})
	if err != nil {
		t.Fatalf("DeleteNetwork --force: %v", err)
	}
}

func TestListNetworks_IncludesCreated(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "net-a", Type: "bridge", Config: `{"interface":"br-a"}`,
	})
	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "net-b", Type: "isolated", Config: `{"interface":"iso-b","subnet":"172.16.0.0/24"}`,
	})

	resp, err := s.ListNetworks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(resp.Networks) < 2 {
		t.Fatalf("expected at least 2 networks, got %d", len(resp.Networks))
	}

	names := map[string]bool{}
	for _, n := range resp.Networks {
		names[n.Name] = true
	}
	if !names["net-a"] {
		t.Error("missing net-a in list")
	}
	if !names["net-b"] {
		t.Error("missing net-b in list")
	}
}

// ── Additional network tests ────────────────────────────────────────────────

func TestCreateNetwork_SRIOVPersistsConfig(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	ni, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "sriov-full", Type: "sriov", Pf: "ens2f0",
		SpoofCheck: true,
	})
	if err != nil {
		t.Fatalf("CreateNetwork sriov: %v", err)
	}
	if ni.Name != "sriov-full" {
		t.Errorf("Name = %q, want sriov-full", ni.Name)
	}
	if ni.Type != "sriov" {
		t.Errorf("Type = %q, want sriov", ni.Type)
	}

	// Verify config JSON was persisted correctly.
	nr, err := corrosion.GetNetwork(ctx, s.db, "sriov-full")
	if err != nil {
		t.Fatalf("GetNetwork from DB: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(nr.Config), &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if pf, _ := cfg["PF"].(string); pf != "ens2f0" {
		t.Errorf("config.PF = %q, want ens2f0", pf)
	}
}

func TestCreateNetwork_RBACViewer(t *testing.T) {
	s := testServerR2(t)
	// viewer role should not be allowed to create networks.
	ctx := context.WithValue(context.Background(), ctxKeyUsername, "viewer-user")
	ctx = context.WithValue(ctx, ctxKeyRole, "viewer")

	_, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "rbac-net", Type: "sriov", Pf: "ens1f0",
	})
	if err == nil {
		t.Fatal("expected permission denied for viewer")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestGetNetwork_MissingName(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.GetNetwork(ctx, &pb.GetNetworkRequest{})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestGetNetwork_WithVMCount(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "counted-net", Type: "bridge", Config: `{"interface":"br-cnt"}`,
	})
	corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active",
	})
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-cnt1", HostName: "h1", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "vm-cnt1", NetworkName: "counted-net", Ordinal: 0, MAC: "52:54:00:00:01:01"},
	}, nil)
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-cnt2", HostName: "h1", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "vm-cnt2", NetworkName: "counted-net", Ordinal: 0, MAC: "52:54:00:00:01:02"},
	}, nil)

	ni, err := s.GetNetwork(ctx, &pb.GetNetworkRequest{Name: "counted-net"})
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if ni.VmCount != 2 {
		t.Errorf("VmCount = %d, want 2", ni.VmCount)
	}
}

// A declared network whose interface name differs from its network name,
// with VMs referencing it by network name, used to get a phantom Type:"bridge"
// duplicate from the second loop of ListNetworks (seen/ifaceToNet were keyed by
// interface name while VM counts are keyed by network name). It must now appear
// exactly once, with its real type.
func TestListNetworks_NoPhantomBridgeTwin(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "ceph-mgmt", Type: "direct", Config: `{"interface":"bond0.206"}`,
	})
	corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
	})
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: "h1", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "vm1", NetworkName: "ceph-mgmt", Ordinal: 0, MAC: "52:54:00:00:02:01"},
	}, nil)

	resp, err := s.ListNetworks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	var count int
	var gotType string
	for _, n := range resp.GetNetworks() {
		if n.Name == "ceph-mgmt" {
			count++
			gotType = n.Type
		}
	}
	if count != 1 {
		t.Fatalf("network ceph-mgmt appears %d times, want 1 (phantom bridge-twin regression)", count)
	}
	if gotType != "direct" {
		t.Errorf("ceph-mgmt type = %q, want \"direct\" (not the phantom bridge)", gotType)
	}
}

func TestGetNetwork_RBACViewer(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "viewer-net", Type: "bridge", Config: `{"interface":"br-v"}`,
	})

	// Viewer should be able to read networks.
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer-user")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	ni, err := s.GetNetwork(viewerCtx, &pb.GetNetworkRequest{Name: "viewer-net"})
	if err != nil {
		t.Fatalf("GetNetwork as viewer: %v", err)
	}
	if ni.Name != "viewer-net" {
		t.Errorf("Name = %q, want viewer-net", ni.Name)
	}
}

func TestDeleteNetwork_MissingName(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{})
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestDeleteNetwork_RBACViewer(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "rbac-del-net", Type: "sriov", Config: `{"pf":"ens1f0"}`,
	})

	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer-user")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.DeleteNetwork(viewerCtx, &pb.DeleteNetworkRequest{Name: "rbac-del-net"})
	if err == nil {
		t.Fatal("expected permission denied for viewer")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestListNetworks_Empty(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	resp, err := s.ListNetworks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(resp.Networks) != 0 {
		t.Errorf("expected 0 networks, got %d", len(resp.Networks))
	}
}

func TestListNetworks_WithVMCounts(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "list-net1", Type: "bridge", Config: `{"interface":"br-l1"}`,
	})
	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "list-net2", Type: "bridge", Config: `{"interface":"br-l2"}`,
	})

	corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active",
	})
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-l1", HostName: "h1", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "vm-l1", NetworkName: "list-net1", Ordinal: 0, MAC: "52:54:00:00:02:01"},
	}, nil)
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-l2", HostName: "h1", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "vm-l2", NetworkName: "list-net1", Ordinal: 0, MAC: "52:54:00:00:02:02"},
	}, nil)

	resp, err := s.ListNetworks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}

	countByName := map[string]int32{}
	for _, n := range resp.Networks {
		countByName[n.Name] = n.VmCount
	}
	if countByName["list-net1"] != 2 {
		t.Errorf("list-net1 VmCount = %d, want 2", countByName["list-net1"])
	}
	if countByName["list-net2"] != 0 {
		t.Errorf("list-net2 VmCount = %d, want 0", countByName["list-net2"])
	}
}

func TestListNetworks_IncludesVMOnlyNetworks(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// No network record in DB, but a VM references "orphan-net".
	corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active",
	})
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm-orphan", HostName: "h1", State: "running",
	}, []corrosion.InterfaceRecord{
		{VMName: "vm-orphan", NetworkName: "orphan-net", Ordinal: 0, MAC: "52:54:00:00:03:01"},
	}, nil)

	resp, err := s.ListNetworks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}

	found := false
	for _, n := range resp.Networks {
		if n.Name == "orphan-net" {
			found = true
			if n.Type != "bridge" {
				t.Errorf("orphan-net Type = %q, want bridge", n.Type)
			}
			if n.VmCount != 1 {
				t.Errorf("orphan-net VmCount = %d, want 1", n.VmCount)
			}
		}
	}
	if !found {
		t.Error("orphan-net not found in ListNetworks output")
	}
}

func TestListNetworks_RBACViewer(t *testing.T) {
	s := testServerR2(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer-user")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	// Viewer should be able to list networks.
	_, err := s.ListNetworks(viewerCtx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListNetworks as viewer: %v", err)
	}
}

func TestListNetworks_AfterDelete(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "del-list-net", Type: "sriov", Config: `{"pf":"ens1f0"}`,
	})

	// Delete it.
	corrosion.DeleteNetwork(ctx, s.db, "del-list-net")

	resp, err := s.ListNetworks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	for _, n := range resp.Networks {
		if n.Name == "del-list-net" {
			t.Error("deleted network should not appear in list")
		}
	}
}

func TestProvisionNetwork_SRIOVType(t *testing.T) {
	s := testServerR2(t)
	ctx := peerCtxFor(t, s, "peer-1")

	cfg := `{"pf":"ens1f0","interface":"sriov-prov"}`
	_, err := s.ProvisionNetwork(ctx, &pb.ProvisionNetworkRequest{
		Name:    "prov-sriov",
		Config:  cfg,
		NetType: "sriov",
	})
	if err != nil {
		t.Fatalf("ProvisionNetwork sriov: %v", err)
	}
}

func TestProvisionNetwork_InvalidConfig(t *testing.T) {
	s := testServerR2(t)
	ctx := peerCtxFor(t, s, "peer-1")

	_, err := s.ProvisionNetwork(ctx, &pb.ProvisionNetworkRequest{
		Name:    "prov-bad",
		Config:  "{invalid json",
		NetType: "bridge",
	})
	if err == nil {
		t.Fatal("expected error for invalid config JSON")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestProvisionNetwork_UnknownType(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.ProvisionNetwork(ctx, &pb.ProvisionNetworkRequest{
		Name:    "prov-unknown",
		Config:  `{"interface":"br-unk"}`,
		NetType: "bogus",
	})
	if err == nil {
		t.Fatal("expected error for unknown network type")
	}
}

func TestDeprovisionNetworkByName_Exists(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Insert a sriov network (Deprovision for sriov is a no-op).
	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "deprov-net", Type: "sriov", Config: `{"pf":"ens1f0"}`,
	})

	err := s.deprovisionNetworkByName(ctx, "deprov-net")
	if err != nil {
		t.Fatalf("deprovisionNetworkByName: %v", err)
	}

	// Verify the DB record was soft-deleted.
	nr, _ := corrosion.GetNetwork(ctx, s.db, "deprov-net")
	if nr != nil {
		t.Error("expected network to be deleted from DB after deprovision")
	}
}

func TestDeprovisionNetworkByName_NotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Should return nil for non-existent network (nothing to deprovision).
	err := s.deprovisionNetworkByName(ctx, "no-such-net")
	if err != nil {
		t.Errorf("expected nil for non-existent network, got %v", err)
	}
}

func TestNetworkRecordToInfo_FullConfig(t *testing.T) {
	nr := &corrosion.NetworkRecord{
		Name:      "info-net",
		StackName: "my-stack",
		Type:      "vxlan",
		Config:    `{"interface":"br-vni50","vni":50,"subnet":"10.100.0.0/24","dhcp":true}`,
	}

	ni := networkRecordToInfo(nr)
	if ni.Name != "info-net" {
		t.Errorf("Name = %q, want info-net", ni.Name)
	}
	if ni.StackName != "my-stack" {
		t.Errorf("StackName = %q, want my-stack", ni.StackName)
	}
	if ni.Type != "vxlan" {
		t.Errorf("Type = %q, want vxlan", ni.Type)
	}
	if ni.Iface != "br-vni50" {
		t.Errorf("Iface = %q, want br-vni50", ni.Iface)
	}
	if ni.Vni != 50 {
		t.Errorf("Vni = %d, want 50", ni.Vni)
	}
	if ni.Subnet != "10.100.0.0/24" {
		t.Errorf("Subnet = %q, want 10.100.0.0/24", ni.Subnet)
	}
	if !ni.Dhcp {
		t.Error("Dhcp should be true when subnet is set")
	}
	if ni.Gateway == "" {
		t.Error("Gateway should be derived from subnet")
	}
}

func TestNetworkRecordToInfo_EmptyConfig(t *testing.T) {
	nr := &corrosion.NetworkRecord{
		Name:   "empty-cfg",
		Type:   "bridge",
		Config: `{}`,
	}

	ni := networkRecordToInfo(nr)
	if ni.Name != "empty-cfg" {
		t.Errorf("Name = %q, want empty-cfg", ni.Name)
	}
	if ni.Iface != "" {
		t.Errorf("Iface = %q, want empty", ni.Iface)
	}
	if ni.Dhcp {
		t.Error("Dhcp should be false for empty config")
	}
}

func TestNetworkRecordToInfo_MalformedConfig(t *testing.T) {
	nr := &corrosion.NetworkRecord{
		Name:   "bad-cfg",
		Type:   "bridge",
		Config: `not json`,
	}

	// Should not panic; fields remain zero-valued.
	ni := networkRecordToInfo(nr)
	if ni.Name != "bad-cfg" {
		t.Errorf("Name = %q, want bad-cfg", ni.Name)
	}
	if ni.Iface != "" {
		t.Errorf("Iface = %q, want empty", ni.Iface)
	}
}

func TestNetworkRecordToDef_RoundTrip(t *testing.T) {
	nr := &corrosion.NetworkRecord{
		Name: "rt-net",
		Type: "vxlan",
		Config: `{"interface":"br-vni99","vni":99,"subnet":"10.99.0.0/24",` +
			`"underlay":"eth0","learning":true,"port":4789}`,
	}

	def := networkRecordToDef(nr)
	if def.Type != "vxlan" {
		t.Errorf("Type = %q, want vxlan", def.Type)
	}
	if def.Interface != "br-vni99" {
		t.Errorf("Interface = %q, want br-vni99", def.Interface)
	}
	if def.VNI != 99 {
		t.Errorf("VNI = %d, want 99", def.VNI)
	}
	if def.Subnet != "10.99.0.0/24" {
		t.Errorf("Subnet = %q, want 10.99.0.0/24", def.Subnet)
	}
}

func TestNetworkRecordToDef_MalformedConfig(t *testing.T) {
	nr := &corrosion.NetworkRecord{
		Name:   "bad-rt",
		Type:   "bridge",
		Config: `{broken`,
	}

	// Should not panic; type is still set from the record.
	def := networkRecordToDef(nr)
	if def.Type != "bridge" {
		t.Errorf("Type = %q, want bridge", def.Type)
	}
}

func TestCreateNetwork_MultipleSRIOV(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Create two different SR-IOV networks.
	_, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "sriov-a", Type: "sriov", Pf: "ens1f0",
	})
	if err != nil {
		t.Fatalf("CreateNetwork sriov-a: %v", err)
	}
	_, err = s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "sriov-b", Type: "sriov", Pf: "ens2f0",
	})
	if err != nil {
		t.Fatalf("CreateNetwork sriov-b: %v", err)
	}

	// Both should appear in ListNetworks.
	resp, err := s.ListNetworks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	names := map[string]bool{}
	for _, n := range resp.Networks {
		names[n.Name] = true
	}
	if !names["sriov-a"] || !names["sriov-b"] {
		t.Errorf("expected both sriov-a and sriov-b in list, got %v", names)
	}
}

func TestDeleteNetwork_ThenRecreate(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Create, delete, then recreate with same name.
	_, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "cycle-net", Type: "sriov", Pf: "ens1f0",
	})
	if err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}

	_, err = s.DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "cycle-net"})
	if err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}

	// Recreate with different config.
	ni, err := s.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "cycle-net", Type: "sriov", Pf: "ens3f0",
	})
	if err != nil {
		t.Fatalf("re-CreateNetwork: %v", err)
	}
	if ni.Type != "sriov" {
		t.Errorf("Type = %q, want sriov", ni.Type)
	}
}

func TestGetNetwork_StackName(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:      "stack-net",
		StackName: "my-app",
		Type:      "bridge",
		Config:    `{"interface":"br-app"}`,
	})

	ni, err := s.GetNetwork(ctx, &pb.GetNetworkRequest{Name: "stack-net"})
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if ni.StackName != "my-app" {
		t.Errorf("StackName = %q, want my-app", ni.StackName)
	}
}

// Every ProvisionNetwork request must carry stack_name and default a blank type
// to "bridge" — the single constructor makes the omission that orphaned networks
// at teardown impossible to reintroduce.
func TestProvisionNetworkRequest_AlwaysSetsStackName(t *testing.T) {
	cases := []struct {
		name, cfg, netType, stack string
		wantType                  string
	}{
		{"lbmix_lbnet", `{"subnet":"10.77.0.0/24"}`, "isolated", "lbmix", "isolated"},
		{"app_lan", "", "", "app", "bridge"}, // blank type defaults to bridge
	}
	for _, c := range cases {
		req := provisionNetworkRequest(c.name, c.cfg, c.netType, c.stack)
		if req.Name != c.name || req.Config != c.cfg || req.NetType != c.wantType || req.StackName != c.stack {
			t.Errorf("provisionNetworkRequest(%q,…,%q,%q) = %+v, want type=%q stack=%q",
				c.name, c.netType, c.stack, req, c.wantType, c.stack)
		}
	}

	// remoteProvisionRequest (migration path) preserves the record's stack_name.
	nr := &corrosion.NetworkRecord{Name: "lbmix_lbnet", StackName: "lbmix", Type: "isolated", Config: `{"x":1}`}
	if got := remoteProvisionRequest(nr.Name, nr); got.StackName != "lbmix" || got.NetType != "isolated" {
		t.Errorf("remoteProvisionRequest dropped fields: %+v", got)
	}
}
