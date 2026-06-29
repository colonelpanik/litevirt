package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

func mkManagedNetwork(t *testing.T, s *Server, name, bridge, subnet string) {
	t.Helper()
	cfg, _ := json.Marshal(compose.NetworkDef{Interface: bridge, Subnet: subnet})
	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{
		Name: name, Type: "bridge", Config: string(cfg),
	}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}
}

// A NIC naming a managed network gets a container_interfaces row, an auto-
// allocated IP + CT-scoped IPAM lease, a deterministic veth, and create_spec
// that records the logical network for faithful rebuild.
func TestCreateContainer_ManagedNIC_WritesInterfaceAndLease(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})
	mkManagedNetwork(t, s, "net1", "br-test", "10.9.0.0/24")

	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "web", Template: "download", Distro: "alpine", Release: "3.19",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "net1"}},
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}

	ifs, _ := corrosion.GetContainerInterfaces(ctx, s.db, "test-host", "web")
	if len(ifs) != 1 {
		t.Fatalf("want 1 interface row, got %d", len(ifs))
	}
	if ifs[0].NetworkName != "net1" || ifs[0].VethDevice == "" || ifs[0].MAC == "" || ifs[0].IP == "" {
		t.Fatalf("incomplete interface row: %+v", ifs[0])
	}
	al, _ := network.GetAllocationFor(ctx, s.db, "net1", "ct", "test-host", "web")
	if al == nil || al.IP != ifs[0].IP {
		t.Fatalf("expected a CT IPAM lease matching the NIC IP, got %+v", al)
	}
	rec, _ := corrosion.GetContainer(ctx, s.db, "test-host", "web")
	spec := corrosion.DecodeCreateSpec(rec.CreateSpec)
	if len(spec.Networks) != 1 || spec.Networks[0].NetworkName != "net1" {
		t.Fatalf("create_spec missing managed network identity: %+v", spec.Networks)
	}
}

// A bare bridge that resolves to no known network is legacy-unmanaged: no
// interface row, no lease (the table is the managed-NIC source of truth).
func TestCreateContainer_LegacyBridge_NoInterfaceRow(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})

	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "raw", Template: "download", Distro: "alpine",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", Bridge: "br-unmanaged"}},
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	ifs, _ := corrosion.GetContainerInterfaces(ctx, s.db, "test-host", "raw")
	if len(ifs) != 0 {
		t.Fatalf("legacy raw-bridge NIC must have no interface row, got %d", len(ifs))
	}
}

// Delete cascades: interface rows tombstoned + IPAM lease released.
func TestDeleteContainer_CascadesNICs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})
	mkManagedNetwork(t, s, "net1", "br-test", "10.9.0.0/24")
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "web", Template: "download", Distro: "alpine",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "net1"}},
	}); err != nil {
		t.Fatalf("CreateContainer: %v", err)
	}
	if _, err := s.DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: "web", HostName: "test-host"}); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	if ifs, _ := corrosion.GetContainerInterfaces(ctx, s.db, "test-host", "web"); len(ifs) != 0 {
		t.Fatalf("interface rows must be tombstoned on delete, got %d", len(ifs))
	}
	if al, _ := network.GetAllocationFor(ctx, s.db, "net1", "ct", "test-host", "web"); al != nil {
		t.Fatalf("CT lease must be released on delete, still held: %+v", al)
	}
}

// A VM and a CT of the same name on one network get DISTINCT leases, and
// releasing the VM lease must not touch the CT's (owner_kind/owner_host keying).
func TestIPAM_VMandCTSameName_NoAlias(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if _, err := network.AllocateIP(ctx, db, "net1", "10.9.0.0/24", "mac-vm", "web"); err != nil {
		t.Fatalf("AllocateIP(vm): %v", err)
	}
	if _, err := network.AllocateIPFor(ctx, db, "net1", "10.9.0.0/24", "mac-ct", "ct", "h1", "web"); err != nil {
		t.Fatalf("AllocateIPFor(ct): %v", err)
	}
	vmAl, _ := network.GetAllocation(ctx, db, "net1", "web")
	ctAl, _ := network.GetAllocationFor(ctx, db, "net1", "ct", "h1", "web")
	if vmAl == nil || ctAl == nil || vmAl.IP == ctAl.IP {
		t.Fatalf("VM and CT leases must be distinct: vm=%+v ct=%+v", vmAl, ctAl)
	}
	if err := network.ReleaseIP(ctx, db, "net1", "web"); err != nil { // VM release
		t.Fatalf("ReleaseIP(vm): %v", err)
	}
	if a, _ := network.GetAllocationFor(ctx, db, "net1", "ct", "h1", "web"); a == nil {
		t.Fatal("releasing the VM lease wrongly released the same-named CT lease")
	}
}

// A clone gets FRESH managed NIC identity keyed on the CLONE's name (deterministic
// veth + MAC matching the on-disk config the runtime clone rewrites) and a dynamic
// IP — it must not reuse the source's address — with a create_spec that records the
// managed network.
func TestCloneContainer_RebuildsManagedNICs(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})
	mkManagedNetwork(t, s, "net1", "br-test", "10.9.0.0/24")
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "src", Template: "download", Distro: "alpine",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "net1"}},
	}); err != nil {
		t.Fatalf("CreateContainer(src): %v", err)
	}
	if _, err := s.CloneContainer(ctx, &pb.CloneContainerRequest{Source: "src", Target: "clone1", HostName: "test-host"}); err != nil {
		t.Fatalf("CloneContainer: %v", err)
	}
	ifs, _ := corrosion.GetContainerInterfaces(ctx, s.db, "test-host", "clone1")
	if len(ifs) != 1 {
		t.Fatalf("clone should have 1 managed interface row, got %d", len(ifs))
	}
	if ifs[0].VethDevice != corrosion.ContainerVethName("clone1", 0) {
		t.Fatalf("clone veth %q not keyed on the clone name", ifs[0].VethDevice)
	}
	if ifs[0].MAC != corrosion.ContainerMAC(s.hostName, "clone1", 0) {
		t.Fatalf("clone MAC %q not the deterministic clone MAC", ifs[0].MAC)
	}
	if ifs[0].IP != "" {
		t.Fatalf("clone NIC must be dynamic (blank IP), got %q", ifs[0].IP)
	}
	rec, _ := corrosion.GetContainer(ctx, s.db, "test-host", "clone1")
	if spec := corrosion.DecodeCreateSpec(rec.CreateSpec); len(spec.Networks) != 1 || spec.Networks[0].NetworkName != "net1" {
		t.Fatalf("clone create_spec lost the managed network identity: %+v", spec.Networks)
	}
}

// A container NIC attaching to a direct/sriov (VM-only) network is rejected.
func TestCreateContainer_RejectsDirectNetwork(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})
	cfg, _ := json.Marshal(compose.NetworkDef{Interface: "eth0"})
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "dnet", Type: "direct", Config: string(cfg)}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}
	_, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "c", Template: "download", Distro: "alpine",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "dnet"}},
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument attaching a container to a direct network, got %v", err)
	}
}

func TestContainerVethName_DeterministicAndIfnameSafe(t *testing.T) {
	a := containerVethName("web", 0)
	if a != containerVethName("web", 0) {
		t.Fatal("veth name must be deterministic")
	}
	if len(a) > 15 {
		t.Fatalf("veth %q exceeds IFNAMSIZ (15)", a)
	}
	if containerVethName("web", 1) == a {
		t.Fatal("different ordinals must yield different veth names")
	}
}
