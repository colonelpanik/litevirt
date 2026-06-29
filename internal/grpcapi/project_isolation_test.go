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
)

// mkProjectNetwork upserts a managed bridge network owned by project (empty =
// global), so the attach-admission tests have a target to (not) attach to.
func mkProjectNetwork(t *testing.T, s *Server, name, project string) {
	t.Helper()
	cfg, _ := json.Marshal(compose.NetworkDef{Interface: name, Subnet: "10.9.0.0/24"})
	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{
		Name: name, Type: "bridge", Config: string(cfg), Project: project,
	}); err != nil {
		t.Fatalf("UpsertNetwork(%s): %v", name, err)
	}
}

// TestCreateContainer_NetworkProjectAdmission: a container attaches only to a
// network its OWN project owns or a GLOBAL one — never another project's.
func TestCreateContainer_NetworkProjectAdmission(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	s.SetContainerRuntime(&fakeCTRuntime{})
	mkProjectNetwork(t, s, "acme-net", "acme")
	mkProjectNetwork(t, s, "shared-net", "") // global

	// Own project → allowed.
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "own", Template: "download", Distro: "alpine", Project: "acme",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "acme-net"}},
	}); err != nil {
		t.Fatalf("own-project attach should succeed: %v", err)
	}
	// Cross project → denied.
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "cross", Template: "download", Distro: "alpine", Project: "beta",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "acme-net"}},
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-project attach: got %v, want PermissionDenied", err)
	}
	// Default project to an OWNED network → denied (default isn't "global").
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "deflt", Template: "download", Distro: "alpine",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "acme-net"}},
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("default→owned attach: got %v, want PermissionDenied", err)
	}
	// Any project → GLOBAL network allowed.
	if _, err := s.CreateContainer(ctx, &pb.CreateContainerRequest{
		Name: "glob", Template: "download", Distro: "alpine", Project: "beta",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: "shared-net"}},
	}); err != nil {
		t.Fatalf("global attach should succeed: %v", err)
	}
}

// TestCreateVM_ProjectAdmissionDenied: a VM may not attach to another project's
// network or place a disk on another project's pool — denied at admission, BEFORE
// any disk/network creation. A default-project workload (skips the project-exists
// check) is enough to exercise the cross-project deny.
func TestCreateVM_ProjectAdmissionDenied(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	mkProjectNetwork(t, s, "acme-net", "acme")
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "acme-pool", Driver: "local", State: "active", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "vm-net", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "acme-net"}},
	}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("VM cross-project network: got %v, want PermissionDenied", err)
	}
	if _, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "vm-pool", Cpu: 1, MemoryMib: 512,
		Disks: []*pb.DiskSpec{{Name: "root", Storage: "acme-pool", Size: "10G"}},
	}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("VM cross-project pool: got %v, want PermissionDenied", err)
	}
}
