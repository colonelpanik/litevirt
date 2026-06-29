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

// TestAdmitRawBridge_RootGated: a raw/unmanaged bridge is the ADMIN escape hatch —
// allowed only with cluster-root network authority (admin/root, or a legacy
// cluster-wide operator via the role fallback), denied for a non-root caller. It's
// gated on the CALLER, not the workload's project (_default is a tenant, not root).
// Wired into VM + container create.
func TestAdmitRawBridge_RootGated(t *testing.T) {
	s := testServer(t)
	if err := s.admitRawBridge(adminCtx(), "br-raw"); err != nil {
		t.Errorf("root/admin caller should be allowed a raw bridge: %v", err)
	}
	if err := s.admitRawBridge(viewerCtx(), "br-raw"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("non-root caller raw bridge: got %v, want PermissionDenied", err)
	}
}

// TestCreateContainer_RootCanUseRawBridge: the wiring still lets a cluster-root
// caller (admin) attach a container to a raw bridge — the legacy escape hatch is
// preserved for admins (only project-scoped/non-root callers are restricted).
func TestCreateContainer_RootCanUseRawBridge(t *testing.T) {
	s := testServer(t)
	s.SetContainerRuntime(&fakeCTRuntime{})
	if _, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{
		Name: "raw-ok", Template: "download", Distro: "alpine",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", Bridge: "br-raw"}},
	}); err != nil {
		t.Fatalf("root caller raw bridge should be allowed: %v", err)
	}
}

// TestReplicationSchedule_CrossProjectPoolDenied: day-2 pool admission — a VM's
// project can't schedule replication into another project's pool. (Covers the
// shared admitVMPoolUse gate used by move/replicate/import/runner too.)
func TestReplicationSchedule_CrossProjectPoolDenied(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: s.hostName, State: "stopped", // default project
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "acme-pool", Driver: "local", State: "active", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateReplicationSchedule(ctx, &pb.CreateReplicationScheduleRequest{
		Scope: "vm", VmName: "vm1", TargetPool: "acme-pool", TargetHost: s.hostName, Cron: "0 0 * * *",
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("cross-project replication target pool: got %v, want PermissionDenied", err)
	}
}

// TestReplicationSchedule_MissingTargetPoolRejected: an explicit target_host whose
// pool doesn't exist is rejected at CREATE, not persisted to fail every tick.
func TestReplicationSchedule_MissingTargetPoolRejected(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "vm1", HostName: s.hostName, State: "stopped",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateReplicationSchedule(ctx, &pb.CreateReplicationScheduleRequest{
		Scope: "vm", VmName: "vm1", TargetPool: "nope", TargetHost: s.hostName, Cron: "0 0 * * *",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("missing target pool: got %v, want FailedPrecondition", err)
	}
}

// TestCreateVM_ProjectAdmissionDenied: a VM may not attach to another project's
// network or place a disk on another project's pool — denied at admission, BEFORE
// any disk/network creation. A default-project workload (skips the project-exists
// check) is enough to exercise the cross-project deny.
func TestCreateVM_ProjectAdmissionDenied(t *testing.T) {
	s := testServerR2(t) // has dataDir/images; register an eligible placement host
	ctx := adminCtx()
	insertTestHostR2(t, ctx, s.db, "test-host", "active")
	mkProjectNetwork(t, s, "acme-net", "acme")
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "acme-pool", Driver: "local", State: "active", Project: "acme",
	}); err != nil {
		t.Fatal(err)
	}

	// Network admission is pre-placement → cross-project denied without a host.
	if _, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "vm-net", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "acme-net"}},
	}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("VM cross-project network: got %v, want PermissionDenied", err)
	}
	// Pool admission is post-placement (host-scoped) → placement resolves to
	// test-host, then the acme-owned pool is denied for the default-project VM.
	if _, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "vm-pool", Cpu: 1, MemoryMib: 512,
		Disks: []*pb.DiskSpec{{Name: "root", Storage: "acme-pool", Size: "10G"}},
	}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("VM cross-project pool: got %v, want PermissionDenied", err)
	}
}
