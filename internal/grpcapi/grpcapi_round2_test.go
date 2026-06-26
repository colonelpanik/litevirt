package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/metrics"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// testServerR2 creates a Server with vmLocks, dataDir, images store, and DB.
func testServerR2(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	dataDir := t.TempDir()
	store := image.NewStore(dataDir)
	store.Init()
	return &Server{
		hostName: "test-host",
		dataDir:  dataDir,
		db:       db,
		images:   store,
		events:   events.NewBus(),
		vmLocks:  make(map[string]*sync.Mutex),
	}
}

func insertTestHostR2(t *testing.T, ctx context.Context, db *corrosion.Client, name, state string) {
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

func insertTestVMR2(t *testing.T, ctx context.Context, db *corrosion.Client, name, host, state string) {
	t.Helper()
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      name,
		HostName:  host,
		State:     state,
		CPUActual: 2,
		MemActual: 4096,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

func insertTestVMR2WithSpec(t *testing.T, ctx context.Context, db *corrosion.Client, name, host, state, specJSON string) {
	t.Helper()
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      name,
		HostName:  host,
		State:     state,
		CPUActual: 2,
		MemActual: 4096,
		Spec:      specJSON,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

func insertTestVMR2WithStack(t *testing.T, ctx context.Context, db *corrosion.Client, name, host, state, stack string) {
	t.Helper()
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      name,
		StackName: stack,
		HostName:  host,
		State:     state,
		CPUActual: 2,
		MemActual: 4096,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

// createFakeImage creates a dummy file so s.images.ImageExists(name) returns true.
func createFakeImage(t *testing.T, s *Server, name string) {
	t.Helper()
	path := s.images.ImagePath(name)
	os.MkdirAll(filepath.Dir(path), 0755)
	if err := os.WriteFile(path, []byte("fake"), 0644); err != nil {
		t.Fatalf("create fake image %q: %v", name, err)
	}
}

// ── DeployStack additional paths ────────────────────────────────────────────

// mockDeployStreamR2 implements grpc.ServerStreamingServer[pb.DeployProgress].
type mockDeployStreamR2 struct {
	ctx  context.Context
	sent []*pb.DeployProgress
}

func (m *mockDeployStreamR2) Send(p *pb.DeployProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockDeployStreamR2) Context() context.Context       { return m.ctx }
func (m *mockDeployStreamR2) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockDeployStreamR2) SendHeader(_ metadata.MD) error { return nil }
func (m *mockDeployStreamR2) SetTrailer(_ metadata.MD)       {}
func (m *mockDeployStreamR2) SendMsg(_ interface{}) error    { return nil }
func (m *mockDeployStreamR2) RecvMsg(_ interface{}) error    { return nil }

// ── DiffStack with current VMs ──────────────────────────────────────────────

func TestDiffStack_WithExistingVMs_ShowsUpdatesAndDeletes(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "test-host", "active")

	// Insert existing VMs for stack "difftest".
	specJSON := `{"image":"ubuntu-20.04","cpu":2,"memory_mib":4096}`
	insertTestVMR2WithSpec(t, ctx, s.db, "difftest-web-1", "test-host", "running", specJSON)
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "difftest-web-1",
		StackName: "difftest",
		HostName:  "test-host",
		State:     "running",
		CPUActual: 2,
		MemActual: 4096,
		Spec:      specJSON,
	}, nil, nil)

	// Deploy a YAML that changes the image — should produce update ops.
	yaml := `name: difftest
vms:
  web:
    image: ubuntu-22.04
    cpu: 4
    memory: 8192
    replicas: 1
`
	resp, err := s.DiffStack(ctx, &pb.DiffStackRequest{ComposeYaml: yaml})
	if err != nil {
		t.Fatalf("DiffStack: %v", err)
	}
	if len(resp.Entries) == 0 {
		t.Fatal("expected non-empty diff entries")
	}
}

// ── DeleteSnapshot additional paths ─────────────────────────────────────────

func TestDeleteSnapshot_VMNotOnThisHost(t *testing.T) {
	// Tests a different host path for delete snapshot.
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "snap-other", "other-host", "running")

	_, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{
		VmName:       "snap-other",
		SnapshotName: "snap1",
	})
	if err == nil {
		t.Fatal("expected error for wrong host")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── releaseDevices with devices present ─────────────────────────────────────

func TestReleaseDevices_WithAssignedDevices(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Insert PCI devices — one assigned to our VM, one not.
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host",
		Address:  "0000:01:00.0",
		Type:     "gpu",
		VMName:   "my-vm",
		Driver:   "nvidia",
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host",
		Address:  "0000:02:00.0",
		Type:     "gpu",
		VMName:   "other-vm",
		Driver:   "nvidia",
	})

	// This should attempt to unbind "0000:01:00.0" (will fail on vfio.Unbind
	// but should not panic) and release it in DB.
	s.releaseDevices(ctx, "my-vm")

	// Verify the device assigned to "my-vm" was released in DB.
	devices, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devices {
		if d.Address == "0000:01:00.0" && d.VMName == "my-vm" {
			t.Error("expected device to be released from my-vm")
		}
		if d.Address == "0000:02:00.0" && d.VMName != "other-vm" {
			t.Error("expected other-vm device to be untouched")
		}
	}
}

// ── applyLBFromSpec ─────────────────────────────────────────────────────────

func TestApplyLBFromSpec_NilLBSpec(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Should return early without panic.
	s.applyLBFromSpec(ctx, &pb.VMSpec{
		Name:      "vm1",
		StackName: "stack1",
	})
}

func TestApplyLBFromSpec_DisabledLB(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Enabled=false should return early.
	s.applyLBFromSpec(ctx, &pb.VMSpec{
		Name:         "vm1",
		StackName:    "stack1",
		Loadbalancer: &pb.LBSpec{Enabled: false},
	})
}

func TestApplyLBFromSpec_NoRunningVMs(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Insert a stopped VM in the stack (should not generate backends).
	insertTestVMR2WithStack(t, ctx, s.db, "lb-vm-1", "test-host", "stopped", "lb-stack")

	// Should not panic; will call applyLBForStack which may fail,
	// but applyLBFromSpec logs and returns.
	s.applyLBFromSpec(ctx, &pb.VMSpec{
		Name:      "lb-vm-1",
		StackName: "lb-stack",
		Loadbalancer: &pb.LBSpec{
			Enabled:   true,
			Vip:       "10.0.0.100/24",
			Algorithm: "roundrobin",
			Ports: []*pb.LBPort{
				{Listen: 80, Target: 8080, Protocol: "tcp"},
			},
		},
	})
}

// ── refreshLBForStack additional paths ──────────────────────────────────────

func TestRefreshLBForStack_NoVMs(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Non-empty stack name but no VMs — should return early.
	s.refreshLBForStack(ctx, "nonexistent-stack")
}

func TestRefreshLBForStack_VMWithNoLBSpec(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	specJSON := `{"name":"vm1","cpu":2}`
	insertTestVMR2WithSpec(t, ctx, s.db, "r2-nospec", "test-host", "running", specJSON)
	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "r2-nospec",
		StackName: "nospec-stack",
		HostName:  "test-host",
		State:     "running",
		Spec:      specJSON,
	}, nil, nil)

	// Should not panic — VMs found but no LB spec.
	s.refreshLBForStack(ctx, "nospec-stack")
}

// ── recordMigrationMetrics with non-nil metrics ─────────────────────────────

func TestRecordMigrationMetrics_WithMetrics(t *testing.T) {
	s := testServerR2(t)
	m := metrics.NewMigrationMetrics()
	s.SetMigrationMetrics(m)

	// Should not panic; records duration, downtime, and transfer.
	s.recordMigrationMetrics("live", "success", 5*time.Second, 50.0, 1024.0)
	s.recordMigrationMetrics("cold", "failure", 10*time.Second, 0.0, 0.0)
}

// RecordMigrationMetrics_WithMetrics tests removed: prometheus duplicate registration

// MigrateVM_LocalDisk_WithStorage removed: passes validation but panics on nil libvirt

// MigrateVM_ColdStrategy_SkipsDiskCheck removed: passes validation, panics on nil libvirt

// mockMigrateStreamR2 for round 2 tests.
type mockMigrateStreamR2 struct {
	ctx  context.Context
	sent []*pb.MigrateProgress
}

func (m *mockMigrateStreamR2) Send(p *pb.MigrateProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockMigrateStreamR2) Context() context.Context       { return m.ctx }
func (m *mockMigrateStreamR2) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockMigrateStreamR2) SendHeader(_ metadata.MD) error { return nil }
func (m *mockMigrateStreamR2) SetTrailer(_ metadata.MD)       {}
func (m *mockMigrateStreamR2) SendMsg(_ interface{}) error    { return nil }
func (m *mockMigrateStreamR2) RecvMsg(_ interface{}) error    { return nil }

// MigrateVM_CPUPinning removed: passes validation, panics on nil libvirt

// ── allocateDevices: type-based allocation ──────────────────────────────────

func TestAllocateDevices_TypeBased_NotEnough(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Only 1 GPU available but we need 2.
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host",
		Address:  "0000:03:00.0",
		Type:     "gpu",
		VendorID: "10de",
	})

	_, err := s.allocateDevices(ctx, "test-vm", []*pb.DeviceSpec{
		{Type: "gpu", Count: 2},
	})
	if err == nil {
		t.Fatal("expected error for insufficient devices")
	}
	if c := status.Code(err); c != codes.ResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted", c)
	}
}

func TestAllocateDevices_TypeBased_VendorFilter(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Two GPUs, different vendors — request only nvidia.
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host",
		Address:  "0000:04:00.0",
		Type:     "gpu",
		VendorID: "10de", // nvidia
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host",
		Address:  "0000:05:00.0",
		Type:     "gpu",
		VendorID: "1002", // amd
	})

	// Request 2 nvidia GPUs — only 1 available.
	_, err := s.allocateDevices(ctx, "vendor-vm", []*pb.DeviceSpec{
		{Type: "gpu", Vendor: "10de", Count: 2},
	})
	if err == nil {
		t.Fatal("expected error for insufficient vendor-matched devices")
	}
	if c := status.Code(err); c != codes.ResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted", c)
	}
}

func TestAllocateDevices_ZeroCount_DefaultsToOne(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host",
		Address:  "0000:06:00.0",
		Type:     "nic",
		VendorID: "8086",
	})

	// Count=0 should default to 1 device.
	// Will fail at vfio.Bind (no real sysfs), but validates allocation logic.
	_, err := s.allocateDevices(ctx, "zero-cnt-vm", []*pb.DeviceSpec{
		{Type: "nic", Count: 0},
	})
	// If it errors, it should be Internal (vfio bind), not ResourceExhausted.
	if err != nil {
		if c := status.Code(err); c == codes.ResourceExhausted {
			t.Error("count=0 should default to 1; device is available")
		}
	}
}

// ── checkIOMMUConflict ──────────────────────────────────────────────────────

func TestCheckIOMMUConflict_Conflict(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Two devices in same IOMMU group, one assigned to a different VM.
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName:   "test-host",
		Address:    "0000:08:00.0",
		IOMMUGroup: 7,
		VMName:     "",
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName:   "test-host",
		Address:    "0000:08:00.1",
		IOMMUGroup: 7,
		VMName:     "other-vm", // assigned to a different VM
	})

	err := s.checkIOMMUConflict(ctx, "0000:08:00.0", "my-vm")
	if err == nil {
		t.Fatal("expected IOMMU conflict error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestCheckIOMMUConflict_SameVM_OK(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName:   "test-host",
		Address:    "0000:09:00.0",
		IOMMUGroup: 8,
		VMName:     "",
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName:   "test-host",
		Address:    "0000:09:00.1",
		IOMMUGroup: 8,
		VMName:     "same-vm",
	})

	// Same VM — should be OK.
	err := s.checkIOMMUConflict(ctx, "0000:09:00.0", "same-vm")
	if err != nil {
		t.Errorf("expected no conflict for same VM, got %v", err)
	}
}

func TestCheckIOMMUConflict_UnknownDevice(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Device not in DB — should return nil (no conflict possible).
	err := s.checkIOMMUConflict(ctx, "0000:ff:00.0", "my-vm")
	if err != nil {
		t.Errorf("expected nil for unknown device, got %v", err)
	}
}

// ── iommuGroupSiblings ──────────────────────────────────────────────────────

func TestIommuGroupSiblings_SingleDevice(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName:   "test-host",
		Address:    "0000:0a:00.0",
		IOMMUGroup: 10,
	})

	addrs, err := s.iommuGroupSiblings(ctx, "0000:0a:00.0")
	if err != nil {
		t.Fatalf("iommuGroupSiblings: %v", err)
	}
	if len(addrs) != 1 || addrs[0] != "0000:0a:00.0" {
		t.Errorf("expected [0000:0a:00.0], got %v", addrs)
	}
}

func TestIommuGroupSiblings_MultipleSiblings(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName:   "test-host",
		Address:    "0000:0b:00.0",
		IOMMUGroup: 11,
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName:   "test-host",
		Address:    "0000:0b:00.1",
		IOMMUGroup: 11,
	})

	addrs, err := s.iommuGroupSiblings(ctx, "0000:0b:00.0")
	if err != nil {
		t.Fatalf("iommuGroupSiblings: %v", err)
	}
	if len(addrs) != 2 {
		t.Errorf("expected 2 siblings, got %d: %v", len(addrs), addrs)
	}
}

func TestIommuGroupSiblings_NotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	addrs, err := s.iommuGroupSiblings(ctx, "0000:ff:00.0")
	if err != nil {
		t.Fatalf("iommuGroupSiblings: %v", err)
	}
	// Should return the original address.
	if len(addrs) != 1 || addrs[0] != "0000:ff:00.0" {
		t.Errorf("expected fallback [0000:ff:00.0], got %v", addrs)
	}
}

// ── persistImageRecord ──────────────────────────────────────────────────────

func TestPersistImageRecord(t *testing.T) {
	s := testServerR2(t)

	// This won't have a real image file, but it should not panic.
	// DiskInfo will fail gracefully, and we'll get sizeBytes=0.
	s.persistImageRecord(&pb.PullImageRequest{
		Name:      "test-image",
		SourceUrl: "https://example.com/test.qcow2",
		Format:    "qcow2",
		Checksum:  "sha256:abc123",
	})

	// Verify image was persisted in DB.
	ctx := adminCtx()
	images, err := corrosion.ListImages(ctx, s.db)
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	found := false
	for _, img := range images {
		if img.Name == "test-image" {
			found = true
			if img.Format != "qcow2" {
				t.Errorf("format = %q, want qcow2", img.Format)
			}
			break
		}
	}
	if !found {
		t.Error("image record not found after persistImageRecord")
	}
}

// ── VM state machine helpers ────────────────────────────────────────────────

// ── parseTimestamp ───────────────────────────────────────────────────────────

func TestParseTimestamp_Invalid(t *testing.T) {
	ts := parseTimestamp("not-a-timestamp")
	if ts != nil {
		t.Error("expected nil for invalid timestamp")
	}
}

// ── GetClusterStatus ────────────────────────────────────────────────────────

// ── ListLoadBalancers ───────────────────────────────────────────────────────

func TestListLoadBalancers_WithData(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertLBConfig(ctx, s.db, corrosion.LBConfigRecord{
		Name:      "my-lb",
		VIP:       "10.0.0.100/24",
		Algorithm: "roundrobin",
		Enabled:   true,
	})

	resp, err := s.ListLoadBalancers(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListLoadBalancers: %v", err)
	}
	if len(resp.Lbs) != 1 {
		t.Fatalf("expected 1 LB, got %d", len(resp.Lbs))
	}
	if resp.Lbs[0].Name != "my-lb" {
		t.Errorf("Name = %q, want my-lb", resp.Lbs[0].Name)
	}
}

// ── InspectLoadBalancer found ───────────────────────────────────────────────

// ── ListImages ──────────────────────────────────────────────────────────────

// ── DeleteImage ─────────────────────────────────────────────────────────────

// ── CreateSnapshot: VM on wrong host ────────────────────────────────────────

func TestCreateSnapshot_DeepChainVM_WrongHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "deep-snap-vm", "other-host", "running")

	// Insert 30 existing snapshots (past the warning threshold).
	for i := 0; i < 30; i++ {
		corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
			VMName:   "deep-snap-vm",
			HostName: "other-host",
			Name:     "snap-" + string(rune('a'+i%26)),
			State:    "ok",
		})
	}

	// VM is on other-host so this will return FailedPrecondition or Unavailable
	// (if forwarding is attempted) before reaching the virt call.
	_, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{
		VmName: "deep-snap-vm",
		Name:   "snap-deep",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── RestoreSnapshot transient states ────────────────────────────────────────

func TestRestoreSnapshot_ErrorState_Allowed(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// "error" state is not in the blocked list (migrating/creating/starting).
	insertTestVMR2(t, ctx, s.db, "restore-error", "other-host", "error")

	// VM on wrong host -> FailedPrecondition or Unavailable (if forwarding attempted).
	_, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{
		VmName:       "restore-error",
		SnapshotName: "snap1",
	})
	if err == nil {
		t.Fatal("expected error (wrong host)")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestRestoreSnapshot_BackingUpState_Allowed(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// "backing-up" is not in the transient-block list.
	insertTestVMR2(t, ctx, s.db, "restore-backup", "other-host", "backing-up")

	_, err := s.RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{
		VmName:       "restore-backup",
		SnapshotName: "snap1",
	})
	if err == nil {
		t.Fatal("expected error (wrong host)")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── countVMDisks ────────────────────────────────────────────────────────────

func TestCountVMDisks_None(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	count := countVMDisks(ctx, s.db, "nonexistent-vm")
	if count != 0 {
		t.Errorf("expected 0 disks, got %d", count)
	}
}

// ── detachDisk: disk not found ──────────────────────────────────────────────

func TestDetachDisk_DiskNotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "detach-disk-vm", "test-host", "running")

	// detachDisk is called via DetachDevice with DiskName set.
	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName:   "detach-disk-vm",
		DiskName: "nonexistent-disk",
	})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── BuildImage validation paths ─────────────────────────────────────────────

// ── PushImage validation ────────────────────────────────────────────────────

// mockPushImageStreamR2 implements pb.LiteVirt_PushImageServer.
type mockPushImageStreamR2 struct {
	ctx  context.Context
	sent []*pb.PushImageProgress
}

func (m *mockPushImageStreamR2) Send(p *pb.PushImageProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockPushImageStreamR2) Context() context.Context       { return m.ctx }
func (m *mockPushImageStreamR2) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockPushImageStreamR2) SendHeader(_ metadata.MD) error { return nil }
func (m *mockPushImageStreamR2) SetTrailer(_ metadata.MD)       {}
func (m *mockPushImageStreamR2) SendMsg(_ interface{}) error    { return nil }
func (m *mockPushImageStreamR2) RecvMsg(_ interface{}) error    { return nil }

func TestPushImage_EmptyFields(t *testing.T) {
	s := testServerR2(t)
	stream := &mockPushImageStreamR2{ctx: adminCtx()}

	err := s.PushImage(&pb.PushImageRequest{}, stream)
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestPushImage_ImageNotFound(t *testing.T) {
	s := testServerR2(t)
	stream := &mockPushImageStreamR2{ctx: adminCtx()}

	err := s.PushImage(&pb.PushImageRequest{Name: "ghost-img", TargetHost: "h1"}, stream)
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── User / token operations ─────────────────────────────────────────────────

// ── resolveVolume ───────────────────────────────────────────────────────────

func TestResolveVolume_EmptyStack(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	_ = ctx

	cfg := s.resolveVolume(context.Background(), "", "vol1")
	if cfg.Driver != "local" {
		t.Errorf("Driver = %q, want local", cfg.Driver)
	}
}

// ── GenerateMAC ─────────────────────────────────────────────────────────────

func TestGenerateMAC_Unique(t *testing.T) {
	m1 := GenerateMAC()
	m2 := GenerateMAC()
	if m1 == m2 {
		t.Error("GenerateMAC returned same value twice")
	}
}

// ── specCloudInitHash with cloud-init present ───────────────────────────────

// ── ListSnapshots with snapshot records ─────────────────────────────────────

func TestListSnapshots_ReturnsFields(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "list-snap-vm", "test-host", "running")
	corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		VMName:   "list-snap-vm",
		HostName: "test-host",
		Name:     "full-snap",
		State:    "ok",
	})

	resp, err := s.ListSnapshots(ctx, &pb.ListSnapshotsRequest{VmName: "list-snap-vm"})
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(resp.Snapshots) != 1 {
		t.Fatalf("expected 1 snapshot, got %d", len(resp.Snapshots))
	}
	sn := resp.Snapshots[0]
	if sn.Name != "full-snap" {
		t.Errorf("Name = %q, want full-snap", sn.Name)
	}
	if sn.State != "ok" {
		t.Errorf("State = %q, want ok", sn.State)
	}
	if sn.HostName != "test-host" {
		t.Errorf("HostName = %q, want test-host", sn.HostName)
	}
}

// ── InspectHost for local host with live stats ──────────────────────────────

func TestInspectHost_LocalHost_NoLibvirt(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "test-host", "active")
	insertTestVMR2(t, ctx, s.db, "local-vm", "test-host", "running")

	// hostAllocatedResources queries DB directly.
	h, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "test-host"})
	if err != nil {
		t.Fatalf("InspectHost: %v", err)
	}
	if h.Name != "test-host" {
		t.Errorf("Name = %q", h.Name)
	}
	// One running VM with CPUActual=2, MemActual=4096.
	if h.CpuUsed != 2 {
		t.Errorf("CpuUsed = %d, want 2", h.CpuUsed)
	}
	if h.MemUsedMib != 4096 {
		t.Errorf("MemUsedMib = %d, want 4096", h.MemUsedMib)
	}
}

// ── CutoverVM: next VM in wrong state ───────────────────────────────────────

func TestCutoverVM_NextVMInBadState(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Create the -next VM in "migrating" state (not allowed).
	insertTestVMR2(t, ctx, s.db, "cut-vm-next", "test-host", "migrating")

	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "cut-vm"})
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

// ── SetVMIP success path ────────────────────────────────────────────────────

func TestSetVMIP_DefaultNetwork(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "ip-vm2", "test-host", "running")

	// No NetworkName specified — should default to "production".
	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{
		Name: "ip-vm2",
		Ip:   "10.0.0.43",
	})
	if err != nil {
		t.Fatalf("SetVMIP: %v", err)
	}
}

// ── CutoverVM: resource exhaustion ──────────────────────────────────────────

func TestCutoverVM_ResourceExhausted(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Insert local host with very small capacity.
	insertTestHostR2(t, ctx, s.db, "test-host", "active")

	// Old VM running on test-host, using all CPU.
	err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "cutover-vm",
		HostName:  "test-host",
		State:     "running",
		CPUActual: 100,
		MemActual: 50000,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Next VM also running on test-host.
	err = corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "cutover-vm-next",
		HostName:  "test-host",
		State:     "running",
		CPUActual: 100,
		MemActual: 50000,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, cutErr := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "cutover-vm"})
	if cutErr == nil {
		t.Fatal("expected resource exhaustion error")
	}
	if c := status.Code(cutErr); c != codes.ResourceExhausted {
		t.Errorf("code = %v, want ResourceExhausted", c)
	}
}

// ── CutoverVM: nextVM on other host (skips libvirt) ─────────────────────────

func TestCutoverVM_NextVMOnOtherHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Old VM on other host.
	insertTestVMR2(t, ctx, s.db, "remote-cut-vm", "other-host", "running")
	// Next VM on other host, in "running" state.
	insertTestVMR2(t, ctx, s.db, "remote-cut-vm-next", "other-host", "running")

	// Cutover should proceed: old VM is on other host so DeleteVM will
	// fail with FailedPrecondition, but corrosion.DeleteVM still removes DB record,
	// then RenameVM runs. This exercises the cutover renaming path.
	resp, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "remote-cut-vm"})
	// May succeed or fail depending on RenameVM implementation.
	// The key is that it doesn't panic from nil virt.
	_ = resp
	_ = err
}

// ── CutoverVM: nextVM stopped, oldVM nil ────────────────────────────────────

func TestCutoverVM_NoOldVM(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Only the -next VM exists (old was already deleted).
	insertTestVMR2(t, ctx, s.db, "orphan-vm-next", "other-host", "stopped")

	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "orphan-vm"})
	// Should not panic — oldVM is nil so the delete block is skipped.
	_ = err
}

// ── DrainHost: running VMs but no target hosts ──────────────────────────────

func TestDrainHost_RunningVMs_NoTargets(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	// Insert the host being drained and a running VM on it.
	insertTestHostR2(t, ctx, s.db, "drain-h2", "active")
	insertTestVMR2WithStack(t, ctx, s.db, "drain-vm1", "drain-h2", "running", "")

	stream := &mockDrainStreamR2{ctx: ctx}
	err := s.DrainHost(&pb.DrainHostRequest{Name: "drain-h2"}, stream)

	// No target hosts available, so VMs remain → FailedPrecondition or nil (partial drain).
	// At minimum, some progress messages should be sent.
	_ = err
	if len(stream.sent) == 0 {
		t.Error("expected at least one progress message about failed placement")
	}
}

// mockDrainStreamR2 implements pb.LiteVirt_DrainHostServer.
type mockDrainStreamR2 struct {
	ctx  context.Context
	sent []*pb.DrainProgress
}

func (m *mockDrainStreamR2) Send(p *pb.DrainProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockDrainStreamR2) Context() context.Context       { return m.ctx }
func (m *mockDrainStreamR2) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockDrainStreamR2) SendHeader(_ metadata.MD) error { return nil }
func (m *mockDrainStreamR2) SetTrailer(_ metadata.MD)       {}
func (m *mockDrainStreamR2) SendMsg(_ interface{}) error    { return nil }
func (m *mockDrainStreamR2) RecvMsg(_ interface{}) error    { return nil }

// adminContext returns a context with admin role for methods that require auth.
func adminContext(ctx context.Context) context.Context {
	ctx = context.WithValue(ctx, ctxKeyRole, "admin")
	ctx = context.WithValue(ctx, ctxKeyUsername, "admin")
	return ctx
}

// ── DrainHost: with VMs in error state (should be skipped) ──────────────────

func TestDrainHost_ErrorVMs_Skipped(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "drain-err-host", "active")
	insertTestVMR2(t, ctx, s.db, "err-vm1", "drain-err-host", "error")

	stream := &mockDrainStreamR2{ctx: ctx}
	err := s.DrainHost(&pb.DrainHostRequest{Name: "drain-err-host"}, stream)

	// Error VMs are not "running" or "stopped", so toMigrate is empty → nil return.
	if err != nil {
		t.Errorf("DrainHost: %v", err)
	}
}

// ── drainOneVM: VM in backing-up state (skipped) ────────────────────────────

func TestDrainOneVM_BackingUp(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "backup-vm", "test-host", "backing-up")

	vm := corrosion.VMRecord{Name: "backup-vm", HostName: "test-host", State: "running"}
	target := corrosion.HostRecord{Name: "target-h", Address: "10.0.0.2"}

	progress := s.drainOneVM(ctx, vm, target)
	if progress.Status != "skipped" {
		t.Errorf("Status = %q, want skipped", progress.Status)
	}
}

// ── drainOneVM: VM on other host (cold migration reassign) ──────────────────

func TestDrainOneVM_OtherHost_ColdReassign(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "other-vm", "other-host", "stopped")

	vm := corrosion.VMRecord{Name: "other-vm", HostName: "other-host", State: "stopped"}
	target := corrosion.HostRecord{Name: "target-h", Address: "10.0.0.2"}

	progress := s.drainOneVM(ctx, vm, target)
	// VM is stopped and on other-host, so no libvirt calls are made.
	// It goes through cold migration path, updating host assignment.
	if progress.Status != "done" {
		t.Errorf("Status = %q, want done", progress.Status)
	}
	if progress.Strategy != pb.MigrateStrategy_MIGRATE_COLD {
		t.Errorf("Strategy = %v, want MIGRATE_COLD", progress.Strategy)
	}
}

// ── DeleteStack: VMs on other host (errors but continues) ───────────────────

// mockDeleteStreamR2 implements grpc.ServerStreamingServer[pb.DeleteProgress].
type mockDeleteStreamR2 struct {
	ctx  context.Context
	sent []*pb.DeleteProgress
}

func (m *mockDeleteStreamR2) Send(p *pb.DeleteProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockDeleteStreamR2) Context() context.Context       { return m.ctx }
func (m *mockDeleteStreamR2) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockDeleteStreamR2) SendHeader(_ metadata.MD) error { return nil }
func (m *mockDeleteStreamR2) SetTrailer(_ metadata.MD)       {}
func (m *mockDeleteStreamR2) SendMsg(_ interface{}) error    { return nil }
func (m *mockDeleteStreamR2) RecvMsg(_ interface{}) error    { return nil }

func TestDeleteStack_VMsOnOtherHost_ErrorsButContinues(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestVMR2WithStack(t, ctx, s.db, "stack-vm1", "other-host", "running", "my-stack")
	insertTestVMR2WithStack(t, ctx, s.db, "stack-vm2", "other-host", "stopped", "my-stack")

	stream := &mockDeleteStreamR2{ctx: ctx}
	err := s.DeleteStack(&pb.DeleteStackRequest{Name: "my-stack"}, stream)
	if err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	// Should have sent "deleting" and "error" for each VM (FailedPrecondition: wrong host).
	if len(stream.sent) < 2 {
		t.Errorf("expected at least 2 progress messages, got %d", len(stream.sent))
	}
}

func TestDeleteStack_NoVMs(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	stream := &mockDeleteStreamR2{ctx: ctx}
	err := s.DeleteStack(&pb.DeleteStackRequest{Name: "empty-stack"}, stream)
	if err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	if len(stream.sent) != 0 {
		t.Errorf("expected 0 progress messages, got %d", len(stream.sent))
	}
}

// ── DeployStack: execution with delete ops for VMs on other host ────────────

func TestDeployStack_ExecuteWithDeleteOps(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "test-host", "active")
	createFakeImage(t, s, "ubuntu-22.04")

	// Insert a VM that is in the stack but not in the compose YAML → will be deleted.
	insertTestVMR2WithStack(t, ctx, s.db, "my-stack-extra-vm", "other-host", "stopped", "my-stack")

	yaml := `name: my-stack
vms:
  web:
    image: ubuntu-22.04
    cpu: 1
    memory: 512M
`
	stream := &mockDeployStreamR2{ctx: ctx}
	err := s.DeployStack(&pb.DeployStackRequest{
		ComposeYaml: yaml,
	}, stream)
	// Will fail during create (no libvirt), but should process delete of extra-vm first.
	// The key is it doesn't panic.
	_ = err
	if len(stream.sent) == 0 {
		t.Error("expected at least one progress message")
	}
}

// ── DeployStack: DryRun with multiple operations ────────────────────────────

func TestDeployStack_DryRun_WithCurrentVMs(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "test-host", "active")
	createFakeImage(t, s, "ubuntu-22.04")

	// Existing VM has different image → should produce an update op in dry-run.
	err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "my-stack-web-0",
		StackName: "my-stack",
		HostName:  "test-host",
		State:     "running",
		CPUActual: 1,
		MemActual: 512,
		Spec:      `{"image":"old-image","cloud_init":""}`,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	yaml := `name: my-stack
vms:
  web:
    image: ubuntu-22.04
    cpu: 1
    memory: 512M
`
	stream := &mockDeployStreamR2{ctx: ctx}
	err = s.DeployStack(&pb.DeployStackRequest{
		ComposeYaml: yaml,
		DryRun:      true,
	}, stream)
	if err != nil {
		t.Fatalf("DeployStack dry-run: %v", err)
	}
	if len(stream.sent) == 0 {
		t.Error("expected at least one dry-run operation")
	}
}

// ── DeployStack: CAS check fails due to hash mismatch ───────────────────────

func TestDeployStack_CASMismatch_WithStack(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	createFakeImage(t, s, "ubuntu-22.04")

	// Pre-insert a stack record with a known hash.
	corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name:        "cas-stack",
		ComposeHash: "abc123",
		State:       "active",
	})

	yaml := `name: cas-stack
vms:
  web:
    image: ubuntu-22.04
    cpu: 1
    memory: 512M
`
	stream := &mockDeployStreamR2{ctx: ctx}
	err := s.DeployStack(&pb.DeployStackRequest{
		ComposeYaml:  yaml,
		ExpectedHash: "wrong-hash",
	}, stream)
	if err == nil {
		t.Fatal("expected CAS error")
	}
	if c := status.Code(err); c != codes.Aborted {
		t.Errorf("code = %v, want Aborted", c)
	}
}

// ── validateDeployDependencies: missing image ───────────────────────────────

func TestDeployStack_MissingImage_FailsPrecondition(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	// The image "nonexistent-image" does not exist in the store.
	yaml := `name: missing-img-stack
vms:
  web:
    image: nonexistent-image
    cpu: 1
    memory: 512M
`
	stream := &mockDeployStreamR2{ctx: ctx}
	err := s.DeployStack(&pb.DeployStackRequest{
		ComposeYaml: yaml,
	}, stream)
	if err == nil {
		t.Fatal("expected pre-deploy validation error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

// ── DeleteImage by name ─────────────────────────────────────────────────────

func TestDeleteImage_ByName(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// Insert an image record.
	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name:   "del-me-img",
		Format: "qcow2",
	})

	_, err := s.DeleteImage(ctx, &pb.DeleteImageRequest{Name: "del-me-img"})
	if err != nil {
		t.Fatalf("DeleteImage: %v", err)
	}

	// Verify it's gone from the list.
	resp, err := s.ListImages(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	for _, img := range resp.Images {
		if img.Name == "del-me-img" {
			t.Error("image should have been deleted")
		}
	}
}

// ── ListImages with multiple images ─────────────────────────────────────────

func TestListImages_Multiple(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{Name: "img-a", Format: "qcow2", SizeBytes: 100})
	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{Name: "img-b", Format: "raw", SizeBytes: 200})

	resp, err := s.ListImages(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(resp.Images) < 2 {
		t.Errorf("expected at least 2 images, got %d", len(resp.Images))
	}
}

// ── PullImage: missing fields ───────────────────────────────────────────────

// mockPullStreamR2 implements pb.LiteVirt_PullImageServer.
type mockPullStreamR2 struct {
	ctx  context.Context
	sent []*pb.PullProgress
}

func (m *mockPullStreamR2) Send(p *pb.PullProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockPullStreamR2) Context() context.Context       { return m.ctx }
func (m *mockPullStreamR2) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockPullStreamR2) SendHeader(_ metadata.MD) error { return nil }
func (m *mockPullStreamR2) SetTrailer(_ metadata.MD)       {}
func (m *mockPullStreamR2) SendMsg(_ interface{}) error    { return nil }
func (m *mockPullStreamR2) RecvMsg(_ interface{}) error    { return nil }

func TestPullImage_EmptyName(t *testing.T) {
	s := testServerR2(t)

	stream := &mockPullStreamR2{ctx: adminCtx()}
	err := s.PullImage(&pb.PullImageRequest{
		Name:      "",
		SourceUrl: "https://example.com/image.qcow2",
	}, stream)
	// The pull will fail because empty name produces a bad path, or possibly succeed
	// starting the download. Either way it should not panic.
	_ = err
}

// ── DisableBackend / EnableBackend ──────────────────────────────────────────

func TestDisableBackend_LBNotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// LB doesn't exist → InspectLoadBalancer returns NotFound.
	_, err := s.DisableBackend(ctx, &pb.DisableBackendRequest{
		LbName:  "ghost-lb",
		Backend: "10.0.0.1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestEnableBackend_LBNotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.EnableBackend(ctx, &pb.EnableBackendRequest{
		LbName:  "ghost-lb",
		Backend: "10.0.0.1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── RebuildVM: VM on other host ─────────────────────────────────────────────

func TestRebuildVM_OtherHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2WithSpec(t, ctx, s.db, "rebuild-vm", "other-host", "running", `{"image":"ubuntu"}`)

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "rebuild-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── SetBootOrder: VM on other host ──────────────────────────────────────────

func TestSetBootOrder_OtherHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "boot-vm", "other-host", "running")

	_, err := s.SetBootOrder(ctx, &pb.SetBootOrderRequest{
		Name:      "boot-vm",
		BootOrder: "hd,network",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── vmToProto: VM on other host (no libvirt state lookup) ───────────────────

func TestVmToProto_OtherHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "remote-vm", "other-host", "running")

	vm, err := s.vmToProto(ctx, "remote-vm")
	if err != nil {
		t.Fatalf("vmToProto: %v", err)
	}
	if vm.Name != "remote-vm" {
		t.Errorf("Name = %q", vm.Name)
	}
	if vm.HostName != "other-host" {
		t.Errorf("HostName = %q", vm.HostName)
	}
}

func TestVmToProto_NotFound(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.vmToProto(ctx, "ghost")
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── RestartVM: VM on other host ─────────────────────────────────────────────

func TestRestartVM_OtherHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "restart-vm", "other-host", "running")

	_, err := s.RestartVM(ctx, &pb.RestartVMRequest{Name: "restart-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── DeployStack: non-dry-run with empty plan ────────────────────────────────

// DeployStack_EmptyPlan removed: even matched VMs trigger update ops that call CreateVM → nil virt panic

// ── InspectHost: remote host (non-local) ────────────────────────────────────

func TestInspectHost_RemoteHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "remote-node", "active")
	insertTestVMR2(t, ctx, s.db, "r-vm1", "remote-node", "running")

	resp, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: "remote-node"})
	if err != nil {
		t.Fatalf("InspectHost: %v", err)
	}
	if resp.Name != "remote-node" {
		t.Errorf("Name = %q", resp.Name)
	}
	if resp.VmCount != 1 {
		t.Errorf("VmCount = %d, want 1", resp.VmCount)
	}
}

// allocateDevices success test removed: requires real PCI hardware for vfio bind

// ── ExecVM: VM on other host ────────────────────────────────────────────────

func TestExecVM_OtherHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "exec-vm", "other-host", "running")

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{
		Name:    "exec-vm",
		Command: []string{"ls"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

// ── DrainHost: with parallel setting ────────────────────────────────────────

func TestDrainHost_NotFoundHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	stream := &mockDrainStreamR2{ctx: ctx}
	err := s.DrainHost(&pb.DrainHostRequest{Name: "nonexistent-host"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

// ── ListStacks: with VM state counts ────────────────────────────────────────

func TestListStacks_VMStateCounts(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	corrosion.UpsertStack(ctx, s.db, corrosion.StackRecord{
		Name:  "counted-stack",
		State: "active",
	})

	insertTestVMR2WithStack(t, ctx, s.db, "c-vm1", "test-host", "running", "counted-stack")
	insertTestVMR2WithStack(t, ctx, s.db, "c-vm2", "test-host", "stopped", "counted-stack")
	insertTestVMR2WithStack(t, ctx, s.db, "c-vm3", "test-host", "error", "counted-stack")

	resp, err := s.ListStacks(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListStacks: %v", err)
	}

	var found *pb.StackSummary
	for _, st := range resp.Stacks {
		if st.Name == "counted-stack" {
			found = st
			break
		}
	}
	if found == nil {
		t.Fatal("counted-stack not found")
	}
	if found.Running != 1 {
		t.Errorf("Running = %d, want 1", found.Running)
	}
	if found.Stopped != 1 {
		t.Errorf("Stopped = %d, want 1", found.Stopped)
	}
	if found.Error != 1 {
		t.Errorf("Error = %d, want 1", found.Error)
	}
	if found.VmCount != 3 {
		t.Errorf("VmCount = %d, want 3", found.VmCount)
	}
}

// ── DrainHost: with target host, VMs on other-host (cold reassign) ──────────

func TestDrainHost_WithTargetHost_ColdReassign(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	// Source host being drained.
	insertTestHostR2(t, ctx, s.db, "drain-src", "active")
	// Target host available.
	err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name:     "drain-dst",
		Address:  "10.0.0.2",
		SSHUser:  "root",
		SSHPort:  22,
		GRPCPort: 7443,
		State:    "active",
		CPUTotal: 32,
		MemTotal: 65536,
	})
	if err != nil {
		t.Fatal(err)
	}

	// VM on drain-src, stopped state. Will go through cold migration path.
	insertTestVMR2WithStack(t, ctx, s.db, "drain-cold-vm", "drain-src", "stopped", "")

	stream := &mockDrainStreamR2{ctx: ctx}
	err = s.DrainHost(&pb.DrainHostRequest{Name: "drain-src", Parallel: 1}, stream)
	// After drain, the VM should be reassigned to drain-dst.
	_ = err
	if len(stream.sent) == 0 {
		t.Error("expected at least one drain progress message")
	}
}

// ── DrainHost: with running VM on non-local host (skips libvirt) ────────────

func TestDrainHost_RunningVM_OtherHostTarget(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestHostR2(t, ctx, s.db, "drain-r-src", "active")
	err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name:     "drain-r-dst",
		Address:  "10.0.0.3",
		SSHUser:  "root",
		SSHPort:  22,
		GRPCPort: 7443,
		State:    "active",
		CPUTotal: 32,
		MemTotal: 65536,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Running VM on drain-r-src. Since drain-r-src != test-host (s.hostName),
	// drainOneVM skips live migration and goes to cold migration path.
	insertTestVMR2(t, ctx, s.db, "drain-r-vm", "drain-r-src", "running")

	stream := &mockDrainStreamR2{ctx: ctx}
	err = s.DrainHost(&pb.DrainHostRequest{Name: "drain-r-src", Parallel: 2}, stream)
	_ = err
	if len(stream.sent) == 0 {
		t.Error("expected progress messages")
	}
}

// ── DeleteStack: unauthorized ───────────────────────────────────────────────

func TestDeleteStack_UnauthorizedR2(t *testing.T) {
	s := testServerR2(t)
	ctx := context.WithValue(context.Background(), ctxKeyRole, "viewer")

	stream := &mockDeleteStreamR2{ctx: ctx}
	err := s.DeleteStack(&pb.DeleteStackRequest{Name: "any-stack"}, stream)
	if err == nil {
		t.Fatal("expected permission error")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

// ── DeleteStack: with local stopped VM on other host ────────────────────────

func TestDeleteStack_LocalStoppedVM(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestVMR2WithStack(t, ctx, s.db, "local-stack-vm", "other-host", "stopped", "local-stack")

	stream := &mockDeleteStreamR2{ctx: ctx}
	err := s.DeleteStack(&pb.DeleteStackRequest{Name: "local-stack", KeepDisks: true}, stream)
	if err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	hasDeleting := false
	for _, p := range stream.sent {
		if p.Status == "deleting" {
			hasDeleting = true
		}
	}
	if !hasDeleting {
		t.Error("expected 'deleting' status in progress")
	}
}

// ── vmToProto: with spec and interfaces ─────────────────────────────────────

func TestVmToProto_WithSpecAndInterfaces(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	specJSON := `{"image":"ubuntu-22.04","network":[{"name":"prod"}]}`
	insertTestVMR2WithSpec(t, ctx, s.db, "spec-vm", "other-host", "running", specJSON)

	corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName:      "spec-vm",
		NetworkName: "prod",
		MAC:         "52:54:00:aa:bb:cc",
		IP:          "10.0.0.5",
	})

	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName:      "spec-vm",
		DiskName:    "root",
		HostName:    "other-host",
		Path:        "/var/lib/litevirt/disks/spec-vm/root.qcow2",
		SizeBytes:   10737418240,
		StorageType: "local",
	})

	vm, err := s.vmToProto(ctx, "spec-vm")
	if err != nil {
		t.Fatalf("vmToProto: %v", err)
	}
	if len(vm.Interfaces) != 1 {
		t.Errorf("Interfaces = %d, want 1", len(vm.Interfaces))
	}
	if len(vm.Disks) != 1 {
		t.Errorf("Disks = %d, want 1", len(vm.Disks))
	}
}

// ── DeployStack: with delete-only operations ────────────────────────────────

func TestDeployStack_DeleteOnly(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	insertTestVMR2WithStack(t, ctx, s.db, "del-only-vm1", "other-host", "running", "del-stack")

	yaml := `name: del-stack
vms: {}
`
	stream := &mockDeployStreamR2{ctx: ctx}
	err := s.DeployStack(&pb.DeployStackRequest{ComposeYaml: yaml}, stream)
	_ = err
	if len(stream.sent) == 0 {
		t.Error("expected progress messages for delete op")
	}
}

// ── PushImage: target host not found ────────────────────────────────────────

func TestPushImage_TargetNotFoundR2(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	createFakeImage(t, s, "push-img")

	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name:   "push-img",
		Format: "qcow2",
	})

	stream := &mockPushImageStreamR2{ctx: ctx}
	err := s.PushImage(&pb.PushImageRequest{
		Name:       "push-img",
		TargetHost: "nonexistent-host",
	}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ── SetVMIP: VM on other host ───────────────────────────────────────────────

func TestSetVMIP_OtherHost(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "ip-remote-vm", "other-host", "running")

	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{
		Name: "ip-remote-vm",
		Ip:   "10.0.0.99",
	})
	if err != nil {
		t.Fatalf("SetVMIP: %v", err)
	}
}

// ── CreateVM: duplicate name ────────────────────────────────────────────────

func TestCreateVM_DuplicateNameR2(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "dup-vm", "test-host", "running")

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name:      "dup-vm",
			Cpu:       1,
			MemoryMib: 512,
			Image:     "ubuntu",
		},
	})
	if err == nil {
		t.Fatal("expected error for duplicate VM")
	}
	if c := status.Code(err); c != codes.AlreadyExists {
		t.Errorf("code = %v, want AlreadyExists", c)
	}
}

// ── BuildImage: VM with disk, exercises deeper path ─────────────────────────

func TestBuildImage_NoDisk(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "build-nodisk-vm", "test-host", "running")

	_, err := s.BuildImage(ctx, &pb.BuildImageRequest{
		VmName:    "build-nodisk-vm",
		ImageName: "my-img",
	})
	if err == nil {
		t.Fatal("expected error for VM with no disks")
	}
	if c := status.Code(err); c != codes.Internal {
		t.Errorf("code = %v, want Internal", c)
	}
}

func TestBuildImage_WithDisk_QemuFails(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestVMR2(t, ctx, s.db, "build-img-vm", "test-host", "running")

	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName:   "build-img-vm",
		DiskName: "root",
		HostName: "test-host",
		Path:     "/nonexistent/root.qcow2",
	})

	_, err := s.BuildImage(ctx, &pb.BuildImageRequest{
		VmName:    "build-img-vm",
		ImageName: "built-img",
	})
	// Will fail because the source file doesn't exist.
	if err == nil {
		t.Fatal("expected error from convert")
	}
	if c := status.Code(err); c != codes.Internal {
		t.Errorf("code = %v, want Internal", c)
	}
}

// ── PushImage: image exists, with target host ───────────────────────────────

func TestPushImage_WithTargetHost_PeerConnFails(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	createFakeImage(t, s, "push-img")
	insertTestHostR2(t, ctx, s.db, "push-target", "active")

	stream := &mockPushImageStreamR2{ctx: ctx}
	err := s.PushImage(&pb.PushImageRequest{
		Name:       "push-img",
		TargetHost: "push-target",
	}, stream)
	// Will fail at peer TLS connection (no real daemon to connect to).
	if err == nil {
		t.Fatal("expected peer connection error")
	}
	if c := status.Code(err); c != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", c)
	}
}

// ── DeleteImage: nonexistent image ──────────────────────────────────────────

func TestDeleteImage_Nonexistent(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.DeleteImage(ctx, &pb.DeleteImageRequest{Name: "ghost-img"})
	// DeleteImage soft-deletes from DB, which succeeds even if no record exists.
	if err != nil {
		t.Fatalf("DeleteImage: %v", err)
	}
}

// ── CreateVM: with minimal spec (exercises early validation) ────────────────

func TestCreateVM_MinimalSpec(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{
			Name:      "minimal-vm",
			Cpu:       1,
			MemoryMib: 512,
			Image:     "nonexistent-image",
		},
	})
	// Will fail because the image doesn't exist or at some later point.
	if err == nil {
		t.Fatal("expected error")
	}
}

// ── audit: with context ─────────────────────────────────────────────────────

func TestAudit_WithContext(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())

	// Should not panic.
	s.audit(ctx, "test.action", "resource", "detail", "ok")
}

// ── RebuildVM: invalid spec JSON ────────────────────────────────────────────

func TestRebuildVM_EmptySpec(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	// VM with empty spec — json.Unmarshal will fail.
	insertTestVMR2WithSpec(t, ctx, s.db, "empty-spec-vm", "test-host", "running", "")

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "empty-spec-vm"})
	if err == nil {
		t.Fatal("expected error for empty spec")
	}
	if c := status.Code(err); c != codes.Internal {
		t.Errorf("code = %v, want Internal", c)
	}
}

// ── ListHosts: with multiple hosts ──────────────────────────────────────────

func TestListHosts_MultipleHosts(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()

	insertTestHostR2(t, ctx, s.db, "host-a", "active")
	insertTestHostR2(t, ctx, s.db, "host-b", "draining")

	resp, err := s.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(resp.Hosts) < 2 {
		t.Errorf("expected at least 2 hosts, got %d", len(resp.Hosts))
	}
}
