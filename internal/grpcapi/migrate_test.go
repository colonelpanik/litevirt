package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
)

// mockMigrateStream implements grpc.ServerStreamingServer[pb.MigrateProgress].
type mockMigrateStream struct {
	ctx  context.Context
	sent []*pb.MigrateProgress
}

func (m *mockMigrateStream) Send(p *pb.MigrateProgress) error {
	m.sent = append(m.sent, p)
	return nil
}
func (m *mockMigrateStream) Context() context.Context       { return m.ctx }
func (m *mockMigrateStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockMigrateStream) SendHeader(_ metadata.MD) error { return nil }
func (m *mockMigrateStream) SetTrailer(_ metadata.MD)       {}
func (m *mockMigrateStream) SendMsg(_ interface{}) error    { return nil }
func (m *mockMigrateStream) RecvMsg(_ interface{}) error    { return nil }

func TestMigrateVM_NotFound(t *testing.T) {
	s := testServerWithLocks(t)
	stream := &mockMigrateStream{ctx: adminCtx()}

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "ghost",
		TargetHost: "host-2",
	}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestMigrateVM_WrongHost(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	stream := &mockMigrateStream{ctx: ctx}

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "remote-vm",
		TargetHost: "host-2",
	}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestMigrateVM_NotRunning(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	stream := &mockMigrateStream{ctx: ctx}

	insertTestVM(t, ctx, s.db, "stopped-vm", "test-host", "stopped")

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "stopped-vm",
		TargetHost: "host-2",
	}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestMigrateVM_TargetNotFound(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	stream := &mockMigrateStream{ctx: ctx}

	insertTestVM(t, ctx, s.db, "local-vm", "test-host", "running")

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "local-vm",
		TargetHost: "nonexistent",
	}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestMigrateVM_TargetNotActive(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	stream := &mockMigrateStream{ctx: ctx}

	insertTestVM(t, ctx, s.db, "local-vm", "test-host", "running")
	insertTestHost(t, ctx, s.db, "drain-host", "draining")

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "local-vm",
		TargetHost: "drain-host",
	}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestMigrateVM_LocalDiskBlocksLive(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	stream := &mockMigrateStream{ctx: ctx}

	insertTestVM(t, ctx, s.db, "local-vm", "test-host", "running")
	insertTestHost(t, ctx, s.db, "target-host", "active")

	// Insert a local disk for the VM.
	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName:      "local-vm",
		DiskName:    "root",
		HostName:    "test-host",
		Path:        "/tmp/disk.qcow2",
		StorageType: "local",
	})

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "local-vm",
		TargetHost: "target-host",
		Strategy:   pb.MigrateStrategy_MIGRATE_LIVE,
	}, stream)
	if err == nil {
		t.Fatal("expected error for local disk live migration")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestRecordMigrationMetrics_NilMetrics(t *testing.T) {
	s := testServer(t)
	// Should not panic when migrationMetrics is nil.
	s.recordMigrationMetrics("live", "success", 0, 0, 0)
}

// ── post-migration tests ────────────────────────────────────────────────────

func TestCleanupPostMigration_RemovesISO(t *testing.T) {
	dataDir := t.TempDir()
	s := &Server{dataDir: dataDir}

	// Create cloud-init ISO.
	isoDir := filepath.Join(dataDir, "cloudinit")
	if err := os.MkdirAll(isoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	isoPath := filepath.Join(isoDir, "my-vm.iso")
	if err := os.WriteFile(isoPath, []byte("fake-iso"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create disk directory (should NOT be removed with withStorage=false).
	diskDir := filepath.Join(dataDir, "disks", "my-vm")
	if err := os.MkdirAll(diskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(diskDir, "root.qcow2"), []byte("disk"), 0o644); err != nil {
		t.Fatal(err)
	}

	s.cleanupPostMigration("my-vm")

	if _, err := os.Stat(isoPath); !os.IsNotExist(err) {
		t.Errorf("expected ISO to be removed, but it still exists")
	}
	if _, err := os.Stat(diskDir); os.IsNotExist(err) {
		t.Errorf("disk directory should NOT be removed by cleanupPostMigration")
	}
}

func TestCleanupPostMigration_WithStorage(t *testing.T) {
	dataDir := t.TempDir()
	s := &Server{dataDir: dataDir}

	// Create cloud-init ISO.
	isoDir := filepath.Join(dataDir, "cloudinit")
	if err := os.MkdirAll(isoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	isoPath := filepath.Join(isoDir, "my-vm.iso")
	if err := os.WriteFile(isoPath, []byte("fake-iso"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Create disk directory with a file.
	diskDir := filepath.Join(dataDir, "disks", "my-vm")
	if err := os.MkdirAll(diskDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(diskDir, "root.qcow2"), []byte("disk"), 0o644); err != nil {
		t.Fatal(err)
	}

	s.cleanupPostMigration("my-vm")

	if _, err := os.Stat(isoPath); !os.IsNotExist(err) {
		t.Errorf("expected ISO to be removed")
	}
	// Even for a --with-storage migration, cleanupPostMigration no longer
	// removes disk files: orphaned source disks are cleaned per-disk and
	// storage-type-aware at the migration site (host-local drivers only).
	if _, err := os.Stat(diskDir); os.IsNotExist(err) {
		t.Errorf("disk directory should NOT be removed by cleanupPostMigration")
	}
}

func TestCleanupPostMigration_MissingFiles(t *testing.T) {
	dataDir := t.TempDir()
	s := &Server{dataDir: dataDir}

	// No files exist — should not panic or error.
	s.cleanupPostMigration("nonexistent-vm")
}

func TestGetHostVTEP(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Insert VTEP records directly.
	now := time.Now().UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`INSERT INTO network_vteps (network_name, host_name, vtep_ip, vni, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"mynet", "host-a", "10.0.0.1", 100, now); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx,
		`INSERT INTO network_vteps (network_name, host_name, vtep_ip, vni, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"mynet", "host-b", "10.0.0.2", 100, now); err != nil {
		t.Fatal(err)
	}

	got := s.getHostVTEP(ctx, "mynet", "host-a")
	if got != "10.0.0.1" {
		t.Errorf("getHostVTEP(host-a) = %q, want %q", got, "10.0.0.1")
	}

	got = s.getHostVTEP(ctx, "mynet", "host-c")
	if got != "" {
		t.Errorf("getHostVTEP(host-c) = %q, want empty", got)
	}
}

func TestUpdateFDBForMigration_NonVXLAN(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Insert a bridge network (type != "vxlan").
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "bridgenet",
		Type: "bridge",
	}); err != nil {
		t.Fatal(err)
	}

	iface := corrosion.InterfaceRecord{
		VMName:      "test-vm",
		NetworkName: "bridgenet",
		MAC:         "52:54:00:aa:bb:cc",
	}

	// Should return without panic for non-vxlan network.
	s.updateFDBForMigration(ctx, iface, "old-host", "new-host")
}

func TestMigrateVM_SnapshotWarning(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	s := &Server{
		hostName: "test-host",
		dataDir:  t.TempDir(),
		db:       db,
		events:   events.NewBus(),
		vmLocks:  make(map[string]*sync.Mutex),
	}

	// Insert a running VM on test-host.
	insertTestVM(t, ctx, s.db, "snap-vm", "test-host", "running")
	// Insert an active target host.
	insertTestHost(t, ctx, s.db, "target-host", "active")

	// Insert 2 snapshots for the VM.
	for _, name := range []string{"snap1", "snap2"} {
		if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
			VMName:   "snap-vm",
			HostName: "test-host",
			Name:     name,
			State:    "complete",
		}); err != nil {
			t.Fatalf("InsertSnapshot(%s): %v", name, err)
		}
	}

	// Insert a local disk so the migration fails at the storage validation
	// step (after the snapshot warning) instead of reaching the nil virt client.
	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName:      "snap-vm",
		DiskName:    "root",
		HostName:    "test-host",
		Path:        "/tmp/disk.qcow2",
		StorageType: "local",
	})

	stream := &mockMigrateStream{ctx: ctx}

	// MigrateVM will fail at local-disk validation (FailedPrecondition),
	// but the snapshot warning should have been sent before that point.
	_ = s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "snap-vm",
		TargetHost: "target-host",
		Strategy:   pb.MigrateStrategy_MIGRATE_LIVE,
	}, stream)

	found := false
	for _, msg := range stream.sent {
		if msg.Status != "" && strings.Contains(msg.Status, "snapshot") && strings.Contains(msg.Status, "2 snapshot(s)") {
			found = true
			break
		}
	}
	if !found {
		var statuses []string
		for _, msg := range stream.sent {
			if msg.Status != "" {
				statuses = append(statuses, msg.Status)
			}
		}
		t.Errorf("expected snapshot warning with '2 snapshot(s)', got statuses: %v", statuses)
	}
}
