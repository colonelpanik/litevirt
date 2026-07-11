package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
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

// A migration is refused at the source when enforcement is latched and the source
// lacks local quorum (ExecutionGate) — the split-brain recheck at the irreversible
// step, covering the loss-of-quorum window and explicit operator migrations. The VM
// is left running (never entered "migrating").
func TestMigrateVM_SplitBrainGateRefusesWithoutQuorum(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	stream := &mockMigrateStream{ctx: ctx}

	insertTestVM(t, ctx, s.db, "local-vm", "test-host", "running")
	insertTestHost(t, ctx, s.db, "active-host", "active")

	// Enforced, but the source's ExecutionGate refuses (no quorum).
	s.SetGate(fakeServerGate{enforced: true, execOK: false})

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "local-vm",
		TargetHost: "active-host",
	}, stream)
	if err == nil {
		t.Fatal("expected the migration to be refused")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
	if !strings.Contains(err.Error(), "migration refused") {
		t.Errorf("error = %q, want it to contain 'migration refused'", err.Error())
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "local-vm")
	if vm.State != "running" {
		t.Errorf("vm state = %q, want running (refused before the irreversible step)", vm.State)
	}
}

// StartVM of an owned VM is refused when enforcement is latched and the source lacks
// local quorum — bringing a possibly-stale-owned VM to running without quorum could
// double-run it. RestartVM shares the same gate.
func TestStartVM_SplitBrainGateRefusesWithoutQuorum(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, "vm1", "test-host", "stopped")

	s.SetGate(fakeServerGate{enforced: true, execOK: false}) // enforced, no quorum

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "vm1"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
	if !strings.Contains(err.Error(), "start refused") {
		t.Errorf("err = %q, want it to contain 'start refused'", err.Error())
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
	if vm.State != "stopped" {
		t.Errorf("vm state = %q, want stopped (start refused, no runtime change)", vm.State)
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

// A VM with a snapshot on local storage must be blocked from migration with a
// clear precondition error — migrating its local disk would leave the snapshot
// overlay's backing chain behind and fail mid-copy (R2). Even --with-storage
// (which otherwise satisfies the local-disk check) must be refused.
func TestMigrateVM_SnapshotOnLocalDiskBlocked(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	stream := &mockMigrateStream{ctx: ctx}

	insertTestVM(t, ctx, s.db, "snap-vm", "test-host", "running")
	insertTestHost(t, ctx, s.db, "target-host", "active")
	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "snap-vm", DiskName: "root", HostName: "test-host",
		Path: "/tmp/snap-vm.qcow2", StorageType: "local",
	})
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		ID: "snap-1", VMName: "snap-vm", HostName: "test-host",
		Name: "s1", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:      "snap-vm",
		TargetHost:  "target-host",
		Strategy:    pb.MigrateStrategy_MIGRATE_LIVE,
		WithStorage: true, // even with storage copy requested, snapshots block it
	}, stream)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
	if err == nil || !strings.Contains(err.Error(), "snapshot") {
		t.Errorf("error should mention snapshots: %v", err)
	}
}

// A snapshot on SHARED storage does NOT block migration (the backing chain
// stays in place and reachable from the target).
func TestMigrateVM_SnapshotOnSharedDiskAllowed(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	stream := &mockMigrateStream{ctx: ctx}

	insertTestVM(t, ctx, s.db, "shared-vm", "test-host", "running")
	insertTestHost(t, ctx, s.db, "target-host", "active")
	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "shared-vm", DiskName: "root", HostName: "test-host",
		Path: "/mnt/nfs/shared-vm.qcow2", StorageType: "nfs",
	})
	if err := corrosion.InsertSnapshot(ctx, s.db, corrosion.SnapshotRecord{
		ID: "snap-2", VMName: "shared-vm", HostName: "test-host",
		Name: "s1", State: "ok", Type: "disk",
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}

	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName: "shared-vm", TargetHost: "target-host",
		Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	}, stream)
	// Shared storage + snapshot must NOT be rejected by the snapshot precondition.
	// (The migration proceeds past preconditions into libvirt and fails there in
	// the unit env — but never with the snapshot FailedPrecondition message.)
	if err != nil && status.Code(err) == codes.FailedPrecondition && strings.Contains(err.Error(), "snapshot") {
		t.Errorf("shared-storage snapshot must not block migration: %v", err)
	}
}

func TestRecordMigrationMetrics_NilMetrics(t *testing.T) {
	s := testServer(t)
	// Should not panic when migrationMetrics is nil.
	s.recordMigrationMetrics("live", "success", 0, 0, 0)
}

// notifyDetachedContext must strip inbound gRPC metadata (so a forwarded
// user's bearer, which can expire mid-migration, can't fail the detached
// post-migration notify — finding 6) while keeping the span so the notify
// still links into the same vm.migrate trace via dialPeer's traceparent, and
// while applying the caller's timeout.
func TestNotifyDetachedContext_StripsInboundMetadataKeepsSpanAndTimeout(t *testing.T) {
	md := metadata.Pairs("authorization", "Bearer usertoken", "x-other", "v")
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx, span := sdktrace.NewTracerProvider().Tracer("test").Start(ctx, "vm.migrate")
	defer span.End()
	wantSpanCtx := oteltrace.SpanContextFromContext(ctx)

	got, cancel := notifyDetachedContext(ctx, 10*time.Second)
	defer cancel()

	if gotMD, ok := metadata.FromIncomingContext(got); !ok || len(gotMD) != 0 {
		t.Errorf("notifyDetachedContext kept inbound metadata %v; want present-but-empty", gotMD)
	}
	if got := oteltrace.SpanContextFromContext(got); !got.Equal(wantSpanCtx) {
		t.Errorf("notifyDetachedContext lost the span context; got %v, want %v", got, wantSpanCtx)
	}
	if _, hasDeadline := got.Deadline(); !hasDeadline {
		t.Error("notifyDetachedContext did not apply a timeout")
	}
	if got.Err() != nil {
		t.Errorf("notifyDetachedContext returned an already-done context: %v", got.Err())
	}

	// Detached from the parent's cancellation: cancelling the original inbound
	// ctx's underlying cause must not cancel the notify context.
	parentCtx, parentCancel := context.WithCancel(context.Background())
	parentCtx = metadata.NewIncomingContext(parentCtx, md)
	detached, cancel2 := notifyDetachedContext(parentCtx, 10*time.Second)
	defer cancel2()
	parentCancel()
	if detached.Err() != nil {
		t.Errorf("notifyDetachedContext was cancelled by parent cancellation; want detached, got %v", detached.Err())
	}
}

// End-to-end of finding 6's threat model: after notifyDetachedContext, the
// pki.propagateFwdBearer path (what PeerDial's interceptor runs) must NOT
// copy a stale user bearer onto the outgoing notify. We re-implement the
// same "read inbound authorization" check here without importing pki's
// unexported helper — the contract is on the context shape.
func TestNotifyDetachedContext_NoInboundBearerForFwdRelay(t *testing.T) {
	md := metadata.Pairs(
		"authorization", "Bearer expired-user-token",
		"x-litevirt-fwd-bearer", "Bearer should-also-be-stripped",
	)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx, span := sdktrace.NewTracerProvider().Tracer("test").Start(ctx, "vm.migrate")
	defer span.End()

	detached, cancel := notifyDetachedContext(ctx, 10*time.Second)
	defer cancel()

	// Present-but-empty inbound MD: FromIncomingContext ok=true, no keys.
	gotMD, ok := metadata.FromIncomingContext(detached)
	if !ok {
		t.Fatal("inbound metadata absent; want present-but-empty so FromIncomingContext semantics stay unambiguous")
	}
	if len(gotMD.Get("authorization")) != 0 {
		t.Errorf("authorization survived detach: %v", gotMD.Get("authorization"))
	}
	if len(gotMD.Get("x-litevirt-fwd-bearer")) != 0 {
		t.Errorf("fwd-bearer survived detach: %v", gotMD.Get("x-litevirt-fwd-bearer"))
	}
	// Span still present for traceparent injection on the peer dial.
	if !oteltrace.SpanContextFromContext(detached).IsValid() {
		t.Error("span context lost; notify would not link into vm.migrate trace")
	}
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

	// A VM with snapshots on local storage is now BLOCKED (FailedPrecondition):
	// previously migration only warned then failed mid-copy because the snapshot
	// overlay's backing chain is left behind (R2). The error names the count and
	// tells the operator to remove snapshots first.
	err = s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "snap-vm",
		TargetHost: "target-host",
		Strategy:   pb.MigrateStrategy_MIGRATE_LIVE,
	}, stream)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
	if err == nil || !strings.Contains(err.Error(), "2 snapshot(s)") || !strings.Contains(err.Error(), "snapshot rm") {
		t.Errorf("expected error naming '2 snapshot(s)' and the remediation, got: %v", err)
	}
}
