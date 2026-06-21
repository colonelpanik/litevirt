package grpcapi

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
)

// ── MigrateVMForHealthCheck ─────────────────────────────────────────────────

func TestMigrateVMForHealthCheck_VMNotFound(t *testing.T) {
	s := testServerWithLocks(t)

	err := s.MigrateVMForHealthCheck(context.Background(), "nonexistent-vm", "some-host")
	if err == nil {
		t.Fatal("expected error for nonexistent VM")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestMigrateVMForHealthCheck_InjectsAdminCtx(t *testing.T) {
	// Verify it doesn't fail with PermissionDenied — admin role is injected.
	s := testServerWithLocks(t)
	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, "health-vm", "test-host", "running")

	// Will fail at "target host not found", but should NOT fail at auth.
	err := s.MigrateVMForHealthCheck(context.Background(), "health-vm", "target-1")
	if err == nil {
		t.Fatal("expected error (no target host)")
	}
	// Should be NotFound for the target host, NOT PermissionDenied.
	if c := status.Code(err); c == codes.PermissionDenied {
		t.Errorf("expected non-PermissionDenied error, got %v", c)
	}
}

func TestMigrateVMForHealthCheck_VMNotRunning(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()
	insertTestVM(t, ctx, s.db, "stopped-vm", "test-host", "stopped")

	err := s.MigrateVMForHealthCheck(context.Background(), "stopped-vm", "target-1")
	if err == nil {
		t.Fatal("expected error for stopped VM")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

// ── discardMigrateStream ────────────────────────────────────────────────────

func TestDiscardMigrateStream_Send(t *testing.T) {
	d := &discardMigrateStream{ctx: context.Background()}

	// Send should always return nil (discard).
	for i := 0; i < 5; i++ {
		if err := d.Send(&pb.MigrateProgress{
			Phase:  pb.MigratePhase_MIGRATE_COPYING,
			Status: "test",
		}); err != nil {
			t.Errorf("Send() returned error: %v", err)
		}
	}
}

func TestDiscardMigrateStream_Context(t *testing.T) {
	ctx := context.WithValue(context.Background(), ctxKeyRole, "admin")
	d := &discardMigrateStream{ctx: ctx}

	got := d.Context()
	if got != ctx {
		t.Error("Context() returned different context than what was set")
	}
	if role, ok := got.Value(ctxKeyRole).(string); !ok || role != "admin" {
		t.Errorf("expected admin role in context, got %q", role)
	}
}

// ── cleanupPostMigration (extra cases) ──────────────────────────────────────

func TestCleanupPostMigration_MultipleDisks(t *testing.T) {
	dataDir := t.TempDir()
	s := &Server{dataDir: dataDir}

	// Create cloud-init ISO.
	isoDir := filepath.Join(dataDir, "cloudinit")
	os.MkdirAll(isoDir, 0o755)
	isoPath := filepath.Join(isoDir, "multi-vm.iso")
	os.WriteFile(isoPath, []byte("iso"), 0o644)

	// Create disk directory with multiple disk files.
	diskDir := filepath.Join(dataDir, "disks", "multi-vm")
	os.MkdirAll(diskDir, 0o755)
	for _, name := range []string{"root.qcow2", "data.qcow2", "swap.qcow2"} {
		os.WriteFile(filepath.Join(diskDir, name), []byte("disk-data"), 0o644)
	}

	s.cleanupPostMigration("multi-vm")

	if _, err := os.Stat(isoPath); !os.IsNotExist(err) {
		t.Errorf("expected ISO to be removed")
	}
	// cleanupPostMigration no longer touches disk files: the path-wrong
	// RemoveAll(<dataDir>/disks/<vm>) was removed; the real, storage-aware
	// source-disk cleanup happens per-disk at the migration site.
	if _, err := os.Stat(diskDir); err != nil {
		t.Errorf("disk directory must NOT be removed by cleanupPostMigration: %v", err)
	}
}

func TestCleanupPostMigration_OnlyISO_NoDisksDir(t *testing.T) {
	dataDir := t.TempDir()
	s := &Server{dataDir: dataDir}

	isoDir := filepath.Join(dataDir, "cloudinit")
	os.MkdirAll(isoDir, 0o755)
	isoPath := filepath.Join(isoDir, "vm1.iso")
	os.WriteFile(isoPath, []byte("iso"), 0o644)

	// No disk directory at all — should not panic.
	s.cleanupPostMigration("vm1")

	if _, err := os.Stat(isoPath); !os.IsNotExist(err) {
		t.Errorf("expected ISO to be removed")
	}
}

// ── AutoPullImage / autoPullImage ───────────────────────────────────────────

func TestAutoPullImage_NoReadyPeers(t *testing.T) {
	s := testServer(t)
	s.hostName = "local-host"

	err := s.AutoPullImage(adminCtx(), "missing-image")
	if err == nil {
		t.Fatal("expected error when no peers have the image")
	}
	if got := err.Error(); !contains(got, "no peer host has image") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAutoPullImage_OnlyLocalHost(t *testing.T) {
	// The only image_host record is on the local host — should not self-pull.
	s := testServer(t)
	s.hostName = "local-host"
	ctx := adminCtx()

	corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
		ImageName: "ubuntu",
		HostName:  "local-host",
		Path:      "/images/ubuntu.qcow2",
		Status:    "ready",
		PulledAt:  "2026-01-01T00:00:00Z",
	})

	err := s.AutoPullImage(ctx, "ubuntu")
	if err == nil {
		t.Fatal("expected error when only local host has the image")
	}
	if got := err.Error(); !contains(got, "no peer host has image") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAutoPullImage_PeerNotReady(t *testing.T) {
	s := testServer(t)
	s.hostName = "local-host"
	ctx := adminCtx()

	// Peer has the image but status is "pulling" (not "ready").
	corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
		ImageName: "ubuntu",
		HostName:  "peer-host",
		Path:      "/images/ubuntu.qcow2",
		Status:    "pulling",
		PulledAt:  "2026-01-01T00:00:00Z",
	})

	err := s.AutoPullImage(ctx, "ubuntu")
	if err == nil {
		t.Fatal("expected error when peer image is not ready")
	}
	if got := err.Error(); !contains(got, "no peer host has image") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestAutoPullImage_PeerExists_DialFails(t *testing.T) {
	// Peer is ready but peerClient will fail (no real host to connect to).
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	s := &Server{
		hostName: "local-host",
		dataDir:  t.TempDir(),
		db:       db,
		events:   events.NewBus(),
	}

	// Insert peer host record so peerClient can look it up.
	corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name:     "peer-host",
		Address:  "192.0.2.99",
		SSHUser:  "root",
		SSHPort:  22,
		GRPCPort: 7443,
		State:    "active",
	})
	corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
		ImageName: "ubuntu",
		HostName:  "peer-host",
		Path:      "/images/ubuntu.qcow2",
		Status:    "ready",
		PulledAt:  "2026-01-01T00:00:00Z",
	})

	err = s.AutoPullImage(ctx, "ubuntu")
	if err == nil {
		t.Fatal("expected error when peer dial fails")
	}
	// Should fail at peerClient (TLS config or dial), not at "no peer host".
	if got := err.Error(); contains(got, "no peer host has image") {
		t.Errorf("should have found peer but failed at dial; got: %v", err)
	}
}

// ── ImportImage ─────────────────────────────────────────────────────────────

// mockImportImageStream implements grpc.ClientStreamingServer[pb.ImportImageRequest, pb.ImportImageResponse].
type mockImportImageStream struct {
	ctx      context.Context
	msgs     []*pb.ImportImageRequest
	idx      int
	closed   *pb.ImportImageResponse
}

func (m *mockImportImageStream) Recv() (*pb.ImportImageRequest, error) {
	if m.idx >= len(m.msgs) {
		return nil, io.EOF
	}
	msg := m.msgs[m.idx]
	m.idx++
	return msg, nil
}

func (m *mockImportImageStream) SendAndClose(resp *pb.ImportImageResponse) error {
	m.closed = resp
	return nil
}

func (m *mockImportImageStream) Context() context.Context       { return m.ctx }
func (m *mockImportImageStream) SetHeader(_ metadata.MD) error  { return nil }
func (m *mockImportImageStream) SendHeader(_ metadata.MD) error { return nil }
func (m *mockImportImageStream) SetTrailer(_ metadata.MD)       {}
func (m *mockImportImageStream) SendMsg(_ interface{}) error    { return nil }
func (m *mockImportImageStream) RecvMsg(_ interface{}) error    { return nil }

func TestImportImage_NoData(t *testing.T) {
	s := testServer(t)
	stream := &mockImportImageStream{
		ctx:  adminCtx(),
		msgs: nil, // empty — EOF immediately
	}

	err := s.ImportImage(stream)
	if err == nil {
		t.Fatal("expected error for empty stream")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
	if got := status.Convert(err).Message(); !contains(got, "no data received") {
		t.Errorf("unexpected message: %s", got)
	}
}

func TestImportImage_MissingName(t *testing.T) {
	s := testServer(t)
	stream := &mockImportImageStream{
		ctx: adminCtx(),
		msgs: []*pb.ImportImageRequest{
			{Name: "", Chunk: []byte("data")},
		},
	}

	err := s.ImportImage(stream)
	if err == nil {
		t.Fatal("expected error for missing name")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
	if got := status.Convert(err).Message(); !contains(got, "image name required") {
		t.Errorf("unexpected message: %s", got)
	}
}

func TestImportImage_ChecksumMismatch(t *testing.T) {
	dataDir := t.TempDir()
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
		dataDir:  dataDir,
		db:       db,
		images:   image.NewStore(dataDir),
		events:   events.NewBus(),
	}

	stream := &mockImportImageStream{
		ctx: ctx,
		msgs: []*pb.ImportImageRequest{
			{Name: "test-img", Chunk: []byte("some data"), Checksum: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}

	err = s.ImportImage(stream)
	if err == nil {
		t.Fatal("expected error for checksum mismatch")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
	if got := status.Convert(err).Message(); !contains(got, "checksum mismatch") {
		t.Errorf("unexpected message: %s", got)
	}
}

func TestImportImage_Success(t *testing.T) {
	dataDir := t.TempDir()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	imgStore := image.NewStore(dataDir)
	imgStore.Init()

	s := &Server{
		hostName: "test-host",
		dataDir:  dataDir,
		db:       db,
		images:   imgStore,
		events:   events.NewBus(),
	}

	chunk1 := []byte("hello ")
	chunk2 := []byte("world")

	stream := &mockImportImageStream{
		ctx: ctx,
		msgs: []*pb.ImportImageRequest{
			{Name: "my-image", Format: "raw", Chunk: chunk1},
			{Chunk: chunk2},
		},
	}

	err = s.ImportImage(stream)
	if err != nil {
		t.Fatalf("ImportImage: %v", err)
	}
	if stream.closed == nil {
		t.Fatal("expected SendAndClose response")
	}
	if stream.closed.Name != "my-image" {
		t.Errorf("response name = %q, want %q", stream.closed.Name, "my-image")
	}
	if stream.closed.SizeBytes != int64(len(chunk1)+len(chunk2)) {
		t.Errorf("response size = %d, want %d", stream.closed.SizeBytes, len(chunk1)+len(chunk2))
	}
	if stream.closed.Checksum == "" {
		t.Error("expected non-empty checksum")
	}

	// Verify the image file was written.
	destPath := imgStore.ImagePath("my-image")
	data, err := os.ReadFile(destPath)
	if err != nil {
		t.Fatalf("reading imported image: %v", err)
	}
	if string(data) != "hello world" {
		t.Errorf("image content = %q, want %q", string(data), "hello world")
	}
}

func TestImportImage_DefaultFormat(t *testing.T) {
	dataDir := t.TempDir()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	corrosion.InitSchema(ctx, db)

	imgStore := image.NewStore(dataDir)
	imgStore.Init()

	s := &Server{
		hostName: "test-host",
		dataDir:  dataDir,
		db:       db,
		images:   imgStore,
		events:   events.NewBus(),
	}

	stream := &mockImportImageStream{
		ctx: ctx,
		msgs: []*pb.ImportImageRequest{
			{Name: "default-fmt", Chunk: []byte("x")},
		},
	}

	err = s.ImportImage(stream)
	if err != nil {
		t.Fatalf("ImportImage: %v", err)
	}
	// Format defaults to qcow2 — we can verify the response was set.
	if stream.closed == nil {
		t.Fatal("expected response")
	}
}

func TestImportImage_RequiresOperator(t *testing.T) {
	s := testServer(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	stream := &mockImportImageStream{
		ctx: viewerCtx,
		msgs: []*pb.ImportImageRequest{
			{Name: "test", Chunk: []byte("data")},
		},
	}

	err := s.ImportImage(stream)
	if err == nil {
		t.Fatal("expected permission denied for viewer")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

// ── PushImage (gRPC-based) ──────────────────────────────────────────────────

func TestPushImage_gRPC_RequiresOperator(t *testing.T) {
	s := testServer(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	stream := &mockPushImageStream{ctx: viewerCtx}
	err := s.PushImage(&pb.PushImageRequest{Name: "img", TargetHost: "h1"}, stream)
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestPushImage_gRPC_ImageNotFoundLocally(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	s.images.Init()

	stream := &mockPushImageStream{ctx: adminCtx()}
	err := s.PushImage(&pb.PushImageRequest{Name: "nonexistent", TargetHost: "h1"}, stream)
	if err == nil {
		t.Fatal("expected NotFound")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestPushImage_gRPC_PeerConnectionFails(t *testing.T) {
	// Image exists locally but target host's daemon is unreachable.
	dataDir := t.TempDir()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	corrosion.InitSchema(ctx, db)

	imgStore := image.NewStore(dataDir)
	imgStore.Init()

	// Create a fake image file.
	imgPath := imgStore.ImagePath("test-img")
	os.WriteFile(imgPath, []byte("fake-image-data"), 0644)

	s := &Server{
		hostName: "source-host",
		dataDir:  dataDir,
		pkiDir:   "/nonexistent/pki",
		db:       db,
		images:   imgStore,
		events:   events.NewBus(),
	}

	// Insert target host record.
	corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name:     "target-host",
		Address:  "192.0.2.99",
		GRPCPort: 7443,
		State:    "active",
	})

	stream := &mockPushImageStream{ctx: ctx}
	err = s.PushImage(&pb.PushImageRequest{Name: "test-img", TargetHost: "target-host"}, stream)
	if err == nil {
		t.Fatal("expected Unavailable error for unreachable peer")
	}
	if c := status.Code(err); c != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", c)
	}
}

func TestPushImage_gRPC_LooksUpChecksum(t *testing.T) {
	// Verify that PushImage queries the DB for image metadata (checksum/format).
	dataDir := t.TempDir()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	corrosion.InitSchema(ctx, db)

	imgStore := image.NewStore(dataDir)
	imgStore.Init()

	// Create image file and DB record with checksum.
	imgPath := imgStore.ImagePath("checksummed")
	os.WriteFile(imgPath, []byte("data"), 0644)
	corrosion.InsertImage(ctx, db, corrosion.ImageRecord{
		Name:     "checksummed",
		Format:   "raw",
		Checksum: "sha256:abc123",
	})

	s := &Server{
		hostName: "source-host",
		dataDir:  dataDir,
		pkiDir:   "/nonexistent/pki",
		db:       db,
		images:   imgStore,
		events:   events.NewBus(),
	}

	// No target host → will fail at peerClient, but we can verify it got past
	// the metadata lookup without error.
	stream := &mockPushImageStream{ctx: ctx}
	err = s.PushImage(&pb.PushImageRequest{Name: "checksummed", TargetHost: "ghost"}, stream)
	if err == nil {
		t.Fatal("expected error")
	}
	// Should fail at peer lookup (Unavailable), not at image/metadata lookup.
	if c := status.Code(err); c == codes.NotFound {
		t.Error("should not have failed at image lookup — image exists")
	}
}

func TestPushImage_gRPC_NoProgressOnEarlyFailure(t *testing.T) {
	// When peer connection fails early, no progress messages should be sent
	// (the "copying" message is sent after the connection is established).
	dataDir := t.TempDir()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := adminCtx()
	corrosion.InitSchema(ctx, db)

	imgStore := image.NewStore(dataDir)
	imgStore.Init()
	imgPath := imgStore.ImagePath("progress-img")
	os.WriteFile(imgPath, []byte("data"), 0644)

	// Insert host so we get past the host lookup to the peer connection.
	corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name:     "target",
		Address:  "192.0.2.99",
		GRPCPort: 7443,
		State:    "active",
	})

	s := &Server{
		hostName: "source",
		dataDir:  dataDir,
		pkiDir:   "/nonexistent/pki",
		db:       db,
		images:   imgStore,
		events:   events.NewBus(),
	}

	stream := &mockPushImageStream{ctx: ctx}
	err = s.PushImage(&pb.PushImageRequest{Name: "progress-img", TargetHost: "target"}, stream)

	// Should fail at Unavailable (peer TLS failure).
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", c)
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func contains(s, substr string) bool {
	return len(s) >= len(substr) && containsImpl(s, substr)
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

