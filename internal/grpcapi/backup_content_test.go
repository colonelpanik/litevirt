package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// fakeBackupReader serves synthetic guest-visible content + a fixed extent
// set, standing in for a libvirt pull-mode NBD session.
type fakeBackupReader struct {
	data    []byte
	extents [][2]int64
	incr    bool
}

func (r *fakeBackupReader) Size() int64       { return int64(len(r.data)) }
func (r *fakeBackupReader) Incremental() bool { return r.incr }
func (r *fakeBackupReader) ChangedExtents() ([][2]int64, error) {
	return r.extents, nil
}
func (r *fakeBackupReader) ReadAt(p []byte, off int64) (int, error) {
	for i := range p {
		p[i] = 0
	}
	if off < int64(len(r.data)) {
		copy(p, r.data[off:])
	}
	return len(p), nil
}
func (r *fakeBackupReader) Close() error { return nil }

// fakeBackupSource hands out a full or incremental reader depending on
// whether a parent checkpoint was supplied, and records what it was asked.
type fakeBackupSource struct {
	full          *fakeBackupReader
	incr          *fakeBackupReader
	lastParentCP  string
	lastNewCP     string
	gcKeep        []string
	lastDeletedCP string
	deleted       []string // every checkpoint name passed to DeleteCheckpoint, in order
}

// deletedCheckpoint reports whether name was ever deleted.
func (s *fakeBackupSource) deletedCheckpoint(name string) bool {
	for _, n := range s.deleted {
		if n == name {
			return true
		}
	}
	return false
}

func (s *fakeBackupSource) BeginBackup(domain, diskPath, parentCP, newCP string) (BackupReader, error) {
	s.lastParentCP, s.lastNewCP = parentCP, newCP
	if parentCP != "" {
		return s.incr, nil
	}
	return s.full, nil
}
func (s *fakeBackupSource) GCCheckpoints(domain, diskName string, keep []string) error {
	s.gcKeep = keep
	return nil
}
func (s *fakeBackupSource) DeleteCheckpoint(domain, name string) error {
	s.lastDeletedCP = name
	s.deleted = append(s.deleted, name)
	return nil
}

var _ BackupSource = (*fakeBackupSource)(nil)

func doneFrame(frames []*pb.BackupSnapshotProgress) *pb.BackupSnapshotProgress {
	for _, p := range frames {
		if p.Phase == pb.BackupSnapshotProgress_DONE {
			return p
		}
	}
	return nil
}

// TestBackupSnapshot_GuestContent_FullThenIncremental drives the real
// guest-content path: a sparse full backup (middle chunk is a hole), then
// an incremental where only the first chunk is dirty. The incremental must
// inherit the unchanged allocated chunk from the parent and read only the
// dirty one — proven by the manifest chunk ids and the bytes_read counter.
func TestBackupSnapshot_GuestContent_FullThenIncremental(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()
	const CS = pbsstore.ChunkSize
	size := int64(CS * 3)

	full := make([]byte, size)
	for i := 0; i < CS; i++ {
		full[i] = 0xAA // chunk 0
	}
	for i := 2 * CS; i < 3*CS; i++ {
		full[i] = 0xCC // chunk 2; chunk 1 is a hole
	}
	src := &fakeBackupSource{
		full: &fakeBackupReader{data: full, extents: [][2]int64{{0, CS}, {2 * CS, CS}}},
	}
	s.SetBackupSource(src)

	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "running"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "vm1", DiskName: "root", HostName: "host-a",
			Path: "/dev/null", SizeBytes: size, StorageType: "local", TargetDev: "vda",
		}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	repoDir := filepath.Join(t.TempDir(), "repo")
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Full backup.
	t1 := "2026-05-10T10:00:00Z"
	fullStream := &progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}
	if err := s.BackupSnapshot(&pb.BackupSnapshotRequest{
		VmName: "vm1", DiskName: "root", RepoPath: repoDir, Timestamp: t1,
	}, fullStream); err != nil {
		t.Fatalf("full: %v", err)
	}

	repo, _ := pbsstore.Open(repoDir)
	base, err := repo.GetManifest("vm1", t1, "root")
	if err != nil {
		t.Fatalf("get base: %v", err)
	}
	if len(base.Chunks) != 2 {
		t.Fatalf("full backup: expected 2 chunks (hole skipped), got %d", len(base.Chunks))
	}
	if base.TotalSize != size {
		t.Errorf("full TotalSize = %d, want virtual size %d", base.TotalSize, size)
	}
	if base.BitmapName != checkpointName("root", t1) {
		t.Errorf("full BitmapName = %q", base.BitmapName)
	}

	// Incremental: change chunk 0; only it is dirty.
	inc := make([]byte, size)
	copy(inc, full)
	for i := 0; i < CS; i++ {
		inc[i] = 0xFF
	}
	src.incr = &fakeBackupReader{data: inc, extents: [][2]int64{{0, CS}}, incr: true}

	t2 := "2026-05-10T11:00:00Z"
	incStream := &progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}
	if err := s.BackupSnapshot(&pb.BackupSnapshotRequest{
		VmName: "vm1", DiskName: "root", RepoPath: repoDir, Timestamp: t2, Incremental: true,
	}, incStream); err != nil {
		t.Fatalf("incremental: %v", err)
	}

	// Session was opened incrementally against the parent's checkpoint.
	if src.lastParentCP != checkpointName("root", t1) {
		t.Errorf("incremental opened with parentCP %q, want %q", src.lastParentCP, checkpointName("root", t1))
	}

	child, err := repo.GetManifest("vm1", t2, "root")
	if err != nil {
		t.Fatalf("get child: %v", err)
	}
	if child.BasedOn != t1 {
		t.Errorf("child.BasedOn = %q, want %q", child.BasedOn, t1)
	}
	// chunk@0 changed (new id); chunk@2*CS inherited from parent (same id);
	// chunk@CS stays a hole (absent).
	byOff := map[int64]pbsstore.ChunkRef{}
	for _, c := range child.Chunks {
		byOff[c.Offset] = c
	}
	if len(child.Chunks) != 2 {
		t.Fatalf("incremental: expected 2 chunks, got %d", len(child.Chunks))
	}
	baseByOff := map[int64]pbsstore.ChunkRef{}
	for _, c := range base.Chunks {
		baseByOff[c.Offset] = c
	}
	if byOff[0].ID == baseByOff[0].ID {
		t.Errorf("chunk@0 should have changed")
	}
	if byOff[2*CS].ID != baseByOff[2*CS].ID {
		t.Errorf("chunk@2*CS should be inherited from parent")
	}

	// bytes_read on DONE = only the one dirty chunk; bytes_processed = full.
	d := doneFrame(incStream.Sent)
	if d == nil {
		t.Fatal("no DONE frame")
	}
	if d.BytesRead != int64(CS) {
		t.Errorf("incremental bytes_read = %d, want one chunk (%d)", d.BytesRead, CS)
	}

	// Restore the incremental and confirm it reconstructs the new content.
	restored := filepath.Join(t.TempDir(), "r.raw")
	rs := &progressStream[pb.RestoreFromBackupProgress]{ctx: adminCtx()}
	if err := s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: t2, TargetPath: restored,
	}, rs); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(inc) {
		t.Fatalf("restored size %d != %d", len(got), len(inc))
	}
	for i := range inc {
		if got[i] != inc[i] {
			t.Fatalf("restored content differs at byte %d", i)
		}
	}
}

// TestBackupSnapshot_NoParentIncremental_FullSession asserts an
// --incremental with no parent opens a FULL session (no parent checkpoint)
// and still produces a manifest.
func TestBackupSnapshot_NoParentIncremental_FullSession(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	ctx := context.Background()
	const CS = pbsstore.ChunkSize
	size := int64(CS)

	src := &fakeBackupSource{
		full: &fakeBackupReader{data: make([]byte, size), extents: [][2]int64{{0, CS}}},
	}
	s.SetBackupSource(src)

	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "host-a",
			Path: "/dev/null", SizeBytes: size, StorageType: "local", TargetDev: "vda"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	repoDir := filepath.Join(t.TempDir(), "repo")
	if _, err := pbsstore.Init(repoDir); err != nil {
		t.Fatalf("Init: %v", err)
	}

	stream := &progressStream[pb.BackupSnapshotProgress]{ctx: adminCtx()}
	if err := s.BackupSnapshot(&pb.BackupSnapshotRequest{
		VmName: "vm1", DiskName: "root", RepoPath: repoDir,
		Timestamp: "2026-05-10T10:00:00Z", Incremental: true,
	}, stream); err != nil {
		t.Fatalf("incremental-no-parent: %v", err)
	}
	if src.lastParentCP != "" {
		t.Errorf("expected a FULL session (no parent checkpoint), got parentCP %q", src.lastParentCP)
	}
	if doneFrame(stream.Sent) == nil {
		t.Fatal("no DONE frame")
	}
}
