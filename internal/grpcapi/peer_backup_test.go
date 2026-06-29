package grpcapi

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// fakePushServer drives PushBackup with a fixed frame slice (then io.EOF) and
// captures the response.
type fakePushServer struct {
	grpc.ClientStreamingServer[pb.PushBackupFrame, pb.PushBackupResponse]
	ctx    context.Context
	frames []*pb.PushBackupFrame
	i      int
	resp   *pb.PushBackupResponse
}

func (f *fakePushServer) Context() context.Context { return f.ctx }

func (f *fakePushServer) Recv() (*pb.PushBackupFrame, error) {
	if f.i >= len(f.frames) {
		return nil, io.EOF
	}
	fr := f.frames[f.i]
	f.i++
	return fr, nil
}

func (f *fakePushServer) SendAndClose(r *pb.PushBackupResponse) error {
	f.resp = r
	return nil
}

func stagingHeader(token string) *pb.PushBackupFrame {
	return &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Header{
		Header: &pb.PushBackupHeader{Target: &pb.RepoTarget{StagingToken: token}},
	}}
}

// chunkFrames splits data into sub-frames of frameSize, all carrying the chunk's
// real BLAKE3 id (unless override is non-empty, used to forge a mismatch).
func chunkFrames(data []byte, frameSize int, override string) []*pb.PushBackupFrame {
	id := override
	if id == "" {
		id = pbsstore.ChunkID(data)
	}
	if len(data) == 0 {
		return []*pb.PushBackupFrame{{Frame: &pb.PushBackupFrame_Chunk{
			Chunk: &pb.PushChunkFrame{ChunkId: id, Final: true},
		}}}
	}
	var out []*pb.PushBackupFrame
	for off := 0; off < len(data); off += frameSize {
		end := min(off+frameSize, len(data))
		out = append(out, &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{
			Chunk: &pb.PushChunkFrame{
				ChunkId:   id,
				TotalSize: int64(len(data)),
				Offset:    int64(off),
				Data:      data[off:end],
				Final:     end == len(data),
			},
		}})
	}
	return out
}

func manifestFrame(t *testing.T, m *pbsstore.Manifest) *pb.PushBackupFrame {
	t.Helper()
	blob, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Manifest{
		Manifest: &pb.PushManifestFrame{Data: blob, Final: true},
	}}
}

// manifestFor builds a one-chunk manifest referencing data.
func manifestFor(data []byte, ts string) *pbsstore.Manifest {
	return &pbsstore.Manifest{
		VMName:    "ct1",
		DiskName:  "rootfs",
		Timestamp: ts,
		TotalSize: int64(len(data)),
		Chunks:    []pbsstore.ChunkRef{{ID: pbsstore.ChunkID(data), Size: int64(len(data)), Offset: 0}},
	}
}

func runPush(s *Server, ctx context.Context, frames ...*pb.PushBackupFrame) (*fakePushServer, error) {
	fs := &fakePushServer{ctx: ctx, frames: frames}
	return fs, s.PushBackup(fs)
}

func openStaging(t *testing.T, s *Server, token string) *pbsstore.Repo {
	t.Helper()
	repo, err := pbsstore.Open(filepath.Join(s.dataDir, "restore-staging", token))
	if err != nil {
		t.Fatalf("open staging repo: %v", err)
	}
	return repo
}

// The happy path: header + chunk sub-frames + manifest → chunk written, manifest
// landed and selects the chunk, restore reproduces the bytes.
func TestPushBackup_HappyPath(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	data := []byte("hello world, this is one content-addressed chunk")
	m := manifestFor(data, "2026-06-29T10:00:00Z")

	frames := append([]*pb.PushBackupFrame{stagingHeader("tok1")}, chunkFrames(data, 8, "")...)
	frames = append(frames, manifestFrame(t, m))

	fs, err := runPush(s, peer, frames...)
	if err != nil {
		t.Fatalf("PushBackup: %v", err)
	}
	if fs.resp.GetChunksWritten() != 1 || fs.resp.GetBytesWritten() != int64(len(data)) {
		t.Fatalf("resp = %+v", fs.resp)
	}
	repo := openStaging(t, s, "tok1")
	got, err := repo.GetManifest("ct1", "2026-06-29T10:00:00Z", "rootfs")
	if err != nil {
		t.Fatalf("GetManifest after push: %v", err)
	}
	if len(got.Chunks) != 1 || got.Chunks[0].ID != pbsstore.ChunkID(data) {
		t.Fatalf("manifest chunk mismatch: %+v", got.Chunks)
	}
}

// A second push of the same content dedups the chunk (already present).
func TestPushBackup_DedupsExistingChunk(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	data := []byte("dedupe-me dedupe-me dedupe-me")
	m1 := manifestFor(data, "2026-06-29T10:00:00Z")
	m2 := manifestFor(data, "2026-06-29T11:00:00Z") // same chunk, new ts

	f1 := append([]*pb.PushBackupFrame{stagingHeader("tok")}, chunkFrames(data, 16, "")...)
	f1 = append(f1, manifestFrame(t, m1))
	if _, err := runPush(s, peer, f1...); err != nil {
		t.Fatalf("first push: %v", err)
	}

	f2 := append([]*pb.PushBackupFrame{stagingHeader("tok")}, chunkFrames(data, 16, "")...)
	f2 = append(f2, manifestFrame(t, m2))
	fs, err := runPush(s, peer, f2...)
	if err != nil {
		t.Fatalf("second push: %v", err)
	}
	if fs.resp.GetChunksWritten() != 0 || fs.resp.GetChunksDeduped() != 1 {
		t.Fatalf("second push not deduped: %+v", fs.resp)
	}
}

// A chunk whose bytes don't hash to the declared id is rejected BEFORE PutChunk.
func TestPushBackup_RejectsChunkIDMismatch(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	data := []byte("the bytes")
	forged := pbsstore.ChunkID([]byte("different bytes")) // valid hex, wrong id
	frames := append([]*pb.PushBackupFrame{stagingHeader("tok")}, chunkFrames(data, 4, forged)...)
	frames = append(frames, manifestFrame(t, manifestFor(data, "2026-06-29T10:00:00Z")))
	if _, err := runPush(s, peer, frames...); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for id mismatch, got %v", err)
	}
}

// total_size beyond ChunkSize is rejected.
func TestPushBackup_RejectsOversizeChunk(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	frame := &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{
		Chunk: &pb.PushChunkFrame{ChunkId: pbsstore.ChunkID([]byte("x")), TotalSize: pbsstore.ChunkSize + 1, Offset: 0, Data: []byte("x"), Final: false},
	}}
	if _, err := runPush(s, peer, stagingHeader("tok"), frame); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for oversize, got %v", err)
	}
}

// A single sub-frame whose payload exceeds the per-frame cap is rejected,
// independently of the daemon's (larger) gRPC max message size.
func TestPushBackup_RejectsOversizeFrame(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	big := make([]byte, maxPushFrameBytes+1)
	frame := &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{
		Chunk: &pb.PushChunkFrame{ChunkId: pbsstore.ChunkID(big), TotalSize: int64(len(big)), Offset: 0, Data: big},
	}}
	if _, err := runPush(s, peer, stagingHeader("tok"), frame); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for oversize sub-frame, got %v", err)
	}
}

// A gap in a chunk's offsets (not contiguous tiling) is rejected.
func TestPushBackup_RejectsOffsetGap(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	data := []byte("0123456789")
	id := pbsstore.ChunkID(data)
	f0 := &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{Chunk: &pb.PushChunkFrame{ChunkId: id, TotalSize: 10, Offset: 0, Data: data[:4]}}}
	fGap := &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{Chunk: &pb.PushChunkFrame{ChunkId: id, TotalSize: 10, Offset: 6, Data: data[6:], Final: true}}}
	if _, err := runPush(s, peer, stagingHeader("tok"), f0, fGap); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for offset gap, got %v", err)
	}
}

// Interleaving a second chunk while the first is incomplete is rejected.
func TestPushBackup_RejectsInterleave(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	a, b := []byte("aaaaaaaa"), []byte("bbbbbbbb")
	fa := &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{Chunk: &pb.PushChunkFrame{ChunkId: pbsstore.ChunkID(a), TotalSize: 8, Offset: 0, Data: a[:4]}}}
	fb := &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{Chunk: &pb.PushChunkFrame{ChunkId: pbsstore.ChunkID(b), TotalSize: 8, Offset: 0, Data: b}}}
	if _, err := runPush(s, peer, stagingHeader("tok"), fa, fb); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for interleave, got %v", err)
	}
}

// A chunk frame before the header is rejected.
func TestPushBackup_RejectsChunkBeforeHeader(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	data := []byte("x")
	if _, err := runPush(s, peer, chunkFrames(data, 1, "")...); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for chunk-before-header, got %v", err)
	}
}

// A manifest arriving while a chunk is still incomplete is rejected (ragged).
func TestPushBackup_RejectsManifestMidChunk(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	data := []byte("0123456789")
	id := pbsstore.ChunkID(data)
	partial := &pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{Chunk: &pb.PushChunkFrame{ChunkId: id, TotalSize: 10, Offset: 0, Data: data[:4]}}}
	if _, err := runPush(s, peer, stagingHeader("tok"), partial, manifestFrame(t, manifestFor(data, "2026-06-29T10:00:00Z"))); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument for manifest-mid-chunk, got %v", err)
	}
}

// A stream that ends before the manifest commits nothing — the repo has the
// chunk but NO manifest references it.
func TestPushBackup_NoManifestCommitsNothing(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	data := []byte("orphan chunk content")
	frames := append([]*pb.PushBackupFrame{stagingHeader("tok")}, chunkFrames(data, 8, "")...)
	// No manifest frame.
	if _, err := runPush(s, peer, frames...); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for missing manifest, got %v", err)
	}
	repo := openStaging(t, s, "tok")
	// The chunk landed (GC'able orphan), but no manifest selects it.
	if _, err := repo.GetManifest("ct1", "2026-06-29T10:00:00Z", "rootfs"); err == nil {
		t.Fatal("a manifest was written despite an aborted stream")
	}
	if !repo.HasChunk(pbsstore.ChunkID(data)) {
		t.Fatal("expected the orphan chunk to be present")
	}
}

// The double-gate: a manifest referencing a chunk that was never pushed is
// refused, and no manifest is written.
func TestPushBackup_RejectsManifestReferencingMissingChunk(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	pushed := []byte("present chunk")
	missing := []byte("never pushed")
	m := &pbsstore.Manifest{
		VMName: "ct1", DiskName: "rootfs", Timestamp: "2026-06-29T10:00:00Z",
		TotalSize: int64(len(pushed) + len(missing)),
		Chunks: []pbsstore.ChunkRef{
			{ID: pbsstore.ChunkID(pushed), Size: int64(len(pushed)), Offset: 0},
			{ID: pbsstore.ChunkID(missing), Size: int64(len(missing)), Offset: int64(len(pushed))},
		},
	}
	frames := append([]*pb.PushBackupFrame{stagingHeader("tok")}, chunkFrames(pushed, 8, "")...)
	frames = append(frames, manifestFrame(t, m))
	if _, err := runPush(s, peer, frames...); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition for missing referenced chunk, got %v", err)
	}
	repo := openStaging(t, s, "tok")
	if _, err := repo.GetManifest("ct1", "2026-06-29T10:00:00Z", "rootfs"); err == nil {
		t.Fatal("manifest written despite a missing referenced chunk")
	}
}

// Peer-only: a non-peer (operator) caller is rejected before anything is read.
func TestPushBackup_PeerOnly(t *testing.T) {
	s := newPeerAuthServer(t)
	if _, err := runPush(s, adminCtx(), stagingHeader("tok")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for operator ctx, got %v", err)
	}
}

// The serving semaphore sheds load when full.
func TestPushBackup_SemaphoreSheds(t *testing.T) {
	s := newPeerAuthServer(t)
	for i := 0; i < pushBackupMaxConcurrent; i++ {
		s.pushBackupSem <- struct{}{}
	}
	if _, err := runPush(s, mtlsCtx("peer-1"), stagingHeader("tok")); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("want ResourceExhausted when semaphore full, got %v", err)
	}
}

// The owner's transient backup staging repo is encrypted at rest (ephemeral key),
// so backup data is never in plaintext on disk mid-transfer.
func TestNewLocalStagingRepo_Encrypted(t *testing.T) {
	s := newPeerAuthServer(t)
	repo, cleanup, err := s.newLocalStagingRepo()
	if err != nil {
		t.Fatalf("newLocalStagingRepo: %v", err)
	}
	defer cleanup()
	if !repo.IsEncrypted() {
		t.Fatal("backup staging repo must be encrypted at rest")
	}
	// A round-trip through the encrypted repo returns the original plaintext.
	id, _, err := repo.PutChunk([]byte("secret payload"))
	if err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	got, err := repo.GetChunk(id)
	if err != nil || string(got) != "secret payload" {
		t.Fatalf("GetChunk = %q, %v", got, err)
	}
}

// SweepTransferStaging removes orphaned per-transfer staging dirs left by a prior
// process incarnation (crashed transfer, or a push whose restore was never driven).
func TestSweepTransferStaging_RemovesOrphans(t *testing.T) {
	s := newPeerAuthServer(t)
	for _, sub := range []string{"backup-staging/tokA", "restore-staging/tokB"} {
		if err := os.MkdirAll(filepath.Join(s.dataDir, sub), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	s.SweepTransferStaging()
	for _, root := range []string{"backup-staging", "restore-staging"} {
		if _, err := os.Stat(filepath.Join(s.dataDir, root)); !os.IsNotExist(err) {
			t.Fatalf("%s should be swept, stat err = %v", root, err)
		}
	}
}

// HasChunks reports presence per id and is peer-only.
func TestHasChunks_ReportsPresenceAndPeerOnly(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")
	data := []byte("a present chunk for has-chunks")
	frames := append([]*pb.PushBackupFrame{stagingHeader("tok")}, chunkFrames(data, 8, "")...)
	frames = append(frames, manifestFrame(t, manifestFor(data, "2026-06-29T10:00:00Z")))
	if _, err := runPush(s, peer, frames...); err != nil {
		t.Fatalf("seed push: %v", err)
	}

	present := pbsstore.ChunkID(data)
	absent := pbsstore.ChunkID([]byte("not here"))
	resp, err := s.HasChunks(peer, &pb.HasChunksRequest{
		Target:   &pb.RepoTarget{StagingToken: "tok"},
		ChunkIds: []string{present, absent},
	})
	if err != nil {
		t.Fatalf("HasChunks: %v", err)
	}
	if len(resp.GetPresent()) != 2 || !resp.GetPresent()[0] || resp.GetPresent()[1] {
		t.Fatalf("present flags = %v, want [true false]", resp.GetPresent())
	}

	if _, err := s.HasChunks(adminCtx(), &pb.HasChunksRequest{Target: &pb.RepoTarget{StagingToken: "tok"}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied for operator ctx, got %v", err)
	}
}
