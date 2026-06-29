package grpcapi

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/safename"
)

// pushBackupMaxConcurrent caps simultaneous PushBackup streams a node serves as
// a sink, so a burst of remote backups/migrations can't exhaust disk/CPU.
const pushBackupMaxConcurrent = 4

// hasChunksMaxBatch bounds a single dedup probe — a manifest can hold hundreds of
// thousands of refs, so the client must batch (mirrors anti-entropy chunking).
const hasChunksMaxBatch = 8192

// maxManifestBytes is a sanity ceiling on a streamed manifest (JSON of chunk
// refs). A manifest is ~ disk_size/4MiB * ~120 bytes; this comfortably covers
// multi-TB disks while refusing an unbounded malicious manifest stream.
const maxManifestBytes = 256 << 20

// HasChunks reports, for each requested id, whether the destination repo already
// holds that chunk — the batched dedup probe behind SyncManifest's wire path.
// Peer-only (host cert CN): a backup transfer is a peer operation, not reachable
// by an operator bearer credential.
func (s *Server) HasChunks(ctx context.Context, req *pb.HasChunksRequest) (*pb.HasChunksResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if n := len(req.GetChunkIds()); n > hasChunksMaxBatch {
		return nil, status.Errorf(codes.InvalidArgument, "has-chunks: batch of %d exceeds max %d", n, hasChunksMaxBatch)
	}
	repo, err := s.resolveRepoTarget(ctx, req.GetTarget())
	if err != nil {
		return nil, err
	}
	out := make([]bool, len(req.GetChunkIds()))
	for i, id := range req.GetChunkIds() {
		out[i] = repo.HasChunk(id) // HasChunk validates the id and returns false on a bad one
	}
	return &pb.HasChunksResponse{Present: out}, nil
}

// PushBackup receives one manifest + its missing chunks streamed from a peer and
// writes them into a destination repo this daemon resolves (a configured logical
// repo, or a per-transfer internal staging repo). Peer-only + serving-semaphore
// bounded.
//
// Frame contract: exactly one header first, then chunk sub-frames (a 4 MiB chunk
// spans multiple ≤1 MiB transport frames), then manifest sub-frames LAST. The
// receiver reassembles ONE chunk at a time — frames for a chunk must arrive
// contiguous, in order, exactly tiling [0,total_size), no interleaving — verifies
// the reassembled chunk's BLAKE3 == chunk_id (and total_size ≤ ChunkSize) BEFORE
// PutChunk, and writes the manifest only after (a) it validates structurally and
// (b) every chunk it references is confirmed present. On an aborted/cancelled
// stream the partial chunk is discarded and NO manifest is written, so the
// already-stored content-addressed chunks remain only as GC'able orphans.
func (s *Server) PushBackup(stream grpc.ClientStreamingServer[pb.PushBackupFrame, pb.PushBackupResponse]) error {
	ctx := stream.Context()
	if err := s.requirePeerCert(ctx); err != nil {
		return err
	}
	if s.pushBackupSem != nil {
		select {
		case s.pushBackupSem <- struct{}{}:
			defer func() { <-s.pushBackupSem }()
		default:
			return status.Error(codes.ResourceExhausted, "push-backup capacity reached; retry shortly")
		}
	}

	var (
		repo          *pbsstore.Repo
		stats         pb.PushBackupResponse
		cr            chunkReassembler
		manifestBuf   []byte
		manifestSeen  bool
		manifestFinal bool
	)

	for {
		frame, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err // transport error or context cancel — nothing committed
		}
		switch f := frame.GetFrame().(type) {
		case *pb.PushBackupFrame_Header:
			if repo != nil {
				return status.Error(codes.InvalidArgument, "push-backup: duplicate header")
			}
			r, err := s.resolveRepoTarget(ctx, f.Header.GetTarget())
			if err != nil {
				return err
			}
			repo = r
		case *pb.PushBackupFrame_Chunk:
			if repo == nil {
				return status.Error(codes.InvalidArgument, "push-backup: chunk frame before header")
			}
			if manifestSeen {
				return status.Error(codes.InvalidArgument, "push-backup: chunk frame after manifest")
			}
			if err := cr.accept(repo, f.Chunk, &stats); err != nil {
				return err
			}
		case *pb.PushBackupFrame_Manifest:
			if repo == nil {
				return status.Error(codes.InvalidArgument, "push-backup: manifest frame before header")
			}
			if cr.inProgress() {
				return status.Error(codes.InvalidArgument, "push-backup: manifest frame while a chunk is incomplete")
			}
			manifestSeen = true
			manifestBuf = append(manifestBuf, f.Manifest.GetData()...)
			if len(manifestBuf) > maxManifestBytes {
				return status.Error(codes.InvalidArgument, "push-backup: manifest exceeds size limit")
			}
			if f.Manifest.GetFinal() {
				manifestFinal = true
			}
		default:
			return status.Error(codes.InvalidArgument, "push-backup: empty/unknown frame")
		}
	}

	// A complete transfer ends with a fully-received manifest. Anything short of
	// that committed nothing.
	if repo == nil {
		return status.Error(codes.InvalidArgument, "push-backup: empty stream (no header)")
	}
	if cr.inProgress() {
		return status.Error(codes.InvalidArgument, "push-backup: stream ended mid-chunk")
	}
	if !manifestFinal {
		return status.Error(codes.FailedPrecondition, "push-backup: stream ended before the manifest completed; nothing committed")
	}

	var m pbsstore.Manifest
	if err := json.Unmarshal(manifestBuf, &m); err != nil {
		return status.Errorf(codes.InvalidArgument, "push-backup: parse manifest: %v", err)
	}
	if err := pbsstore.ValidateManifest(&m); err != nil {
		return status.Errorf(codes.InvalidArgument, "push-backup: invalid manifest: %v", err)
	}
	// Double-gate: structural validity alone doesn't prove a skipped/mis-streamed
	// chunk actually landed. Refuse to write a manifest whose chunks aren't all
	// present at the destination.
	for _, ref := range m.AllChunks() {
		if !repo.HasChunk(ref.ID) {
			return status.Errorf(codes.FailedPrecondition, "push-backup: manifest references chunk %s not present at destination", ref.ID)
		}
	}
	// Manifest written LAST — every chunk it references is now confirmed present.
	if err := repo.PutManifest(&m); err != nil {
		return status.Errorf(codes.Internal, "push-backup: write manifest: %v", err)
	}
	return stream.SendAndClose(&stats)
}

// chunkReassembler buffers exactly one in-flight chunk while a PushBackup stream
// delivers it as ordered sub-frames.
type chunkReassembler struct {
	id    string
	buf   []byte
	total int64
}

func (cr *chunkReassembler) inProgress() bool { return cr.id != "" }

// accept folds one chunk sub-frame into the in-flight chunk, enforcing the
// ordering contract, and on the final sub-frame verifies + persists it.
func (cr *chunkReassembler) accept(repo *pbsstore.Repo, c *pb.PushChunkFrame, stats *pb.PushBackupResponse) error {
	if c.GetTotalSize() < 0 || c.GetTotalSize() > pbsstore.ChunkSize {
		return status.Errorf(codes.InvalidArgument, "push-backup: chunk total_size %d out of range (0..%d)", c.GetTotalSize(), pbsstore.ChunkSize)
	}
	if err := safename.ValidateChunkID(c.GetChunkId()); err != nil {
		return status.Errorf(codes.InvalidArgument, "push-backup: chunk id: %v", err)
	}
	if !cr.inProgress() {
		// First sub-frame of a new chunk.
		if c.GetOffset() != 0 {
			return status.Errorf(codes.InvalidArgument, "push-backup: chunk %s opens at offset %d, want 0", c.GetChunkId(), c.GetOffset())
		}
		cr.id = c.GetChunkId()
		cr.total = c.GetTotalSize()
		cr.buf = make([]byte, 0, c.GetTotalSize())
	} else {
		if c.GetChunkId() != cr.id {
			return status.Errorf(codes.InvalidArgument, "push-backup: interleaved chunk %s while %s is incomplete", c.GetChunkId(), cr.id)
		}
		if c.GetTotalSize() != cr.total {
			return status.Errorf(codes.InvalidArgument, "push-backup: chunk %s total_size changed mid-stream", cr.id)
		}
	}
	// Offsets must exactly tile [0,total_size): the next byte goes where we are.
	if c.GetOffset() != int64(len(cr.buf)) {
		return status.Errorf(codes.InvalidArgument, "push-backup: chunk %s frame offset %d, want %d (gap/overlap)", cr.id, c.GetOffset(), len(cr.buf))
	}
	if int64(len(cr.buf))+int64(len(c.GetData())) > cr.total {
		return status.Errorf(codes.InvalidArgument, "push-backup: chunk %s overruns total_size %d", cr.id, cr.total)
	}
	cr.buf = append(cr.buf, c.GetData()...)

	if !c.GetFinal() {
		return nil
	}
	if int64(len(cr.buf)) != cr.total {
		return status.Errorf(codes.InvalidArgument, "push-backup: chunk %s assembled %d bytes, want %d", cr.id, len(cr.buf), cr.total)
	}
	// Verify the reassembled plaintext hashes to the declared id BEFORE persisting.
	if got := pbsstore.ChunkID(cr.buf); got != cr.id {
		return status.Errorf(codes.InvalidArgument, "push-backup: chunk id mismatch: declared %s, computed %s", cr.id, got)
	}
	_, created, err := repo.PutChunk(cr.buf)
	if err != nil {
		return status.Errorf(codes.Internal, "push-backup: put chunk %s: %v", cr.id, err)
	}
	if created {
		stats.ChunksWritten++
		stats.BytesWritten += int64(len(cr.buf))
	} else {
		stats.ChunksDeduped++
	}
	cr.id, cr.buf, cr.total = "", nil, 0
	return nil
}

// resolveRepoTarget maps a wire RepoTarget to a destination *Repo this daemon
// owns. Exactly one of repo_name / staging_token must be set. Only LOGICAL repo
// names are accepted (resolved in this daemon's own config / cluster registry) —
// never an arbitrary absolute path, which no peer could resolve and which would
// let a peer read/write anywhere on the host.
func (s *Server) resolveRepoTarget(ctx context.Context, t *pb.RepoTarget) (*pbsstore.Repo, error) {
	if t == nil {
		return nil, status.Error(codes.InvalidArgument, "repo target required")
	}
	name, token := t.GetRepoName(), t.GetStagingToken()
	switch {
	case token != "" && name != "":
		return nil, status.Error(codes.InvalidArgument, "repo target: set exactly one of repo_name / staging_token")
	case token != "":
		return s.openStagingRepo(token)
	case name != "":
		path, ok := s.backupRepos[name]
		if !ok && s.db != nil {
			if p, err := corrosion.GetBackupRepoPath(ctx, s.db, name); err == nil && p != "" {
				path, ok = p, true
			}
		}
		if !ok {
			return nil, status.Errorf(codes.NotFound, "unknown backup repo %q (remote streaming requires a configured logical repo name)", name)
		}
		return pbsstore.Open(path)
	default:
		return nil, status.Error(codes.InvalidArgument, "repo target: repo_name or staging_token required")
	}
}

// stagingRepoRoot is the parent of all per-transfer staging repos on this daemon.
func (s *Server) stagingRepoRoot() string { return filepath.Join(s.dataDir, "restore-staging") }

// openStagingRepo opens (or creates) the per-transfer internal staging repo for
// token. The token is validated and contained under <DataDir>/restore-staging/ so
// a wire-supplied value can't escape the directory. Staging repos are plaintext
// transfer buffers, cleaned up by the coordinator after the restore.
func (s *Server) openStagingRepo(token string) (*pbsstore.Repo, error) {
	if err := safename.ValidateName(token); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "staging token: %v", err)
	}
	path, err := safename.SafeJoin(s.stagingRepoRoot(), token)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "staging token: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, "repo.json")); err == nil {
		return pbsstore.Open(path)
	}
	return pbsstore.Init(path)
}

// removeStagingRepo deletes a per-transfer staging repo and everything under it.
// Best-effort: a leftover staging dir is GC-noise, never correctness.
func (s *Server) removeStagingRepo(token string) {
	if safename.ValidateName(token) != nil {
		return
	}
	path, err := safename.SafeJoin(s.stagingRepoRoot(), token)
	if err != nil {
		return
	}
	_ = os.RemoveAll(path)
}
