package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// pushFrameSize caps a single PushBackup transport frame's payload. A pbsstore
// chunk is up to ChunkSize (4 MiB) — above a safe gRPC message size — so a chunk
// is streamed as several ≤1 MiB sub-frames (same cap as FetchBinary /
// StreamStateDump).
const pushFrameSize = 1 << 20

// remoteRepoSink is the peer-stream implementation of pbsstore.ChunkSink: it
// drives SyncManifest's diff over a PushBackup/HasChunks pair to a peer daemon,
// so the SAME transfer logic that copies a manifest locally also moves it over
// mTLS. Chunks travel as plaintext (the source decrypted on read); the receiving
// daemon re-encrypts at rest with its own key.
//
// Lifecycle: HasChunks is stateless (batched unary calls). The first PutChunk (or
// PutManifest if every chunk deduped) lazily opens the PushBackup stream and
// sends the header. PutManifest sends the manifest frames and CloseAndRecv —
// committing the transfer. Close aborts an opened-but-uncommitted stream so the
// receiver discards the partial transfer; callers MUST defer it.
type remoteRepoSink struct {
	ctx    context.Context
	client pb.LiteVirtClient
	target *pb.RepoTarget

	stream    grpc.ClientStreamingClient[pb.PushBackupFrame, pb.PushBackupResponse]
	resp      *pb.PushBackupResponse
	committed bool
}

func newRemoteRepoSink(ctx context.Context, client pb.LiteVirtClient, target *pb.RepoTarget) *remoteRepoSink {
	return &remoteRepoSink{ctx: ctx, client: client, target: target}
}

// HasChunks probes the destination in bounded batches.
func (rs *remoteRepoSink) HasChunks(ctx context.Context, ids []string) ([]bool, error) {
	out := make([]bool, 0, len(ids))
	for start := 0; start < len(ids); start += hasChunksMaxBatch {
		end := min(start+hasChunksMaxBatch, len(ids))
		batch := ids[start:end]
		resp, err := rs.client.HasChunks(ctx, &pb.HasChunksRequest{Target: rs.target, ChunkIds: batch})
		if err != nil {
			return nil, err
		}
		if len(resp.GetPresent()) != len(batch) {
			return nil, fmt.Errorf("has-chunks: peer returned %d flags for %d ids", len(resp.GetPresent()), len(batch))
		}
		out = append(out, resp.GetPresent()...)
	}
	return out, nil
}

func (rs *remoteRepoSink) ensureStream() error {
	if rs.stream != nil {
		return nil
	}
	st, err := rs.client.PushBackup(rs.ctx)
	if err != nil {
		return err
	}
	if err := st.Send(&pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Header{
		Header: &pb.PushBackupHeader{Target: rs.target},
	}}); err != nil {
		return err
	}
	rs.stream = st
	return nil
}

// PutChunk streams one plaintext chunk as ordered ≤pushFrameSize sub-frames.
func (rs *remoteRepoSink) PutChunk(_ context.Context, data []byte) error {
	if err := rs.ensureStream(); err != nil {
		return err
	}
	id := pbsstore.ChunkID(data)
	total := int64(len(data))
	if total == 0 {
		// Degenerate zero-length chunk: one final, empty sub-frame.
		return rs.stream.Send(&pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{
			Chunk: &pb.PushChunkFrame{ChunkId: id, TotalSize: 0, Offset: 0, Final: true},
		}})
	}
	for off := 0; off < len(data); off += pushFrameSize {
		end := min(off+pushFrameSize, len(data))
		if err := rs.stream.Send(&pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Chunk{
			Chunk: &pb.PushChunkFrame{
				ChunkId:   id,
				TotalSize: total,
				Offset:    int64(off),
				Data:      data[off:end],
				Final:     end == len(data),
			},
		}}); err != nil {
			return err
		}
	}
	return nil
}

// PutManifest streams the manifest LAST and closes the stream, committing the
// transfer. After this, Close is a no-op.
func (rs *remoteRepoSink) PutManifest(_ context.Context, m *pbsstore.Manifest) error {
	if err := rs.ensureStream(); err != nil {
		return err
	}
	blob, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	for off := 0; off < len(blob); off += pushFrameSize {
		end := min(off+pushFrameSize, len(blob))
		if err := rs.stream.Send(&pb.PushBackupFrame{Frame: &pb.PushBackupFrame_Manifest{
			Manifest: &pb.PushManifestFrame{Data: blob[off:end], Final: end == len(blob)},
		}}); err != nil {
			return err
		}
	}
	resp, err := rs.stream.CloseAndRecv()
	if err != nil {
		return err
	}
	rs.resp = resp
	rs.committed = true
	return nil
}

// Close aborts the stream if it was opened but never committed (no manifest sent
// / commit failed), so the receiver — which writes the manifest only on a clean
// final frame — discards the partial transfer, leaving only GC'able orphan
// chunks. Idempotent; safe to defer.
func (rs *remoteRepoSink) Close() {
	if rs.stream == nil || rs.committed {
		return
	}
	_ = rs.stream.CloseSend() // EOF without a final manifest → receiver commits nothing
	rs.stream = nil
}
