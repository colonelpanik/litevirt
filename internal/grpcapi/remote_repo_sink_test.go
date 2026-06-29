package grpcapi

import (
	"bytes"
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// fakePushClient is the client end of a PushBackup stream that captures the
// frames the sink sends and, on CloseAndRecv, replays them through the REAL
// PushBackup handler on srv — a true sink↔receiver round-trip with no network.
type fakePushClient struct {
	grpc.ClientStreamingClient[pb.PushBackupFrame, pb.PushBackupResponse]
	srv     *Server
	peerCtx context.Context
	frames  []*pb.PushBackupFrame
}

func (c *fakePushClient) Send(f *pb.PushBackupFrame) error { c.frames = append(c.frames, f); return nil }
func (c *fakePushClient) CloseSend() error                 { return nil }
func (c *fakePushClient) CloseAndRecv() (*pb.PushBackupResponse, error) {
	fs := &fakePushServer{ctx: c.peerCtx, frames: c.frames}
	if err := c.srv.PushBackup(fs); err != nil {
		return nil, err
	}
	return fs.resp, nil
}

// fakeLVClient routes the two transport RPCs to the real server handlers with a
// peer context; every other method panics (unused here).
type fakeLVClient struct {
	pb.LiteVirtClient
	srv     *Server
	peerCtx context.Context
}

func (c *fakeLVClient) HasChunks(_ context.Context, in *pb.HasChunksRequest, _ ...grpc.CallOption) (*pb.HasChunksResponse, error) {
	return c.srv.HasChunks(c.peerCtx, in)
}

func (c *fakeLVClient) PushBackup(_ context.Context, _ ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushBackupFrame, pb.PushBackupResponse], error) {
	return &fakePushClient{srv: c.srv, peerCtx: c.peerCtx}, nil
}

func grpcRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	r := rand.New(rand.NewSource(1))
	r.Read(b)
	return b
}

// The remoteRepoSink frames a manifest + its chunks (a 4 MiB chunk spanning
// several ≤1 MiB sub-frames) such that the real PushBackup handler reassembles,
// verifies, and writes them; the restored bytes match the source.
func TestRemoteRepoSink_RoundTrip(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")

	src, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init src: %v", err)
	}
	payload := grpcRandomBytes(t, pbsstore.ChunkSize*2+4096) // forces multi-sub-frame chunks
	m, err := pbsstore.PushDisk(context.Background(), src, bytes.NewReader(payload), pbsstore.PushOptions{
		VMName: "ct1", DiskName: "rootfs", Timestamp: "2026-06-29T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}

	client := &fakeLVClient{srv: s, peerCtx: peer}
	sink := newRemoteRepoSink(context.Background(), client, &pb.RepoTarget{StagingToken: "tok"})
	defer sink.Close()

	stats, err := pbsstore.SyncManifest(context.Background(), src, m, sink)
	if err != nil {
		t.Fatalf("SyncManifest over remote sink: %v", err)
	}
	if stats.ChunksCopied != len(m.Chunks) || stats.ManifestsCopied != 1 {
		t.Fatalf("stats = %+v (want %d chunks, 1 manifest)", stats, len(m.Chunks))
	}

	// The destination staging repo now restores the exact source bytes.
	dst, err := pbsstore.Open(filepath.Join(s.dataDir, "restore-staging", "tok"))
	if err != nil {
		t.Fatalf("open dst staging: %v", err)
	}
	got, err := dst.GetManifest("ct1", "2026-06-29T10:00:00Z", "rootfs")
	if err != nil {
		t.Fatalf("dst.GetManifest: %v", err)
	}
	out := filepath.Join(t.TempDir(), "out.bin")
	if err := pbsstore.RestoreToFile(context.Background(), dst, got, out, pbsstore.RestoreOptions{}); err != nil {
		t.Fatalf("RestoreToFile: %v", err)
	}
	restored, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, payload) {
		t.Fatalf("restored bytes differ from source")
	}
}

// A second transfer of the same manifest dedups every chunk over the wire — the
// sink probes HasChunks (now all present) and sends only the manifest.
func TestRemoteRepoSink_DedupsSecondTransfer(t *testing.T) {
	s := newPeerAuthServer(t)
	peer := mtlsCtx("peer-1")

	src, err := pbsstore.Init(t.TempDir())
	if err != nil {
		t.Fatalf("Init src: %v", err)
	}
	payload := grpcRandomBytes(t, pbsstore.ChunkSize+1024)
	m, err := pbsstore.PushDisk(context.Background(), src, bytes.NewReader(payload), pbsstore.PushOptions{
		VMName: "ct1", DiskName: "rootfs", Timestamp: "2026-06-29T10:00:00Z",
	})
	if err != nil {
		t.Fatalf("PushDisk: %v", err)
	}
	client := &fakeLVClient{srv: s, peerCtx: peer}

	sink1 := newRemoteRepoSink(context.Background(), client, &pb.RepoTarget{StagingToken: "tok"})
	if _, err := pbsstore.SyncManifest(context.Background(), src, m, sink1); err != nil {
		t.Fatalf("first transfer: %v", err)
	}
	sink1.Close()

	// Second transfer: a fresh manifest timestamp, same chunks → all deduped.
	m2 := *m
	m2.Timestamp = "2026-06-29T11:00:00Z"
	sink2 := newRemoteRepoSink(context.Background(), client, &pb.RepoTarget{StagingToken: "tok"})
	defer sink2.Close()
	stats, err := pbsstore.SyncManifest(context.Background(), src, &m2, sink2)
	if err != nil {
		t.Fatalf("second transfer: %v", err)
	}
	if stats.ChunksCopied != 0 || stats.ChunksSkipped != len(m.Chunks) {
		t.Fatalf("second transfer not deduped: %+v", stats)
	}
}
