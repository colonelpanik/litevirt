package grpcapi

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeDumpStream implements grpc.ServerStreamingServer[pb.StateDumpChunk] and
// captures everything the handler sends. Send copies the data because the
// handler legitimately slices a single shared backing array.
type fakeDumpStream struct {
	grpc.ServerStreamingServer[pb.StateDumpChunk]
	ctx    context.Context
	chunks []*pb.StateDumpChunk
}

func (f *fakeDumpStream) Context() context.Context { return f.ctx }
func (f *fakeDumpStream) Send(c *pb.StateDumpChunk) error {
	cp := append([]byte(nil), c.Data...)
	f.chunks = append(f.chunks, &pb.StateDumpChunk{Data: cp, Final: c.Final})
	return nil
}

func freshSyncClient(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func digestMap(t *testing.T, c *corrosion.Client) map[string]string {
	t.Helper()
	ds, err := c.StateDigest(context.Background())
	if err != nil {
		t.Fatalf("StateDigest: %v", err)
	}
	m := map[string]string{}
	for _, d := range ds {
		m[d.Name] = fmt.Sprintf("%d:%s", d.Count, d.Hash)
	}
	return m
}

// reassemble drains a fakeDumpStream into one blob, asserting the chunk
// structure: every non-final chunk is exactly chunkSize, none exceed it, and
// exactly the last chunk carries Final.
func reassemble(t *testing.T, chunks []*pb.StateDumpChunk, chunkSize int) []byte {
	t.Helper()
	var got []byte
	for i, c := range chunks {
		got = append(got, c.Data...)
		last := i == len(chunks)-1
		if c.Final != last {
			t.Errorf("chunk %d: Final=%v, want %v", i, c.Final, last)
		}
		if len(c.Data) > chunkSize {
			t.Errorf("chunk %d: len=%d exceeds chunkSize %d", i, len(c.Data), chunkSize)
		}
		if !last && len(c.Data) != chunkSize {
			t.Errorf("non-final chunk %d: len=%d, want full %d", i, len(c.Data), chunkSize)
		}
	}
	return got
}

// StreamStateDump must reassemble to the exact bytes GetStateDump returns, and
// merge into a fresh node to an identical per-table digest — across many chunks.
func TestStreamStateDump_MatchesUnaryAndMerges(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "h1", State: "active", CPUTotal: 8, MemTotal: 4096,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	for i := 0; i < 25; i++ {
		vm := corrosion.VMRecord{
			Name: fmt.Sprintf("vm%02d", i), StackName: "s1", HostName: "h1",
			Spec: "{}", State: "running", CPUActual: 1, MemActual: 256,
		}
		if err := corrosion.InsertVM(ctx, s.db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
	}

	want := s.db.DumpStateBytes()
	if len(want) == 0 {
		t.Fatal("expected a non-empty dump")
	}

	// Shrink the chunk size so the small fixture still spans many chunks.
	defer func(orig int) { stateDumpChunkSize = orig }(stateDumpChunkSize)
	stateDumpChunkSize = 16

	stream := &fakeDumpStream{ctx: adminCtx()}
	if err := s.StreamStateDump(&emptypb.Empty{}, stream); err != nil {
		t.Fatalf("StreamStateDump: %v", err)
	}
	if len(stream.chunks) < 2 {
		t.Fatalf("expected multiple chunks at chunkSize=%d, got %d", stateDumpChunkSize, len(stream.chunks))
	}

	got := reassemble(t, stream.chunks, stateDumpChunkSize)
	if !bytes.Equal(got, want) {
		t.Fatalf("reassembled stream (%d bytes) != unary GetStateDump (%d bytes)", len(got), len(want))
	}

	// Semantic equivalence: merge into a fresh node, digests must match the source.
	fresh := freshSyncClient(t)
	fresh.MergeStateBytesLWW(got)
	wantDigest, gotDigest := digestMap(t, s.db), digestMap(t, fresh)
	for tbl, d := range wantDigest {
		if gotDigest[tbl] != d {
			t.Errorf("table %q digest after merge = %q, want %q", tbl, gotDigest[tbl], d)
		}
	}
}

// An empty dump still terminates cleanly: one final, data-less chunk.
func TestStreamStateDump_EmptyDump(t *testing.T) {
	s := testServer(t)
	// A fresh schema with no replicated rows dumps to empty.
	if data := s.db.DumpStateBytes(); len(data) != 0 {
		t.Skipf("test DB is not empty (%d bytes); empty-dump path not exercised", len(data))
	}
	stream := &fakeDumpStream{ctx: adminCtx()}
	if err := s.StreamStateDump(&emptypb.Empty{}, stream); err != nil {
		t.Fatalf("StreamStateDump: %v", err)
	}
	if len(stream.chunks) != 1 || !stream.chunks[0].Final || len(stream.chunks[0].Data) != 0 {
		t.Fatalf("empty dump should send exactly one final empty chunk, got %+v", stream.chunks)
	}
}

// Non-operators are rejected, same as the unary GetStateDump.
func TestStreamStateDump_RequiresOperator(t *testing.T) {
	s := testServer(t)
	stream := &fakeDumpStream{ctx: context.Background()} // no principal
	if err := s.StreamStateDump(&emptypb.Empty{}, stream); err == nil {
		t.Fatal("expected an auth error for an unauthenticated caller")
	}
}

func replicationPeerCtx(name string) context.Context {
	ctx := context.WithValue(adminCtx(), ctxKeyAuthMethod, authMethodMTLS)
	return context.WithValue(ctx, ctxKeyMTLSCommonName, name)
}

func TestReplicationRPCsRequirePeerMTLS(t *testing.T) {
	s := testServer(t)
	s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})

	if _, err := s.PushMutations(adminCtx(), &pb.ReplicateRequest{Sender: "node-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("PushMutations with non-mTLS auth code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	if _, err := s.AckMutations(adminCtx(), &pb.AckRequest{Sender: "node-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("AckMutations with non-mTLS auth code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}

	if _, err := s.PushMutations(replicationPeerCtx("node-b"), &pb.ReplicateRequest{Sender: "node-a"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("PushMutations with mismatched peer CN code = %v, want PermissionDenied (err=%v)", status.Code(err), err)
	}

	if _, err := s.PushMutations(replicationPeerCtx("node-a"), &pb.ReplicateRequest{Sender: "node-a", AfterSeq: 7}); err != nil {
		t.Fatalf("PushMutations with matching peer CN: %v", err)
	}
	if _, err := s.AckMutations(replicationPeerCtx("node-a"), &pb.AckRequest{Sender: "node-a", AckedSeq: 7}); err != nil {
		t.Fatalf("AckMutations with matching peer CN: %v", err)
	}
}
