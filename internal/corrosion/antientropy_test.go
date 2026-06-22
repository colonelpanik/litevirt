package corrosion

import (
	"context"
	"io"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// fakeDumpRecvStream is a client-side StreamStateDump stream backed by a fixed
// list of chunks, optionally terminated by a non-EOF error (e.g. Unimplemented
// from an old peer).
type fakeDumpRecvStream struct {
	grpc.ServerStreamingClient[pb.StateDumpChunk]
	chunks  []*pb.StateDumpChunk
	idx     int
	recvErr error // returned once chunks are drained (nil → io.EOF)
}

func (s *fakeDumpRecvStream) Recv() (*pb.StateDumpChunk, error) {
	if s.idx < len(s.chunks) {
		c := s.chunks[s.idx]
		s.idx++
		return c, nil
	}
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	return nil, io.EOF
}

// fakeDumpClient embeds the full LiteVirtClient interface (so the unused methods
// satisfy it) and overrides only the two state-dump RPCs.
type fakeDumpClient struct {
	pb.LiteVirtClient
	chunks      []*pb.StateDumpChunk
	recvErr     error
	streamErr   error // error returned by the StreamStateDump call itself
	unary       []byte
	unaryErr    error
	streamCalls int
	getCalls    int
}

func (f *fakeDumpClient) StreamStateDump(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.StateDumpChunk], error) {
	f.streamCalls++
	if f.streamErr != nil {
		return nil, f.streamErr
	}
	return &fakeDumpRecvStream{chunks: f.chunks, recvErr: f.recvErr}, nil
}

func (f *fakeDumpClient) GetStateDump(_ context.Context, _ *emptypb.Empty, _ ...grpc.CallOption) (*pb.StateDumpResponse, error) {
	f.getCalls++
	if f.unaryErr != nil {
		return nil, f.unaryErr
	}
	return &pb.StateDumpResponse{Data: f.unary}, nil
}

func chunk(data string, final bool) *pb.StateDumpChunk {
	return &pb.StateDumpChunk{Data: []byte(data), Final: final}
}

// The happy path reassembles streamed chunks and never touches the unary RPC.
func TestFetchStateDump_StreamReassembles(t *testing.T) {
	c := &fakeDumpClient{chunks: []*pb.StateDumpChunk{chunk("foo", false), chunk("bar", false), chunk("baz", true)}}
	got, err := fetchStateDump(context.Background(), c)
	if err != nil {
		t.Fatalf("fetchStateDump: %v", err)
	}
	if string(got) != "foobarbaz" {
		t.Fatalf("got %q, want foobarbaz", got)
	}
	if c.getCalls != 0 {
		t.Errorf("unary GetStateDump called %d times, want 0 (stream succeeded)", c.getCalls)
	}
}

// An old peer that doesn't implement the stream reports Unimplemented on Recv;
// fetchStateDump must fall back to the unary GetStateDump.
func TestFetchStateDump_FallbackOnRecvUnimplemented(t *testing.T) {
	c := &fakeDumpClient{
		recvErr: status.Error(codes.Unimplemented, "unknown method StreamStateDump"),
		unary:   []byte("legacy-dump"),
	}
	got, err := fetchStateDump(context.Background(), c)
	if err != nil {
		t.Fatalf("fetchStateDump: %v", err)
	}
	if string(got) != "legacy-dump" {
		t.Fatalf("got %q, want legacy-dump", got)
	}
	if c.streamCalls != 1 || c.getCalls != 1 {
		t.Errorf("streamCalls=%d getCalls=%d, want 1 and 1", c.streamCalls, c.getCalls)
	}
}

// Some stacks surface Unimplemented on the call itself rather than the first
// Recv — that must also fall back.
func TestFetchStateDump_FallbackOnCallUnimplemented(t *testing.T) {
	c := &fakeDumpClient{
		streamErr: status.Error(codes.Unimplemented, "unknown method"),
		unary:     []byte("legacy"),
	}
	got, err := fetchStateDump(context.Background(), c)
	if err != nil {
		t.Fatalf("fetchStateDump: %v", err)
	}
	if string(got) != "legacy" || c.getCalls != 1 {
		t.Fatalf("got %q getCalls=%d, want legacy and 1", got, c.getCalls)
	}
}

// A genuine transport error (not Unimplemented) must propagate, NOT silently
// fall back — otherwise a transient stream failure would mask real problems.
func TestFetchStateDump_NonUnimplementedErrorPropagates(t *testing.T) {
	c := &fakeDumpClient{recvErr: status.Error(codes.Unavailable, "connection reset")}
	_, err := fetchStateDump(context.Background(), c)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("err = %v, want Unavailable propagated", err)
	}
	if c.getCalls != 0 {
		t.Errorf("unary fallback called on a non-Unimplemented error (getCalls=%d)", c.getCalls)
	}
}
