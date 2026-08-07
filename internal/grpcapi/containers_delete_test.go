package grpcapi

import (
	"context"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeCTDeletePeer records DeleteContainer forwards.
type fakeCTDeletePeer struct {
	pb.LiteVirtClient
	mu         sync.Mutex
	calls      []*pb.DeleteContainerRequest
	startCalls []*pb.StartContainerRequest
	stopCalls  []*pb.StopContainerRequest
}

func (f *fakeCTDeletePeer) DeleteContainer(_ context.Context, req *pb.DeleteContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	return &emptypb.Empty{}, nil
}

// TestDeleteContainer_HostlessResolvesTheOwner: `lv ct rm <name>` without
// --host used to execute "locally" on whichever node the client dialed, where
// the runtime not-found and the zero-row tombstone are BOTH idempotent
// successes — rc=0, nothing deleted anywhere, an operator typo
// indistinguishable from a clean delete. A host-less delete now resolves the
// OWNER by name and forwards there; a name that exists nowhere is NotFound.
// Explicit-host deletes keep their full retry idempotency.
func TestDeleteContainer_HostlessResolvesTheOwner(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	s.SetContainerRuntime(&fakeCTRuntime{})
	fake := &fakeCTDeletePeer{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return fake, func() {}, nil
	}
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "other-host", Name: "wanderer", State: "stopped", Project: "proj",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "wanderer"}); err != nil {
		t.Fatalf("host-less delete of a container owned elsewhere: %v", err)
	}
	fake.mu.Lock()
	nCalls := len(fake.calls)
	var got *pb.DeleteContainerRequest
	if nCalls > 0 {
		got = fake.calls[0]
	}
	fake.mu.Unlock()
	if nCalls != 1 || got.HostName != "other-host" || got.Name != "wanderer" {
		t.Fatalf("delete forwarded %d times (last %+v), want exactly one forward to other-host — "+
			"a local no-op 'success' is the silent-typo bug", nCalls, got)
	}

	// A name that exists nowhere surfaces as NotFound, not a silent ok.
	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "no-such-ct"}); status.Code(err) != codes.NotFound {
		t.Fatalf("host-less delete of a nonexistent container: got %v, want NotFound", err)
	}

	// EXPLICIT host: an already-gone row stays an idempotent success (the
	// documented retry-safety exception for failover/relocation re-issues).
	if _, err := s.DeleteContainer(adminCtx(), &pb.DeleteContainerRequest{Name: "no-such-ct", HostName: s.hostName}); err != nil {
		t.Fatalf("explicit-host delete of an absent container: %v — retry idempotency must be preserved", err)
	}
}

func (f *fakeCTDeletePeer) StartContainer(_ context.Context, req *pb.StartContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls = append(f.startCalls, req)
	return &emptypb.Empty{}, nil
}

func (f *fakeCTDeletePeer) StopContainer(_ context.Context, req *pb.StopContainerRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopCalls = append(f.stopCalls, req)
	return &emptypb.Empty{}, nil
}

// TestStartStopContainer_HostlessResolvesTheOwner: start and stop get the same
// owner resolution as delete. They failed LOUDLY without --host from a
// non-owning node ("not found on host <local>") — an inconvenience rather than
// delete's silent no-op, but the same wrong shape: the daemon knows exactly
// where the container lives. A name that exists nowhere is NotFound; the
// explicit-host form is unchanged.
func TestStartStopContainer_HostlessResolvesTheOwner(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	s.SetContainerRuntime(&fakeCTRuntime{})
	fake := &fakeCTDeletePeer{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return fake, func() {}, nil
	}
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "other-host", Name: "wanderer", State: "stopped", Project: "proj",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}

	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "wanderer"}); err != nil {
		t.Fatalf("host-less start of a container owned elsewhere: %v", err)
	}
	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "wanderer", TimeoutSec: 7}); err != nil {
		t.Fatalf("host-less stop of a container owned elsewhere: %v", err)
	}
	fake.mu.Lock()
	nStart, nStop := len(fake.startCalls), len(fake.stopCalls)
	var gotStart *pb.StartContainerRequest
	var gotStop *pb.StopContainerRequest
	if nStart > 0 {
		gotStart = fake.startCalls[0]
	}
	if nStop > 0 {
		gotStop = fake.stopCalls[0]
	}
	fake.mu.Unlock()
	if nStart != 1 || gotStart.HostName != "other-host" || gotStart.Name != "wanderer" {
		t.Fatalf("start forwarded %d times (last %+v), want one forward to other-host", nStart, gotStart)
	}
	if nStop != 1 || gotStop.HostName != "other-host" || gotStop.Name != "wanderer" || gotStop.TimeoutSec != 7 {
		t.Fatalf("stop forwarded %d times (last %+v), want one forward to other-host with TimeoutSec 7", nStop, gotStop)
	}

	if _, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "no-such-ct"}); status.Code(err) != codes.NotFound {
		t.Fatalf("host-less start of a nonexistent container: got %v, want NotFound", err)
	}
	if _, err := s.StopContainer(adminCtx(), &pb.StopContainerRequest{Name: "no-such-ct"}); status.Code(err) != codes.NotFound {
		t.Fatalf("host-less stop of a nonexistent container: got %v, want NotFound", err)
	}
}
