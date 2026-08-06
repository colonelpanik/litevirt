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
	mu    sync.Mutex
	calls []*pb.DeleteContainerRequest
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
