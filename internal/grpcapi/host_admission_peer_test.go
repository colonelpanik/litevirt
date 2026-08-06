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

// fakeDestPeer stands in for a migration DESTINATION daemon in single-server
// unit tests: it answers the two destination-owned host-admission RPCs and
// records what it was asked. Every other client method panics via the embedded
// nil interface, which is exactly right — these tests must not silently grow a
// dependency on another peer RPC.
type fakeDestPeer struct {
	pb.LiteVirtClient
	mu           sync.Mutex
	reserveCalls []*pb.ReserveHostCapacityRequest
	releaseCalls []string
	reserveErr   error
	leaseID      string
}

func (f *fakeDestPeer) ReserveHostCapacity(_ context.Context, req *pb.ReserveHostCapacityRequest, _ ...grpc.CallOption) (*pb.ReserveHostCapacityResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.reserveErr != nil {
		return nil, f.reserveErr
	}
	f.reserveCalls = append(f.reserveCalls, req)
	return &pb.ReserveHostCapacityResponse{LeaseId: f.leaseID}, nil
}

func (f *fakeDestPeer) ReleaseHostCapacity(_ context.Context, req *pb.ReleaseHostCapacityRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.releaseCalls = append(f.releaseCalls, req.LeaseId)
	return &emptypb.Empty{}, nil
}

func (f *fakeDestPeer) released() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.releaseCalls...)
}

// fakeDestinationAdmission wires s to an always-admitting fake destination and
// returns it for assertions. Tests that exercise a migration WITHOUT standing
// up a second daemon use this so the destination-owned admission hop succeeds.
func fakeDestinationAdmission(s *Server) *fakeDestPeer {
	f := &fakeDestPeer{leaseID: "dest-lease-1"}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return f, func() {}, nil
	}
	return f
}

// TestReserveHostCapacity_PeerOnlyAndSelfAddressed: the RPC is peer-mTLS-only,
// and the destination answers only for ITSELF — a request naming another host
// is a routing error, not a decision to make on that host's behalf.
func TestReserveHostCapacity_PeerOnlyAndSelfAddressed(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)

	req := &pb.ReserveHostCapacityRequest{
		Host: "test-host", Project: "proj", Method: "MigrateVM", Principal: "op@local",
		ResourceId: "vm:probe", CpuDelta: 1, MemMibDelta: 512, NewResidency: true, VmOverhead: true,
	}
	if _, err := s.ReserveHostCapacity(adminCtx(), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator caller: got %v, want PermissionDenied — this RPC is peer-only", err)
	}

	peer := peerCtxFor(t, s, "src-node")
	foreign := &pb.ReserveHostCapacityRequest{Host: "other-host", Project: "proj", Method: "MigrateVM",
		ResourceId: "vm:probe", CpuDelta: 1, MemMibDelta: 512, NewResidency: true, VmOverhead: true}
	if _, err := s.ReserveHostCapacity(peer, foreign); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("request naming another host: got %v, want FailedPrecondition", err)
	}
}

// TestReserveHostCapacity_LeaseVisibleUntilReleased: a remote reservation must
// consume the destination's headroom exactly like a local one while held, and
// stop consuming it on release. This is the property the lease exists for — a
// concurrent local create racing an inbound migration must see its draw.
func TestReserveHostCapacity_LeaseVisibleUntilReleased(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	ctx := peerCtxFor(t, s, "src-node")

	resp, err := s.ReserveHostCapacity(ctx, &pb.ReserveHostCapacityRequest{
		Host: "test-host", Project: "proj", Method: "MigrateVM", Principal: "op@local",
		ResourceId: "vm:mover", CpuDelta: 2, MemMibDelta: 1024, NewResidency: true, VmOverhead: true,
	})
	if err != nil {
		t.Fatalf("ReserveHostCapacity: %v", err)
	}
	if resp.LeaseId == "" {
		t.Fatal("a sized reservation returned an empty lease id")
	}
	cpu, mem, rerr := corrosion.HostReserved(context.Background(), s.db, "test-host")
	if rerr != nil {
		t.Fatalf("HostReserved: %v", rerr)
	}
	if cpu != 2 || mem != 1024+128 {
		t.Fatalf("held remote lease reserves %d vCPU/%d MiB, want 2/%d (guest memory + qemu overhead)", cpu, mem, 1024+128)
	}

	if _, err := s.ReleaseHostCapacity(ctx, &pb.ReleaseHostCapacityRequest{LeaseId: resp.LeaseId}); err != nil {
		t.Fatalf("ReleaseHostCapacity: %v", err)
	}
	cpu, mem, rerr = corrosion.HostReserved(context.Background(), s.db, "test-host")
	if rerr != nil || cpu != 0 || mem != 0 {
		t.Fatalf("after release HostReserved = %d/%d (err=%v), want 0/0", cpu, mem, rerr)
	}
	// Idempotent: releasing again is not an error.
	if _, err := s.ReleaseHostCapacity(ctx, &pb.ReleaseHostCapacityRequest{LeaseId: resp.LeaseId}); err != nil {
		t.Fatalf("second release: %v", err)
	}
}

// TestReserveHostCapacity_LocalRogueChargesTheDecision: the destination decides
// with its own runtime-only load in the arithmetic. A bounded rogue container
// the database knows nothing about must come out of the headroom an inbound
// migration is admitted against — the exact input a source-side decision
// structurally lacks.
func TestReserveHostCapacity_LocalRogueChargesTheDecision(t *testing.T) {
	origCap := lxcCapable
	lxcCapable = func() bool { return true }
	defer func() { lxcCapable = origCap }()

	s := testServer(t)
	admissionHost(t, s) // allocatable 1536 MiB
	s.SetContainerRuntime(&fakeCT{
		names:  []string{"finite-rogue"},
		states: map[string]string{"finite-rogue": "running"},
		limits: map[string][2]int{"finite-rogue": {2, 1024}},
	})
	s.invalidateInventoryCache()
	ctx := peerCtxFor(t, s, "src-node")

	// 512 MiB guest + 128 overhead fits 1536 MiB of DB headroom — but not the
	// 512 left once the rogue's 1024 are charged.
	_, err := s.ReserveHostCapacity(ctx, &pb.ReserveHostCapacityRequest{
		Host: "test-host", Project: "proj", Method: "MigrateVM", Principal: "op@local",
		ResourceId: "vm:squeezed", CpuDelta: 1, MemMibDelta: 512, NewResidency: true, VmOverhead: true,
	})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("inbound migration beside a 1024 MiB runtime-only rogue on a 1536 MiB host: got %v, "+
			"want ResourceExhausted — the destination's own runtime load must charge the decision", err)
	}

	// Shrink the rogue: the same admission fits.
	s.SetContainerRuntime(&fakeCT{
		names:  []string{"finite-rogue"},
		states: map[string]string{"finite-rogue": "running"},
		limits: map[string][2]int{"finite-rogue": {2, 256}},
	})
	s.invalidateInventoryCache()
	resp, err := s.ReserveHostCapacity(ctx, &pb.ReserveHostCapacityRequest{
		Host: "test-host", Project: "proj", Method: "MigrateVM", Principal: "op@local",
		ResourceId: "vm:squeezed", CpuDelta: 1, MemMibDelta: 512, NewResidency: true, VmOverhead: true,
	})
	if err != nil {
		t.Fatalf("inbound migration beside a small rogue: %v", err)
	}
	if _, err := s.ReleaseHostCapacity(ctx, &pb.ReleaseHostCapacityRequest{LeaseId: resp.LeaseId}); err != nil {
		t.Fatalf("release: %v", err)
	}
}

// TestReleaseHostCapacity_RefusesWhatItDoesNotHold: release is not a blind
// terminal-step writer. An unknown id, a non-capacity operation, and a lease
// reserving capacity on a DIFFERENT host are each refused — otherwise a peer
// could erase any node's live reservation (or complete an unrelated workload
// operation) by guessing its id.
func TestReleaseHostCapacity_RefusesWhatItDoesNotHold(t *testing.T) {
	s := testServer(t)
	admissionHost(t, s)
	ctx := peerCtxFor(t, s, "src-node")
	bg := context.Background()

	if _, err := s.ReleaseHostCapacity(adminCtx(), &pb.ReleaseHostCapacityRequest{LeaseId: "x"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator caller: got %v, want PermissionDenied", err)
	}
	if _, err := s.ReleaseHostCapacity(ctx, &pb.ReleaseHostCapacityRequest{LeaseId: "no-such-op"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown lease id: got %v, want NotFound", err)
	}

	// A non-capacity operation must not be completable through this door.
	if err := corrosion.InsertOperation(bg, s.db, corrosion.OperationRecord{
		ID: "vm-op-1", Method: "CreateVM", ResourceKind: "vm", ResourceID: "some-vm",
		OperationKind: string(corrosion.OpResourceUpdateRunning),
	}); err != nil {
		t.Fatalf("insert vm op: %v", err)
	}
	if _, err := s.ReleaseHostCapacity(ctx, &pb.ReleaseHostCapacityRequest{LeaseId: "vm-op-1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("non-capacity operation: got %v, want FailedPrecondition", err)
	}

	// A capacity lease for ANOTHER host is foreign here, and refusing must leave
	// it alive there.
	plantReservation(t, s, "foreign-lease", "other-host", "proj", 1, 512)
	if _, err := s.ReleaseHostCapacity(ctx, &pb.ReleaseHostCapacityRequest{LeaseId: "foreign-lease"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("foreign-host lease: got %v, want FailedPrecondition", err)
	}
	cpu, mem, rerr := corrosion.HostReserved(bg, s.db, "other-host")
	if rerr != nil {
		t.Fatalf("HostReserved: %v", rerr)
	}
	if cpu != 1 || mem != 512 {
		t.Fatalf("refused foreign release still altered the lease: reserved %d/%d, want 1/512", cpu, mem)
	}
}

// TestMigrateContainer_DestinationOwnsTheLease_NoSourceLocalReservation: one
// move, one lease, held by the DESTINATION. The source must ask the target
// (with the container's residency intent), must not also mint a source-local
// capacity reservation for the target host, and must hand the lease back once
// the move lands.
func TestMigrateContainer_DestinationOwnsTheLease_NoSourceLocalReservation(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	_ = rt
	ctx := context.Background()
	fake := &fakeDestPeer{leaseID: "dest-lease-9"}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return fake, func() {}, nil
	}
	s.migrateRestoreOverride = func(_ context.Context, target, _, name, _ string, _ bool) (corrosion.RestoreOutcome, error) {
		if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
			HostName: target, Name: name, State: "running", Project: "acme",
		}); err != nil {
			return corrosion.RestoreNotAttempted, err
		}
		return corrosion.RestoreLanded, nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	if err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st); err != nil {
		t.Fatalf("MigrateContainer: %v", err)
	}

	if n := len(fake.reserveCalls); n != 1 {
		t.Fatalf("destination admission asked %d times, want exactly 1", n)
	}
	got := fake.reserveCalls[0]
	if got.Host != "host-b" || got.ResourceId != "ct:ct1" || got.MemMibDelta != 256 {
		t.Errorf("reserve request = host %q resource %q mem %d, want host-b/ct:ct1/256", got.Host, got.ResourceId, got.MemMibDelta)
	}
	if !got.NewResidency || got.VmOverhead {
		t.Errorf("reserve intent = residency %v overhead %v, want residency without qemu overhead", got.NewResidency, got.VmOverhead)
	}
	if rel := fake.released(); len(rel) != 1 || rel[0] != "dest-lease-9" {
		t.Errorf("destination lease releases = %v, want exactly [dest-lease-9]", rel)
	}

	// The source's own journal must hold NO capacity reservation for this move:
	// the destination's database is the one serializing host admission.
	rows, qerr := s.db.Query(ctx, `SELECT id FROM operations WHERE resource_kind = 'capacity' AND deleted_at IS NULL`)
	if qerr != nil {
		t.Fatalf("scan source capacity operations: %v", qerr)
	}
	if len(rows) != 0 {
		t.Fatalf("the source minted %d local capacity operation(s) for a destination-admitted move, want 0", len(rows))
	}
}

// TestMigrateContainer_OldDestinationFailsClosed_BeforeStoppingAnything: a
// destination that does not implement ReserveHostCapacity refuses the migration
// with FailedPrecondition — no source-side fallback — and the refusal lands
// BEFORE the cold-transfer stop, so the mixed-version edge costs availability
// of migration, never an outage of the workload.
func TestMigrateContainer_OldDestinationFailsClosed_BeforeStoppingAnything(t *testing.T) {
	s, rt, repo := migrateTestServer(t, "running")
	fake := &fakeDestPeer{reserveErr: status.Error(codes.Unimplemented, "unknown method ReserveHostCapacity")}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return fake, func() {}, nil
	}

	st := &progressStream[pb.MigrateContainerProgress]{ctx: adminCtx()}
	err := s.MigrateContainer(&pb.MigrateContainerRequest{
		Name: "ct1", SourceHost: "host-a", TargetHost: "host-b", RepoPath: repo,
	}, st)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("migrating to a destination without the admission RPC: got %v, want FailedPrecondition", err)
	}
	if n := len(rt.stopCalls); n != 0 {
		t.Fatalf("source container was stopped %d times for a migration the destination could not admit; want 0", n)
	}
}
