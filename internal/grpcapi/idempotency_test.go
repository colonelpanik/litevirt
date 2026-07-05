package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestIdempotencyFinish_FailsClosedWhenClaimLost proves a successful op whose
// completion can't be durably recorded (the claim vanished / was reclaimed) is
// reported as an error, not a clean success we can't replay.
func TestIdempotencyFinish_FailsClosedWhenClaimLost(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	req := &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "vmx"}, IdempotencyKey: "kx"}
	h := idempotencyRequestHash(req)

	_, claimID, err := s.idempotencyBegin(ctx, "kx", "CreateVM", h)
	if err != nil || claimID == "" {
		t.Fatalf("claim: %q,%v", claimID, err)
	}
	// The claim disappears out from under us (crash-reclaim / reap / steal).
	if err := corrosion.ReleaseIdempotencyKey(ctx, s.db, "kx", claimID); err != nil {
		t.Fatalf("release: %v", err)
	}
	if ferr := s.idempotencyFinish(ctx, "kx", claimID, &pb.VM{Name: "vmx"}, nil); status.Code(ferr) != codes.Aborted {
		t.Errorf("finish after a lost claim = %v; want Aborted (fail closed)", ferr)
	}
}

// TestIdempotency_ClaimReplayConflictInProgress covers the full claim protocol:
// claim → in-progress on a concurrent retry → replay after completion → 409 on a
// different payload → re-claimable after release.
func TestIdempotency_ClaimReplayConflictInProgress(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	req := &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "vm1"}, IdempotencyKey: "key-1"}
	h := idempotencyRequestHash(req)

	// First call claims → proceed (returns an owner claim_id, no replay).
	replay, claimID, err := s.idempotencyBegin(ctx, "key-1", "CreateVM", h)
	if err != nil || replay != nil || claimID == "" {
		t.Fatalf("first begin = %v,%q,%v; want claim (nil, claimID, nil)", replay, claimID, err)
	}
	// A concurrent retry (claim held, not yet finished) → Aborted (retryable), NOT proceed.
	if _, _, err := s.idempotencyBegin(ctx, "key-1", "CreateVM", h); status.Code(err) != codes.Aborted {
		t.Errorf("concurrent begin = %v; want Aborted (in progress)", err)
	}
	// Different payload, same key → 409 even while in progress.
	if _, _, err := s.idempotencyBegin(ctx, "key-1", "CreateVM", "other-hash"); status.Code(err) != codes.AlreadyExists {
		t.Errorf("different-payload begin = %v; want AlreadyExists", err)
	}

	// A STALE owner (different claim_id) must not overwrite the live claim: finishing
	// with the wrong id is a no-op, so the key stays in_progress.
	s.idempotencyFinish(ctx, "key-1", "not-the-owner", &pb.VM{Name: "evil"}, nil)
	if _, _, err := s.idempotencyBegin(ctx, "key-1", "CreateVM", h); status.Code(err) != codes.Aborted {
		t.Errorf("after a stale-owner finish, key-1 must still be in progress; got %v", err)
	}

	// The real owner finishes successfully → a later retry replays the stored response.
	s.idempotencyFinish(ctx, "key-1", claimID, &pb.VM{Name: "vm1", State: pb.VMState_VM_RUNNING}, nil)
	replay, _, err = s.idempotencyBegin(ctx, "key-1", "CreateVM", h)
	if err != nil || replay == nil {
		t.Fatalf("post-finish begin = %v,%v; want replay", replay, err)
	}
	out := &pb.VM{}
	if proto.Unmarshal(replay, out) != nil || out.Name != "vm1" || out.State != pb.VMState_VM_RUNNING {
		t.Errorf("replayed = %+v, want vm1/RUNNING", out)
	}

	// A failed op releases its claim → the key is claimable again.
	_, claimID2, err := s.idempotencyBegin(ctx, "key-2", "CreateVM", h)
	if err != nil || claimID2 == "" {
		t.Fatalf("claim key-2: %q,%v", claimID2, err)
	}
	s.idempotencyFinish(ctx, "key-2", claimID2, nil, status.Error(codes.Internal, "boom"))
	if replay, _, err := s.idempotencyBegin(ctx, "key-2", "CreateVM", h); err != nil || replay != nil {
		t.Errorf("after a failed op, key-2 must be re-claimable; got %v,%v", replay, err)
	}
}

// TestIdempotencyRequestHash_Deterministic proves map fields don't make two
// identical requests hash apart (which would spuriously 409 a legitimate retry).
func TestIdempotencyRequestHash_Deterministic(t *testing.T) {
	mk := func() *pb.CreateContainerRequest {
		return &pb.CreateContainerRequest{Name: "ct1", Labels: map[string]string{"a": "1", "b": "2", "c": "3"}}
	}
	if idempotencyRequestHash(mk()) != idempotencyRequestHash(mk()) {
		t.Error("identical requests (with a map field) must hash identically")
	}
	other := mk()
	other.Name = "ct2"
	if idempotencyRequestHash(mk()) == idempotencyRequestHash(other) {
		t.Error("different requests must hash differently")
	}
}
