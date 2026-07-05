package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestIdempotency_ReplayStoreConflict covers the full dedup decision: store a
// response, replay it, reject a same-key-different-payload (409), and re-execute
// once expired.
func TestIdempotency_ReplayStoreConflict(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	req := &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "vm1"}, IdempotencyKey: "key-1"}
	h := idempotencyRequestHash(req)

	// No record yet → proceed (replay nil, no error).
	if replay, err := s.idempotencyReplay(ctx, "key-1", "CreateVM", h); err != nil || replay != nil {
		t.Fatalf("first call = %v, %v; want proceed", replay, err)
	}

	// Record a completed response, then a retry with the same key+payload replays it.
	orig := &pb.VM{Name: "vm1", State: pb.VMState_VM_RUNNING}
	s.idempotencyStore(ctx, "key-1", "CreateVM", h, orig)
	replay, err := s.idempotencyReplay(ctx, "key-1", "CreateVM", h)
	if err != nil || replay == nil {
		t.Fatalf("retry replay = %v, %v; want the stored response", replay, err)
	}
	out := &pb.VM{}
	if perr := proto.Unmarshal(replay, out); perr != nil || out.Name != "vm1" || out.State != pb.VMState_VM_RUNNING {
		t.Errorf("replayed response = %+v (%v), want vm1/RUNNING", out, perr)
	}

	// Same key, DIFFERENT payload → 409 AlreadyExists.
	_, cErr := s.idempotencyReplay(ctx, "key-1", "CreateVM", "different-hash")
	if status.Code(cErr) != codes.AlreadyExists {
		t.Errorf("key reuse with a different payload = %v; want AlreadyExists", cErr)
	}

	// An expired record → treated as absent (re-execute).
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	_ = corrosion.PutIdempotencyRecord(ctx, s.db, corrosion.IdempotencyRecord{
		Key: "key-exp", Method: "CreateVM", RequestHash: h, Response: "x", ExpiresAt: past,
	})
	if replay, err := s.idempotencyReplay(ctx, "key-exp", "CreateVM", h); err != nil || replay != nil {
		t.Errorf("expired record = %v, %v; want proceed (nil,nil)", replay, err)
	}
}

// TestIdempotencyRequestHash_Deterministic proves map fields don't make two
// identical requests hash apart (which would spuriously 409 a legitimate retry).
func TestIdempotencyRequestHash_Deterministic(t *testing.T) {
	mk := func() *pb.CreateContainerRequest {
		return &pb.CreateContainerRequest{
			Name:   "ct1",
			Labels: map[string]string{"a": "1", "b": "2", "c": "3"},
		}
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
