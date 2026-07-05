package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const (
	// idempotencyClaimTTL bounds an in-progress claim: if the operation crashes
	// mid-flight, the key becomes reclaimable after this so retries aren't blocked
	// forever. It must comfortably exceed a create's duration.
	idempotencyClaimTTL = 15 * time.Minute
	// idempotencyReplayTTL is how long a completed result stays replayable — the
	// client retry window, not the workload's lifetime.
	idempotencyReplayTTL = 24 * time.Hour
)

// idempotencyRequestHash is a stable digest of a request, used to detect a key
// reused with a DIFFERENT payload (client misuse → 409). Deterministic marshal so
// map ordering (e.g. spec labels) can't make two identical requests hash apart and
// spuriously reject a legitimate retry.
func idempotencyRequestHash(m proto.Message) string {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// idempotencyBegin claims key for a mutating op or reports a prior outcome:
//   - (nil, nil)              → claim acquired; run the op and call idempotencyFinish.
//   - (replay!=nil, nil)      → a completed record for the same request; return this
//     stored response instead of re-executing.
//   - (nil, AlreadyExists)    → same key, DIFFERENT request (client misuse, 409).
//   - (nil, Aborted)          → the operation is already in progress; retry shortly.
//   - (nil, Unavailable)      → idempotency store error.
//
// It FAILS CLOSED: for an explicit idempotency key, a store error or a corrupt
// record returns an error rather than proceeding, so a transient DB problem can't
// silently turn a protected retry into a second execution. (The durable claim is
// what prevents the double-act; without it we must not run the op.)
func (s *Server) idempotencyBegin(ctx context.Context, key, method, reqHash string) ([]byte, error) {
	expires := time.Now().Add(idempotencyClaimTTL).UTC().Format(time.RFC3339Nano)
	claimed, existing, err := corrosion.ClaimIdempotencyKey(ctx, s.db, key, method, reqHash, expires)
	if err != nil {
		return nil, status.Error(codes.Unavailable, "idempotency store unavailable; retry")
	}
	if claimed {
		return nil, nil // we own it — proceed
	}
	if existing == nil {
		return nil, status.Error(codes.Unavailable, "idempotency claim contended; retry")
	}
	if existing.Method != method || existing.RequestHash != reqHash {
		return nil, status.Error(codes.AlreadyExists,
			"idempotency key already used for a different request")
	}
	switch existing.Status {
	case corrosion.IdempotencyCompleted:
		b, derr := base64.StdEncoding.DecodeString(existing.Response)
		if derr != nil {
			return nil, status.Error(codes.Internal, "corrupt idempotency record")
		}
		return b, nil
	default: // in_progress (a non-expired live claim — ClaimIdempotencyKey steals expired ones)
		return nil, status.Error(codes.Aborted,
			"an operation with this idempotency key is already in progress; retry")
	}
}

// idempotencyFinish completes the claim with the response on success, or releases
// it on failure so a later retry can proceed. Best-effort: a completion-write
// failure just leaves the claim to lapse (retries get "in progress" until the
// claim TTL), which is safe — no double-act, since the op already succeeded once.
func (s *Server) idempotencyFinish(ctx context.Context, key string, resp proto.Message, retErr error) {
	if retErr != nil || resp == nil {
		_ = corrosion.ReleaseIdempotencyKey(ctx, s.db, key)
		return
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		_ = corrosion.ReleaseIdempotencyKey(ctx, s.db, key)
		return
	}
	expires := time.Now().Add(idempotencyReplayTTL).UTC().Format(time.RFC3339Nano)
	_ = corrosion.CompleteIdempotencyKey(ctx, s.db, key, base64.StdEncoding.EncodeToString(b), expires)
}
