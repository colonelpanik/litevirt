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

// idempotencyTTL is how long a completed operation's result stays replayable.
// After this a record is reaped and a retry re-executes — the window only needs
// to cover client retry behavior, not the workload's lifetime.
const idempotencyTTL = 24 * time.Hour

// idempotencyRequestHash is a stable digest of a request, used to detect a key
// reused with a DIFFERENT payload (client misuse → 409). Deterministic marshal so
// map ordering (e.g. spec labels) can't make two identical requests hash apart and
// spuriously reject a legitimate retry.
func idempotencyRequestHash(m proto.Message) string {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// idempotencyReplay checks for a prior record of (key, method):
//   - (replay!=nil, nil): a matching completed record — unmarshal into the typed
//     response and return it instead of re-executing.
//   - (nil, AlreadyExists err): the key was used with a different request (misuse).
//   - (nil, nil): no usable record — proceed and execute.
//
// It fails OPEN on a read error (dedup is a best-effort convenience, never a gate
// that could block a legitimate operation).
func (s *Server) idempotencyReplay(ctx context.Context, key, method, reqHash string) ([]byte, error) {
	rec, err := corrosion.GetIdempotencyRecord(ctx, s.db, key)
	if err != nil || rec == nil {
		return nil, nil
	}
	if t, perr := time.Parse(time.RFC3339, rec.ExpiresAt); perr == nil && time.Now().After(t) {
		return nil, nil // expired → treat as absent
	}
	if rec.Method != method || rec.RequestHash != reqHash {
		return nil, status.Error(codes.AlreadyExists,
			"idempotency key already used for a different request")
	}
	b, derr := base64.StdEncoding.DecodeString(rec.Response)
	if derr != nil {
		return nil, nil
	}
	return b, nil
}

// idempotencyStore records a completed operation's response under key (first
// writer wins; see corrosion.PutIdempotencyRecord). Best-effort: a write failure
// just means a later retry re-executes instead of replaying.
func (s *Server) idempotencyStore(ctx context.Context, key, method, reqHash string, resp proto.Message) {
	b, err := proto.Marshal(resp)
	if err != nil {
		return
	}
	_ = corrosion.PutIdempotencyRecord(ctx, s.db, corrosion.IdempotencyRecord{
		Key:         key,
		Method:      method,
		RequestHash: reqHash,
		Response:    base64.StdEncoding.EncodeToString(b),
		Status:      "completed",
		ExpiresAt:   time.Now().Add(idempotencyTTL).UTC().Format(time.RFC3339Nano),
	})
}
