package grpcapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const (
	// idempotencyClaimTTL bounds an in-progress claim: if the operation crashes
	// mid-flight, the key becomes reclaimable after this. The owner heartbeats the
	// lease while working (idempotencyHeartbeat), so a legitimately long create
	// (slow image pull, blocked libvirt) keeps its claim and is NOT stolen — the
	// lease only lapses when heartbeating stops, i.e. a genuine crash.
	idempotencyClaimTTL = 15 * time.Minute
	// idempotencyHeartbeat is how often the owner extends the lease; a fraction of
	// the TTL so a couple of missed beats still don't expire a live claim.
	idempotencyHeartbeat = idempotencyClaimTTL / 3
	// idempotencyReplayTTL is how long a completed result stays replayable — the
	// client retry window, not the workload's lifetime.
	idempotencyReplayTTL = 24 * time.Hour
	// Completion is recorded synchronously with bounded retries before the RPC
	// returns success — if it isn't persisted the claim lapses and the op could be
	// re-run after the steal window, so a transient store blip must not skip it.
	idempotencyCompleteAttempts = 5
	idempotencyCompleteBackoff  = 200 * time.Millisecond
)

// newClaimID mints an opaque owner token for a claim so complete/release/extend
// can prove ownership (a stale owner whose claim was stolen can't mutate the new one).
func newClaimID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

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
//   - (nil, claimID, nil)     → claim acquired; run the op, then idempotencyFinish
//     with claimID. Start a heartbeat (startIdempotencyHeartbeat) for the duration.
//   - (replay!=nil, "", nil)  → a completed record for the same request; return this
//     stored response instead of re-executing.
//   - (nil, "", AlreadyExists)→ same key, DIFFERENT request (client misuse, 409).
//   - (nil, "", Aborted)      → the operation is already in progress; retry shortly.
//   - (nil, "", Unavailable)  → idempotency store error.
//
// It FAILS CLOSED: for an explicit idempotency key, a store error or a corrupt
// record returns an error rather than proceeding, so a transient DB problem can't
// silently turn a protected retry into a second execution. (The durable claim is
// what prevents the double-act; without it we must not run the op.)
func (s *Server) idempotencyBegin(ctx context.Context, key, method, reqHash string) (replay []byte, claimID string, err error) {
	claimID = newClaimID()
	expires := time.Now().Add(idempotencyClaimTTL).UTC().Format(time.RFC3339Nano)
	claimed, existing, cerr := corrosion.ClaimIdempotencyKey(ctx, s.db, key, claimID, method, reqHash, expires)
	if cerr != nil {
		return nil, "", status.Error(codes.Unavailable, "idempotency store unavailable; retry")
	}
	if claimed {
		return nil, claimID, nil // we own it — proceed
	}
	if existing == nil {
		return nil, "", status.Error(codes.Unavailable, "idempotency claim contended; retry")
	}
	if existing.Method != method || existing.RequestHash != reqHash {
		return nil, "", status.Error(codes.AlreadyExists,
			"idempotency key already used for a different request")
	}
	switch existing.Status {
	case corrosion.IdempotencyCompleted:
		b, derr := base64.StdEncoding.DecodeString(existing.Response)
		if derr != nil {
			return nil, "", status.Error(codes.Internal, "corrupt idempotency record")
		}
		return b, "", nil
	default: // in_progress (a non-expired live claim — ClaimIdempotencyKey steals expired ones)
		return nil, "", status.Error(codes.Aborted,
			"an operation with this idempotency key is already in progress; retry")
	}
}

// startIdempotencyHeartbeat extends the claim's lease periodically while the op
// runs, so a legitimately long-running create isn't mistaken for a crash and
// stolen. The returned stop func halts it (call before idempotencyFinish). If the
// claim is stolen out from under us (ownership lost) the heartbeat self-stops.
func (s *Server) startIdempotencyHeartbeat(ctx context.Context, key, claimID string) (stop func()) {
	hbCtx, cancel := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(idempotencyHeartbeat)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				exp := time.Now().Add(idempotencyClaimTTL).UTC().Format(time.RFC3339Nano)
				if ok, err := corrosion.ExtendIdempotencyClaim(hbCtx, s.db, key, claimID, exp); err == nil && !ok {
					return // lost ownership (stolen / reaped) — stop heartbeating
				}
			}
		}
	}()
	return cancel
}

// idempotencyFinish records the claim's outcome: complete it with the response on
// success, or release it on failure so a later retry can proceed. It matches on
// claimID, so if our claim was stolen (we lost the race) it no-ops rather than
// clobbering the new owner's record.
//
// It is FAIL-CLOSED and returns an error the caller MUST fold into the RPC result:
// completion is written synchronously (with bounded retries, on a context detached
// from the caller's cancellation) BEFORE the RPC returns. If it can't be persisted,
// or our claim was stolen mid-op, we do NOT report a clean success — a recorded
// result is part of the guarantee. The claim is then released best-effort so a
// retry re-runs and resolves via the create name-uniqueness constraint
// (AlreadyExists) rather than sitting in Aborted limbo until the lease lapses.
//
// The returned error is only meaningful on the success path (retErr == nil): when
// the op itself already failed, the claim is released and nil is returned so the
// original failure stands.
func (s *Server) idempotencyFinish(ctx context.Context, key, claimID string, resp proto.Message, retErr error) error {
	if claimID == "" {
		return nil // no claim held (replay path, or no key)
	}
	fctx := context.WithoutCancel(ctx)
	if retErr != nil || resp == nil {
		_ = corrosion.ReleaseIdempotencyKey(fctx, s.db, key, claimID)
		return nil // the op already failed; its own error stands
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		_ = corrosion.ReleaseIdempotencyKey(fctx, s.db, key, claimID)
		return status.Error(codes.Internal, "could not encode idempotent result")
	}
	respB64 := base64.StdEncoding.EncodeToString(b)
	expires := time.Now().Add(idempotencyReplayTTL).UTC().Format(time.RFC3339Nano)
	var lastErr error
	for attempt := 0; attempt < idempotencyCompleteAttempts; attempt++ {
		ok, cerr := corrosion.CompleteIdempotencyKey(fctx, s.db, key, claimID, respB64, expires)
		if cerr == nil {
			if ok {
				return nil // recorded — clean success
			}
			// Our claim was reclaimed mid-op: another actor owns the key now, so we
			// can't vouch that THIS result is what will replay. Fail closed.
			slog.Warn("idempotency: claim reclaimed before completion", "key", key)
			return status.Error(codes.Aborted, "idempotency claim was reclaimed mid-operation; retry")
		}
		lastErr = cerr
		select {
		case <-fctx.Done():
			lastErr = fctx.Err()
		case <-time.After(idempotencyCompleteBackoff):
			continue
		}
		break
	}
	// Result isn't durably recorded. Release best-effort so a retry re-runs (and
	// hits the name-uniqueness backstop) instead of getting Aborted until the lease
	// lapses, and fail closed rather than returning a success we can't replay.
	_ = corrosion.ReleaseIdempotencyKey(fctx, s.db, key, claimID)
	slog.Error("idempotency: could not record completion; failing closed", "key", key, "error", lastErr)
	return status.Error(codes.Unavailable, "operation completed but its result could not be recorded; retry")
}
