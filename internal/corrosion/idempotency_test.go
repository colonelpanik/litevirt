package corrosion

import (
	"context"
	"testing"
	"time"
)

func TestClaimIdempotencyKey_ClaimReplayInProgress(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)

	// First claim succeeds.
	claimed, existing, err := ClaimIdempotencyKey(ctx, c, "k1", "owner-A", "CreateVM", "h1", future)
	if err != nil || !claimed || existing != nil {
		t.Fatalf("first claim = %v,%v,%v; want claimed", claimed, existing, err)
	}
	// A concurrent claim (still in_progress) does NOT acquire and reports the live claim.
	claimed, existing, err = ClaimIdempotencyKey(ctx, c, "k1", "owner-B", "CreateVM", "h1", future)
	if err != nil || claimed || existing == nil {
		t.Fatalf("second claim = %v,%v,%v; want not-claimed + existing", claimed, existing, err)
	}
	if existing.Status != IdempotencyInProgress || existing.ClaimID != "owner-A" {
		t.Errorf("existing = %+v; want in_progress owned by owner-A", existing)
	}
	// Complete it (as the owner); a later claim now sees the completed record + response.
	if ok, err := CompleteIdempotencyKey(ctx, c, "k1", "owner-A", "resp-A", future); err != nil || !ok {
		t.Fatalf("complete = %v,%v; want ok", ok, err)
	}
	_, existing, _ = ClaimIdempotencyKey(ctx, c, "k1", "owner-C", "CreateVM", "h1", future)
	if existing == nil || existing.Status != IdempotencyCompleted || existing.Response != "resp-A" {
		t.Errorf("after complete = %+v; want completed/resp-A", existing)
	}
}

// TestIdempotency_OwnerTokenGuards is the fix for "a stale owner can complete or
// delete a newer stolen claim": complete/release/extend must match claim_id.
func TestIdempotency_OwnerTokenGuards(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)

	// owner-A claims with an already-lapsed lease (simulating a stalled/crashed op).
	if claimed, _, _ := ClaimIdempotencyKey(ctx, c, "k", "owner-A", "m", "h", past); !claimed {
		t.Fatal("seed claim by owner-A")
	}
	// owner-B steals the expired claim and becomes the live owner.
	claimed, _, err := ClaimIdempotencyKey(ctx, c, "k", "owner-B", "m", "h", future)
	if err != nil || !claimed {
		t.Fatalf("owner-B steal = %v,%v; want claimed", claimed, err)
	}

	// The stale owner-A must NOT be able to complete, release, or extend owner-B's claim.
	if ok, _ := CompleteIdempotencyKey(ctx, c, "k", "owner-A", "stale-resp", future); ok {
		t.Error("stale owner-A completed a claim it no longer owns")
	}
	if ok, _ := ExtendIdempotencyClaim(ctx, c, "k", "owner-A", future); ok {
		t.Error("stale owner-A extended a claim it no longer owns")
	}
	_ = ReleaseIdempotencyKey(ctx, c, "k", "owner-A")
	rec, _ := GetIdempotencyRecord(ctx, c, "k")
	if rec == nil || rec.ClaimID != "owner-B" || rec.Status != IdempotencyInProgress {
		t.Fatalf("after stale-owner ops, record = %+v; want owner-B still in_progress", rec)
	}

	// The real owner-B can extend (heartbeat) while in_progress, then complete.
	if ok, _ := ExtendIdempotencyClaim(ctx, c, "k", "owner-B", future); !ok {
		t.Error("owner-B extend should succeed")
	}
	if ok, err := CompleteIdempotencyKey(ctx, c, "k", "owner-B", "resp-B", future); err != nil || !ok {
		t.Errorf("owner-B complete = %v,%v; want ok", ok, err)
	}
}

func TestReleaseIdempotencyKey_OnlyInProgressAndOwned(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)

	if claimed, _, _ := ClaimIdempotencyKey(ctx, c, "k", "own", "m", "h", future); !claimed {
		t.Fatal("initial claim should succeed")
	}
	// Release the in-progress claim (op failed) → the key is claimable again.
	if err := ReleaseIdempotencyKey(ctx, c, "k", "own"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if claimed, _, _ := ClaimIdempotencyKey(ctx, c, "k", "own2", "m", "h", future); !claimed {
		t.Error("after release, the key must be re-claimable")
	}
	// Release must NOT delete a completed record.
	_, _ = CompleteIdempotencyKey(ctx, c, "k", "own2", "done", future)
	_ = ReleaseIdempotencyKey(ctx, c, "k", "own2")
	if rec, _ := GetIdempotencyRecord(ctx, c, "k"); rec == nil || rec.Status != IdempotencyCompleted {
		t.Error("release must not remove a completed record")
	}
}

func TestReapExpiredIdempotencyKeys(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	_, _, _ = ClaimIdempotencyKey(ctx, c, "old", "o1", "m", "h", past)
	_, _, _ = ClaimIdempotencyKey(ctx, c, "new", "o2", "m", "h", future)

	n, err := ReapExpiredIdempotencyKeys(ctx, c)
	if err != nil || n != 1 {
		t.Fatalf("reap = %d,%v; want 1 (only the expired record)", n, err)
	}
	if rec, _ := GetIdempotencyRecord(ctx, c, "new"); rec == nil {
		t.Error("unexpired record must survive")
	}
}
