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
	claimed, existing, err := ClaimIdempotencyKey(ctx, c, "k1", "CreateVM", "h1", future)
	if err != nil || !claimed || existing != nil {
		t.Fatalf("first claim = %v,%v,%v; want claimed", claimed, existing, err)
	}
	// A concurrent claim (still in_progress) does NOT acquire and reports the live claim.
	claimed, existing, err = ClaimIdempotencyKey(ctx, c, "k1", "CreateVM", "h1", future)
	if err != nil || claimed || existing == nil {
		t.Fatalf("second claim = %v,%v,%v; want not-claimed + existing", claimed, existing, err)
	}
	if existing.Status != IdempotencyInProgress {
		t.Errorf("status = %q, want in_progress", existing.Status)
	}
	// Complete it; a later claim now sees the completed record + response.
	if err := CompleteIdempotencyKey(ctx, c, "k1", "resp-A", future); err != nil {
		t.Fatalf("complete: %v", err)
	}
	_, existing, _ = ClaimIdempotencyKey(ctx, c, "k1", "CreateVM", "h1", future)
	if existing == nil || existing.Status != IdempotencyCompleted || existing.Response != "resp-A" {
		t.Errorf("after complete = %+v; want completed/resp-A", existing)
	}
}

func TestClaimIdempotencyKey_ReleaseAndReclaim(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)

	if claimed, _, _ := ClaimIdempotencyKey(ctx, c, "k", "m", "h", future); !claimed {
		t.Fatal("initial claim should succeed")
	}
	// Release the in-progress claim (op failed) → the key is claimable again.
	if err := ReleaseIdempotencyKey(ctx, c, "k"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if claimed, _, _ := ClaimIdempotencyKey(ctx, c, "k", "m", "h", future); !claimed {
		t.Error("after release, the key must be re-claimable")
	}
	// Release must NOT delete a completed record.
	_ = CompleteIdempotencyKey(ctx, c, "k", "done", future)
	_ = ReleaseIdempotencyKey(ctx, c, "k")
	if rec, _ := GetIdempotencyRecord(ctx, c, "k"); rec == nil || rec.Status != IdempotencyCompleted {
		t.Error("release must not remove a completed record")
	}
}

func TestClaimIdempotencyKey_StealsExpired(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)

	// A crashed in-progress claim whose lease has lapsed...
	if claimed, _, _ := ClaimIdempotencyKey(ctx, c, "k", "m", "h", past); !claimed {
		t.Fatal("seed claim")
	}
	// ...is stolen by the next claimant rather than blocking it.
	claimed, existing, err := ClaimIdempotencyKey(ctx, c, "k", "m", "h", future)
	if err != nil || !claimed || existing != nil {
		t.Fatalf("expired claim should be stealable: %v,%v,%v", claimed, existing, err)
	}
}

func TestReapExpiredIdempotencyKeys(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	_, _, _ = ClaimIdempotencyKey(ctx, c, "old", "m", "h", past)
	_, _, _ = ClaimIdempotencyKey(ctx, c, "new", "m", "h", future)

	n, err := ReapExpiredIdempotencyKeys(ctx, c)
	if err != nil || n != 1 {
		t.Fatalf("reap = %d,%v; want 1 (only the expired record)", n, err)
	}
	if rec, _ := GetIdempotencyRecord(ctx, c, "new"); rec == nil {
		t.Error("unexpired record must survive")
	}
}
