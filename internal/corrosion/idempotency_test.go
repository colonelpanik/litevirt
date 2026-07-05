package corrosion

import (
	"context"
	"testing"
	"time"
)

func TestIdempotencyRecord_PutGetFirstWriterWins(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)

	if err := PutIdempotencyRecord(ctx, c, IdempotencyRecord{
		Key: "k1", Method: "CreateVM", RequestHash: "h1", Response: "resp-A", ExpiresAt: future,
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Second write with the same key must NOT overwrite (first writer wins).
	if err := PutIdempotencyRecord(ctx, c, IdempotencyRecord{
		Key: "k1", Method: "CreateVM", RequestHash: "h1", Response: "resp-B", ExpiresAt: future,
	}); err != nil {
		t.Fatalf("Put 2: %v", err)
	}
	got, err := GetIdempotencyRecord(ctx, c, "k1")
	if err != nil || got == nil {
		t.Fatalf("Get: %v, %v", got, err)
	}
	if got.Response != "resp-A" {
		t.Errorf("response = %q, want the original resp-A (first writer wins)", got.Response)
	}
	if got.Method != "CreateVM" || got.RequestHash != "h1" {
		t.Errorf("unexpected record: %+v", got)
	}
	// Absent key → nil, no error.
	if r, err := GetIdempotencyRecord(ctx, c, "nope"); err != nil || r != nil {
		t.Errorf("absent key = %v, %v; want nil, nil", r, err)
	}
}

func TestReapExpiredIdempotencyKeys(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	_ = PutIdempotencyRecord(ctx, c, IdempotencyRecord{Key: "old", Method: "m", RequestHash: "h", ExpiresAt: past})
	_ = PutIdempotencyRecord(ctx, c, IdempotencyRecord{Key: "new", Method: "m", RequestHash: "h", ExpiresAt: future})

	n, err := ReapExpiredIdempotencyKeys(ctx, c)
	if err != nil {
		t.Fatalf("reap: %v", err)
	}
	if n != 1 {
		t.Errorf("reaped %d, want 1 (only the expired record)", n)
	}
	if r, _ := GetIdempotencyRecord(ctx, c, "old"); r != nil {
		t.Error("expired record should be gone")
	}
	if r, _ := GetIdempotencyRecord(ctx, c, "new"); r == nil {
		t.Error("unexpired record must survive")
	}
}
