package corrosion

import (
	"context"
	"errors"
	"testing"
)

func TestProjectAuthority_ClaimAndTakeover(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	// Initial claim by node-a → epoch 1.
	applied, err := ClaimInitialProjectAuthority(ctx, db, "acme", "node-a")
	if err != nil || !applied {
		t.Fatalf("initial claim: applied=%v err=%v", applied, err)
	}
	// A second claim (node-b) must NOT succeed — authority already exists.
	if applied, _ := ClaimInitialProjectAuthority(ctx, db, "acme", "node-b"); applied {
		t.Fatal("second initial claim should not succeed")
	}
	cur, ok, err := CurrentProjectAuthority(ctx, db, "acme")
	if err != nil || !ok || cur.Epoch != 1 || cur.Holder != "node-a" {
		t.Fatalf("current = %+v ok=%v err=%v, want epoch1/node-a", cur, ok, err)
	}

	// Planned handoff to node-b → epoch 2.
	ep, applied, err := TakeoverProjectAuthority(ctx, db, "acme", "node-b", "planned", "", 1)
	if err != nil || !applied || ep != 2 {
		t.Fatalf("planned takeover: ep=%d applied=%v err=%v", ep, applied, err)
	}
	// The old holder/epoch is now stale.
	if okA, _ := ValidateProjectAuthority(ctx, db, "acme", 1, "node-a"); okA {
		t.Error("stale epoch-1/node-a must not validate")
	}
	if okB, _ := ValidateProjectAuthority(ctx, db, "acme", 2, "node-b"); !okB {
		t.Error("current epoch-2/node-b must validate")
	}

	// A CAS miss (wrong expected prev) → not applied.
	if _, applied, _ := TakeoverProjectAuthority(ctx, db, "acme", "node-c", "planned", "", 1); applied {
		t.Error("takeover with a stale expected-prev epoch must not apply")
	}
}

func TestProjectAuthority_FencedRequiresProof(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := ClaimInitialProjectAuthority(ctx, db, "acme", "node-a"); err != nil {
		t.Fatalf("claim: %v", err)
	}

	// Unplanned takeover with no proof → refused.
	if _, _, err := TakeoverProjectAuthority(ctx, db, "acme", "node-b", "fenced", "", 1); !errors.Is(err, ErrFenceProofRequired) {
		t.Fatalf("fenced takeover without proof: want ErrFenceProofRequired, got %v", err)
	}
	// With a proof → epoch 2.
	ep, applied, err := TakeoverProjectAuthority(ctx, db, "acme", "node-b", "fenced", "fencing_log:xyz", 1)
	if err != nil || !applied || ep != 2 {
		t.Fatalf("fenced takeover with proof: ep=%d applied=%v err=%v", ep, applied, err)
	}
}
