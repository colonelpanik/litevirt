package corrosion

import (
	"context"
	"testing"
	"time"
)

// A renewal must never report a term the ledger has already superseded.
//
// The race: this caller classifies the lease as its own live tenure at term N
// and stalls. The lease lapses, a sibling rebalancer caller on the SAME host
// re-takes it and mints N+1. This caller resumes and renews — which the
// unguarded renewal allows, because the row still names the same holder — and
// returns N. Its caller then stamps work with a superseded term and every
// executor refuses it as stale.
func TestAcquireLeaseWithTerm_NeverReturnsASupersededTerm(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	const key, holder = "failover", "host-a"
	now := time.Now().UTC()

	// An established tenure at term 1.
	held, term, err := AcquireLeaseWithTerm(ctx, c, key, holder, time.Minute, now)
	if err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	if !held || term != 1 {
		t.Fatalf("initial acquire: held=%v term=%d, want true/1", held, term)
	}

	// The sibling: fires once, while this caller is stalled between classifying
	// the lease at term 1 and committing its renewal. It does what a real
	// sibling caller does after the lease lapses — re-takes it and mints the
	// next term under the same holder.
	fired := false
	renewClassifiedHook = func() {
		if fired {
			return
		}
		fired = true
		stamp := time.Now().UTC().Format(time.RFC3339)
		if err := c.execLocal(ctx,
			`INSERT INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			key, int64(2), holder, stamp, stamp, c.NowTS()); err != nil {
			t.Fatalf("sibling mint: %v", err)
		}
	}
	defer func() { renewClassifiedHook = nil }()

	held, term, err = AcquireLeaseWithTerm(ctx, c, key, holder, time.Minute, now.Add(time.Second))
	if err != nil {
		t.Fatalf("renewal: %v", err)
	}
	if !held {
		t.Fatal("renewal reported the lease not held; this node does hold it")
	}
	if term == 1 {
		t.Fatal("renewal returned term 1, which the ledger superseded with term 2 while " +
			"this caller was classifying — work stamped with it is refused as stale by every " +
			"executor, on a node that holds the lease perfectly well")
	}
	if term != 2 {
		t.Errorf("term = %d, want 2 (the term the ledger actually holds)", term)
	}
}

// The ordinary renewal still works and must NOT bump the term: a renewal that
// minted would make the holder invalidate its own in-flight work every interval.
func TestAcquireLeaseWithTerm_APlainRenewalKeepsItsTerm(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	const key, holder = "failover", "host-a"
	now := time.Now().UTC()
	if _, term, err := AcquireLeaseWithTerm(ctx, c, key, holder, time.Minute, now); err != nil {
		t.Fatalf("acquire: %v", err)
	} else if term != 1 {
		t.Fatalf("acquire term = %d, want 1", term)
	}

	held, term, err := AcquireLeaseWithTerm(ctx, c, key, holder, time.Minute, now.Add(time.Second))
	if err != nil {
		t.Fatalf("renew: %v", err)
	}
	if !held {
		t.Fatal("a plain renewal of our own live tenure reported not-held")
	}
	if term != 1 {
		t.Errorf("term = %d, want 1: a renewal must not mint", term)
	}
}

// A tenure that fully LAPSED is a new tenure, even when the same holder takes it
// back and no peer ever minted anything. The lapse is precisely the window other
// nodes were entitled to act in, so renewing across it would make work from
// before it indistinguishable from work after it — which is the reasoning
// AcquireLeaseWithTerm's own classification already follows, and why the
// renewal's guard checks expiry and not just holder identity.
func TestAcquireLeaseWithTerm_ALapsedTenureIsNotRenewedAcross(t *testing.T) {
	ctx := context.Background()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	const key, holder = "failover", "host-a"
	now := time.Now().UTC()
	if _, term, err := AcquireLeaseWithTerm(ctx, c, key, holder, time.Minute, now); err != nil {
		t.Fatalf("acquire: %v", err)
	} else if term != 1 {
		t.Fatalf("acquire term = %d, want 1", term)
	}

	// The lease lapses while this caller is stalled mid-classification. Nobody
	// else takes it; the ledger still reads term 1.
	fired := false
	renewClassifiedHook = func() {
		if fired {
			return
		}
		fired = true
		if err := c.execLocal(ctx,
			`UPDATE leader_election SET expires_at = ? WHERE key = ?`,
			now.Add(-time.Hour).Format(time.RFC3339), key); err != nil {
			t.Fatalf("lapse the lease: %v", err)
		}
	}
	defer func() { renewClassifiedHook = nil }()

	held, term, err := AcquireLeaseWithTerm(ctx, c, key, holder, time.Minute, now.Add(time.Second))
	if err != nil {
		t.Fatalf("re-acquire after the lapse: %v", err)
	}
	if !held {
		t.Fatal("the lease was not held after re-taking a lapsed tenure")
	}
	if term == 1 {
		t.Fatal("the renewal carried term 1 across a full lapse — work from before the " +
			"lapse is now indistinguishable from work after it, in exactly the window other " +
			"nodes were entitled to act")
	}
	if term != 2 {
		t.Errorf("term = %d, want 2: re-taking a lapsed lease is a new tenure and mints", term)
	}
}
