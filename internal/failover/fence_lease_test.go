package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// seedLease writes the failover lease with an explicit holder and expiry.
func seedLease(t *testing.T, db *corrosion.Client, holder string, expiresAt time.Time) {
	t.Helper()
	exp := expiresAt.UTC().Format(time.RFC3339)
	if err := db.Execute(context.Background(),
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET holder = excluded.holder,
		   expires_at = excluded.expires_at, updated_at = excluded.updated_at`,
		holder, exp, exp); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
}

func leaseHolder(t *testing.T, db *corrosion.Client) string {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT holder FROM leader_election WHERE key = 'failover'`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read lease: %v", err)
	}
	return rows[0].String("holder")
}

func fenceLogCount(t *testing.T, db *corrosion.Client, host string) int {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT id FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		t.Fatalf("read fencing_log: %v", err)
	}
	return len(rows)
}

// TestHoldLeaseAtLeast_RenewsWhenShortOfNeed pins why holdLeaseAtLeast exists.
//
// holdLease returns true whenever more than leaseRenewBefore remains, WITHOUT
// renewing — so its floor is leaseRenewBefore (10s), which is less than an IPMI
// power-off verification takes. A caller that treats that true as "I have the
// lease for a while" can run past expiry. holdLeaseAtLeast must renew to reach
// the head-room the caller actually asked for.
func TestHoldLeaseAtLeast_RenewsWhenShortOfNeed(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }

	// Ours, but only 12s left: more than leaseRenewBefore (so plain holdLease
	// would say yes and not renew) yet short of minFenceLease.
	seedLease(t, db, "me", now.Add(12*time.Second))
	if 12*time.Second <= leaseRenewBefore || 12*time.Second >= minFenceLease {
		t.Fatalf("test fixture no longer sits between leaseRenewBefore (%s) and minFenceLease (%s)",
			leaseRenewBefore, minFenceLease)
	}

	remaining, ok := c.holdLeaseAtLeast(context.Background(), minFenceLease)
	if !ok {
		t.Fatal("holdLeaseAtLeast refused a lease it could have renewed")
	}
	if remaining < minFenceLease {
		t.Errorf("remaining = %s, want at least minFenceLease %s — it reported head-room it does not have",
			remaining, minFenceLease)
	}
}

// TestHoldLeaseAtLeast_RefusesForeignLease pins that head-room never overrides
// ownership: refusing to start is the safe direction.
func TestHoldLeaseAtLeast_RefusesForeignLease(t *testing.T) {
	db := newTestDB(t)
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	seedLease(t, db, "other", now.Add(time.Hour))

	if _, ok := c.holdLeaseAtLeast(context.Background(), minFenceLease); ok {
		t.Error("holdLeaseAtLeast approved a lease held by another coordinator")
	}
}

// TestFailover_FenceIsBoundedByTheLease pins that the fence's deadline comes
// from the lease actually held, not from a constant. Nothing renews the lease
// while the fencer blocks (run() is synchronous inside the ticker), so a fence
// permitted to outlive it lets a second coordinator fence the same host.
func TestFailover_FenceIsBoundedByTheLease(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	seedLease(t, db, "me", now.Add(leaseDuration))

	var gotDeadline time.Time
	var hadDeadline bool
	c.SetFencer(func(fctx context.Context, h fence.HostConfig) fence.Result {
		gotDeadline, hadDeadline = fctx.Deadline()
		return fence.Result{Method: "test", Detail: "stub", Success: true}
	})

	h, _ := corrosion.GetHost(ctx, db, "h1")
	c.failover(ctx, h)

	if !hadDeadline {
		t.Fatal("the fencer ran on a context with NO deadline — an unbounded fence can outlive the lease")
	}
	// The deadline is derived from real wall-clock remaining lease, so compare
	// against a budget rather than the injected clock: it must be at most
	// (lease head-room - margin) and clearly bounded.
	budget := time.Until(gotDeadline)
	if budget > leaseDuration-leaseFenceMargin {
		t.Errorf("fence budget %s exceeds the lease minus its margin (%s)",
			budget, leaseDuration-leaseFenceMargin)
	}
	if budget <= 0 {
		t.Errorf("fence budget %s leaves no time to fence", budget)
	}
}

// TestFailover_LeaseLostDuringFence_DoesNotReschedule is the load-bearing guard.
//
// The fence is bounded by the lease, but it can still end with the lease gone (a
// slow fence, a clock jump, a peer taking over). Everything after it — host
// state, placement, reschedule proofs, container relocation — is the half that
// must not run twice, and gate.go states the property as
// "holdLease() && DecisionGate.OK". Without a post-fence re-check, two
// coordinators can each recover the same host.
//
// The fence_log row must SURVIVE: it records what physically happened to the
// host, which is true regardless of who holds the lease.
func TestFailover_LeaseLostDuringFence_DoesNotReschedule(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	seedLease(t, db, "me", now.Add(leaseDuration))

	// The fence succeeds, but by the time it returns another coordinator holds
	// the lease — exactly the race a fence longer than its lease opens.
	c.SetFencer(func(fctx context.Context, h fence.HostConfig) fence.Result {
		seedLease(t, db, "other", now.Add(leaseDuration))
		return fence.Result{Method: "ipmi", Detail: "powered off", Success: true}
	})

	h, _ := corrosion.GetHost(ctx, db, "h1")
	c.failover(ctx, h)

	if got := leaseHolder(t, db); got != "other" {
		t.Fatalf("fixture failed: lease holder = %q, want other", got)
	}

	// The audit fact is kept.
	if n := fenceLogCount(t, db, "h1"); n != 1 {
		t.Errorf("fencing_log rows for h1 = %d, want 1 — the power-off happened and must be recorded", n)
	}

	// The recovery half must NOT have run.
	after, _ := corrosion.GetHost(ctx, db, "h1")
	if after == nil {
		t.Fatal("host disappeared")
	}
	if after.State != "active" {
		t.Errorf("host state = %q, want unchanged \"active\": the coordinator recovered a host "+
			"after losing the lease, so a second coordinator can do it concurrently", after.State)
	}
}
