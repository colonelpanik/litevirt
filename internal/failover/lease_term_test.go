package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedLeaseTerm writes a term row for the failover lease as though another host
// had minted it, which is what makes it the REJECTION THRESHOLD this coordinator
// is judged against (corrosion.CurrentLeaseTerm reads the highest live term).
func seedLeaseTerm(t *testing.T, db *corrosion.Client, term int64, holder string) {
	t.Helper()
	ts := time.Now().UTC().Format(time.RFC3339)
	if err := db.Execute(context.Background(),
		`INSERT OR IGNORE INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		failoverLeaseKey, term, holder, ts, ts, db.NowTS()); err != nil {
		t.Fatalf("seed term %d for %s: %v", term, holder, err)
	}
}

// TestCoordinator_AcquireRecordsLeaseTerm: a successful acquire must leave a
// non-zero fencing term on the coordinator.
//
// This exists because Phase 1 only RECORDS the term — nothing enforces on it
// yet — so without an assertion the store is unobservable and could be dropped
// silently, leaving Phase 2 to read a permanent zero. Terms start at 1
// precisely so that 0 stays distinguishable from a real acquisition.
func TestCoordinator_AcquireRecordsLeaseTerm(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }

	if got := c.LeaseTerm(); got != 0 {
		t.Fatalf("term before any acquire = %d, want 0", got)
	}
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	if got := c.LeaseTerm(); got <= 0 {
		t.Fatalf("term after a successful acquire = %d, want > 0 — the term is "+
			"recorded nowhere observable, so Phase 2 has nothing to read", got)
	}
}

// TestCoordinator_NonLeaderHasNoTerm: losing the lease must clear the term
// rather than leave a stale one behind.
//
// A term is only meaningful to its holder. A coordinator that kept its previous
// number after being displaced would carry a token it no longer owns into the
// Phase-2 enforcement path.
func TestCoordinator_NonLeaderHasNoTerm(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	if c.LeaseTerm() == 0 {
		t.Fatal("expected a term after acquiring")
	}

	// Another host takes it with a lease valid well past our clock.
	valid := now.Add(time.Hour).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', 'other', ?, ?)
		 ON CONFLICT(key) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at`, valid, valid); err != nil {
		t.Fatalf("hand the lease to another host: %v", err)
	}

	if c.acquireLease(ctx) {
		t.Fatal("must not take a lease another host holds validly")
	}
	if got := c.LeaseTerm(); got != 0 {
		t.Errorf("term after losing the lease = %d, want 0 — a displaced "+
			"coordinator must not keep a token it no longer holds", got)
	}
}

// TestCoordinator_RenewalKeepsItsOwnTerm: renewing must NOT mint a new term.
//
// acquireLease is the renewal path too (holdLease calls it), so a mint on every
// call would make the holder invalidate its own in-flight work once per renewal
// interval — which would defeat the entire point of a fencing token.
func TestCoordinator_RenewalKeepsItsOwnTerm(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	first := c.LeaseTerm()

	for i := 0; i < 3; i++ {
		if !c.acquireLease(ctx) {
			t.Fatalf("renewal %d must succeed", i)
		}
		if got := c.LeaseTerm(); got != first {
			t.Fatalf("renewal %d changed the term %d -> %d; a renewal that mints "+
				"makes the holder fence its own in-flight work", i, first, got)
		}
	}
}

// TestCoordinator_LeaseUsesInjectedClockAndDuration pins BOTH the coordinator's
// clock and its TTL, which the shared helper takes as parameters.
//
// The clock half matters because the fleet harness overrides Now with a virtual
// clock to advance past lease expiry without sleeping; passing time.Now() into
// the shared helper instead would break those scenarios in a way that a
// takeover test with a past-dated clock only catches by accident. The TTL half
// matters because leaseDuration is sized against worst-case fence latency, and
// the other two consumers deliberately use different TTLs through the same
// helper — so a copy-paste of the wrong one is exactly the plausible mistake.
func TestCoordinator_LeaseUsesInjectedClockAndDuration(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	// Deliberately NOT near the real clock, in either direction.
	now := time.Date(2031, 3, 14, 1, 59, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}

	rows, err := db.Query(ctx,
		`SELECT expires_at FROM leader_election WHERE key = ?`, failoverLeaseKey)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read lease: %v", err)
	}
	want := now.Add(leaseDuration).UTC().Format(time.RFC3339)
	if got := rows[0].String("expires_at"); got != want {
		t.Errorf("expires_at = %q, want %q — the lease must expire at "+
			"c.now()+leaseDuration, not on the wall clock or another consumer's TTL",
			got, want)
	}
}

// TestCoordinator_StampsItsOwnTermNotTheLedgerMaximum is the invariant Phase 1
// closed and this task must not reopen.
//
// A displaced holder A can receive the winner B's higher term row while A's
// leader_election row still names A — the two tables replicate independently. If
// the stamp read the ledger MAXIMUM, A would stamp fresh proofs with B's term and
// sail through the executor's equal-term check without ever having acquired that
// incarnation. The term must come from what this coordinator recorded at
// acquisition, and from nowhere else.
func TestCoordinator_StampsItsOwnTermNotTheLedgerMaximum(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	mine := c.LeaseTerm()
	if mine <= 0 {
		t.Fatalf("term after a successful acquire = %d; the rest of this test is vacuous", mine)
	}

	// A peer's higher term lands in the ledger. Our lease row still names us.
	seedLeaseTerm(t, db, mine+5, "node-b")

	_, _, term, ok := c.leaseStamp(ctx)
	if !ok {
		t.Fatal("leaseStamp refused while enforcement is off")
	}
	if term == mine+5 {
		t.Fatalf("stamped the ledger MAXIMUM (%d) rather than this coordinator's own term — a "+
			"displaced holder would stamp the winner's term and pass the executor's check", mine+5)
	}
	if term != mine {
		t.Errorf("stamped term %d, want this coordinator's own %d", term, mine)
	}
}

// TestCoordinator_LeaseTermStampAllowed covers the local precheck across the
// whole (flag, latch, own term, threshold) space.
//
// The two cases that matter most are the ones where the flag is set but the
// token has NOT latched. Enforcement in this family is always `flag AND
// Enforced(token)` — see grpcapi's leaseTermEnforced, which is the executor half
// of this exact decision. An operator sets enforcement.lease_term ahead of the
// latch during a roll, by design, and pre-latch a perfectly healthy leader holds
// term 0 because the ledger mint gate is still closed. A precheck that refused on
// the flag alone would abandon every reschedule and relocation on every node for
// the whole rollout, while the executor accepted term-0 proofs happily — all
// cost, no safety.
func TestCoordinator_LeaseTermStampAllowed(t *testing.T) {
	cases := []struct {
		name      string
		flag      bool
		latched   bool
		nilGate   bool
		ownTerm   int64
		ledgerMax int64
		want      bool
	}{
		{name: "pre-latch holder, flag off: no term exists and none is required",
			flag: false, latched: false, ownTerm: 0, ledgerMax: 0, want: true},
		{name: "pre-latch holder, flag ON: term 0 is correct, not stale",
			flag: true, latched: false, ownTerm: 0, ledgerMax: 0, want: true},
		{name: "flag ON but unlatched: the flag alone must not enforce",
			flag: true, latched: false, ownTerm: 1, ledgerMax: 6, want: true},
		{name: "latched but flag off: the kill switch still works",
			flag: false, latched: true, ownTerm: 1, ledgerMax: 6, want: true},
		{name: "nil gate: fail open like the rest of the family",
			flag: true, nilGate: true, ownTerm: 1, ledgerMax: 6, want: true},
		{name: "enforcing, current holder",
			flag: true, latched: true, ownTerm: 6, ledgerMax: 6, want: true},
		{name: "enforcing, our term above the threshold we can see",
			flag: true, latched: true, ownTerm: 7, ledgerMax: 6, want: true},
		{name: "enforcing, superseded",
			flag: true, latched: true, ownTerm: 1, ledgerMax: 6, want: false},
		{name: "enforcing, no recorded term",
			flag: true, latched: true, ownTerm: 0, ledgerMax: 6, want: false},
		// Isolates the term <= 0 guard, which the threshold compare cannot cover:
		// with an empty ledger the threshold is 0 too, so `term < threshold` is
		// false and only the explicit guard refuses. The state is reachable — a
		// coordinator holding a lease it acquired PRE-latch has term 0, and post
		// latch it keeps that 0 until its next renewal mints one — and enforcing
		// with no token is precisely the unfenced write the term exists to stop.
		{name: "enforcing, no term anywhere: the guard the threshold cannot replace",
			flag: true, latched: true, ownTerm: 0, ledgerMax: 0, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			ctx := context.Background()
			c := NewCoordinator("me", db)
			c.LeaseTermEnforce = tc.flag
			if !tc.nilGate {
				c.Gate = fakeFailoverGate{enforced: map[string]bool{capabilities.LeaseTermV1: tc.latched}}
			}
			c.leaseTerm.Store(tc.ownTerm)
			if tc.ledgerMax > 0 {
				seedLeaseTerm(t, db, tc.ledgerMax, "node-b")
			}
			if got := c.leaseTermStampAllowed(ctx); got != tc.want {
				t.Errorf("leaseTermStampAllowed = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCoordinator_PreLatchHolderStampsRatherThanStandingDown drives the real
// pre-latch state rather than simulating it: with the ledger mint gate closed,
// AcquireLeaseWithTerm takes the lease and reports NO term.
//
// This is the mid-rolling-upgrade state on every node, and the operator is
// expected to have set enforcement.lease_term ahead of the latch. If the
// coordinator treats term 0 as "stale" here it stands down from every action it
// coordinates, cluster-wide, for the duration of the roll — the same
// failover-stops-entirely outcome as an unstamped proof, reached from the
// opposite direction.
func TestCoordinator_PreLatchHolderStampsRatherThanStandingDown(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	// A peer is still on a build that cannot resolve the mint's statement shape.
	db.SetLeaseTermLedgerGate(func() bool { return false })

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	c.LeaseTermEnforce = true
	c.Gate = fakeFailoverGate{enforced: map[string]bool{capabilities.LeaseTermV1: false}}

	if !c.acquireLease(ctx) {
		t.Fatal("a pre-latch coordinator must still take the lease")
	}
	if got := c.LeaseTerm(); got != 0 {
		t.Fatalf("pre-latch term = %d, want 0 — this test's premise is that no term is minted", got)
	}

	_, _, term, ok := c.leaseStamp(ctx)
	if !ok {
		t.Fatal("a healthy pre-latch leader was refused permission to stamp. With the ledger gate " +
			"closed no term is minted, so term 0 is the CORRECT state; refusing here abandons every " +
			"reschedule and relocation on every node for the whole rollout, and the executor is not " +
			"enforcing yet, so nothing is gained")
	}
	if term != 0 {
		t.Errorf("stamped term %d pre-latch, want 0 — a term that was never minted must not be invented", term)
	}
}

// TestCoordinator_StampDoesNotFabricateAHolder: the proof's LeaseHolder must come
// from the lease row, never from this process's own identity.
//
// Two of the three stamp sites used to write LeaseHolder: c.hostName, which
// asserts "I hold the lease" on the authority of the node making the claim —
// precisely the assertion a fencing term exists to stop trusting. leaseSnapshot
// deliberately returns empty when it cannot read the row, so blank is a correct
// value on a valid proof and self-reporting is not.
func TestCoordinator_StampDoesNotFabricateAHolder(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	// The lease row is unreadable at stamp time.
	if err := db.Execute(ctx, `DELETE FROM leader_election WHERE key = ?`, failoverLeaseKey); err != nil {
		t.Fatalf("clear the lease row: %v", err)
	}

	holder, _, _, ok := c.leaseStamp(ctx)
	if !ok {
		t.Fatal("leaseStamp refused while enforcement is off")
	}
	if holder == c.hostName {
		t.Errorf("stamped LeaseHolder = %q from this process's own identity — the proof asserts "+
			"'I hold the lease' on the authority of the node making the claim, which is the "+
			"assertion the fencing term exists to stop trusting", holder)
	}
	if holder != "" {
		t.Errorf("stamped holder = %q, want empty (unknown)", holder)
	}
}

// TestCoordinator_RefusesToRescheduleWhenSuperseded: the precheck reaches the
// reschedule site, so a superseded coordinator abandons the action instead of
// writing a proof the executor will refuse anyway.
// Note the window this drives, because it is narrower than it first looks.
// AcquireLeaseWithTerm ALREADY fails closed when a peer's term is newer than
// ours while our lease row still names us — it returns no term, so the whole tick
// stands down and never reaches a stamp site. The precheck therefore covers the
// case the lease layer cannot: the peer's term row arriving mid-cycle, after
// holdLease has already passed. So this seeds the higher term after acquisition
// and drives the failover path directly, rather than through run().
//
// The superseded case is paired with a positive control on purpose. Asserting
// "no proof was written" alone would pass just as well if failover never reached
// the stamp site for some unrelated reason, which would make the test prove
// nothing.
func TestCoordinator_RefusesToRescheduleWhenSuperseded(t *testing.T) {
	setup := func(t *testing.T) (*corrosion.Client, *Coordinator, *corrosion.HostRecord) {
		t.Helper()
		db := newTestDB(t)
		ctx := context.Background()
		for _, h := range []string{"dead", "live"} {
			if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
				Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
				GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
			}); err != nil {
				t.Fatalf("InsertHost %s: %v", h, err)
			}
		}
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: "vm1", HostName: "dead", State: "running",
			Spec: `{"on_host_failure":"restart-any"}`,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
		fenceQuorum(t, ctx, db, []string{"coord", "live"}, "dead")

		c := newTestCoordinator("coord", db)
		c.LeaseTermEnforce = true
		c.Gate = fakeFailoverGate{
			supports: map[string]bool{"live": true},
			enforced: map[string]bool{
				capabilities.SplitBrainGateV1: true,
				capabilities.LeaseTermV1:      true,
			},
		}
		if !c.acquireLease(ctx) {
			t.Fatal("must acquire an unheld lease")
		}
		if c.LeaseTerm() <= 0 {
			t.Fatal("no term after acquiring; the rest of this test is vacuous")
		}
		dead, err := corrosion.GetHost(ctx, db, "dead")
		if err != nil || dead == nil {
			t.Fatalf("GetHost dead: %v", err)
		}
		return db, c, dead
	}

	proofCount := func(t *testing.T, db *corrosion.Client) int {
		t.Helper()
		rows, err := db.Query(context.Background(),
			`SELECT id FROM runtime_action_proofs WHERE target_name = 'vm1'`)
		if err != nil {
			t.Fatalf("read proofs: %v", err)
		}
		return len(rows)
	}

	t.Run("current term stamps a proof", func(t *testing.T) {
		db, c, dead := setup(t)
		c.failover(context.Background(), dead)
		if got := proofCount(t, db); got != 1 {
			t.Fatalf("proof rows = %d, want 1. This is the positive control: without it the "+
				"superseded case below could pass for the wrong reason", got)
		}
	})

	t.Run("superseded term writes nothing", func(t *testing.T) {
		db, c, dead := setup(t)
		// The peer's term lands after our renewal, inside the cycle.
		seedLeaseTerm(t, db, c.LeaseTerm()+499, "node-b")
		c.failover(context.Background(), dead)
		if got := proofCount(t, db); got != 0 {
			t.Errorf("a superseded coordinator wrote %d reschedule proof(s); a coordinator whose "+
				"term a peer has taken must not mint fresh authority", got)
		}
	})
}

// TestCoordinator_ThresholdReadErrorFailsOpen: an unreadable threshold must NOT
// refuse the stamp.
//
// Every stamp site is past the fence — the host is powered off and persisted
// offline, and a fenced host is processed only once — so a refusal abandons the
// workload rather than deferring it. An unreadable threshold is no evidence this
// coordinator is superseded; the likely cause is a transient DB error on a
// perfectly current holder. Since the executor's barrier is the actual guarantee
// and runs either way, failing closed here trades a guaranteed stranded workload
// for a check that was never load-bearing.
func TestCoordinator_ThresholdReadErrorFailsOpen(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Date(2026, 6, 8, 12, 0, 0, 0, time.UTC)

	c := NewCoordinator("me", db)
	c.Now = func() time.Time { return now }
	c.LeaseTermEnforce = true
	c.Gate = fakeFailoverGate{enforced: map[string]bool{capabilities.LeaseTermV1: true}}
	if !c.acquireLease(ctx) {
		t.Fatal("must acquire an unheld lease")
	}
	mine := c.LeaseTerm()
	if mine <= 0 {
		t.Fatal("no term after acquiring; the rest of this test is vacuous")
	}

	// Make the threshold read fail. Dropping the ledger table is the cheapest
	// injection that leaves the lease row itself readable, so the failure is
	// isolated to the threshold query.
	if err := db.Execute(ctx, `DROP TABLE leader_lease_terms`); err != nil {
		t.Fatalf("drop the term ledger: %v", err)
	}
	if _, err := corrosion.CurrentLeaseTerm(ctx, db, failoverLeaseKey); err == nil {
		t.Fatal("threshold read still succeeds; this test is not injecting the error it claims to")
	}

	_, _, term, ok := c.leaseStamp(ctx)
	if !ok {
		t.Fatal("an unreadable threshold refused the stamp. The host is already fenced and is " +
			"processed only once, so this does not defer the reschedule — it abandons it, and the " +
			"VM stays assigned to a powered-off host. The executor's barrier still guards the " +
			"stale case, so refusing here buys nothing")
	}
	if term != mine {
		t.Errorf("stamped term %d, want this coordinator's own %d", term, mine)
	}
}

// TestContainerRelocationProofsCarryLeaseTerm gives each of the two container
// stamp sites its own red test.
//
// Both sites are reached through relocateContainers and differ only in which
// route the container takes: with a working Restorer it relocates from backup
// (startRelocation's proof, bound to the restore token), and without one it falls
// back to image-recreate (imageRecreateOrSkip's proof, bound to a fresh
// relocation token). Neither site had any assertion on its proof fields before
// this, so zeroing the term at either one was a silent change.
func TestContainerRelocationProofsCarryLeaseTerm(t *testing.T) {
	// relocate is deliberately NOT in leaseTermRequiredActions — mintRelocationProof
	// has no lease and legitimately stamps term 0 — so an unstamped proof here is
	// not refused outright. It is still wrong: the term is the only evidence of
	// WHICH tenure ordered the relocation, and a proof without it cannot be judged
	// against a competing one.
	cases := []struct {
		name        string
		withRestore bool
	}{
		{name: "restore-relocation site", withRestore: true},
		{name: "image-recreate site", withRestore: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, src, cands := relocateSetup(t, "alpine:3.19", corrosion.CurrentSchemaVersion)
			ctx := context.Background()
			c := newTestCoordinator("coord", db)
			c.Gate = fakeFailoverGate{
				supports: map[string]bool{"surv": true},
				enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
			}
			if tc.withRestore {
				c.Restorer = &fakeRestorer{db: db, outcome: corrosion.RestoreLanded}
			}
			if !c.acquireLease(ctx) {
				t.Fatal("must acquire an unheld lease")
			}
			mine := c.LeaseTerm()
			if mine <= 0 {
				t.Fatal("no term after acquiring; the rest of this case is vacuous")
			}

			c.relocateContainers(ctx, src, cands)

			rows, err := db.Query(ctx,
				`SELECT lease_term, lease_key FROM runtime_action_proofs
				 WHERE target_name = 'ct1' AND action = ?`, corrosion.ActionRelocate)
			if err != nil {
				t.Fatalf("read proofs: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("relocation proof rows = %d, want 1 — this case is not exercising its "+
					"stamp site", len(rows))
			}
			if got := rows[0].Int64("lease_term"); got != mine {
				t.Errorf("proof lease_term = %d, want %d (this coordinator's own recorded term)", got, mine)
			}
			if got := rows[0].String("lease_key"); got != corrosion.LeaseKeyFailover {
				t.Errorf("proof lease_key = %q, want %q — the three leases allocate terms "+
					"independently and their numbers collide by design, so a term without its "+
					"key cannot be judged against anything", got, corrosion.LeaseKeyFailover)
			}
		})
	}
}

// MUTATION RESULTS (2026-09-09). Every mutation below was applied to
// coordinator.go, run, and reverted. A passing test proves nothing until it has
// been seen to fail.
//
//	# | mutation                                          | outcome
//	--+---------------------------------------------------+------------------------------
//	1 | leaseStamp returns CurrentLeaseTerm() not         | KILLED StampsItsOwnTermNot-
//	  |   c.LeaseTerm()                                   |   TheLedgerMaximum
//	2 | drop the `term < threshold` refusal               | KILLED StampAllowed/superseded
//	  |                                                   |   + RefusesToReschedule/superseded
//	3 | drop the `term <= 0` guard                        | SURVIVED at first, then KILLED
//	4 | enforce on the flag alone, ignoring the latch     | KILLED StampAllowed × 3
//	5a| reschedule site: LeaseTerm -> 0                   | KILLED VMRescheduleProofCarries-
//	  |                                                   |   LeaseTerm
//	5b| restore-relocation site: LeaseTerm -> 0           | KILLED ContainerRelocation/restore
//	5c| image-recreate site: LeaseTerm -> 0               | KILLED ContainerRelocation/image
//	6 | leaseStamp returns c.hostName as the holder       | KILLED StampDoesNotFabricate-
//	  |                                                   |   AHolder
//	7 | hoist the `term <= 0` guard ABOVE the enforcement | KILLED StampAllowed × 2
//	  |   check (the implementation plan's own ordering)  |   + PreLatchHolderStamps
//	8 | threshold read failure returns false (fail        | KILLED ThresholdReadError-
//	  |   CLOSED) instead of true                         |   FailsOpen
//
// Mutation 3 is why this block exists. It SURVIVED the first run: the
// "no recorded term" case seeds a ledger maximum of 6, so `term < threshold`
// already refuses term 0 and the explicit guard is dead weight for that input.
// The guard is only load-bearing when the ledger is EMPTY — threshold 0, so the
// compare cannot fire — which is the post-latch window before the first mint.
// Adding "no term anywhere" killed it, and only that case goes red, which is the
// proof the other cases never covered the guard. The plan's mutation table had
// predicted this mutation would be caught by a test that could not have caught it.
//
// Mutation 8 exists because a two-codex crossexam found, and source confirmed,
// that every stamp site is reached AFTER the host has been fenced: c.fenced is
// set and the fencer has run, and the host row is persisted offline, all before
// the stamp. A fenced host is processed only once, so a refusal here abandons the
// workload instead of deferring it. That makes fail-closed on an unreadable
// threshold the wrong trade — it converts a transient DB blip into a VM stranded
// on a powered-off host, to protect a check that was never the guarantee.
//
// Mutation 7 is the ordering this task was written against. The plan put the
// `term <= 0` guard first, unconditionally, above any enforcement check. Pre-latch
// a healthy leader holds term 0 by design — AcquireLeaseWithTerm takes the lease
// and deliberately reports no term while the ledger gate is closed — so that
// ordering makes leaseStamp refuse on every node for the whole rollout, and every
// reschedule and relocation is abandoned. Note WHICH cases it kills: the flag-OFF
// pre-latch case dies too, because a guard above the enforcement check ignores the
// kill switch entirely. So the plan's version would have stopped failover
// cluster-wide even on nodes that had never opted in.
