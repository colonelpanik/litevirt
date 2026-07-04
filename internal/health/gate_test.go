package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func gateHost(t *testing.T, db *corrosion.Client, name, state, role string) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), db, corrosion.HostRecord{
		Name: name, Address: "10.0.0.9", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: state, Role: role, CertSerial: name,
	}); err != nil {
		t.Fatalf("InsertHost(%s): %v", name, err)
	}
}

// warm marks the checker past its warmup window and sets peer probe results as a
// real probe cycle would — including the lastHealthyAt/lastFailureAt monotonic
// anchors, since quorum counts a peer only on a restart-local fresh probe success
// (a healthy status alone, e.g. seeded from a stale DB row, must not count).
func warm(c *Checker, healthy map[string]bool) {
	c.mu.Lock()
	c.probedOnce = true
	c.startedAt = time.Now().Add(-time.Hour)
	mono := time.Now()
	for name, ok := range healthy {
		ps := &peerState{}
		if ok {
			ps.status = "healthy"
			ps.lastHealthyAt = mono
		} else {
			ps.status = "suspect"
			ps.lastFailureAt = mono
		}
		c.peers[name] = ps
	}
	c.mu.Unlock()
}

func TestQuorumProof_SelfCounting_WitnessMajority(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker") // self
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "wit-1", "active", "witness")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	// All reachable: self + b + witness = 3, needed = 3/2+1 = 2 → Yes.
	warm(c, map[string]bool{"host-b": true, "wit-1": true})
	if st, live, needed := c.QuorumProof(context.Background()); st != QuorumYes || live != 3 || needed != 2 {
		t.Fatalf("all-up: got state=%d live=%d needed=%d; want Yes/3/2", st, live, needed)
	}

	// Lose the worker peer: self + witness = 2 >= 2 → still Yes (witness counts).
	warm(c, map[string]bool{"host-b": false, "wit-1": true})
	if st, live, _ := c.QuorumProof(context.Background()); st != QuorumYes || live != 2 {
		t.Fatalf("worker-down: got state=%d live=%d; want Yes/2 (witness must count)", st, live)
	}

	// Lose the witness too: only self = 1 < 2 → No.
	warm(c, map[string]bool{"host-b": false, "wit-1": false})
	if st, live, _ := c.QuorumProof(context.Background()); st != QuorumNo || live != 1 {
		t.Fatalf("both-down: got state=%d live=%d; want No/1", st, live)
	}
}

// A peer whose status was SEEDED "healthy" from the host_health DB row at bootstrap
// (a restart) but has NOT been probed healthy THIS run (lastHealthyAt zero) must
// NOT count toward quorum — otherwise a just-restarted isolated node briefly
// regains quorum from stale pre-restart rows.
func TestQuorumProof_StaleSeededPeerNotCounted(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker") // self
	gateHost(t, db, "host-b", "active", "worker")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.mu.Lock()
	c.probedOnce = true
	c.startedAt = time.Now().Add(-time.Hour)
	// Simulate the checker.go bootstrap: status seeded healthy from the DB, but
	// lastHealthyAt is zero (no fresh in-run probe success yet).
	c.peers["host-b"] = &peerState{status: "healthy"}
	c.mu.Unlock()

	// denom = self + host-b = 2 → needed = 2. host-b is stale-seeded, so live =
	// self only = 1 < 2 → No (must NOT count the stale row).
	st, live, needed := c.QuorumProof(context.Background())
	if st != QuorumNo || live != 1 || needed != 2 {
		t.Fatalf("stale-seeded: got state=%d live=%d needed=%d; want No/1/2 — a DB-seeded healthy status must not count without a fresh probe", st, live, needed)
	}

	// Once a fresh probe lands (lastHealthyAt set), host-b counts → Yes.
	c.mu.Lock()
	c.peers["host-b"].lastHealthyAt = time.Now()
	c.mu.Unlock()
	if st, live, _ := c.QuorumProof(context.Background()); st != QuorumYes || live != 2 {
		t.Fatalf("after fresh probe: got state=%d live=%d; want Yes/2", st, live)
	}
}

func TestQuorumProof_Warmup(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-b", "active", "worker")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.mu.Lock()
	c.startedAt = time.Now() // fresh, no probe cycle yet
	c.mu.Unlock()
	if st, _, _ := c.QuorumProof(context.Background()); st != QuorumUnknown {
		t.Fatalf("fresh start: got state=%d; want Unknown (warmup)", st)
	}
}

// A local DB-read failure must yield QuorumUnknown, NOT No: gates still fail closed on
// Unknown, but the VIPDemoter treats No as a trigger to demote local VIPs (self-fencing
// only on a demote failure with a verified watchdog), so a transient SQLite error on a
// healthy quorum-holding node must not be read as confirmed quorum loss.
func TestQuorumProof_DBErrorIsUnknownNotNo(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-b", "active", "worker")
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.mu.Lock()
	c.probedOnce = true // past warmup — so a bare No would be a "confirmed" loss
	c.startedAt = time.Now().Add(-time.Hour)
	c.mu.Unlock()

	// Break the host-table read.
	if err := db.Execute(context.Background(), `DROP TABLE hosts`); err != nil {
		t.Fatalf("drop hosts: %v", err)
	}
	if st, _, _ := c.QuorumProof(context.Background()); st != QuorumUnknown {
		t.Fatalf("DB read error: got state=%d; want Unknown (not No — the demoter must not act)", st)
	}
}

func TestQuorumProof_FencedPeerNotCounted(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker") // self
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "host-c", "fenced", "worker") // fenced: out of denominator AND live

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	// A fenced host is not voting-eligible even if we "probed" it healthy.
	warm(c, map[string]bool{"host-b": true, "host-c": true})
	// denom = self + host-b = 2 → needed = 2. live = self + host-b = 2 → Yes.
	st, live, needed := c.QuorumProof(context.Background())
	if st != QuorumYes || live != 2 || needed != 2 {
		t.Fatalf("fenced-excluded: got state=%d live=%d needed=%d; want Yes/2/2", st, live, needed)
	}
}

// M1: a healthy cluster with >2 workers must NOT be missing-witness-blocked — quorum math
// already arbitrates a clean split (a 2-2 of four needs 3 to act), so the block is scoped
// to exactly 2 workers; a broader even-count block would permanently stop the rebalance
// executor on a healthy 4/6-worker cluster.
func TestDecisionGate_FourWorkersNotBlocked(t *testing.T) {
	db := testCheckHostDB(t)
	for _, n := range []string{"host-a", "host-b", "host-c", "host-d"} {
		gateHost(t, db, n, "active", "worker")
	}
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true, "host-c": true, "host-d": true})
	if r := c.DecisionGate(context.Background()); !r.OK {
		t.Fatalf("healthy 4-worker cluster must not be blocked; got refused %q", r.Reason)
	}
}

func TestDecisionGate_MissingWitness(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker") // self
	gateHost(t, db, "host-b", "active", "worker")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true}) // both up → QuorumYes
	if r := c.DecisionGate(context.Background()); r.OK || r.Reason != ReasonMissingWitness {
		t.Fatalf("2-worker no-witness: got OK=%v reason=%q; want refused missing_witness", r.OK, r.Reason)
	}

	// Add a witness → 2 workers + 1 witness, no longer blocked.
	gateHost(t, db, "wit-1", "active", "witness")
	warm(c, map[string]bool{"host-b": true, "wit-1": true})
	if r := c.DecisionGate(context.Background()); !r.OK {
		t.Fatalf("2-worker+witness: got refused %q; want OK", r.Reason)
	}
}

// A self-fenced node fails BOTH gates closed regardless of otherwise-perfect quorum/role —
// a doomed node must take no runtime-ownership decide/execute while it waits to reboot.
func TestGates_SelfFencedFailClosed(t *testing.T) {
	db := testCheckHostDB(t)
	for _, n := range []string{"host-a", "host-b", "host-c"} {
		gateHost(t, db, n, "active", "worker")
	}
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true, "host-c": true}) // healthy quorum, active worker

	// Sanity: without the fence both gates pass.
	if r := c.ExecutionGate(context.Background()); !r.OK {
		t.Fatalf("precondition: ExecutionGate should pass unfenced; got %q", r.Reason)
	}
	if r := c.DecisionGate(context.Background()); !r.OK {
		t.Fatalf("precondition: DecisionGate should pass unfenced; got %q", r.Reason)
	}

	fenced := false
	c.SetSelfFenced(func() bool { return fenced })
	if r := c.ExecutionGate(context.Background()); !r.OK { // predicate false → still passes
		t.Fatalf("nil/false fence must not block; got %q", r.Reason)
	}
	fenced = true
	if r := c.ExecutionGate(context.Background()); r.OK || r.Reason != ReasonSelfFenced {
		t.Fatalf("fenced ExecutionGate: got OK=%v reason=%q; want self_fenced", r.OK, r.Reason)
	}
	if r := c.DecisionGate(context.Background()); r.OK || r.Reason != ReasonSelfFenced {
		t.Fatalf("fenced DecisionGate: got OK=%v reason=%q; want self_fenced", r.OK, r.Reason)
	}
}

func TestExecutionGate_WitnessCannotExecute(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "wit-1", "active", "witness") // self is a witness
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "host-c", "active", "worker")

	c := NewChecker("wit-1", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true, "host-c": true})
	// Quorum is held (self+2 = 3, needed 2), but a witness must not execute.
	if r := c.ExecutionGate(context.Background()); r.OK || r.Reason != ReasonLocalNotActiveWorker {
		t.Fatalf("witness execute: got OK=%v reason=%q; want local_not_active_worker", r.OK, r.Reason)
	}
}

func TestDecisionGate_NotCoordinatorEligibleWhenDraining(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "draining", "worker") // self draining: votes but can't coordinate
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "wit-1", "active", "witness")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true, "wit-1": true})
	if r := c.DecisionGate(context.Background()); r.OK || r.Reason != ReasonNotCoordinatorElig {
		t.Fatalf("draining coordinator: got OK=%v reason=%q; want not_coordinator_eligible", r.OK, r.Reason)
	}
}

// A transient PeerTLSConfig failure at Start must NOT leave startedAt==0 (which would make
// QuorumProof skip warmup and report a permanent false QuorumNo — refusing every gated action).
// Start anchors the warmup clock BEFORE the (now-retrying) TLS load, so QuorumProof reports
// Unknown (warmup, safe fail-closed) instead of a bogus confirmed loss.
func TestChecker_TLSLoadFailureAnchorsWarmup(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "host-c", "active", "worker")
	c := NewChecker("host-a", "/nonexistent/litevirt/pki", db) // PeerTLSConfig fails → retry loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Start(ctx)
	var st QuorumState
	for i := 0; i < 200; i++ {
		if st, _, _ = c.QuorumProof(context.Background()); st == QuorumUnknown {
			return // PASS: warmup (anchored), never a false loss
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("QuorumProof never reached Unknown despite the startedAt anchor (last=%v) — false quorum-loss on TLS failure", st)
}
