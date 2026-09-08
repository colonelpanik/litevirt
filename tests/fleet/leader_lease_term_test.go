// Fleet scenarios for leader-lease fencing terms.
//
// Every failure the term ledger exists to catch is multi-node, and the
// single-package tests structurally cannot reach any of them: they run one
// Client, so they can drive the anti-entropy merge OR the WAL apply path but
// never both against two real nodes with separate DBs. Four defects reached
// review in exactly that blind spot — the two paths resolving a contested term
// to different holders, a merge loser minting a higher term on its next renewal,
// a reseed regressing the allocation high-water mark, and the same-holder double
// mint.
//
// These scenarios run the real spine: separate per-node DBs, statements carried
// over real gRPC + mTLS + applyStatementLWW, and the real anti-entropy dump.
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const leaseTermKey = "failover"

// leaseRowFor reads a node's own leader_election row for the lease key. holder
// is "" when the row is absent, which is how a node that never received a
// peer's upsert sees the key.
func leaseRowFor(t *testing.T, n *Node) (holder, expiresAt string, err error) {
	t.Helper()
	rows, qerr := n.DB.Query(context.Background(),
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, leaseTermKey)
	if qerr != nil {
		return "", "", qerr
	}
	if len(rows) == 0 {
		return "", "", nil
	}
	return rows[0].String("holder"), rows[0].String("expires_at"), nil
}

func leaseTermHolderAt(t *testing.T, n *Node, term int64) (string, bool) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT holder FROM leader_lease_terms WHERE key = ? AND term = ? AND deleted_at IS NULL`,
		leaseTermKey, term)
	if err != nil {
		t.Fatalf("read term %d on %s: %v", term, n.Name, err)
	}
	if len(rows) == 0 {
		return "", false
	}
	return rows[0].String("holder"), true
}

// TestFleet_LeaseTerm_BothPathsAgreeOnAContestedHolder is the scenario the
// review's headline finding lived in.
//
// Two partitioned nodes each compute MAX(term)+1 = 1 and each name themselves
// holder. One node then learns the other's claim over the WAL, and a second
// pair learns the identical claim by anti-entropy repair. Before the fix the WAL
// path (INSERT OR IGNORE, first-writer-wins) and the dump path (LWW on
// updated_at, last-writer-wins) produced DIFFERENT holders — so the executor's
// (term, holder) check refused opposite claimants depending on which path
// delivered, and a WAL-converged node silently flipped its own answer on its
// next repair cycle.
//
// The property: whichever path delivers, a node keeps the claim it already had.
func TestFleet_LeaseTerm_BothPathsAgreeOnAContestedHolder(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]

	now := time.Now().UTC()

	// Both nodes acquire term 1 for the same key while partitioned — each sees
	// an empty ledger and an unheld lease.
	c.Partition(a, b)
	heldA, termA, err := corrosion.AcquireLeaseWithTerm(ctx, a.DB, leaseTermKey, a.Name, 30*time.Second, now)
	if err != nil || !heldA {
		t.Fatalf("%s acquire: held=%v err=%v", a.Name, heldA, err)
	}
	heldB, termB, err := corrosion.AcquireLeaseWithTerm(ctx, b.DB, leaseTermKey, b.Name, 30*time.Second, now)
	if err != nil || !heldB {
		t.Fatalf("%s acquire: held=%v err=%v", b.Name, heldB, err)
	}
	if termA != 1 || termB != 1 {
		t.Fatalf("partitioned nodes got terms %d and %d; both must compute 1 for this "+
			"scenario to be the contested case", termA, termB)
	}
	c.Heal(a, b)

	// Path 1: b learns a's claim over the WAL.
	pumpMutations(t, c, a, b)
	// Path 2: a learns b's claim by anti-entropy repair.
	if err := a.DB.MergeStateBytesLWW(b.DB.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy b→a: %v", err)
	}
	// And in the OTHER direction too. Doing only one is not enough: a merge that
	// converges by comparing encoded rows keeps whichever holder sorts lower, so
	// a single direction passes or fails purely on how the two node names happen
	// to sort. Merging both ways means one direction always has the local row
	// sorting higher, where a converging merge would adopt the incoming holder.
	if err := b.DB.MergeStateBytesLWW(a.DB.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy a→b: %v", err)
	}

	holderA, okA := leaseTermHolderAt(t, a, 1)
	holderB, okB := leaseTermHolderAt(t, b, 1)
	if !okA || !okB {
		t.Fatalf("term 1 missing after exchange: a=%v b=%v", okA, okB)
	}
	if holderA != a.Name {
		t.Errorf("%s resolved term 1 to %q after ANTI-ENTROPY delivery, want its own claim %q. "+
			"The dump path must not rewrite an existing term row, or it disagrees with the "+
			"WAL path about who held the tenure", a.Name, holderA, a.Name)
	}
	if holderB != b.Name {
		t.Errorf("%s resolved term 1 to %q, want its own claim %q", b.Name, holderB, b.Name)
	}

	// The disagreement must be RAISED, not merely preserved. This is the
	// assertion that separates "kept local and flagged" from "converged
	// deterministically": a converging merge also leaves one node holding its
	// own claim, but records a tie-break rather than an unresolved conflict, so
	// nothing tells the operator two nodes claimed one tenure.
	if a.DB.UnresolvedTieCount() == 0 && b.DB.UnresolvedTieCount() == 0 {
		t.Error("neither node flagged an unresolved tie for the contested term. " +
			"litevirt_lww_tie_unresolved_current is the signal docs/operating-model.md " +
			"sends operators to; a merge that silently elects a winner leaves them nothing")
	}
}

// TestFleet_LeaseTerm_MergeLoserDoesNotMintAHigherTerm: a node whose ledger
// learns a peer's competing claim must not respond by minting a term ABOVE it.
//
// leader_election is anti-entropy excluded while leader_lease_terms is
// replicated, so "our lease row still names us, but the ledger's newest term
// names a peer" is reachable in ordinary operation — not just under partition.
// Reading that as "no term recorded yet" and falling through to acquisition
// promoted the node that lost the term race above the winner, inverting fencing.
func TestFleet_LeaseTerm_MergeLoserDoesNotMintAHigherTerm(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]

	now := time.Now().UTC()

	// a holds the lease and term 1.
	if held, _, err := corrosion.AcquireLeaseWithTerm(ctx, a.DB, leaseTermKey, a.Name, 30*time.Second, now); err != nil || !held {
		t.Fatalf("%s acquire: held=%v err=%v", a.Name, held, err)
	}
	// b, partitioned, takes what it believes is a free lease and mints term 2
	// (it has already seen term 1 by repair, so it allocates above it).
	if err := b.DB.MergeStateBytesLWW(a.DB.DumpStateBytes()); err != nil {
		t.Fatalf("seed b's ledger: %v", err)
	}
	// b's own lease row: it never received a's, so b sees the key as unheld.
	// Nothing to clear — assert that, so the scenario cannot silently degrade
	// into "b renewed its own lease".
	if holder, _, err := leaseRowFor(t, b); err != nil {
		t.Fatalf("read %s lease row: %v", b.Name, err)
	} else if holder != "" {
		t.Fatalf("%s already sees holder %q; this scenario needs b to view the lease as "+
			"unheld so its acquisition is genuine", b.Name, holder)
	}
	heldB, termB, err := corrosion.AcquireLeaseWithTerm(ctx, b.DB, leaseTermKey, b.Name, 30*time.Second, now)
	if err != nil {
		t.Fatalf("%s acquire: %v", b.Name, err)
	}
	if !heldB || termB <= 1 {
		t.Fatalf("%s must take a term above 1 for this scenario: held=%v term=%d", b.Name, heldB, termB)
	}

	// a now learns b's higher claim by repair, while a's OWN leader_election row
	// still names a (that table is anti-entropy excluded).
	if err := a.DB.MergeStateBytesLWW(b.DB.DumpStateBytes()); err != nil {
		t.Fatalf("anti-entropy b→a: %v", err)
	}
	before, err := corrosion.CurrentLeaseTerm(ctx, a.DB, leaseTermKey)
	if err != nil {
		t.Fatalf("threshold: %v", err)
	}

	// a's next ordinary renewal tick.
	held, term, err := corrosion.AcquireLeaseWithTerm(ctx, a.DB, leaseTermKey, a.Name,
		30*time.Second, now.Add(time.Second))
	if err != nil {
		t.Fatalf("%s renewal: %v", a.Name, err)
	}
	if held && term > before {
		t.Errorf("%s was superseded (threshold %d) and its renewal minted term %d — the "+
			"node that LOST the term race now owns MAX(term), which inverts fencing",
			a.Name, before, term)
	}
	if held {
		t.Errorf("%s reported holding the lease with term %d after a peer's newer term "+
			"superseded it; it must fail closed", a.Name, term)
	}
	after, err := corrosion.CurrentLeaseTerm(ctx, a.DB, leaseTermKey)
	if err != nil {
		t.Fatalf("threshold after: %v", err)
	}
	if after != before {
		t.Errorf("the rejection threshold moved %d -> %d on a superseded node's renewal",
			before, after)
	}
}

// TestFleet_LeaseTerm_ReseedDoesNotRegressTheHighWaterMark: a reseed must not
// hand out a term number a previous incarnation already used.
//
// A reseed discards local replicated state and re-merges from one peer, so the
// terms an isolated node minted are precisely the ones the peer never received.
// With the ledger discarded, MAX(term) regressed and the next acquisition reused
// a number — and because a term row is immutable, peers holding the old row
// IGNORE the reallocated one, so the two incarnations' (term, holder) mapping
// diverges permanently.
func TestFleet_LeaseTerm_ReseedDoesNotRegressTheHighWaterMark(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	defer c.Stop()
	a, b := c.Nodes[0], c.Nodes[1]

	now := time.Now().UTC()

	// a mints several terms while b hears nothing about them.
	c.Partition(a, b)
	for i := 0; i < 3; i++ {
		at := now.Add(time.Duration(i) * time.Hour) // each lapse ends a tenure
		if _, _, err := corrosion.AcquireLeaseWithTerm(ctx, a.DB, leaseTermKey, a.Name, time.Second, at); err != nil {
			t.Fatalf("%s acquire %d: %v", a.Name, i, err)
		}
	}
	c.Heal(a, b)

	high, err := corrosion.CurrentLeaseTerm(ctx, a.DB, leaseTermKey)
	if err != nil {
		t.Fatalf("high-water: %v", err)
	}
	if high < 3 {
		t.Fatalf("expected at least 3 terms minted while partitioned, got %d", high)
	}

	// a reseeds from b, which has none of those terms.
	if _, err := a.DB.DiscardReplicatedStateForReseed(ctx); err != nil {
		t.Fatalf("reseed discard: %v", err)
	}
	if err := a.DB.MergeStateBytesLWW(b.DB.DumpStateBytes()); err != nil {
		t.Fatalf("reseed merge: %v", err)
	}

	after, err := corrosion.CurrentLeaseTerm(ctx, a.DB, leaseTermKey)
	if err != nil {
		t.Fatalf("high-water after reseed: %v", err)
	}
	if after < high {
		t.Errorf("the allocation high-water mark regressed %d -> %d across a reseed. The "+
			"terms this node minted are exactly the ones its reseed source never received, "+
			"so the next acquisition reuses a number a prior incarnation already holds — "+
			"and an immutable term row means peers IGNORE the reallocation, diverging "+
			"permanently", high, after)
	}
}
