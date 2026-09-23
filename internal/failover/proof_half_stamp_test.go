package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A proof is either STAMPED (a real term plus the key naming its ledger) or
// UNSTAMPED (term 0, empty key). judgeProofLeaseTerm is built on exactly that
// split: the unstamped shape takes a documented branch — refused only for the
// actions whose every producer holds a lease, exempt otherwise — and anything
// in between is rejected as "not a judgeable pair", on the stated grounds that
// "neither is something a producer emits".
//
// This pins WHY that claim holds, because it is not obvious from the failover
// coordinator, which binds LeaseKey to the failover constant unconditionally
// while leaseStamp returns NO term pre-latch. Read from the coordinator alone,
// a pre-latch proof looks like the half-stamped (0, "failover").
//
// It is not, and the reason is a coupling two packages away:
// proofInsertStmt switches to a pre-term SQL shape when
// MayEmitTermCarryingProof() is false, so the term columns are not written at
// all and the row defaults to (0, ""). And MayEmitTermCarryingProof is the SAME
// predicate as MayMintLeaseTerm — both are c.leaseTermLedger — so minting a
// term and persisting a term open together, always. Gate closed gives a clean
// unstamped proof; gate open gives a real term with its key.
//
// Decoupling those two gates would make the malformed shape reachable and
// silently defeat the unstamped exemption for every non-required action. This
// test fails if that ever happens.
func TestProof_ATermlessProofCarriesNoLeaseKey(t *testing.T) {
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

	// Close the ledger mint gate: pre-latch, AcquireLeaseWithTerm deliberately
	// takes the lease and reports NO term. The test client opens this by
	// default, which is why terms mint in most tests.
	db.SetLeaseTermLedgerGate(func() bool { return false })

	// Split-brain gate enforced so a proof is written at all; lease_term_v1
	// NOT latched, which is the ordinary pre-rollout state.
	c := newTestCoordinator("coord", db)
	c.Gate = fakeFailoverGate{
		supports: map[string]bool{"live": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true},
	}
	c.run(ctx)

	rows, err := db.Query(ctx,
		`SELECT lease_term, lease_key FROM runtime_action_proofs WHERE target_name = 'vm1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("proof rows=%d err=%v; want one", len(rows), err)
	}
	term, key := rows[0].Int64("lease_term"), rows[0].String("lease_key")

	// Precondition: this is the pre-latch state the test is about.
	if term != 0 {
		t.Skipf("coordinator minted term %d, so this is not the pre-latch state", term)
	}
	if key != "" {
		t.Errorf("proof carries lease_term %d with lease_key %q\n"+
			"that is the HALF-stamped shape judgeProofLeaseTerm rejects as "+
			"'not a judgeable pair' while documenting that no producer emits it. "+
			"A termless proof must carry no key, so it takes the unstamped branch "+
			"and a non-required action keeps its exemption.", term, key)
	}
}
