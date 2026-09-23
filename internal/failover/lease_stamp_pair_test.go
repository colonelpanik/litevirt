package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A proof stamp is a PAIR, and half of one is worse than none.
//
// leaseStamp exists so a stamp site cannot omit the term — its own doc says the
// term is returned rather than read at each site for exactly that reason. But
// the KEY was not returned: all three sites set
// `LeaseKey: corrosion.LeaseKeyFailover` themselves, unconditionally, while the
// term they were handed can legitimately be 0.
//
// judgeProofLeaseTerm treats only (0, "") as the legacy/unstamped form. A
// (0, "failover") pair falls through to "not a judgeable pair" and the executor
// refuses with FailedPrecondition — for every action, including relocate, which
// was deliberately left out of leaseTermRequiredActions.
//
// The reachable producer is a coordinator that cannot MINT: holdLeaseWithoutTerm
// returns held with term ALWAYS 0, taken when MayMintLeaseTerm is false — a
// freshly joined or re-imaged host, or one whose activation marker never
// persisted. Its leaseTermEnforced is false, so leaseTermStampAllowed
// short-circuits and allows the stamp. Executors that HAVE latched enforce
// permanently (the latch never un-latches), so they refuse. A fenced host is
// processed exactly once, so every reschedule and relocation in that window is
// abandoned for good.
//
// Note this is NOT reachable by clearing enforcement.lease_term, which is what
// it first looked like: minting gates on DurablyLatched(LeaseTermLedgerV1), a
// separate token with no config flag, so clearing the enforcement flag leaves
// the mint working and the term positive.
func TestLeaseStamp_NeverReturnsAKeyWithoutATerm(t *testing.T) {
	ctx := context.Background()

	t.Run("no term means no key", func(t *testing.T) {
		c := NewCoordinator("me", newTestDB(t))
		// Not enforcing and holding no term: exactly holdLeaseWithoutTerm's result.
		c.LeaseTermEnforce = false
		holder, exp, term, key, ok := c.leaseStamp(ctx)
		if !ok {
			t.Skip("this coordinator refuses to stamp at all; the pair cannot be half-set")
		}
		if term == 0 && key != "" {
			t.Errorf("leaseStamp returned term=0 with key=%q — judgeProofLeaseTerm reads that "+
				"as 'not a judgeable pair' and the executor refuses every action it stamps; "+
				"the unstamped sentinel is (0, \"\")", key)
		}
		_, _ = holder, exp
	})

	t.Run("a term comes with its key", func(t *testing.T) {
		c := NewCoordinator("me", newTestDB(t))
		c.LeaseTermEnforce = false
		c.leaseTerm.Store(7)
		_, _, term, key, ok := c.leaseStamp(ctx)
		if !ok {
			t.Fatal("a coordinator holding term 7 must be allowed to stamp")
		}
		if term != 7 {
			t.Fatalf("term = %d, want 7", term)
		}
		if key != corrosion.LeaseKeyFailover {
			t.Errorf("key = %q, want %q: a positive term with no key is the other half of the "+
				"same malformed pair", key, corrosion.LeaseKeyFailover)
		}
	})
}
