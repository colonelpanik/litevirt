// THE ADOPTION WINDOW: every path that makes a NetBox binding live must
// re-validate AFTER the adoption, not before it.
//
// The hazard is not that a bind forgets to validate. All four activation paths
// validated, then adopted, then went live — and the argument for that order was
// "the premise is the bind's own validation, in the same RPC". Same RPC does not
// mean unchanged external state: adoption issues up to 256 NetBox POSTs, and
// anything can happen across them. Switch a VRF's uniqueness enforcement off
// during one and the binding used to go LIVE on every door — over the precise
// condition each of them had just checked for.
//
// So each scenario here does the same thing at a different door: disable
// uniqueness from INSIDE an adoption claim, and require that the binding stays
// suspended, that the adopted claims are kept anyway, and that no allocation is
// served. Fleet rather than package-local because the drift has to land between
// two real HTTP requests of one real RPC, against a real replicated row.
//
// WHAT THESE DO NOT CLAIM. Closing the adoption window does not make NetBox
// changes atomic with local activation, and no assertion here should be read as
// saying it does — uniqueness switched off one millisecond after the final
// revalidation read still leaves the binding live, and the periodic revalidation
// pass is what catches that. What is pinned is the window with a known cause and
// a known duration: the adoption's own requests.

package fleet

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
)

// disableUniquenessDuringAdoption makes the fake switch the bound VRF's
// uniqueness enforcement OFF from inside the first adoption claim, and reports
// whether a claim was ever reached.
//
// The "was it reached" half is not optional. Every assertion below is vacuously
// true on a pass that never adopted anything — the binding would stay suspended
// for the ordinary reason — so a scenario that stopped short would read as a
// pass for the wrong reason.
func disableUniquenessDuringAdoption(nb *NetBoxFake) func() bool {
	var (
		mu      sync.Mutex
		reached bool
	)
	nb.SetOnClaimSpecific(func(string) error {
		mu.Lock()
		reached = true
		mu.Unlock()
		// The claim itself SUCCEEDS. The adoption has to finish for this to be
		// a test of the activation gate rather than of the adoption's own
		// error path.
		nb.SetVRFEnforceUnique(adoptVRF, false)
		return nil
	})
	return func() bool {
		mu.Lock()
		defer mu.Unlock()
		return reached
	}
}

// assertSuspendedOverAdoptionDrift is the shared assertion: the binding did not
// go live, it says why, and the adoption's work was KEPT.
//
// Keeping the work is half the property. Refusing to activate must not roll the
// adoption back — the NetBox object and the local lease behind it are what stop
// `/available-ips/` offering a running guest's address to the next VM, and a
// retry that had to redo them would be re-POSTing objects that already exist.
func assertSuspendedOverAdoptionDrift(t *testing.T, nb *NetBoxFake, c *Cluster, n *Node, door string) {
	t.Helper()
	b := bindingFor(t, n)
	if b == nil {
		t.Fatalf("%s: the binding row is gone; a refused activation must leave one to retry", door)
	}
	if !b.Suspended {
		t.Fatalf("%s activated the binding even though uniqueness was disabled DURING the "+
			"adoption: %+v", door, b)
	}
	if !strings.Contains(b.SuspendReason, "uniqueness") {
		t.Fatalf("%s: the suspension must name the drift the post-adoption revalidation read, "+
			"got %q", door, b.SuspendReason)
	}
	// THE ADOPTED CLAIMS STAND.
	if got := nb.Addresses(); len(got) != 1 || got[0] != adoptFirstIP+"/24" {
		t.Fatalf("%s: NetBox holds %v, want the adopted [%s/24] — a refused activation must not "+
			"discard the adoption", door, got, adoptFirstIP)
	}
	if lease := leaseFor(t, n, adoptNetName, adoptFirstIP); lease == nil || lease.NetBoxIPID == 0 {
		t.Fatalf("%s: the adopted address must stay leased locally, got %+v", door,
			leaseFor(t, n, adoptNetName, adoptFirstIP))
	}
	// …and no allocation is served while it is suspended, which is what the
	// suspension is FOR. Asserted alongside the row rather than instead of it:
	// the flag is the mechanism, the refused create is the behaviour.
	if _, err := createVMOnNetwork(c, n, "newcomer", adoptNetName); err == nil {
		t.Fatalf("%s: a suspended binding must refuse a create on that network", door)
	}
}

// TestBindDoesNotActivateOnAValidationThatPredatesItsAdoption is the bind's own
// finisher: `lv network create` against a prefix whose guests already hold
// addresses.
func TestBindDoesNotActivateOnAValidationThatPredatesItsAdoption(t *testing.T) {
	nb, c, n := adoptCluster(t)
	mustCreateUnboundNetwork(t, c, n, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, n, "incumbent", adoptNetName, adoptFirstIP)

	reached := disableUniquenessDuringAdoption(nb)
	err := relink(c, n, t)

	if !reached() {
		t.Fatal("the bind never reached its adoption, so nothing was tested")
	}
	if err == nil {
		t.Fatal("a bind whose post-adoption revalidation refused activation must report it")
	}
	assertSuspendedOverAdoptionDrift(t, nb, c, n, "bind")
}

// TestResumeDoorsDoNotActivateOnAValidationThatPredatesTheirAdoption covers the
// two OPERATOR doors, which reproduce identically because their checks also ran
// before the adoption.
func TestResumeDoorsDoNotActivateOnAValidationThatPredatesTheirAdoption(t *testing.T) {
	for _, door := range []string{"resume", "rekey"} {
		t.Run(door, func(t *testing.T) {
			nb, c, n := adoptCluster(t)
			aSuspendedBindingOwingAdoption(t, nb, c, n, adoptFirstIP)

			reached := disableUniquenessDuringAdoption(nb)
			var err error
			if door == "resume" {
				err = resumeBinding(c, n, adoptNetName)
			} else {
				err = rekey(c, n, adoptNetName)
			}

			if !reached() {
				t.Fatalf("%s never reached the adoption, so nothing was tested", door)
			}
			if err == nil {
				t.Fatalf("%s must report that it did not activate the binding", door)
			}
			assertSuspendedOverAdoptionDrift(t, nb, c, n, door)
		})
	}
}

// TestAutomaticCompletionDoesNotActivateOnAValidationThatPredatesItsAdoption is
// the FOURTH door, and the one with no operator in it.
//
// A bind on a node that could not corroborate its VM inventory leaves the
// binding in the one suspension class the revalidation pass lifts by itself. So
// this door activates a binding with nobody watching, on a schedule — which is
// exactly why it is the easiest of the four to leave behind.
//
// Two nodes, because the uncorroborated empty read needs a peer that genuinely
// holds rows this node has not received; see netbox_unhydrated_test.go.
func TestAutomaticCompletionDoesNotActivateOnAValidationThatPredatesItsAdoption(t *testing.T) {
	nb, c, holder, binder := unhydratedCluster(t)
	ctx := context.Background()

	mustCreateUnboundNetwork(t, c, holder, adoptNetName, adoptSubnet)
	mustCreateVMHoldingIP(t, c, holder, "incumbent", adoptNetName, adoptFirstIP)
	mustCreateSuspendedBoundNetwork(t, c, binder)

	// The rows arrive over the production repair path, so the next pass CAN
	// enumerate what needs adopting and will therefore reach the adoption.
	binder.DB.MergeStateBytesLWW(pullDump(t, c, holder))

	reached := disableUniquenessDuringAdoption(nb)
	if err := binder.Server.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce: %v", err)
	}
	if !reached() {
		t.Fatal("the pass never reached the adoption, so nothing was tested")
	}
	assertSuspendedOverAdoptionDrift(t, nb, c, binder, "automatic-completion")

	// AND IT IS NO LONGER SELF-LIFTING. The gate re-stated the reason as the
	// drift it read, which takes the binding out of the one class a pass may
	// lift on its own — correctly, because a VRF that stopped enforcing
	// uniqueness is an operator's repair and not a pass's. Pinned, because the
	// alternative (leaving the unhydrated reason in place) would have the pass
	// activate this binding on its next tick over drift it had already read.
	nb.SetOnClaimSpecific(nil)
	if err := binder.Server.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce (second): %v", err)
	}
	if b := bindingFor(t, binder); b == nil || !b.Suspended {
		t.Fatalf("a later pass activated a binding suspended over drift an operator has to "+
			"repair: %+v", b)
	}

	// The operator's repair, then the operator's resume: live again, and
	// allocating.
	nb.SetVRFEnforceUnique(adoptVRF, true)
	mustResume(t, c, binder, adoptNetName)
	if b := bindingFor(t, binder); b == nil || b.Suspended {
		t.Fatalf("a resume after the drift was repaired must activate the binding: %+v", b)
	}
}

// errPrefixUnreadable is what a NetBox that cannot answer looks like to
// bindingDrift: its THIRD answer, "I could not look" — not a clean read and not
// a definite refusal.
var errPrefixUnreadable = errors.New("the prefix read did not complete")

// TestRekeyKeepsItsRewritesWhenTheDriftAnswerCannotBeRead is the unknown-answer
// outcome, behaviourally.
//
// A structural guard can pin that the re-key BINDS bindingDrift's error rather
// than discarding it. It cannot establish what happens next, and what happens
// next is the whole question: an unread answer must refuse the activation while
// keeping every identity the re-key already rewrote, because a re-key that
// discarded its own progress on a transient NetBox failure would have to redo
// the whole rewrite — and a re-key is the ONLY path that re-stamps a moved
// fingerprint, so making it lossy makes the recovery unusable.
//
// Both subtests drive the failure AFTER the identity rewriting, at the two
// points a drift answer is read: the cheap pre-adoption refusal, and the final
// gate's own revalidation.
func TestRekeyKeepsItsRewritesWhenTheDriftAnswerCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		// readsToAllow is how many prefix reads answer normally once the
		// rewriting has begun. 0 fails the pre-adoption check; 1 lets that one
		// through and fails the gate's post-adoption revalidation.
		readsToAllow int
	}{
		{name: "before_the_adoption", readsToAllow: 0},
		{name: "after_the_adoption", readsToAllow: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nb, c := boundCluster(t, 1)
			n := c.Nodes[0]
			mustCreateVMOnNetwork(t, c, n, "vm-1", orphanNetwork)
			mustCreateVMOnNetwork(t, c, n, "vm-2", orphanNetwork)
			oldFP := clusterFP(t, n)

			c.MoveClusterFingerprint()
			newFP := clusterFP(t, n)
			mustRevalidate(t, n)
			if !bindingSuspended(t, n, orphanPrefixID) {
				t.Fatal("precondition: a moved fingerprint must suspend the binding")
			}

			// The prefix read starts failing only once an identity has actually
			// been rewritten, so the failure lands after the rewriting rather
			// than instead of it.
			var (
				mu       sync.Mutex
				rewrites int
				allowed  int
			)
			nb.SetOnPatch(func(int) error {
				mu.Lock()
				rewrites++
				mu.Unlock()
				return nil
			})
			nb.SetOnPrefixRead(func(int) error {
				mu.Lock()
				defer mu.Unlock()
				if rewrites == 0 {
					return nil
				}
				if allowed < tc.readsToAllow {
					allowed++
					return nil
				}
				return errPrefixUnreadable
			})

			err := rekey(c, n, orphanNetwork)

			mu.Lock()
			didRewrite := rewrites
			mu.Unlock()
			if didRewrite == 0 {
				t.Fatal("no identity was rewritten, so the failure did not land after the rewriting")
			}
			if err == nil {
				t.Fatal("a re-key whose drift answer could not be read must not report success")
			}

			// 1. SUSPENDED.
			if !bindingSuspended(t, n, orphanPrefixID) {
				t.Fatal("an unread drift answer must leave the binding suspended — an activation " +
					"may not rest on a validation nobody made")
			}
			// 2. THE REWRITING PROGRESS IS PRESERVED. Every address identity
			//    carries the NEW fingerprint; none was rolled back.
			if got := fingerprintCounts(t, nb); got[newFP] != 2 || got[oldFP] != 0 {
				t.Fatalf("identities after the refused activation = %v, want both under the new "+
					"fingerprint %s — a refused activation must not undo the rewrite",
					got, newFP)
			}
			// 3. ALLOCATION IS REFUSED while it is suspended.
			if _, verr := createVMOnNetwork(c, n, "vm-3", orphanNetwork); verr == nil {
				t.Fatal("a suspended binding must refuse a create on that network")
			}
			// 4. A RETRY SUCCEEDS once the read recovers, and the binding
			//    allocates again.
			nb.SetOnPrefixRead(nil)
			nb.SetOnPatch(nil)
			mustRekey(t, c, n, orphanNetwork)
			if bindingSuspended(t, n, orphanPrefixID) {
				t.Fatalf("the retry must activate the binding, reason: %q",
					bindingSuspendReason(t, n, orphanPrefixID))
			}
			if _, verr := createVMOnNetwork(c, n, "vm-4", orphanNetwork); verr != nil {
				t.Fatalf("the activated binding must allocate again, got %v", verr)
			}
		})
	}
}
