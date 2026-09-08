// The standing advisory over premises resting on an operator attestation — and
// the two things it must never do.
//
// A retirement is the one premise in this subsystem that no machine verifies. It
// substitutes human-established evidence for machine evidence a destroyed
// machine can no longer produce, litevirt cannot check it, and recording it does
// not make it true. Every OTHER premise here degrades loudly when it stops being
// provable: a peer that will not answer leaves the membership closure open, a
// digest that disagrees suspends the bind, so an operator finds out because
// something refuses. A retirement degrades SILENTLY, by design — the proof
// completes and nothing refuses — so the substitution needs a standing surface
// that lasts as long as the grant authorises action.
//
// WHY THESE SCENARIOS NEED A FLEET. Each turns on state only another node has:
//
//   - the advisory must key on the incarnation the CLUSTER RECORDED for the lost
//     machine — a real per-node certificate serial, not one a test invented, or
//     every assertion here would pass for the wrong reason;
//   - it must not block the one operation that removes state from NetBox, which
//     means driving a real reclamation to completion over real gRPC and real
//     per-host proofs;
//   - clearing it must neither revoke nor validate the grant, and the only
//     honest way to show that is a SECOND real reclamation afterwards — one that
//     succeeds when the grant is in force and refuses when it has lapsed.

package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// The advisory's condition codes as they appear in the rows. Spelled out rather
// than imported: they are unexported in internal/grpcapi, and the string is what
// an operator's tooling actually matches on.
const (
	condPremiseAttested          = "netbox_premise_attested"
	condAttestationUnvalidatable = "netbox_attestation_unvalidatable"
)

// A second and third leaked address, so a scenario can drive more than one
// reclamation. Same distinctive .100+ band as the fixture's orphan, so they
// could only have come from NetBox.
const (
	secondOrphanCIDR = "10.0.5.151/24"
	secondOrphanMAC  = "52:54:00:0a:0b:0d"
	secondOrphanUUID = "6f1b0c2e-0000-4000-8000-0000000000bb"
)

// seedSecondOrphan plants another genuinely reclaimable address: a real identity
// under THIS cluster's fingerprint, and no local row anywhere pointing at it.
func seedSecondOrphan(t *testing.T, nb *NetBoxFake, n *Node) string {
	t.Helper()
	fp, err := corrosion.ClusterFingerprint(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("ClusterFingerprint on %s: %v", n.Name, err)
	}
	identity := netbox.Identity(fp, secondOrphanUUID, secondOrphanMAC)
	nb.SeedIP(secondOrphanCIDR, orphanVRF, identity, time.Now().UTC().Add(-orphanAge))
	return identity
}

// advisoryCondition reads one health condition off a node's own database,
// resolved rows included, so a scenario can assert on a transition rather than
// only on presence.
func advisoryCondition(t *testing.T, n *Node, code, subject string) (corrosion.HealthCondition, bool) {
	t.Helper()
	all, err := corrosion.ListHealthConditions(context.Background(), n.DB, true)
	if err != nil {
		t.Fatalf("ListHealthConditions on %s: %v", n.Name, err)
	}
	for _, h := range all {
		if h.Code == code && h.SubjectID == subject {
			return h, true
		}
	}
	return corrosion.HealthCondition{}, false
}

// clearEveryAdvisory deletes every health condition row on every node — the
// strongest form of "the advisory was cleared", stronger than any resolve an
// operator can perform, because the row is gone rather than marked.
func clearEveryAdvisory(t *testing.T, c *Cluster) {
	t.Helper()
	for _, n := range c.Nodes {
		if err := n.DB.Execute(context.Background(), `DELETE FROM health_conditions`); err != nil {
			t.Fatalf("clear the health conditions on %s: %v", n.Name, err)
		}
	}
}

// incarnationOf is the certificate serial the CLUSTER recorded for a host. Read
// from the rows rather than taken as an argument, for the reason retireHost does
// the same: a serial a test invented would match nothing.
func incarnationOf(t *testing.T, n *Node, host string) string {
	t.Helper()
	inc, found, err := corrosion.HostIncarnationOf(context.Background(), n.DB, host)
	if err != nil || !found || inc == "" {
		t.Fatalf("read the recorded incarnation for %s: inc=%q found=%v err=%v",
			host, inc, found, err)
	}
	return inc
}

// TestFleetTheAdvisorySurfacesAnInForceAttestationAndBlocksNoReclamation is the
// visibility requirement together with the "gates nothing" requirement, in the
// one scenario where both are live at once.
//
// Reclamation's two premises are met — membership accounted for by an
// attestation, the host attested off by fencing evidence — so the sweep reclaims
// the orphan. That is the point of the recovery path, and the advisory must not
// interfere with it: a surface that could stop a reclamation would be a control,
// and this one is a view.
//
// At the same time, the grant IS authorising that reclamation, so something has
// to say so. The advisory is keyed on the incarnation the cluster recorded for
// the lost machine, and carries what a reviewer needs to find the assertion.
func TestFleetTheAdvisorySurfacesAnInForceAttestationAndBlocksNoReclamation(t *testing.T) {
	nb, c := boundClusterWithOrphan(t, 2)
	sweeper, lost := c.Nodes[0], c.Nodes[1]
	incarnation := incarnationOf(t, sweeper, lost.Name)

	lost.Stop()
	mustFenceConfirm(t, sweeper, lost.Name)
	retireHost(t, c, lost.Name, corrosion.PremiseMembership)

	mustSweep(t, sweeper)

	// THE ADVISORY DID NOT BLOCK THE RECLAMATION. Every doubt in this subsystem
	// resolves towards leaving an address allocated, so an address that survived
	// is exactly what a wrongly-gating condition would look like.
	if held := len(nb.Identities()); held != 0 {
		t.Fatalf("the reclamation did not complete with the advisory standing (%d address(es) "+
			"still held). The advisory is a view: it must block no allocation, quorum or "+
			"execution path, and the sweep is the one path that removes state", held)
	}

	got, ok := advisoryCondition(t, sweeper, condPremiseAttested, incarnation)
	if !ok {
		t.Fatalf("the reclamation rested on an operator's attestation and nothing says so. "+
			"Expected a standing advisory on incarnation %s — the certificate serial the "+
			"cluster recorded for the lost machine", incarnation)
	}
	if got.Severity != corrosion.SeverityInfo {
		t.Errorf("severity = %q, want %q: a grant can stand for months, and a warning for "+
			"all of it would make `lv health` exit non-zero indefinitely",
			got.Severity, corrosion.SeverityInfo)
	}
	if got.Lifecycle == corrosion.ConditionResolved {
		t.Error("the advisory is already resolved while the grant is in force")
	}
	for _, want := range []struct{ what, needle string }{
		{"the incarnation it applies to", incarnation},
		{"the premise it supplies", string(corrosion.PremiseMembership)},
		{"the lost host it is about", lost.Name},
		{"who attested it", "operator"},
		{"that litevirt cannot check what was attested", "cannot check"},
		{"that recording it does not make it true", "does not make it true"},
		{"that it is not power-off evidence", "fence-confirm"},
		{"how to review it", "lv netbox retirements"},
	} {
		if !strings.Contains(got.Evidence, want.needle) {
			t.Errorf("the advisory does not name %s (%q missing).\nevidence: %s",
				want.what, want.needle, got.Evidence)
		}
	}
	// It must NOT read as inventory: only the membership premise was attested,
	// and the lost host's unique address records are still owed.
	if strings.Contains(got.Evidence, "supplying="+string(corrosion.PremiseInventory)) {
		t.Errorf("a membership-only grant reads as supplying the INVENTORY premise. Nobody "+
			"accounted for the lost host's unique address records.\nevidence: %s", got.Evidence)
	}
	// And nothing is uncertain: every read succeeded.
	if _, ok := advisoryCondition(t, sweeper, condAttestationUnvalidatable, "netbox"); ok {
		t.Error("a pass that revalidated everything reported uncertainty")
	}
}

// TestFleetClearingTheAdvisoryNeitherRevokesNorValidatesTheRetirement is the
// "view, not a control" requirement, pinned in BOTH directions with a
// DIFFERENTIAL on the state of the grant.
//
// Both cases clear every advisory row on every node and then drive a second real
// reclamation. The ONLY difference is whether the grant is still in force:
//
//   - IN FORCE → the second reclamation must still succeed. If clearing the
//     advisory had revoked the grant, the closure would stop closing and the
//     address would survive: a display would have destroyed an exception an
//     operator deliberately recorded, silently.
//   - LAPSED (a replacement admitted under the same hostname) → the second
//     reclamation must refuse. If clearing the advisory could VALIDATE the
//     grant, dismissing a warning would launder the attestation into evidence
//     and free an address on the strength of a display having been tidied away.
//
// Either case alone would be satisfiable by a build that ignored retirements in
// one direction. Together they pin that clearing the view changes nothing about
// what the proofs act on.
func TestFleetClearingTheAdvisoryNeitherRevokesNorValidatesTheRetirement(t *testing.T) {
	for _, tc := range []struct {
		name string
		// lapse runs after the first sweep and before the advisory is cleared.
		lapse       func(t *testing.T, c *Cluster, lost *Node)
		wantSecond  int // addresses still held after the second sweep
		wantAdvised bool
		why         string
	}{{
		name:        "the grant is still in force",
		lapse:       func(*testing.T, *Cluster, *Node) {},
		wantSecond:  0,
		wantAdvised: true,
		why: "clearing the advisory must not revoke the grant: the retirement is a recorded " +
			"attestation, and a display has no business destroying one. The premise is still " +
			"supplied, so the closure still closes and the second orphan is still reclaimed — " +
			"and the advisory says so again, because it is derived on every pass and " +
			"remembered between none",
	}, {
		name: "the grant has lapsed",
		lapse: func(t *testing.T, c *Cluster, lost *Node) {
			readmitUnderANewIncarnation(t, c, lost.Name)
		},
		wantSecond:  1,
		wantAdvised: false,
		why: "clearing the advisory must not validate the grant: a different machine now " +
			"answers to that name and inherits nothing, so the premise is owed again and the " +
			"second orphan must survive. Dismissing a warning is not evidence",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			nb, c := boundClusterWithOrphan(t, 2)
			sweeper, lost := c.Nodes[0], c.Nodes[1]
			incarnation := incarnationOf(t, sweeper, lost.Name)

			lost.Stop()
			mustFenceConfirm(t, sweeper, lost.Name)
			retireHost(t, c, lost.Name, corrosion.PremiseMembership)

			// The positive control: with the grant in force the first orphan is
			// reclaimed and the advisory is raised. Without this, a build that
			// never honoured retirements at all would satisfy the lapsed case.
			mustSweep(t, sweeper)
			if held := len(nb.Identities()); held != 0 {
				t.Fatalf("fixture: the first reclamation did not complete (%d held)", held)
			}
			if _, ok := advisoryCondition(t, sweeper, condPremiseAttested, incarnation); !ok {
				t.Fatal("fixture: no advisory was raised for a grant that was in force")
			}

			tc.lapse(t, c, lost)
			clearEveryAdvisory(t, c)
			seedSecondOrphan(t, nb, sweeper)

			mustSweep(t, sweeper)

			if held := len(nb.Identities()); held != tc.wantSecond {
				t.Fatalf("%s: %s — held %d address(es), want %d (released %v)",
					tc.name, tc.why, held, tc.wantSecond, nb.Released())
			}
			_, advised := advisoryCondition(t, sweeper, condPremiseAttested, incarnation)
			if advised != tc.wantAdvised {
				t.Fatalf("%s: advisory present = %v, want %v — %s",
					tc.name, advised, tc.wantAdvised, tc.why)
			}
		})
	}
}

// TestFleetTheAdvisoryStopsShowingAGrantThatIsNoLongerInForce pins the two
// invalidations that only a fleet can produce, and pins them on the SURFACE
// rather than on the proof.
//
// Recorded is not in force. A grant that has stopped applying authorises
// nothing, and showing it as though it still did is worse than showing nothing:
// it invites an operator to reason about an exception that is not there. Both
// invalidations happen with nothing written and no operator action.
//
// The RPC assertion is the second half. `lv netbox retirements` is the review
// surface, and it must agree with the advisory: a listing that still said
// APPLIES while the advisory had cleared would leave an operator with two
// answers and no way to choose.
func TestFleetTheAdvisoryStopsShowingAGrantThatIsNoLongerInForce(t *testing.T) {
	for _, tc := range []struct {
		name       string
		invalidate func(t *testing.T, c *Cluster, lost *Node)
		why        string
	}{{
		name: "a replacement was admitted under the same hostname",
		invalidate: func(t *testing.T, c *Cluster, lost *Node) {
			readmitUnderANewIncarnation(t, c, lost.Name)
		},
		why: "the grant names an incarnation, so a replacement machine — which necessarily " +
			"presents a different certificate serial — inherits nothing",
	}, {
		name: "the host is answering again",
		invalidate: func(_ *testing.T, _ *Cluster, lost *Node) {
			lost.Rejoin()
		},
		why: "a machine that answers refutes the attestation that it was lost, so its live " +
			"state governs",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			_, c := boundClusterWithOrphan(t, 2)
			sweeper, lost := c.Nodes[0], c.Nodes[1]
			incarnation := incarnationOf(t, sweeper, lost.Name)
			ctx := context.Background()

			lost.Stop()
			mustFenceConfirm(t, sweeper, lost.Name)
			retireHost(t, c, lost.Name, corrosion.PremiseMembership)

			mustSweep(t, sweeper)
			if _, ok := advisoryCondition(t, sweeper, condPremiseAttested, incarnation); !ok {
				t.Fatal("fixture: no advisory was raised for a grant that was in force")
			}

			tc.invalidate(t, c, lost)

			// Two consecutive clean passes resolve it, matching the durable
			// condition model everywhere else: one clean pass can be a probe
			// racing a restart.
			mustSweep(t, sweeper)
			mustSweep(t, sweeper)

			got, ok := advisoryCondition(t, sweeper, condPremiseAttested, incarnation)
			if !ok {
				t.Fatalf("%s: the advisory row vanished rather than resolving; the transition "+
					"is what an operator sees", tc.name)
			}
			if got.Lifecycle != corrosion.ConditionResolved {
				t.Fatalf("%s: lifecycle = %q, want %q — %s. A lapsed grant shown as usable "+
					"evidence is worse than showing nothing",
					tc.name, got.Lifecycle, corrosion.ConditionResolved, tc.why)
			}

			// And the review surface agrees, over real gRPC.
			resp, err := c.SelfClient(sweeper).ListLostHostRetirements(ctx, &emptypb.Empty{})
			if err != nil {
				t.Fatalf("ListLostHostRetirements: %v", err)
			}
			for _, r := range resp.GetRetirements() {
				if r.GetHostIncarnation() != incarnation {
					continue
				}
				if r.GetApplies() {
					t.Fatalf("%s: `lv netbox retirements` still reports the grant as applying "+
						"while the advisory has cleared — %s", tc.name, tc.why)
				}
			}
		})
	}
}
