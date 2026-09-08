package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// THE STANDING ADVISORY over premises resting on an operator attestation.
//
// A retirement is the one premise in this subsystem that no machine verifies,
// and the one that degrades SILENTLY: every other premise blocks something when
// it stops being provable, so an operator finds out because something refuses.
// A retirement makes the proof complete instead. These tests pin the surface
// that keeps the substitution visible while it authorises action, and — just as
// hard — pin what it must NOT do: it may not report a grant that is not in
// force, it may not present uncertainty as evidence, it may not gate anything,
// and clearing it may neither revoke nor validate the grant underneath.

const (
	// advisoryLostHost is the permanently lost host every scenario retires.
	advisoryLostHost = "lost-node"
	// advisoryIncarnation is its recorded certificate serial — the identity a
	// retirement is written against, because a hostname is reusable.
	advisoryIncarnation = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
	// advisoryReplacement is the serial a REPLACEMENT machine presents under the
	// same hostname. AdmitHost refuses to re-admit a name with the certificate
	// it was removed under, so a replacement necessarily differs.
	advisoryReplacement = "ffffffff0000111122223333444455ff"
)

// newAttestationServer is a bare server with a database and a cluster row: the
// advisory reads replicated rows and writes replicated rows, so it needs no
// NetBox client and no libvirt.
func newAttestationServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// Retirements are scoped by cluster fingerprint, which derives from
	// cluster.ca_cert — without the row nothing can be revalidated at all.
	if err := db.Execute(ctx,
		`INSERT INTO cluster (id, name, domain, ca_cert, created_at, updated_at)
		 VALUES ('default', 'test-cluster', 'test.local', 'test-ca-cert',
		         '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')`); err != nil {
		t.Fatalf("insert cluster: %v", err)
	}
	return &Server{hostName: "surviving-node", db: db}
}

// seedLostHostRow records the lost host with an exact incarnation. The row is
// what a retirement is revalidated against; with no row there is nothing to
// match and the premise stays owed.
func seedLostHostRow(t *testing.T, s *Server, name, incarnation string) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: name, Address: "192.0.2.10", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CertSerial: incarnation,
		FenceStrategy: "best-effort", CPUTotal: 8, MemTotal: 16384,
	}); err != nil {
		t.Fatalf("insert host row %q: %v", name, err)
	}
}

// recordRetirement writes one manifest plus the narrow grant that rests on it,
// exactly as RetireLostHost does, and returns the manifest id so a test can
// assert the advisory reports the reference an operator would follow.
func recordRetirement(t *testing.T, s *Server, host, incarnation string,
	premise corrosion.RetirementPremise, accounting ...string) string {

	t.Helper()
	ctx := context.Background()
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	id := "manifest-" + string(premise)
	at := "2026-09-08T10:00:00Z"
	if err := corrosion.InsertRecoveryManifest(ctx, s.db, corrosion.RecoveryManifest{
		ID: id, ClusterFingerprint: fp, HostName: host, HostIncarnation: incarnation,
		Premise: premise, Accounting: accounting,
		AttestedBy: "the-attesting-operator", AttestedAt: at,
	}); err != nil {
		t.Fatalf("InsertRecoveryManifest(%s): %v", premise, err)
	}
	if err := corrosion.InsertHostRetirement(ctx, s.db, corrosion.HostRetirement{
		ClusterFingerprint: fp, HostIncarnation: incarnation, Premise: premise,
		HostName: host, ManifestID: id,
		AttestedBy: "the-attesting-operator", AttestedAt: at,
	}); err != nil {
		t.Fatalf("InsertHostRetirement(%s): %v", premise, err)
	}
	return id
}

// retireInForce is the common fixture: a host recorded with an exact
// incarnation, not responding, with one premise retired against that
// incarnation. Every "stops applying" scenario starts from here and breaks one
// thing.
func retireInForce(t *testing.T, premises ...corrosion.RetirementPremise) *Server {
	t.Helper()
	s := newAttestationServer(t)
	seedLostHostRow(t, s, advisoryLostHost, advisoryIncarnation)
	for _, p := range premises {
		acc := []string{}
		if p == corrosion.PremiseInventory {
			// An inventory accounting may not be empty: an empty one retires the
			// premise with nothing behind it.
			acc = []string{"its unique address records were recovered onto a surviving node"}
		}
		recordRetirement(t, s, advisoryLostHost, advisoryIncarnation, p, acc...)
	}
	return s
}

// TestAdvisorySurfacesAnInForceAttestationWithItsIdentifyingElements is the
// visibility requirement: while a grant is supplying a premise there is a
// standing condition that says so, carrying everything a reviewer needs to
// find the assertion and judge it.
func TestAdvisorySurfacesAnInForceAttestationWithItsIdentifyingElements(t *testing.T) {
	s := retireInForce(t, corrosion.PremiseMembership)
	ctx := context.Background()

	s.evaluateAttestedPremises(ctx)

	got, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation)
	if !ok {
		t.Fatal("a retirement that is IN FORCE — validated now, supplying the membership " +
			"premise — raised no standing advisory. It authorises action and nothing says so")
	}
	if got.SubjectKind != attestedIncarnationSubjectKind {
		t.Errorf("subject_kind = %q, want %q: the subject is the INCARNATION, because a "+
			"hostname is reusable and two machines that answered to one name must not share "+
			"a row", got.SubjectKind, attestedIncarnationSubjectKind)
	}
	if got.Severity != corrosion.SeverityInfo {
		t.Errorf("severity = %q, want %q: the advisory must not page and must not degrade "+
			"the cluster — it reports a substitution an operator chose, not a fault",
			got.Severity, corrosion.SeverityInfo)
	}

	// THE FOUR IDENTIFYING ELEMENTS, each one something an operator has to have
	// to review the assertion or to find out how it ends.
	for _, want := range []struct{ what, needle string }{
		{"the host incarnation (the recorded certificate serial)", advisoryIncarnation},
		{"the recovery-manifest reference", "manifest-membership"},
		{"the premise it currently supplies", "membership"},
		{"the attesting operator", "the-attesting-operator"},
		{"the attestation timestamp", "2026-09-08T10:00:00Z"},
		{"how to inspect it", "lv netbox retirements"},
		{"that litevirt cannot check what was attested", "cannot check"},
		{"that recording it does not make it true", "does not make it true"},
		{"that it is NOT power-off evidence", "fence-confirm"},
	} {
		if !strings.Contains(got.Evidence, want.needle) {
			t.Errorf("the advisory does not name %s (%q missing).\nevidence: %s",
				want.what, want.needle, got.Evidence)
		}
	}
	// The lost host's NAME belongs there too — as a label, never as the identity.
	if !strings.Contains(got.Evidence, advisoryLostHost) {
		t.Errorf("the advisory does not name the host the attestation is about.\nevidence: %s",
			got.Evidence)
	}
}

// TestAdvisoryLabelsOnlyThePremisesItActuallySupplies is the mislabelling
// requirement, and it is the round-five conflation in advisory clothing.
//
// Membership accounting is not inventory accounting. A membership-only grant
// that read as supplying inventory would tell an operator that the lost host's
// unique VM/NIC rows had been accounted for when nothing had accounted for
// them — the exact belief this subsystem's bind refusal exists to prevent.
func TestAdvisoryLabelsOnlyThePremisesItActuallySupplies(t *testing.T) {
	for _, tc := range []struct {
		name     string
		retired  []corrosion.RetirementPremise
		want     []corrosion.RetirementPremise
		mustNot  string
		whyItsIt string
	}{{
		name:    "membership only",
		retired: []corrosion.RetirementPremise{corrosion.PremiseMembership},
		want:    []corrosion.RetirementPremise{corrosion.PremiseMembership},
		mustNot: string(corrosion.PremiseInventory),
		whyItsIt: "the lost host's digest of the address-bearing tables is still owed, and " +
			"an advisory that claimed otherwise would report an accounting nobody gave",
	}, {
		name:    "inventory only",
		retired: []corrosion.RetirementPremise{corrosion.PremiseInventory},
		want:    []corrosion.RetirementPremise{corrosion.PremiseInventory},
		mustNot: string(corrosion.PremiseMembership),
		whyItsIt: "the obligation to ask that host what it knew is untouched, so the closure " +
			"is still waiting for it",
	}, {
		name: "both",
		retired: []corrosion.RetirementPremise{
			corrosion.PremiseMembership, corrosion.PremiseInventory},
		want: []corrosion.RetirementPremise{
			corrosion.PremiseInventory, corrosion.PremiseMembership},
		whyItsIt: "two separate attestations were made, and both are in force",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			s := retireInForce(t, tc.retired...)

			sur := s.surveyAttestedPremises(context.Background())

			if len(sur.InForce) != 1 {
				t.Fatalf("in-force findings = %d, want 1 (%s)", len(sur.InForce), tc.whyItsIt)
			}
			got := sur.InForce[0].premises()
			if len(got) != len(tc.want) {
				t.Fatalf("premises supplied = %v, want %v — %s", got, tc.want, tc.whyItsIt)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("premises supplied = %v, want %v — %s", got, tc.want, tc.whyItsIt)
				}
			}
			if tc.mustNot == "" {
				return
			}
			for _, p := range got {
				if string(p) == tc.mustNot {
					t.Fatalf("a %s-only grant reads as supplying %s: %s",
						tc.retired[0], tc.mustNot, tc.whyItsIt)
				}
			}
			// And the same must be true of the operator-facing text, which is
			// what anybody actually reads.
			detail := sur.InForce[0].detail()
			if strings.Contains(detail, "supplying="+tc.mustNot) ||
				strings.Contains(detail, tc.mustNot+" premise is now supplied") {
				t.Fatalf("the advisory text claims the %s premise is supplied: %s",
					tc.mustNot, detail)
			}
		})
	}
}

// TestAdvisoryStopsShowingAGrantThatIsNoLongerInForce is the "recorded is not in
// force" requirement. Showing a grant that has stopped applying as if it still
// authorised something is worse than showing nothing: it invites an operator to
// reason about an exception that is not there.
//
// Each case is one of the ways a grant lapses, and every one of them is detected
// on the READ with nothing written and no operator action.
func TestAdvisoryStopsShowingAGrantThatIsNoLongerInForce(t *testing.T) {
	for _, tc := range []struct {
		name string
		// lapse runs after the retirement is recorded and in force.
		lapse func(t *testing.T, s *Server)
		// stillRecorded says the grant is still a row (so it must appear as NOT
		// in force); a revoked grant is gone from the records entirely.
		stillRecorded bool
		why           string
	}{{
		name: "revoked",
		lapse: func(t *testing.T, s *Server) {
			// A revocation is a tombstone on the grant. There is no revocation
			// column and no `lv` verb: this is what withdrawing one looks like
			// in the rows, and the read side filters it out.
			if err := s.db.Execute(context.Background(),
				`UPDATE netbox_host_retirements SET deleted_at = ?, updated_at = ?
				   WHERE host_incarnation = ?`,
				"2026-09-08T11:00:00Z", s.db.NowTS(), advisoryIncarnation); err != nil {
				t.Fatalf("revoke the retirement: %v", err)
			}
		},
		why: "a revoked grant excuses nothing, so it must not appear as usable evidence",
	}, {
		name: "the incarnation was replaced",
		lapse: func(t *testing.T, s *Server) {
			if err := s.db.Execute(context.Background(),
				`UPDATE hosts SET cert_serial = ?, updated_at = ? WHERE name = ?`,
				advisoryReplacement, s.db.NowTS(), advisoryLostHost); err != nil {
				t.Fatalf("re-admit under a new incarnation: %v", err)
			}
		},
		stillRecorded: true,
		why: "a different machine now answers to that name, and a re-admission does not " +
			"inherit its predecessor's exception",
	}, {
		name: "the host record is gone",
		lapse: func(t *testing.T, s *Server) {
			if err := s.db.Execute(context.Background(),
				`DELETE FROM hosts WHERE name = ?`, advisoryLostHost); err != nil {
				t.Fatalf("delete the host row: %v", err)
			}
		},
		stillRecorded: true,
		why: "with no recorded incarnation there is nothing to match the grant against, so " +
			"the premise stays owed",
	}, {
		name: "the host is responding again",
		lapse: func(_ *testing.T, s *Server) {
			// Reachable again: whatever was attested about it, it is not gone,
			// and its live state governs.
			s.gate = fakeServerGate{healthy: []string{advisoryLostHost}}
		},
		stillRecorded: true,
		why:           "a machine that answers refutes the attestation that it was lost",
	}} {
		t.Run(tc.name, func(t *testing.T) {
			s := retireInForce(t, corrosion.PremiseMembership)
			ctx := context.Background()

			// The positive control: it IS in force first, so the assertion below
			// cannot pass against a build that never surfaces anything.
			s.evaluateAttestedPremises(ctx)
			if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); !ok {
				t.Fatal("the grant was not in force before the lapse — fixture is wrong, and " +
					"every assertion below would pass for the wrong reason")
			}

			tc.lapse(t, s)
			sur := s.surveyAttestedPremises(ctx)

			if len(sur.InForce) != 0 {
				t.Fatalf("%s: %s — the advisory still reports it as in force: %+v",
					tc.name, tc.why, sur.InForce)
			}
			if tc.stillRecorded && len(sur.NotInForce) == 0 {
				t.Fatalf("%s: the grant is still recorded, so it must be surveyed as NOT in "+
					"force rather than vanishing — three states, not two", tc.name)
			}
			// And it must not read as uncertainty either: this is a settled
			// answer, not a validation that could not complete.
			if len(sur.Unvalidatable) != 0 {
				t.Fatalf("%s: a lapsed grant was reported as unvalidatable: %+v",
					tc.name, sur.Unvalidatable)
			}

			// The standing condition clears on the durable-condition model: two
			// consecutive clean passes, so one probe racing a restart cannot
			// resolve it.
			s.evaluateAttestedPremises(ctx)
			s.evaluateAttestedPremises(ctx)
			got, _ := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation)
			if got.Lifecycle != corrosion.ConditionResolved {
				t.Fatalf("%s: lifecycle = %q, want %q — %s",
					tc.name, got.Lifecycle, corrosion.ConditionResolved, tc.why)
			}
		})
	}
}

// TestAdvisoryShowsOnlyTheCurrentIncarnationsGrant is the SUPERSEDED case, and
// the one shape a hostname-keyed answer gets wrong.
//
// A replacement machine can be permanently lost too, so one hostname can carry
// several grants — one per incarnation that ever answered to it. Only the grant
// written against the incarnation the cluster records NOW is in force; its
// predecessor was superseded the moment a different machine was admitted under
// that name, and a re-admission inherits nothing.
//
// The premise resolvers are keyed by host NAME, because that is what their
// consumers have in hand and revalidation has already matched the name to its
// current incarnation. A surface holding a SPECIFIC grant has to ask the
// stronger question, or it reports a superseded exception as though it still
// authorised something — with the same host name, the same operator and the same
// wording as the live one, which is the worst possible way to be wrong.
func TestAdvisoryShowsOnlyTheCurrentIncarnationsGrant(t *testing.T) {
	s := newAttestationServer(t)
	ctx := context.Background()
	// The machine answering to this name NOW is the replacement.
	seedLostHostRow(t, s, advisoryLostHost, advisoryReplacement)
	// Both incarnations were attested lost: the original, then its replacement.
	recordRetirement(t, s, advisoryLostHost, advisoryIncarnation, corrosion.PremiseMembership)
	recordRetirement(t, s, advisoryLostHost, advisoryReplacement, corrosion.PremiseMembership)

	sur := s.surveyAttestedPremises(ctx)

	if len(sur.InForce) != 1 {
		t.Fatalf("in-force grants = %d, want 1: only the grant written against the "+
			"incarnation the cluster records now applies. Got %+v", len(sur.InForce), sur.InForce)
	}
	if got := sur.InForce[0].Incarnation; got != advisoryReplacement {
		t.Fatalf("in force = incarnation %s, want %s (the one currently recorded)",
			got, advisoryReplacement)
	}
	var supersededSurveyed bool
	for _, l := range sur.NotInForce {
		if l.Incarnation == advisoryIncarnation {
			supersededSurveyed = true
		}
	}
	if !supersededSurveyed {
		t.Error("the superseded grant is still recorded, so it must be surveyed as NOT in " +
			"force rather than vanishing")
	}

	s.evaluateAttestedPremises(ctx)
	if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); ok {
		t.Error("the SUPERSEDED grant has a standing advisory: it authorises nothing, and a " +
			"row that names the same host and the same operator as the live one is the " +
			"hardest kind of wrong to notice")
	}
	if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryReplacement); !ok {
		t.Error("the grant that IS in force has no advisory")
	}
}

// TestAdvisoryReportsUnvalidatableSeparatelyAndWithholdsThePremise is the third
// state, and the one most likely to be collapsed into two.
//
// A validation that cannot complete is NOT "in force" and NOT "lapsed". An
// unvalidatable attestation supplies no premise, so it must not appear in the
// in-force list; and the uncertainty is itself a thing an operator has to know,
// so it must appear SOMEWHERE — on its own surface.
func TestAdvisoryReportsUnvalidatableSeparatelyAndWithholdsThePremise(t *testing.T) {
	s := retireInForce(t, corrosion.PremiseMembership)
	ctx := context.Background()

	// The positive control first.
	s.evaluateAttestedPremises(ctx)
	if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); !ok {
		t.Fatal("the grant was not in force before the read was broken — fixture is wrong")
	}

	// Break the read the revalidation depends on. Renaming the table is the only
	// way to make a SELECT fail: SQLite has no BEFORE SELECT trigger, and a
	// missing table is what an unavailable or corrupt one yields.
	if err := s.db.Execute(ctx, `ALTER TABLE hosts RENAME TO hosts_hidden_by_test`); err != nil {
		t.Fatalf("hide the hosts table: %v", err)
	}

	sur := s.surveyAttestedPremises(ctx)
	if len(sur.InForce) != 0 {
		t.Fatalf("a grant whose validity could not be established was reported as IN FORCE: "+
			"%+v. An unvalidatable attestation supplies no premise", sur.InForce)
	}
	if len(sur.Unvalidatable) == 0 {
		t.Fatal("validation could not complete and nothing said so. Silence here is the worst " +
			"answer: the grant may still be authorising action and nothing can establish it")
	}

	// THE PREMISE IS WITHHELD MEANWHILE. This is the half that matters most:
	// the consumer must get an error, not an empty map that reads as "nothing
	// is retired" — the two lead to opposite decisions.
	if _, err := s.membershipRetirementsFor(ctx, []string{advisoryLostHost}); err == nil {
		t.Fatal("the membership premise resolver returned success while the revalidation " +
			"could not be performed. An unvalidatable attestation must withhold, not resolve " +
			"to 'nothing is retired'")
	}

	s.evaluateAttestedPremises(ctx)

	// SEPARATE SURFACE, not folded in: its own code, on its own subject.
	if _, ok := netboxCondition(t, s, condNetBoxAttestationUnvalidatable, netboxSweepSubject); !ok {
		t.Fatal("the uncertainty has no surface of its own")
	}
	// And the in-force advisory must NOT have been clean-counted towards
	// resolution: a pass that could not read observed nothing, and silence is
	// not a clean pass.
	standing, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation)
	if !ok {
		t.Fatal("the standing advisory disappeared during a pass that could establish nothing")
	}
	if standing.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("a pass that could not validate anything RESOLVED the standing advisory. " +
			"That is the collapse this state exists to prevent: uncertainty reported as an " +
			"all-clear")
	}
	if standing.CleanCount != 0 {
		t.Errorf("clean_count = %d, want 0: a pass that could not read must not count as a "+
			"clean one", standing.CleanCount)
	}
}

// TestTheAdvisoryIsInertClearingItNeitherRevokesNorValidates is the "view, not a
// control" requirement, pinned in BOTH directions because each is wrong in its
// own way.
//
// One direction would let a display silently destroy a grant an operator
// deliberately recorded. The other would let dismissing a warning launder an
// attestation into evidence. Nothing about the advisory row may be an input to
// whether a premise is supplied.
func TestTheAdvisoryIsInertClearingItNeitherRevokesNorValidates(t *testing.T) {
	t.Run("clearing it does not revoke the retirement", func(t *testing.T) {
		s := retireInForce(t, corrosion.PremiseMembership)
		ctx := context.Background()
		s.evaluateAttestedPremises(ctx)
		if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); !ok {
			t.Fatal("the advisory was not raised — fixture is wrong")
		}

		clearEveryCondition(t, s)
		// The pass that sees NO advisory row at all — the one that would have to
		// misread its own absence as a withdrawal. Run BEFORE the assertions, so
		// a build that treated a missing row as a revocation fails here rather
		// than passing because nothing had recomputed yet.
		s.evaluateAttestedPremises(ctx)

		// The grant is untouched...
		fp, err := corrosion.ClusterFingerprint(ctx, s.db)
		if err != nil {
			t.Fatalf("ClusterFingerprint: %v", err)
		}
		grants, err := corrosion.ListHostRetirements(ctx, s.db, fp, corrosion.PremiseMembership)
		if err != nil {
			t.Fatalf("ListHostRetirements: %v", err)
		}
		if _, ok := grants[advisoryIncarnation]; !ok {
			t.Fatal("clearing the advisory DESTROYED the retirement. The advisory is a view: " +
				"a display must never be able to revoke a grant an operator recorded")
		}
		// ...and still supplies its premise, which is the thing that matters.
		applicable, err := s.membershipRetirementsFor(ctx, []string{advisoryLostHost})
		if err != nil {
			t.Fatalf("membershipRetirementsFor: %v", err)
		}
		if !applicable.retired(advisoryLostHost) {
			t.Fatal("clearing the advisory stopped the membership premise being supplied. " +
				"Clearing a view must not change what the proofs act on")
		}
		// And that pass simply said so again — the standing condition is derived
		// on every pass and remembered between none.
		if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); !ok {
			t.Fatal("the advisory did not come back after being cleared, so the grant is now " +
				"authorising action with nothing saying so")
		}
	})

	t.Run("clearing it does not validate the retirement", func(t *testing.T) {
		s := retireInForce(t, corrosion.PremiseMembership)
		ctx := context.Background()
		// A grant whose validation cannot complete: the state where a reader
		// might be tempted to treat the operator's dismissal as an answer.
		if err := s.db.Execute(ctx, `ALTER TABLE hosts RENAME TO hosts_hidden_by_test`); err != nil {
			t.Fatalf("hide the hosts table: %v", err)
		}
		s.evaluateAttestedPremises(ctx)
		if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); ok {
			t.Fatal("a grant whose validation could not complete was advertised as IN FORCE. " +
				"An unvalidatable attestation supplies no premise, whatever any surface says " +
				"about it")
		}
		if _, ok := netboxCondition(t, s, condNetBoxAttestationUnvalidatable, netboxSweepSubject); !ok {
			t.Fatal("no uncertainty was raised for a grant that could not be revalidated, so " +
				"there is nothing for an operator to clear and nothing below is being tested")
		}

		clearEveryCondition(t, s)
		s.evaluateAttestedPremises(ctx)

		// Dismissing the warning changed nothing about the grant.
		if _, err := s.membershipRetirementsFor(ctx, []string{advisoryLostHost}); err == nil {
			t.Fatal("clearing the advisory VALIDATED the retirement: the premise resolver now " +
				"answers where it could not before. Dismissing a warning must never launder " +
				"an attestation into evidence")
		}
		sur := s.surveyAttestedPremises(ctx)
		if len(sur.InForce) != 0 {
			t.Fatalf("clearing the advisory promoted an unvalidatable grant to IN FORCE: %+v",
				sur.InForce)
		}
		if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); ok {
			t.Fatal("an in-force advisory appeared for a grant nothing could validate, after " +
				"the uncertainty was cleared")
		}
	})

	t.Run("clearing it does not validate a lapsed retirement", func(t *testing.T) {
		s := retireInForce(t, corrosion.PremiseMembership)
		ctx := context.Background()
		if err := s.db.Execute(ctx,
			`UPDATE hosts SET cert_serial = ?, updated_at = ? WHERE name = ?`,
			advisoryReplacement, s.db.NowTS(), advisoryLostHost); err != nil {
			t.Fatalf("re-admit under a new incarnation: %v", err)
		}

		clearEveryCondition(t, s)
		s.evaluateAttestedPremises(ctx)

		if _, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation); ok {
			t.Fatal("a lapsed grant appeared as in force after the conditions were cleared")
		}
		applicable, err := s.membershipRetirementsFor(ctx, []string{advisoryLostHost})
		if err != nil {
			t.Fatalf("membershipRetirementsFor: %v", err)
		}
		if applicable.retired(advisoryLostHost) {
			t.Fatal("clearing the advisory made a replaced incarnation's retirement apply again")
		}
	})
}

// clearEveryCondition removes every health condition row — the strongest form of
// "the advisory was cleared", stronger than any resolve an operator could
// perform, since the row is gone rather than marked.
func clearEveryCondition(t *testing.T, s *Server) {
	t.Helper()
	if err := s.db.Execute(context.Background(), `DELETE FROM health_conditions`); err != nil {
		t.Fatalf("clear the health conditions: %v", err)
	}
}

// TestTheAdvisoryGatesNothing is the requirement that has to be ASSERTED rather
// than inspected. An earlier round on this branch found a condition that gated
// nothing only by accident; here gating nothing is the specification.
//
// It exercises the real admission paths with the advisory standing and
// CONFIRMED, which is the strongest form a condition takes.
func TestTheAdvisoryGatesNothing(t *testing.T) {
	s := retireInForce(t, corrosion.PremiseMembership, corrosion.PremiseInventory)
	ctx := context.Background()
	s.evaluateAttestedPremises(ctx)
	s.evaluateAttestedPremises(ctx) // observed → confirmed

	standing, ok := netboxCondition(t, s, condNetBoxPremiseAttested, advisoryIncarnation)
	if !ok || standing.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("fixture: want a CONFIRMED advisory, got ok=%v lifecycle=%q",
			ok, standing.Lifecycle)
	}
	// The uncertainty surface, active at the same time — neither may gate.
	seedUnvalidatableCondition(t, s)

	// 1. THE ADMISSION GATE'S OWN LIST. A code absent from it cannot refuse
	//    anything through checkHostSafety's ownership clause.
	for _, code := range []string{condNetBoxPremiseAttested, condNetBoxAttestationUnvalidatable} {
		if ownershipConditionCodes[code] {
			t.Errorf("%s is in ownershipConditionCodes, so it blocks capacity-growing "+
				"admission and every runtime-changing action on its subject. This advisory "+
				"reports a substitution an operator chose; it must block nothing", code)
		}
	}

	// 2. ALLOCATION. A create/start/migrate-in that GROWS capacity on a remote
	//    host — the case the host-involvement clause exists for. The host is
	//    remote so the local-inventory probe (which needs libvirt) is not what
	//    the answer turns on.
	if err := s.checkHostSafety(ctx, "another-node", "", "", true, true); err != nil {
		t.Errorf("the advisory refused a capacity-growing admission: %v", err)
	}

	// 3. EXECUTION. A runtime-changing action on a workload that happens to be
	//    NAMED like the advisory's subject — the workload-scoped clause.
	if err := s.checkHostSafety(ctx, "another-node", corrosion.WorkloadVM,
		advisoryIncarnation, false, false); err != nil {
		t.Errorf("the advisory refused a runtime-changing action: %v", err)
	}
	if err := s.checkHostSafety(ctx, "another-node", corrosion.WorkloadContainer,
		advisoryLostHost, false, false); err != nil {
		t.Errorf("the advisory refused a container action: %v", err)
	}

	// 4. VIP OWNERSHIP, the other condition-driven gate.
	if err := s.checkVIPSafety(ctx, advisoryIncarnation); err != nil {
		t.Errorf("the advisory refused a VIP ownership change: %v", err)
	}
}

// seedUnvalidatableCondition raises the uncertainty condition directly, so a
// test can have both surfaces active without breaking a read.
func seedUnvalidatableCondition(t *testing.T, s *Server) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: netboxEvaluator, Code: condNetBoxAttestationUnvalidatable,
		SubjectKind: "cluster", SubjectID: netboxSweepSubject,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
		Evidence: "seeded", ObserveCount: 2, FirstSeen: now, LastSeen: now, ConfirmedAt: now,
		Reporter: s.hostName,
	}); err != nil {
		t.Fatalf("seed the uncertainty condition: %v", err)
	}
}

// TestTheStandingAdvisoryDoesNotPage is the other half of "blocks nothing": a
// condition that turned `lv health` amber for the life of a cluster would be
// read as a fault, and the exit code is what a monitor acts on.
//
// The roll-up's INFO tier is what makes a standing advisory possible at all. The
// warning case is the control: it keeps this test from passing against a
// roll-up that had stopped noticing conditions entirely.
func TestTheStandingAdvisoryDoesNotPage(t *testing.T) {
	fresh := []corrosion.HealthEvaluatorStatus{{
		Evaluator: "dual_run", LastScan: time.Now().UTC().Format(time.RFC3339),
		Coverage: corrosion.CoverageComplete,
	}}
	advisory := corrosion.HealthCondition{
		Evaluator: netboxEvaluator, Code: condNetBoxPremiseAttested,
		SubjectKind: attestedIncarnationSubjectKind, SubjectID: advisoryIncarnation,
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityInfo,
	}
	if got := overallHealth([]corrosion.HealthCondition{advisory}, fresh, nil, time.Now().UTC()); got != HealthHealthy {
		t.Errorf("overall = %q, want %q: a standing INFO advisory must not degrade the "+
			"cluster. `lv health` exits non-zero on DEGRADED, so this one would page for as "+
			"long as the retirement stood", got, HealthHealthy)
	}
	warning := advisory
	warning.Severity = corrosion.SeverityWarning
	if got := overallHealth([]corrosion.HealthCondition{warning}, fresh, nil, time.Now().UTC()); got != HealthDegraded {
		t.Errorf("overall = %q, want %q: a WARNING condition must still degrade — without "+
			"this the test above would pass against a roll-up that ignored conditions", got, HealthDegraded)
	}
}
