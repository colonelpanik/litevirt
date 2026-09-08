package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ── A STANDING ADVISORY FOR EVERY PREMISE RESTING ON AN ATTESTATION ─────────
//
// WHY A STANDING SURFACE AND NOT A TRANSITION. Every other premise in this
// subsystem degrades LOUDLY when it stops being provable: a peer that will not
// answer leaves the membership closure open, a digest that disagrees suspends
// the bind, a runtime that cannot be scanned aborts the reclamation. An operator
// finds out because something refuses.
//
// A RETIREMENT DEGRADES SILENTLY, BY DESIGN. That is what it is for — it
// substitutes human-established evidence for machine evidence a destroyed
// machine can no longer produce, so the proof completes and nothing refuses.
// litevirt CANNOT CHECK what was attested, and recording it DOES NOT MAKE IT
// TRUE: an audit row establishes who claimed something, not whether the claim
// was correct. So for as long as a grant is AUTHORISING ACTION, something has to
// say so — without anyone having had to be watching at the moment it was
// written, days or months earlier, possibly by somebody who has since left.
//
// WHAT THIS DOES NOT DO, and saying it here is part of the point: closing this
// gap does not establish the correctness of the attested facts and is not a
// substitute for reviewing them. It makes the trust VISIBLE. Nothing more.
//
// IT IS A VIEW, NEVER A CONTROL. Two failures are available here and they are
// opposite, so both are foreclosed structurally rather than by care:
//
//   - If clearing the advisory could REVOKE the grant, a display would be able
//     to destroy an exception an operator deliberately recorded — and the next
//     proof would silently start withholding with no record of why.
//   - If clearing the advisory could VALIDATE the grant, dismissing a warning
//     would launder an attestation into evidence. Nothing about the condition
//     row is an input to whether a premise is supplied: the survey below DERIVES
//     its answer from the premise resolvers on every pass and remembers nothing.
//
// The mechanism is that this file writes to exactly one table — health_conditions
// — and the premise resolvers read from none of it. Guarded structurally in
// netbox_attestation_advisory_guard_test.go.
//
// IT MUST NEVER READ AS POWER-OFF EVIDENCE. A retirement excuses knowing what a
// machine KNEW or what ROWS it held. Neither says anything about whether its
// libvirt is running a domain, and there is no retirement for that premise at
// all: runtime exclusion still requires fencing evidence. The advisory sits
// BESIDE that, never over it, so it says so in as many words and is neither
// named nor grouped with anything fencing-shaped.
//
// IT GATES NOTHING. Not allocation, not quorum, not execution. The code appears
// in no gating list, and the standing form carries INFO severity so it does not
// degrade the cluster roll-up — a permanent amber would be read as a permanent
// fault. An earlier round on this branch found a condition that gated nothing
// only by accident; here that is the requirement, so it is asserted rather than
// left to inspection.

const (
	// condNetBoxPremiseAttested is the STANDING advisory: a NetBox proof premise
	// is being supplied right now by an operator's attestation rather than by
	// machine evidence.
	//
	// Deliberately named for the PREMISE and not for the host. A code that read
	// as "host retired" or "host lost" would be grouped with fencing by anybody
	// skimming `lv health`, and the one thing a retirement can never supply is
	// power-off evidence.
	condNetBoxPremiseAttested = "netbox_premise_attested"

	// condNetBoxAttestationUnvalidatable is the THIRD state on its own surface:
	// a recorded retirement whose validity this pass could not establish.
	//
	// A SEPARATE CODE, never a field on the advisory above, because it means the
	// opposite thing. The advisory says "this grant is supplying a premise"; this
	// says "we cannot tell whether it is", and reliance is withheld while it
	// lasts. Folding the two would present uncertainty as evidence, which is the
	// single worst answer available here.
	condNetBoxAttestationUnvalidatable = "netbox_attestation_unvalidatable"
)

// attestedIncarnationSubjectKind is the standing advisory's subject kind: the
// host INCARNATION, which is the recorded certificate serial.
//
// NOT the hostname, and that is the same reason the retirement itself names an
// incarnation. A hostname is the `hosts` primary key and is meant to be reused,
// so two machines that answered to one name would share a condition row: the
// replacement's advisory would overwrite the predecessor's under LWW, and a
// grant could appear to have moved to a machine that inherited nothing. Keyed on
// the incarnation, each machine gets its own row — the leak direction.
const attestedIncarnationSubjectKind = "host_incarnation"

// attestationSurveySubject is the cluster-wide subject of the uncertainty
// finding. The same string netboxSweepSubject carries, because it is the same
// singular subject — this cluster's NetBox reasoning — and condition identity
// includes the CODE, so the two findings are separate rows that cannot collide.
const attestationSurveySubject = netboxSweepSubject

// attestedGrant is one narrow grant that is IN FORCE, with everything a reviewer
// needs to find the assertion behind it.
type attestedGrant struct {
	Premise    corrosion.RetirementPremise
	ManifestID string
	AttestedBy string
	AttestedAt string
}

// attestedPremiseAdvisory is one host incarnation's in-force grants — the
// standing advisory's content for one subject.
type attestedPremiseAdvisory struct {
	// Incarnation is the recorded certificate serial: the identity.
	Incarnation string
	// HostName is a LABEL for an operator reading the row. Nothing matches on
	// it; see attestedIncarnationSubjectKind.
	HostName string
	// Grants are the premises IN FORCE right now, sorted by premise. Never
	// empty: an incarnation with nothing in force produces no advisory at all.
	Grants []attestedGrant
}

// premises is the premises this grant currently supplies, sorted.
//
// ONLY the ones validated on this pass. A premise that was retired but is no
// longer honoured, or that could not be revalidated, is absent — those are the
// other two states and they have their own places to be.
func (a attestedPremiseAdvisory) premises() []corrosion.RetirementPremise {
	out := make([]corrosion.RetirementPremise, 0, len(a.Grants))
	for _, g := range a.Grants {
		out = append(out, g.Premise)
	}
	return out
}

// detail is the operator-facing evidence.
//
// It carries the four identifying elements — the retirement's identity and the
// host's certificate serial, which premises it currently supplies, who attested
// it and when together with the recovery-manifest reference, and how to inspect
// it and what ends it — plus the two things it must never be read as implying.
func (a attestedPremiseAdvisory) detail() string {
	names := make([]string, 0, len(a.Grants))
	lines := make([]string, 0, len(a.Grants))
	for _, g := range a.Grants {
		names = append(names, string(g.Premise))
		lines = append(lines, fmt.Sprintf(
			"%s (retirement %s/%s, resting on recovery manifest %s, attested by %s at %s)",
			g.Premise, a.Incarnation, g.Premise, g.ManifestID, g.AttestedBy, g.AttestedAt))
	}
	return fmt.Sprintf(
		"NetBox proof premises for host %q rest on an operator's attestation rather than on "+
			"machine evidence (supplying=%s). The grant applies to incarnation %s — the "+
			"certificate serial recorded for that exact machine, never the reusable hostname. "+
			"In force now: %s. "+
			"litevirt cannot check what was attested, and recording it does not make it true: "+
			"this advisory makes the substitution visible and establishes nothing about the "+
			"attested facts. "+
			"IT IS NOT EVIDENCE THAT THE MACHINE IS POWERED OFF and cannot become any: "+
			"excluding a runtime still requires fencing evidence (`lv host fence-confirm`). "+
			"Review the accounting with `lv netbox retirements`. Nothing withdraws a "+
			"retirement by hand — it stops applying on its own once the host answers again, "+
			"or once a different machine is admitted under its name.",
		a.HostName, strings.Join(names, ","), a.Incarnation, strings.Join(lines, "; "))
}

// lapsedAttestation is a grant that is RECORDED but NOT IN FORCE: revoked,
// superseded by a replaced incarnation, or invalidated by a rejoin.
//
// Surveyed so the three states are three in the code as well as in the docs, and
// so a test can assert that a lapsed grant lands here rather than vanishing into
// the same silence as a grant that was never recorded. It is deliberately NOT
// published as a condition: a grant that has stopped applying authorises
// nothing, and showing it as though it still did is worse than showing nothing.
type lapsedAttestation struct {
	Incarnation string
	HostName    string
	Premise     corrosion.RetirementPremise
}

// unvalidatableAttestation is the THIRD state: validation could not complete.
//
// Because is what could not be established, in the operator's terms. Grants
// names the affected identities when they are known — when the failure was the
// read that ENUMERATES the grants, they are not, and saying so is the honest
// answer.
type unvalidatableAttestation struct {
	Premise corrosion.RetirementPremise
	Because string
	Grants  []string
}

// attestationSurvey is THE THREE STATES, and it exists as one type so that
// nothing can quietly become two.
//
// Only InForce may ever be presented as usable evidence. NotInForce is recorded
// and no longer honoured. Unvalidatable is neither: reliance on those grants is
// withheld by the premise resolvers themselves (they return an error, which
// every consumer treats as "the premise is still owed"), and this surface exists
// so the withholding is not silent.
type attestationSurvey struct {
	InForce       []attestedPremiseAdvisory
	NotInForce    []lapsedAttestation
	Unvalidatable []unvalidatableAttestation

	// blind is set when this pass could not even ENUMERATE the recorded grants.
	// It is not merely one more uncertainty: it means an existing advisory may
	// describe a grant this pass cannot see, so no subject may be clean-counted
	// towards resolution.
	blind bool
	// uncertain is the incarnations this pass could not fully validate, keyed by
	// incarnation. Same rule, per subject.
	uncertain map[string]bool
}

// uncertainAbout reports whether this pass established too little to treat
// `incarnation` as clean. Silence is not a clean pass.
func (sur attestationSurvey) uncertainAbout(incarnation string) bool {
	return sur.blind || sur.uncertain[incarnation]
}

// surveyAttestedPremises classifies every recorded retirement into exactly one
// of the three states.
//
// IN FORCE IS DECIDED BY THE PREMISE'S OWN RESOLVER, never by a second copy of
// the validity rules. That is the whole design of this function: an advisory that
// re-derived "does this still apply" would be a fourth reading of a rule this
// branch has already had to correct three times, and the first drift between the
// two would produce the worst possible output — a surface reporting that a
// premise is supplied while the proof withholds, or the reverse. So the
// membership answer comes from membershipRetirementsFor and the inventory answer
// from inventoryRetirementsFor: the same functions, with the same revalidation,
// that the closure and the bind act on.
//
// The premise-to-resolver pairing is the one thing a mistake here could corrupt
// invisibly (the two maps have identical shape), so each pairing is written once,
// beside its own premise literal, and the resolver's own method value is what
// answers — a swap would have to be deliberate, and a guard fails it.
//
// A READ THAT FAILS IS NEVER FOLDED INTO AN ANSWER. Each failure lands in
// Unvalidatable and marks its subjects uncertain; nothing is inferred from it.
func (s *Server) surveyAttestedPremises(ctx context.Context) attestationSurvey {
	sur := attestationSurvey{uncertain: map[string]bool{}}
	if s.db == nil {
		sur.blind = true
		sur.Unvalidatable = append(sur.Unvalidatable, unvalidatableAttestation{
			Because: "this node has no cluster database, so no recorded retirement can be revalidated",
		})
		return sur
	}
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		// Not "nothing is retired": retirements are scoped by cluster
		// fingerprint, so without one nothing can be matched to this
		// installation — which is a different fact with a different remedy.
		sur.blind = true
		sur.Unvalidatable = append(sur.Unvalidatable, unvalidatableAttestation{
			Because: fmt.Sprintf("the cluster fingerprint could not be read (%v), so no "+
				"recorded retirement can be matched to this installation", err),
		})
		return sur
	}

	// The RECORDED grants, per premise. Premise-scoped at the query, like every
	// other read of this table: a caller that received all of them would have to
	// filter, and a caller that forgot would treat a membership grant as an
	// inventory one.
	recorded := map[corrosion.RetirementPremise][]corrosion.HostRetirement{}
	candidates := map[string]bool{}
	for _, premise := range []corrosion.RetirementPremise{
		corrosion.PremiseMembership, corrosion.PremiseInventory,
	} {
		byIncarnation, err := corrosion.ListHostRetirements(ctx, s.db, fp, premise)
		if err != nil {
			// The enumeration itself failed, so an existing advisory may name a
			// grant this pass cannot see.
			sur.blind = true
			sur.Unvalidatable = append(sur.Unvalidatable, unvalidatableAttestation{
				Premise: premise,
				Because: fmt.Sprintf("the recorded %s retirements could not be read (%v)",
					premise, err),
			})
			continue
		}
		for _, r := range byIncarnation {
			recorded[premise] = append(recorded[premise], r)
			candidates[r.HostName] = true
		}
	}
	names := sortedNames(candidates)

	// THE PREMISE-TO-RESOLVER PAIRINGS. One site each, each next to its own
	// premise literal, each taking that resolver's own predicate.
	//
	// appliesToIncarnation, never `retired`: the resolvers are keyed by host NAME
	// because that is what their consumers hold, but this reader holds a SPECIFIC
	// grant and one hostname can carry several — a replacement machine can be
	// permanently lost too. Asked by name alone, a superseded grant answers true.
	inForce := map[corrosion.RetirementPremise]func(host, incarnation string) bool{}
	if len(recorded[corrosion.PremiseMembership]) > 0 {
		applicable, err := s.membershipRetirementsFor(ctx, names)
		if err != nil {
			sur.noteUnvalidatable(corrosion.PremiseMembership,
				recorded[corrosion.PremiseMembership], err)
		} else {
			inForce[corrosion.PremiseMembership] = applicable.appliesToIncarnation
		}
	}
	if len(recorded[corrosion.PremiseInventory]) > 0 {
		applicable, err := s.inventoryRetirementsFor(ctx, names)
		if err != nil {
			sur.noteUnvalidatable(corrosion.PremiseInventory,
				recorded[corrosion.PremiseInventory], err)
		} else {
			inForce[corrosion.PremiseInventory] = applicable.appliesToIncarnation
		}
	}

	// Fold each grant into exactly one state. A premise with no resolver answer
	// is already accounted for above and contributes to NEITHER of the other
	// two: an unvalidatable attestation supplies no premise, and it has not
	// lapsed either.
	byIncarnation := map[string]*attestedPremiseAdvisory{}
	var order []string
	for _, premise := range []corrosion.RetirementPremise{
		corrosion.PremiseMembership, corrosion.PremiseInventory,
	} {
		applies, resolved := inForce[premise]
		if !resolved {
			continue
		}
		for _, r := range recorded[premise] {
			if !applies(r.HostName, r.HostIncarnation) {
				sur.NotInForce = append(sur.NotInForce, lapsedAttestation{
					Incarnation: r.HostIncarnation, HostName: r.HostName, Premise: r.Premise,
				})
				continue
			}
			a, ok := byIncarnation[r.HostIncarnation]
			if !ok {
				a = &attestedPremiseAdvisory{
					Incarnation: r.HostIncarnation, HostName: r.HostName,
				}
				byIncarnation[r.HostIncarnation] = a
				order = append(order, r.HostIncarnation)
			}
			a.Grants = append(a.Grants, attestedGrant{
				Premise: r.Premise, ManifestID: r.ManifestID,
				AttestedBy: r.AttestedBy, AttestedAt: r.AttestedAt,
			})
		}
	}
	sort.Strings(order)
	for _, inc := range order {
		a := byIncarnation[inc]
		sort.Slice(a.Grants, func(i, j int) bool { return a.Grants[i].Premise < a.Grants[j].Premise })
		sur.InForce = append(sur.InForce, *a)
	}
	sort.Slice(sur.NotInForce, func(i, j int) bool {
		if sur.NotInForce[i].Incarnation != sur.NotInForce[j].Incarnation {
			return sur.NotInForce[i].Incarnation < sur.NotInForce[j].Incarnation
		}
		return sur.NotInForce[i].Premise < sur.NotInForce[j].Premise
	})
	return sur
}

// noteUnvalidatable records a premise whose revalidation could not be performed,
// and marks every incarnation it covers uncertain so no clean pass is counted
// for them.
func (sur *attestationSurvey) noteUnvalidatable(premise corrosion.RetirementPremise,
	grants []corrosion.HostRetirement, err error) {

	ids := make([]string, 0, len(grants))
	for _, g := range grants {
		ids = append(ids, g.HostIncarnation)
		sur.uncertain[g.HostIncarnation] = true
	}
	sort.Strings(ids)
	sur.Unvalidatable = append(sur.Unvalidatable, unvalidatableAttestation{
		Premise: premise,
		Because: fmt.Sprintf("the %s retirements could not be revalidated (%v), so whether "+
			"they still apply is unknown and the premise stays owed", premise, err),
		Grants: ids,
	})
}

// evaluateAttestedPremises advances both surfaces from one survey.
//
// WRITTEN FROM THE SWEEP, which runs under the `netbox` leader lease — so the
// cluster has one writer at a time, which is what the LWW row merge assumes, and
// the reachability view the advisory reports is the same one the sweep's own
// premise resolution acted on. A per-node evaluation would have every node
// writing the same subject from its own view of who is answering.
//
// NO SECOND CADENCE AND NO SECOND CHANNEL. It rides the maintenance pass and
// writes health conditions through the same helper the other NetBox findings
// use, which logs on TRANSITIONS ONLY — activation when the condition is
// observed and confirmed, invalidation and revocation when it resolves — and
// leaves the standing condition in place between them. There is deliberately no
// audit row and no notification per pass: recording the attestation was the
// audited event, and re-announcing it every fifteen minutes would train an
// operator to ignore the one surface that has to stay legible for months.
func (s *Server) evaluateAttestedPremises(ctx context.Context) {
	if s.db == nil {
		return
	}
	sur := s.surveyAttestedPremises(ctx)

	// THE STANDING ADVISORY. Only grants validated on this pass appear.
	positive := map[string]string{}
	for _, a := range sur.InForce {
		positive[a.Incarnation] = a.detail()
	}
	// `owns` decides which EXISTING subjects a clean pass may clean-count. A
	// subject this pass could not fully validate is silence, not an all-clear:
	// resolving it here is precisely how uncertainty would come to be reported
	// as "the substitution has ended".
	s.applyNetBoxConditionsWithSeverity(ctx, condNetBoxPremiseAttested,
		attestedIncarnationSubjectKind, corrosion.SeverityInfo, positive,
		func(subject string) bool { return !sur.uncertainAbout(subject) })

	// THE UNCERTAINTY, ON ITS OWN SURFACE. One row for the cluster: the grants
	// are named in the evidence, and a per-grant subject would need a per-grant
	// clean-count over state that may not be enumerable at all.
	uncertain := map[string]string{}
	if len(sur.Unvalidatable) > 0 {
		reasons := make([]string, 0, len(sur.Unvalidatable))
		for _, u := range sur.Unvalidatable {
			reason := u.Because
			if len(u.Grants) > 0 {
				reason += " (affected incarnations: " + strings.Join(u.Grants, ", ") + ")"
			}
			reasons = append(reasons, reason)
		}
		sort.Strings(reasons)
		uncertain[attestationSurveySubject] = fmt.Sprintf(
			"%d recorded permanent-loss retirement premise(s) could not be revalidated on this "+
				"pass: %s. Reliance on them is WITHHELD while this lasts — an attestation that "+
				"cannot be revalidated supplies no premise, so reclamation and bind/adoption "+
				"keep withholding rather than proceeding. This says nothing about whether what "+
				"was attested is true; litevirt cannot check that either. Review with "+
				"`lv netbox retirements`.",
			len(sur.Unvalidatable), strings.Join(reasons, " | "))
	}
	s.applyNetBoxConditions(ctx, condNetBoxAttestationUnvalidatable, "cluster", uncertain)

	// A lapsed grant gets no condition — it authorises nothing, and publishing it
	// would invite reasoning about an exception that is not there. It is logged
	// once here at DEBUG so the record exists for anybody reading a log after the
	// fact; the transition an operator sees is the standing condition resolving.
	for _, l := range sur.NotInForce {
		slog.Debug("netbox advisory: recorded retirement is no longer in force",
			"host", l.HostName, "incarnation", l.Incarnation, "premise", l.Premise)
	}
}

// sortedNames is the sorted key set of a name set.
func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
