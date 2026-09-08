package grpcapi

import (
	"context"
	"fmt"
	"sort"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ── PERMANENT HOST LOSS: THE EXIT FROM A CLOSURE THAT CAN NEVER CLOSE ───────
//
// THE TRUST BOUNDARY IS THIS FILE'S SUBJECT. SAY IT PLAINLY OR NOT AT ALL.
//
// Every other premise in this subsystem is machine-verified. The membership
// closure asks each peer what IT knows; the inventory corroboration asks each
// peer for ITS OWN digest; the runtime proof scans each peer's OWN libvirt. A
// wrong answer anywhere in there is a defect a machine can notice.
//
// A retirement is not like that. IT SUBSTITUTES HUMAN-ESTABLISHED EVIDENCE FOR
// UNAVAILABLE MACHINE EVIDENCE. An operator asserts something about a machine
// that is gone, and litevirt cannot check it — not partially, not heuristically,
// not at all. The row is attributed, audited, replicated and immutable, and
// RECORDING IT DOES NOT MAKE IT TRUE. An audit trail records who said something;
// it does not corroborate what they said. Anyone reading this code should come
// away knowing that the premise here is a person's judgement, so that nobody
// later reasons "it is audited, therefore it is established" and widens what a
// retirement excuses on that basis.
//
// WHY IT EXISTS ANYWAY. The previous round made an unreachable participant block
// the closure, which is right: power-off evidence excuses a RUNTIME, never a
// MEMORY. The consequence was a dead end — after a PERMANENT loss the closure
// can never close, so reclamation and bind/adoption stay suspended forever with
// no remedy. A safety property with no exit gets worked around in the field,
// which is strictly worse than a narrow, recorded, honestly-labelled exit.
//
// WHAT KEEPS IT NARROW, and each of these is load-bearing:
//
//  1. IT IS PER-HOST AND PER-PREMISE, never a cluster-wide "membership is
//     complete" switch. There is no such row and no way to write one, so several
//     permanent losses compose as several narrow grants rather than as a global
//     bypass. See corrosion/netbox_recovery.go.
//  2. IT NAMES AN EXACT IDENTITY: the cluster fingerprint plus the host
//     INCARNATION (its recorded certificate serial), never a reusable hostname.
//  3. RETIRING A SOURCE DOES NOT DISCARD WHAT IT KNEW. The manifest's host
//     identities stay inputs to discovery, so retiring a witness still causes
//     the holder only that witness could name to be asked.
//  4. THE PREMISES DO NOT IMPLY ONE ANOTHER. Membership accounting is not
//     inventory accounting, and NEITHER is power-off evidence.
//  5. IT IS REVALIDATED ON EVERY READ, not only when it was written: a
//     reachable host's live state governs, and a re-admitted machine's new
//     incarnation matches nothing.
//  6. IT CAN BE WITHDRAWN, per GRANT VERSION, by a named person — and that is
//     the one thing on this list that is DURABLE rather than re-derived. The
//     conditions above describe a grant that has stopped MATCHING and that
//     applies again the moment it matches again; a dormant grant is a live
//     grant. A withdrawal is a decision, so it does not lapse when the host
//     next goes unreachable, and a replayed copy of the old grant cannot undo
//     it. Removing trust needs no evidence, which is the reverse of the
//     asymmetry that governs granting it.
//
// THE THREE PERMISSIONS, AND WHY THEY ARE THREE.
//
//	RECLAMATION needs MEMBERSHIP ACCOUNTING + RUNTIME POWER-OFF EVIDENCE.
//	BINDING     needs MEMBERSHIP ACCOUNTING + INVENTORY ACCOUNTING.
//
// Membership accounting is common to both, and it is the only premise a
// membership retirement touches. Inventory accounting is an ADDITIONAL premise
// that only the bind needs and that only an inventory retirement touches.
// Power-off evidence is not retirable at all: there is no constant for a runtime
// premise, so no row can name one and no reader can find one. Knowing what a
// machine knew, and knowing what rows it held, say NOTHING about whether its
// workloads are stopped — that still requires the fencing log, exactly as before.
//
// DO NOT COLLAPSE THESE INTO ONE "recovered" FLAG. That is the same conflation
// this branch has now hit three times, and doing it here would undo both of the
// previous rounds at once: a membership retirement excusing the inventory
// comparison brings back the witness-unique-inventory collision, and either one
// excusing the runtime brings back freeing a live guest's address.

// membershipRetirements are the retirements that APPLY RIGHT NOW to the
// MEMBERSHIP premise, keyed by HOST NAME.
//
// A DISTINCT TYPE from inventoryRetirements, and that is the mechanism rather
// than a naming convention: the two maps have identical shape, so without
// separate types a call site could pass either to either and the compiler would
// accept it. The inventory consumer takes an inventoryRetirements and cannot be
// handed one of these; the runtime derivation takes neither.
type membershipRetirements map[string]corrosion.HostRetirement

// retired reports whether this host's obligation to say WHAT IT KNEW has been
// retired. It never reports anything about that host's rows or its runtime.
func (m membershipRetirements) retired(host string) bool { _, ok := m[host]; return ok }

// appliesToIncarnation reports whether the retirement in force for this host is
// the one recorded against THIS incarnation.
//
// THE STRONGER QUESTION, and a reader holding a SPECIFIC grant has to ask it.
// The map is keyed by host NAME, because that is what its consumers have in hand
// and because revalidation has already established that the entry matches the
// name's currently-recorded incarnation. But one hostname can carry SEVERAL
// grants — a replacement machine can be permanently lost too — and only the one
// written against the current incarnation applies. Asking `retired` with the
// name alone would answer true for a superseded grant as well, which is how a
// surface comes to present an expired exception, under the same host name and
// the same attribution as the live one.
func (m membershipRetirements) appliesToIncarnation(host, incarnation string) bool {
	r, ok := m[host]
	return ok && r.HostIncarnation == incarnation
}

// hosts is the retired host names, sorted — for the operator-facing reason a
// closure gives when it closed over a retirement rather than over an answer.
func (m membershipRetirements) hosts() []string {
	out := make([]string, 0, len(m))
	for h := range m {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// inventoryRetirements are the retirements that APPLY RIGHT NOW to the INVENTORY
// premise, keyed by HOST NAME. Distinct type, for the reason above.
type inventoryRetirements map[string]corrosion.HostRetirement

// retired reports whether this host's obligation to produce a digest of the
// address-bearing tables has been retired. A MEMBERSHIP retirement never
// produces a true answer here: this map is built from a query that filters on
// the inventory premise, so a membership grant is not in it at all.
func (i inventoryRetirements) retired(host string) bool { _, ok := i[host]; return ok }

// appliesToIncarnation is the stronger question for the inventory premise. A
// separate method on a separate type, deliberately, for the reason `retired` is:
// the two maps have identical shape, so a shared helper would take either.
func (i inventoryRetirements) appliesToIncarnation(host, incarnation string) bool {
	r, ok := i[host]
	return ok && r.HostIncarnation == incarnation
}

// membershipRetirementsFor resolves the MEMBERSHIP retirements applicable to
// these candidates.
//
// It passes corrosion.PremiseMembership and nothing else. The premise is a
// literal at this one site, so what this function can return is fixed by the
// source and not by a caller's argument — which is what makes the two premises
// unable to leak into each other's consumer.
func (s *Server) membershipRetirementsFor(ctx context.Context, names []string) (membershipRetirements, error) {
	applicable, err := s.applicableRetirements(ctx, names, corrosion.PremiseMembership)
	if err != nil {
		return nil, err
	}
	return membershipRetirements(applicable), nil
}

// inventoryRetirementsFor resolves the INVENTORY retirements applicable to these
// candidates. It passes corrosion.PremiseInventory and nothing else.
//
// A host whose MEMBERSHIP premise has been retired and whose inventory premise
// has not is absent from what this returns, and that is the round-five lesson
// applied to the recovery path: a lost machine's unique VM/NIC/address rows are
// exactly what an inventory comparison exists to notice, so "we have recovered
// what it knew" must not excuse producing them. That host keeps blocking the
// bind until its inventory is accounted for as its own attestation.
func (s *Server) inventoryRetirementsFor(ctx context.Context, names []string) (inventoryRetirements, error) {
	applicable, err := s.applicableRetirements(ctx, names, corrosion.PremiseInventory)
	if err != nil {
		return nil, err
	}
	return inventoryRetirements(applicable), nil
}

// applicableRetirements is the REVALIDATION, shared by both premises because the
// validity rules are identical and must stay identical — a premise that revalidated
// more weakly than the other would be the soft spot everything else migrates to.
//
// It is deliberately UNEXPORTED and returns a bare map that neither consumer can
// use: only the two premise-named wrappers above convert it to a typed map, and
// each passes its own premise literal. There is no way to call this with a
// premise a caller chose at runtime, because nothing passes one.
//
// FIVE THINGS MUST HOLD before a retirement applies to a host, and every one of
// them fails CLOSED — an unmet condition means the premise is still owed:
//
//  1. THE CLUSTER MATCHES. Retirements are scoped by cluster fingerprint, so a
//     database restored from another installation carries no authority here.
//     An unreadable fingerprint is an error, never "no retirements".
//  2. THE HOST'S INCARNATION IS RECORDED AND KNOWN. With no `hosts` row for the
//     name there is nothing to compare a retirement against, so nothing applies
//     — the retirement is NOT allowed to fall back to matching the hostname,
//     which is the failure the incarnation exists to prevent. A recorded
//     incarnation of "unknown" (the daemon's placeholder for a certificate it
//     could not read) identifies no incarnation either.
//  3. A RETIREMENT EXISTS FOR THAT EXACT INCARNATION AND THAT PREMISE. This is
//     where hostname reuse is caught: a re-admitted machine necessarily presents
//     a different certificate serial, so its row records a different incarnation
//     and the prior incarnation's retirement matches nothing. Re-admission
//     cannot inherit an exception.
//  4. TRUST IN THE GRANT HAS NOT BEEN WITHDRAWN. This is the one condition that
//     is DURABLE rather than re-derived from live state, and the distinction
//     matters: the others all describe a grant that has stopped MATCHING and
//     will apply again the moment it matches again, whereas a withdrawal is a
//     recorded decision by a named person that does not come back when the host
//     next goes unreachable. It is checked BEFORE the live reads below because
//     it needs none of them — removing trust is not conditional on anything
//     about the host — and it is checked per GRANT VERSION, so an attestation
//     recorded after the withdrawal supplies the premise again on its own
//     strength. See corrosion.RetirementWithdrawals.Withdrawn.
//  5. THE HOST IS NOT CURRENTLY RESPONDING. Same rule hasFreshPowerOffProof
//     applies to a fence attestation, for the same reason: a retirement asserts
//     that a machine is GONE, so a machine that is answering refutes it and its
//     LIVE STATE GOVERNS. This is what makes a detected rejoin invalidate the
//     exception with nothing written and no operator action.
//
// CONDITIONS 4 AND 5 ARE NOT INTERCHANGEABLE, and conflating them is the
// mistake this file must not make. A grant whose host is reachable is merely
// SKIPPED here — nothing is written, and if that incarnation goes unreachable
// again the stored grant applies again. A dormant grant is a live grant. That is
// exactly why a withdrawal has to be recorded rather than inferred from the host
// having answered once.
func (s *Server) applicableRetirements(ctx context.Context, names []string,
	premise corrosion.RetirementPremise) (map[string]corrosion.HostRetirement, error) {

	if s.db == nil {
		return nil, fmt.Errorf("no cluster database — cannot read host retirements")
	}
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		// Not folded into "no retirements": an unreadable cluster identity and
		// "nothing has been retired" lead to the same withholding here, but the
		// error names the real problem instead of reporting a missing host.
		return nil, fmt.Errorf("read cluster fingerprint for %s retirements: %w", premise, err)
	}
	byIncarnation, err := corrosion.ListHostRetirements(ctx, s.db, fp, premise)
	if err != nil {
		return nil, err
	}
	if len(byIncarnation) == 0 {
		// The overwhelmingly common case: nothing has been retired, so nothing
		// below can change any decision. Returning early keeps a cluster with no
		// permanent loss from doing one `hosts` read per candidate per round.
		return nil, nil
	}
	// THE WITHDRAWALS, once for the whole premise. An error propagates rather
	// than degrading to "nothing is withdrawn": a withdrawal that cannot be
	// read is a grant whose standing is unknown, and honouring it on that basis
	// would be reading an unreadable table as permission.
	withdrawals, err := corrosion.LoadRetirementWithdrawals(ctx, s.db, fp, premise)
	if err != nil {
		return nil, err
	}
	out := make(map[string]corrosion.HostRetirement, len(byIncarnation))
	for _, name := range names {
		if name == "" || name == s.hostName {
			// This node is never retired: it is executing this code, so it is
			// demonstrably present, and it answers for itself from its own
			// database. A retirement of the running node would be a node
			// excusing itself from being consulted about what it knows.
			continue
		}
		inc, found, err := corrosion.HostIncarnationOf(ctx, s.db, name)
		if err != nil {
			return nil, err
		}
		if !found || inc == "" || inc == corrosion.UnknownIncarnation {
			continue // no identity to match — the premise stays owed
		}
		r, ok := byIncarnation[inc]
		if !ok {
			continue // no retirement for THIS incarnation
		}
		if withdrawals.Withdrawn(inc) {
			// Trust in every version this grant rests on has been withdrawn by
			// a named person. Unlike everything below, this does not depend on
			// the host's current state, so it does not lapse when the host next
			// goes unreachable.
			continue
		}
		if s.hostIsReachable(ctx, name) {
			// It is answering. Whatever was attested about it, it is not gone.
			continue
		}
		out[name] = r
	}
	return out, nil
}

// recoveredMembershipCandidates is the host identities every MEMBERSHIP manifest
// names, folded into the candidate universe as BARE NAMES.
//
// THIS IS WHAT KEEPS A RETIREMENT FROM DISCARDING WHAT THE LOST HOST KNEW.
// Retiring a source retires the obligation to ask THAT host; the hosts it could
// have told us about are still hosts that may be running a domain, and they come
// from here. The decisive case is a permanently lost witness that was the only
// node able to name a third, still-running holder: its manifest names the
// holder, the holder is therefore queried by name, and its scan stops the
// reclamation. Drop this from the closure's inputs and the recovery path becomes
// the collision it exists to avoid.
//
// FOLDED IN UNCONDITIONALLY, whether or not anything has been retired, because
// naming a host can only ever cause it to be ASKED. That is the leak direction:
// a manifest can widen the set of hosts that must answer and can never narrow
// it, so consuming it needs no permission of its own. The cost is real and is
// the designed one — a manifest naming a host that cannot answer leaves the
// closure open until that host is retired too, which is how several permanent
// losses compose without a global bypass.
//
// BARE NAMES, NEVER ROLES. candidateSet.addNamed establishes existence and not a
// role reading, deliberately: a role is what excuses a host from a RUNTIME SCAN,
// and an operator's recollection of a role is exactly the unverified premise that
// must never reach that decision. An attestation can cause a host to be queried;
// it can never cause one to be skipped.
func (s *Server) recoveredMembershipCandidates(ctx context.Context) ([]string, error) {
	if s.db == nil {
		return nil, fmt.Errorf("no cluster database — cannot read recovered membership")
	}
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("read cluster fingerprint for recovered membership: %w", err)
	}
	return corrosion.RecoveredMembershipIdentities(ctx, s.db, fp)
}
