package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// withdrawnByUnknown is what a withdrawal records when the caller's identity
// cannot be read. See the branch that uses it: refusing there would leave the
// grant applying, which is the wrong direction for this operation.
const withdrawnByUnknown = "unknown"

// WithdrawHostRetirement removes trust in a recorded permanent-loss grant.
//
// WHY IT EXISTS. A retirement substitutes an operator's judgement for evidence a
// destroyed machine can no longer produce, and litevirt cannot check it. Without
// a way to take one back, a mistaken attestation stands indefinitely — which is
// the one failure mode a subsystem built around reviewability cannot have.
//
// IT HAS NO PREREQUISITES, AND THAT ASYMMETRY IS THE DESIGN. RetireLostHost has
// six controls because GRANTING trust needs evidence: an accounting, an exact
// identity, a host that is not answering, a revalidation immediately before the
// write. REMOVING trust needs none of them, because every consequence of a
// withdrawal is a WITHHELD premise — the proof goes back to being owed, so the
// sweep and the bind withhold rather than proceed. Adding a control here would
// trade a safe outcome for an unsafe one.
//
// So this deliberately does NOT check that the host is dead, unreachable, or
// currently matching the grant, and does not read the `hosts` table at all.
//
// RECORDED IS NOT THE SAME AS INACTIVE, which is why "already lapsed" is not a
// refusal either. applicableRetirements merely SKIPS a grant whose host is
// reachable; it does not durably invalidate it, so if that incarnation becomes
// unreachable again the stored grant APPLIES AGAIN. A dormant grant is a live
// grant, and refusing to withdraw one would block withdrawal in exactly the
// state that most needs it.
//
// WHAT IT DOES CHECK, and each is about the RECORD rather than about the host:
//
//  1. PRIVILEGED, like every other write that changes what the cluster's proofs
//     rest on. Audited on both outcomes.
//  2. THE DURABLE LATCH. The withdrawal table is new in v51, so its INSERT is a
//     new REPLICATED STATEMENT SHAPE: a peer on the old build cannot resolve the
//     fingerprint, fails the apply closed, rolls its batch back and stalls its
//     replication watermark, head-of-line blocking every not-yet-rolled node.
//     This cannot lock an operator out of withdrawing something — recording a
//     retirement required the same durable latch, and the latch is MONOTONE, so
//     any grant that exists is proof the latch already formed and cannot un-form.
//  3. AN EXACT GRANT: cluster, incarnation, premise. Never the hostname, which
//     is reusable — a withdrawal aimed by name would land on whichever grant
//     that name currently carries rather than on the one the operator meant,
//     leaving the mistaken grant standing.
//  4. ATTRIBUTION AND A REASON. The original attestation records who asserted
//     what and why; this records who took it back and why, BESIDE it. Neither is
//     verified. Both are the whole of what a reviewer has to read.
//
// WHAT IT WRITES. One append-only row per GRANT VERSION — the id of each
// recovery manifest the grant currently rests on. The grant row and every
// manifest are left untouched: withdrawal is an addition to the record, not an
// edit of it. See corrosion.InsertRetirementWithdrawal for why a second
// retirement row and a revocation column are both wrong.
//
// AND WHAT IT DOES NOT TOUCH: the manifest's host identities stay inputs to
// discovery. Withdrawing permission to trust a source does not establish that
// the hosts it named never existed, and dropping them is how withdrawing a
// source would come to hide a still-running holder.
func (s *Server) WithdrawHostRetirement(ctx context.Context, req *pb.WithdrawHostRetirementRequest) (*pb.WithdrawHostRetirementResponse, error) {
	host := strings.TrimSpace(req.GetHost())
	incarnation := strings.TrimSpace(req.GetHostIncarnation())
	premise := corrosion.RetirementPremise(strings.TrimSpace(req.GetPremise()))
	reason := strings.TrimSpace(req.GetReason())
	subject := host
	if subject == "" {
		subject = incarnation
	}
	detail := fmt.Sprintf("incarnation=%s premise=%s", incarnation, premise)

	if err := RequireRole(ctx, "admin"); err != nil {
		s.audit(ctx, "netbox.withdraw-retirement", subject, "permission denied", "denied")
		return nil, err
	}
	if s.db == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"this node has no cluster database; run the withdrawal on a node that does")
	}
	// The latch, DURABLY — see control 2 above.
	if s.gate == nil || !s.gate.DurablyLatched(capabilities.NetBoxIPAMV1) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is not durably latched cluster-wide, so recording a withdrawal would put a "+
				"statement shape on the wire that a peer still on the old build cannot apply — "+
				"which would stall its replication. Finish the rollout first. Nothing is lost "+
				"by waiting: a grant can only exist if that latch has already formed, and the "+
				"latch is monotone", capabilities.NetBoxIPAMV1)
	}
	if incarnation == "" {
		return nil, status.Error(codes.InvalidArgument,
			"name the host incarnation whose grant is being withdrawn (--incarnation, the "+
				"certificate serial `lv netbox retirements` reports). A hostname cannot "+
				"identify a grant, because a hostname is meant to be reused — a withdrawal "+
				"aimed by name would land on whichever grant that name carries now")
	}
	if incarnation == corrosion.UnknownIncarnation {
		return nil, status.Errorf(codes.InvalidArgument,
			"%q is the placeholder for a certificate serial that could not be read and "+
				"identifies no incarnation, so no grant is keyed to it",
			corrosion.UnknownIncarnation)
	}
	if !corrosion.ValidPremise(premise) {
		return nil, status.Errorf(codes.InvalidArgument,
			"unknown retirement premise %q; only %q and %q are retirable, so only those can "+
				"be withdrawn", premise, corrosion.PremiseMembership, corrosion.PremiseInventory)
	}
	if reason == "" {
		return nil, status.Error(codes.InvalidArgument,
			"pass --reason: the attestation records who asserted what and why, and a "+
				"withdrawal records who took it back and why. Neither is verified, and the "+
				"pair of them is the whole of what a reviewer has to read")
	}
	withdrawnBy := callerUsername(ctx)
	if withdrawnBy == "" {
		// NOT A REFUSAL, and this is the one place the asymmetry differs from
		// RetireLostHost. There, an unattributable caller is refused: an
		// attestation nobody stands behind looks like evidence, so refusing
		// leaves the premise owed, which is safe. HERE refusing would leave the
		// grant APPLYING — the fail-OPEN direction — so the withdrawal is
		// recorded with the attribution honestly marked unknown instead.
		//
		// RequireRole above has already established an authenticated admin, so
		// this is a residual case rather than a normal one.
		withdrawnBy = withdrawnByUnknown
	}

	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"read this cluster's fingerprint: %v", err)
	}
	// THE EXACT GRANT, read from the retirements table and NOT from `hosts`. The
	// grant is what is being withdrawn, and it is recorded independently of any
	// host row — which is what makes a withdrawal possible for a machine whose
	// record is gone entirely.
	grants, err := corrosion.ListHostRetirements(ctx, s.db, fp, premise)
	if err != nil {
		s.audit(ctx, "netbox.withdraw-retirement", subject, detail, "error")
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	grant, ok := grants[incarnation]
	if !ok {
		// Refused rather than silently succeeding: telling an operator they had
		// revoked something while the grant they meant stood untouched is the
		// worst answer available here. The message names what IS recorded so
		// they can aim again.
		recorded := make([]string, 0, len(grants))
		for inc := range grants {
			recorded = append(recorded, inc)
		}
		sort.Strings(recorded)
		if len(recorded) == 0 {
			return nil, status.Errorf(codes.NotFound,
				"no %s grant is recorded for incarnation %q in this cluster, so there is "+
					"nothing to withdraw", premise, incarnation)
		}
		return nil, status.Errorf(codes.NotFound,
			"no %s grant is recorded for incarnation %q. Recorded %s incarnation(s): %s. A "+
				"withdrawal names the exact machine, never the hostname",
			premise, incarnation, premise, strings.Join(recorded, ", "))
	}

	// THE GRANT VERSIONS. Every manifest recorded for this (cluster,
	// incarnation, premise) is one version of the grant's evidence, and the
	// withdrawal covers exactly the ones recorded NOW — a version attested after
	// this enumeration is not reached by it, which is what keeps a withdrawal
	// from cancelling a newer attestation.
	before, err := corrosion.LoadRetirementWithdrawals(ctx, s.db, fp, premise)
	if err != nil {
		s.audit(ctx, "netbox.withdraw-retirement", subject, detail, "error")
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	versions := before.Versions(incarnation)
	// The grant row's OWN manifest reference, always included. A grant whose
	// manifests have not replicated here yet would otherwise enumerate no
	// versions, and a withdrawal covering nothing would report success while the
	// grant kept applying. Including it guarantees at least one row, which is
	// what makes the withdrawal predicate fire.
	if grant.ManifestID != "" && !containsString(versions, grant.ManifestID) {
		versions = append(versions, grant.ManifestID)
		sort.Strings(versions)
	}
	if len(versions) == 0 {
		// Unreachable in practice — InsertHostRetirement refuses a grant with no
		// manifest id — but a hand-written row could reach it, and a withdrawal
		// that recorded nothing must not report success.
		s.audit(ctx, "netbox.withdraw-retirement", subject, detail, "error")
		return nil, status.Errorf(codes.FailedPrecondition,
			"the %s grant for incarnation %q names no manifest, so there is no grant "+
				"version to withdraw trust in", premise, incarnation)
	}

	withdrawnAt := time.Now().UTC().Format(time.RFC3339)
	newly := 0
	for _, version := range versions {
		// Per VERSION rather than per grant, so a PARTIALLY withdrawn grant is
		// completed — which is exactly what withdrawing again after a
		// re-attestation has to do — while a fully withdrawn one adds nothing.
		if withdrawalRecorded(before, incarnation, version) {
			continue
		}
		if err := corrosion.InsertRetirementWithdrawal(ctx, s.db, corrosion.RetirementWithdrawal{
			ClusterFingerprint: fp,
			HostIncarnation:    incarnation,
			Premise:            premise,
			ManifestID:         version,
			HostName:           grant.HostName,
			WithdrawnBy:        withdrawnBy,
			WithdrawnAt:        withdrawnAt,
			Reason:             reason,
		}); err != nil {
			// Audited on both outcomes, and this branch is why: an earlier
			// version in this loop may already be recorded, so "nothing
			// happened" would be wrong.
			s.audit(ctx, "netbox.withdraw-retirement", subject, detail, "error")
			return nil, status.Errorf(codes.Internal,
				"record the withdrawal of %s grant version %s: %v", premise, version, err)
		}
		newly++
	}

	// RE-READ, so the response describes what the cluster now holds rather than
	// what this call intended. A re-attestation that raced the write shows up
	// here as an UNCOVERED version, which is how the loser of that race is
	// reported instead of swallowed.
	after, err := corrosion.LoadRetirementWithdrawals(ctx, s.db, fp, premise)
	if err != nil {
		s.audit(ctx, "netbox.withdraw-retirement", subject, detail, "error")
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	uncovered := after.UnwithdrawnVersions(incarnation)
	withdrawn := after.Withdrawn(incarnation)

	detail = fmt.Sprintf("%s versions=%d newly=%d uncovered=%d withdrawn=%t",
		detail, len(versions), newly, len(uncovered), withdrawn)
	s.audit(ctx, "netbox.withdraw-retirement", subject, detail, "ok")
	s.publish("netbox.retirement-withdrawn", subject, detail)
	return &pb.WithdrawHostRetirementResponse{
		HostIncarnation:   incarnation,
		Premise:           string(premise),
		WithdrawnVersions: versions,
		NewlyRecorded:     int32(newly),
		UncoveredVersions: uncovered,
		GrantWithdrawn:    withdrawn,
	}, nil
}

// withdrawalRecorded reports whether this grant version already carries a
// withdrawal, so a repeat adds nothing and reports zero rather than erroring.
func withdrawalRecorded(w corrosion.RetirementWithdrawals, incarnation, version string) bool {
	for _, rec := range w.Records(incarnation) {
		if rec.ManifestID == version {
			return true
		}
	}
	return false
}

// containsString is a local membership test over a small sorted slice.
func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
