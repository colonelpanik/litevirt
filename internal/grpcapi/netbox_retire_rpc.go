package grpcapi

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/randid"
)

// RetireLostHost records an operator's attestation about a PERMANENTLY LOST host
// and narrowly retires the premises it names.
//
// THIS IS THE ONE WRITE IN THE SUBSYSTEM THAT RECORDS AN UNVERIFIED PREMISE.
// Everything else the NetBox proofs rest on is a machine's answer about itself.
// Here a person asserts something about a machine that no longer exists, and
// litevirt cannot check the assertion. The controls below make it attributable,
// deliberate and reviewable; they do not make it correct, and the operator-facing
// text says so rather than implying that an audit row settles anything.
//
// SIX CONTROLS, in the order they run:
//
//  1. PRIVILEGED. Admin, like every other destructive host operation.
//  2. THE DURABLE LATCH. Both tables are new in v51 and both writes are new
//     REPLICATED STATEMENT SHAPES. A peer still on the old build cannot resolve
//     the fingerprint, so its apply fails closed, its whole batch rolls back and
//     its replication watermark stalls — which head-of-line blocks the stream
//     into every not-yet-rolled node. netbox_ipam_v1 cannot latch while any
//     advertising peer is on the old build, and it is monotone, so gating on the
//     DURABLE form keeps these shapes off a mid-roll cluster's wire. This branch
//     has already shipped one Critical of exactly this kind.
//  3. EXPLICIT CONFIRMATION. Refusing without it is the point: this is the one
//     operation that substitutes judgement for proof.
//  4. AN EXACT IDENTITY. The retirement is written against the host's recorded
//     INCARNATION (its certificate serial), never its name.
//  5. IT REFUSES A HOST THAT IS STILL RESPONDING. A machine that answers refutes
//     the attestation that it is gone.
//  6. IT REVALIDATES IMMEDIATELY BEFORE COMMITTING, not merely at request time.
//     Between the checks above and the write there is a NetBox-free but real
//     window — a database read, an audit build — and a host can rejoin inside it.
//     Both the reachability check and the incarnation read are repeated, and the
//     write is refused if either has moved.
//
// Audited on BOTH outcomes: a refusal is exactly what a reviewer needs to see,
// and a partial success (membership written, inventory refused) has changed the
// cluster's premises and must not read as "nothing happened".
func (s *Server) RetireLostHost(ctx context.Context, req *pb.RetireLostHostRequest) (*pb.RetireLostHostResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		s.audit(ctx, "netbox.retire-host", req.GetHost(), "permission denied", "denied")
		return nil, err
	}
	host := strings.TrimSpace(req.GetHost())
	if host == "" {
		return nil, status.Error(codes.InvalidArgument, "name the host that was lost")
	}
	if s.db == nil {
		return nil, status.Error(codes.FailedPrecondition,
			"this node has no cluster database; run the retirement on a node that does")
	}
	// The latch, DURABLY — see control 2 above.
	if s.gate == nil || !s.gate.DurablyLatched(capabilities.NetBoxIPAMV1) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"%s is not durably latched cluster-wide, so recording a retirement would put a "+
				"statement shape on the wire that a peer still on the old build cannot apply — "+
				"which would stall its replication. Finish the rollout first",
			capabilities.NetBoxIPAMV1)
	}
	if !req.GetConfirmed() {
		return nil, status.Error(codes.InvalidArgument,
			"pass --confirmed: a retirement substitutes your judgement for evidence litevirt "+
				"cannot obtain, and nothing verifies it")
	}
	if host == s.hostName {
		// A node retiring itself would be excusing itself from being consulted
		// about what it knows, while demonstrably running.
		return nil, status.Error(codes.InvalidArgument,
			"a node cannot retire itself: it is running this command, so it is not lost")
	}

	// WHICH PREMISES. Derived from what the operator actually supplied, so a
	// premise is retired only where an accounting for it was given.
	knew := dedupeNonEmpty(req.GetKnewHosts())
	wantMembership := len(knew) > 0 || req.GetKnewNobody()
	inventoryAccounting := strings.TrimSpace(req.GetInventoryAccounting())
	wantInventory := inventoryAccounting != ""
	if !wantMembership && !wantInventory {
		return nil, status.Error(codes.InvalidArgument,
			"nothing to retire: pass --knew (or --knew-nobody) to account for what the lost "+
				"host knew, and/or --inventory to account for its unique address records. "+
				"They are separate premises and neither implies the other")
	}
	if len(knew) > 0 && req.GetKnewNobody() {
		// One says it knew of these hosts, the other says it knew of none. A
		// contradictory attestation is not a narrower one.
		return nil, status.Error(codes.InvalidArgument,
			"--knew and --knew-nobody contradict each other; pass one")
	}
	for _, n := range knew {
		if n == host {
			// Naming itself adds nothing and would read as an accounting.
			return nil, status.Errorf(codes.InvalidArgument,
				"--knew must name the hosts %s knew ABOUT, not %s itself", host, host)
		}
	}

	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"read this cluster's fingerprint: %v", err)
	}
	// An EXACT IDENTITY, read from the host's own row — tombstone included, since
	// a permanently lost host is usually one already removed.
	incarnation, found, err := corrosion.HostIncarnationOf(ctx, s.db, host)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	if !found {
		return nil, status.Errorf(codes.NotFound,
			"no host record for %q, so there is no incarnation to retire. A retirement names a "+
				"specific machine (its recorded certificate serial) and never a hostname, "+
				"because a hostname is reusable", host)
	}
	if incarnation == "" || incarnation == corrosion.UnknownIncarnation {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %q has no usable recorded incarnation (its certificate serial reads %q, the "+
				"placeholder for one that could not be read). A retirement naming it would "+
				"apply to whichever host next failed to read its own certificate, so it is "+
				"refused", host, incarnation)
	}
	// IT REFUSES A HOST THAT IS STILL RESPONDING.
	if s.hostIsReachable(ctx, host) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %q is still responding, so it is not permanently lost and nothing needs "+
				"retiring — it can answer for itself. If it is about to be decommissioned, "+
				"drain and remove it instead", host)
	}

	premises := make([]corrosion.RetirementPremise, 0, 2)
	if wantMembership {
		premises = append(premises, corrosion.PremiseMembership)
	}
	if wantInventory {
		premises = append(premises, corrosion.PremiseInventory)
	}
	detail := fmt.Sprintf("incarnation=%s premises=%s knew=%d inventory_accounted=%t",
		incarnation, premiseNames(premises), len(knew), wantInventory)

	// REVALIDATED IMMEDIATELY BEFORE COMMITTING. The checks above ran against a
	// state that a rejoin or a re-admission can have moved since; re-reading them
	// here is what makes the window between check and write not matter.
	if s.onBeforeRetireRevalidate != nil {
		// The test seam sits HERE and nowhere else: it is the window itself.
		s.onBeforeRetireRevalidate()
	}
	if err := s.revalidateBeforeRetiring(ctx, host, incarnation); err != nil {
		s.audit(ctx, "netbox.retire-host", host, detail, "error")
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}

	attestedBy := callerUsername(ctx)
	if attestedBy == "" {
		// Never write an unattributable attestation: it looks like evidence and
		// names nobody who stands behind it.
		s.audit(ctx, "netbox.retire-host", host, detail, "error")
		return nil, status.Error(codes.PermissionDenied,
			"a retirement must be attributable and this request carries no caller identity")
	}
	attestedAt := time.Now().UTC().Format(time.RFC3339)

	for _, premise := range premises {
		accounting := knew
		if premise == corrosion.PremiseInventory {
			accounting = []string{inventoryAccounting}
		}
		id := randid.New()
		if err := corrosion.InsertRecoveryManifest(ctx, s.db, corrosion.RecoveryManifest{
			ID:                 id,
			ClusterFingerprint: fp,
			HostName:           host,
			HostIncarnation:    incarnation,
			Premise:            premise,
			Accounting:         accounting,
			AttestedBy:         attestedBy,
			AttestedAt:         attestedAt,
		}); err != nil {
			// Audited on both outcomes, and this branch is why: an earlier
			// premise in this loop may already have been recorded, so "nothing
			// happened" would be wrong.
			s.audit(ctx, "netbox.retire-host", host, detail, "error")
			return nil, status.Errorf(codes.Internal, "record the %s manifest: %v", premise, err)
		}
		if err := corrosion.InsertHostRetirement(ctx, s.db, corrosion.HostRetirement{
			ClusterFingerprint: fp,
			HostIncarnation:    incarnation,
			Premise:            premise,
			HostName:           host,
			ManifestID:         id,
			AttestedBy:         attestedBy,
			AttestedAt:         attestedAt,
		}); err != nil {
			s.audit(ctx, "netbox.retire-host", host, detail, "error")
			return nil, status.Errorf(codes.Internal, "record the %s retirement: %v", premise, err)
		}
	}

	// Whether the RUNTIME premise is covered, reported rather than left to be
	// inferred: an operator who has retired both retirable premises has every
	// reason to think they are done, and reclamation will still withhold.
	runtimeMissing := true
	if off, ferr := s.hasFreshPowerOffProof(ctx, host); ferr == nil {
		runtimeMissing = !off
	}

	s.audit(ctx, "netbox.retire-host", host, detail, "ok")
	s.publish("netbox.host-retired", host, detail)
	return &pb.RetireLostHostResponse{
		HostIncarnation:        incarnation,
		Premises:               premiseNames(premises),
		RecoveredHosts:         knew,
		RuntimeEvidenceMissing: runtimeMissing,
	}, nil
}

// revalidateBeforeRetiring re-runs the two checks that can go stale between the
// request and the write.
//
// It is a separate function so the "immediately before committing" property is
// visible at the call site rather than being three lines an edit could drift
// away from the write.
func (s *Server) revalidateBeforeRetiring(ctx context.Context, host, incarnation string) error {
	if s.hostIsReachable(ctx, host) {
		return fmt.Errorf("host %q started responding while the retirement was being prepared, "+
			"so nothing was recorded: it can answer for itself", host)
	}
	now, found, err := corrosion.HostIncarnationOf(ctx, s.db, host)
	if err != nil {
		return fmt.Errorf("re-read the recorded incarnation for %q: %w", host, err)
	}
	if !found {
		return fmt.Errorf("the host record for %q disappeared while the retirement was being "+
			"prepared, so there is no incarnation to write it against", host)
	}
	if now != incarnation {
		return fmt.Errorf("the incarnation recorded for %q moved while the retirement was "+
			"being prepared (%s -> %s), which means a different machine now answers to that "+
			"name; nothing was recorded", host, incarnation, now)
	}
	return nil
}

// ListLostHostRetirements reports every recovery attestation in this cluster and
// whether it still APPLIES.
//
// It exists because a premise no machine verifies has to be reviewable instead.
// The only defence against a wrong attestation is a person reading it, so this
// surfaces the accounting itself — not merely that a grant exists — and says
// plainly when a grant has stopped being honoured.
func (s *Server) ListLostHostRetirements(ctx context.Context, _ *emptypb.Empty) (*pb.ListLostHostRetirementsResponse, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if s.db == nil {
		return nil, status.Error(codes.FailedPrecondition, "this node has no cluster database")
	}
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "read cluster fingerprint: %v", err)
	}

	out := &pb.ListLostHostRetirementsResponse{}
	for _, premise := range []corrosion.RetirementPremise{
		corrosion.PremiseMembership, corrosion.PremiseInventory,
	} {
		byIncarnation, err := corrosion.ListHostRetirements(ctx, s.db, fp, premise)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "%v", err)
		}
		for _, r := range byIncarnation {
			applies, why := s.retirementStillApplies(ctx, r)
			row := &pb.LostHostRetirement{
				HostName:           r.HostName,
				HostIncarnation:    r.HostIncarnation,
				Premise:            string(r.Premise),
				AttestedBy:         r.AttestedBy,
				AttestedAt:         r.AttestedAt,
				Applies:            applies,
				NotApplyingBecause: why,
			}
			// The accounting from the manifests this grant rests on — the union,
			// newest first, because the read side unions them too and a listing
			// that showed only one would misreport what discovery is using.
			manifests, merr := corrosion.ManifestsForIncarnation(ctx, s.db, fp, r.HostIncarnation)
			if merr != nil {
				return nil, status.Errorf(codes.Internal, "%v", merr)
			}
			for _, m := range manifests {
				if m.Premise == r.Premise {
					row.Accounting = append(row.Accounting, m.Accounting...)
				}
			}
			out.Retirements = append(out.Retirements, row)
		}
	}
	sort.Slice(out.Retirements, func(i, j int) bool {
		a, b := out.Retirements[i], out.Retirements[j]
		if a.GetHostName() != b.GetHostName() {
			return a.GetHostName() < b.GetHostName()
		}
		return a.GetPremise() < b.GetPremise()
	})
	return out, nil
}

// retirementStillApplies re-runs the read-side validity rules for the listing,
// so an operator sees the same answer the proofs act on.
//
// It reports the REASON as well as the verdict, because "recorded but not
// honoured" is the state most likely to confuse somebody who ran the command and
// then watched the sweep keep withholding.
func (s *Server) retirementStillApplies(ctx context.Context, r corrosion.HostRetirement) (bool, string) {
	now, found, err := corrosion.HostIncarnationOf(ctx, s.db, r.HostName)
	switch {
	case err != nil:
		return false, fmt.Sprintf("the host record could not be read (%v), so the retirement "+
			"cannot be revalidated and the premise stays owed", err)
	case !found:
		return false, "no host record names this host any more, so there is no incarnation to " +
			"match the retirement against and the premise stays owed"
	case now != r.HostIncarnation:
		return false, fmt.Sprintf("a different machine now answers to this name (incarnation "+
			"%s, retired %s), and a re-admission does not inherit its predecessor's exception",
			now, r.HostIncarnation)
	case s.hostIsReachable(ctx, r.HostName):
		return false, "the host is responding again, so its live state governs rather than an " +
			"attestation that it was gone"
	}
	return true, ""
}

// dedupeNonEmpty trims, drops blanks, dedupes and sorts, so the recorded
// accounting does not depend on how the operator typed the list.
func dedupeNonEmpty(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func premiseNames(ps []corrosion.RetirementPremise) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}
