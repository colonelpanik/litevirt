package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// RevalidateBindingsOnce runs exactly one revalidation pass. It exists so a
// test can drive revalidation deterministically instead of waiting on a ticker;
// the daemon runs the same pass on an interval.
func (s *Server) RevalidateBindingsOnce(ctx context.Context) error {
	return s.revalidateBindings(ctx)
}

// revalidateBindings re-runs every bind-time precondition on every sweep.
//
// Bind-time validation goes stale: a prefix can be re-CIDRed, moved out of its
// VRF, or have that VRF's uniqueness enforcement switched off, all long after
// the bind succeeded and none of it announced to litevirt. A prefix ID remains a
// stable binding IDENTITY — it will not silently rebind the way a CIDR match
// would — but stable identity is not continued validity.
//
// Drift SUSPENDS the binding: new allocations refuse, running VMs are untouched.
// A suspension is never lifted by this pass — an already-suspended binding is
// skipped entirely — because the whole point is that litevirt stopped trusting
// the binding and only an operator's `lv netbox rekey` says otherwise.
func (s *Server) revalidateBindings(ctx context.Context) error {
	if s.db == nil || s.netbox == nil {
		// A node with no NetBox configuration cannot read the facts a
		// suspension would rest on, and has no standing to suspend a binding
		// every configured node can still validate.
		return nil
	}
	bindings, err := corrosion.ListBindings(ctx, s.db)
	if err != nil {
		return fmt.Errorf("list bindings: %w", err)
	}
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return fmt.Errorf("derive cluster fingerprint: %w", err)
	}
	for _, b := range bindings {
		if b.Suspended {
			continue
		}
		reason := s.bindingDrift(ctx, b, fp)
		if reason == "" {
			continue
		}
		slog.Warn("netbox binding suspended", "network", b.Network,
			"prefix", b.PrefixID, "reason", reason)
		if err := corrosion.SuspendBinding(ctx, s.db, b.PrefixID, reason); err != nil {
			return fmt.Errorf("suspend binding %d: %w", b.PrefixID, err)
		}
		s.nbMetrics().IncBindingSuspended()
	}
	return nil
}

// bindingDrift returns a non-empty reason when a binding is no longer valid.
//
// Every branch that returns "" on an error is deliberate: an unreachable or
// erroring NetBox is SILENCE, not drift. Suspension is sticky — nothing lifts it
// but an operator — so suspending on a transport failure would turn a NetBox
// maintenance window into a network that refuses every create until a human
// intervenes, with nothing actually having changed. The failure is logged and
// counted instead, and the next pass asks again.
func (s *Server) bindingDrift(ctx context.Context, b corrosion.BindingRecord, liveFingerprint string) string {
	// The PIN, not a recomputation. A CA replacement must be an operation, not a
	// silent re-identification of every object litevirt has written: recomputing
	// here would compare a value with itself, never disagree, and quietly leave
	// every existing NetBox object stranded under an identity this cluster no
	// longer recognises as its own.
	if b.ClusterFingerprint != liveFingerprint {
		return fmt.Sprintf(
			"cluster CA changed; run `lv netbox rekey %s` to rewrite identities", b.Network)
	}

	p, err := s.netbox.GetPrefix(ctx, b.PrefixID)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		slog.Warn("netbox: prefix read failed during revalidation; binding left as it is",
			"network", b.Network, "prefix", b.PrefixID, "error", err)
		return ""
	}
	if p.Prefix != b.ObservedCIDR {
		// The addresses already handed out do NOT move with the prefix, so the
		// binding now names a range litevirt's leases are not inside.
		return fmt.Sprintf("prefix re-CIDRed from %s to %s", b.ObservedCIDR, p.Prefix)
	}
	if p.VRFID == 0 {
		// The same refusal bind makes: NetBox does not expose the global
		// ENFORCE_GLOBAL_UNIQUE setting, so uniqueness is unverifiable here.
		return "prefix moved to the global table, where uniqueness is not verifiable"
	}

	unique, err := s.netbox.VRFEnforcesUnique(ctx, p.VRFID)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		slog.Warn("netbox: VRF read failed during revalidation; binding left as it is",
			"network", b.Network, "vrf", p.VRFID, "error", err)
		return ""
	}
	if !unique {
		return fmt.Sprintf("VRF %d no longer enforces uniqueness", p.VRFID)
	}
	return ""
}

// ── the CA re-key ───────────────────────────────────────────────────────────

// RekeyBinding rewrites the identities a bound network owns in NetBox under the
// cluster's CURRENT fingerprint, then resumes the binding IF nothing else is
// wrong with it.
//
// A pinned fingerprint with no rotation path is an outage waiting for the first
// CA replacement, so this is the operation that turns one into a chore. It
// answers the fingerprint pin and only that: a binding that had also drifted in
// NetBox stays suspended under the remaining reason, for `lv netbox resume`
// once an operator has repaired it.
func (s *Server) RekeyBinding(ctx context.Context, req *pb.RekeyBindingRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.GetNetwork() == "" {
		return nil, status.Error(codes.InvalidArgument, "network is required")
	}
	if s.netbox == nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this node has no netbox configuration; run the re-key on a node that does")
	}
	if s.db == nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this node has no cluster database; run the re-key on a node that does")
	}
	b, err := corrosion.GetBindingByNetwork(ctx, s.db, req.GetNetwork())
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"read binding for network %q: %v", req.GetNetwork(), err)
	}
	if b == nil {
		return nil, status.Errorf(codes.NotFound,
			"network %q is not bound to a NetBox prefix", req.GetNetwork())
	}
	rewritten, err := s.rekeyBinding(ctx, *b)
	detail := fmt.Sprintf("prefix=%d rewritten=%d", b.PrefixID, rewritten)
	if err != nil {
		// Audited on BOTH outcomes: a re-key that failed partway has still
		// rewritten objects in NetBox, so "nothing happened" is exactly the
		// wrong thing for the audit trail to imply.
		s.audit(ctx, "netbox.rekey", req.GetNetwork(), detail, "error")
		var drifted stillDriftedError
		if errors.As(err, &drifted) {
			// Not an internal failure: the rewrite succeeded and the operator
			// has a prefix to repair.
			return nil, status.Errorf(codes.FailedPrecondition,
				"re-key network %q: %v", req.GetNetwork(), err)
		}
		return nil, status.Errorf(codes.Internal, "re-key network %q: %v", req.GetNetwork(), err)
	}
	s.audit(ctx, "netbox.rekey", req.GetNetwork(), detail, "ok")
	return &emptypb.Empty{}, nil
}

// stillDriftedError is a re-key that rewrote every identity and then found the
// binding still invalid for a reason a re-key does not address.
type stillDriftedError struct{ reason string }

func (e stillDriftedError) Error() string {
	return fmt.Sprintf("identities re-keyed, but the binding remains suspended: %s"+
		" — repair it in NetBox, then run `lv netbox resume`", e.reason)
}

// rekeyBinding is the re-key itself: rewrite, then re-validate, then resume —
// never any other order.
//
// SCOPE: this rewrites identities on `ipam.ip-address` objects only. P2 extends
// this function to `virtual_machine` and `vminterface` objects; until then, do
// not enable the P2 mirror on a cluster whose CA has rotated. Rewriting only
// addresses leaves inventory objects carrying the old fingerprint, and P2's
// sweep would fail to find them by identity and create DUPLICATES.
//
// It is idempotent and RESUMABLE. Objects already carrying the new fingerprint
// no longer match the binding's (old) pin and are skipped, so a re-run finishes
// exactly the work a failed run left. What it is not is safe to interleave with
// a SECOND CA replacement: objects stamped with an intermediate fingerprint
// match neither the old pin nor the new one. Finish a re-key before rotating
// again.
func (s *Server) rekeyBinding(ctx context.Context, b corrosion.BindingRecord) (int, error) {
	newFP, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return 0, fmt.Errorf("derive cluster fingerprint: %w", err)
	}

	// Suspend FIRST when the pin is already stale. Every claim stamps the LIVE
	// fingerprint, so a binding left allocating during a partial rewrite would
	// keep minting objects under a fingerprint its own pin does not cover. This
	// is also what revalidation would do on its next pass; doing it here makes
	// the re-key safe to run on its own, before any pass has noticed.
	if b.ClusterFingerprint != newFP && !b.Suspended {
		reason := fmt.Sprintf("cluster CA changed; re-key in progress for %s", b.Network)
		if err := corrosion.SuspendBinding(ctx, s.db, b.PrefixID, reason); err != nil {
			return 0, fmt.Errorf("suspend binding %d before re-key: %w", b.PrefixID, err)
		}
	}

	addrs, err := s.netbox.ListIPsByPrefix(ctx, b.ObservedCIDR, b.VRFID)
	if err != nil {
		// A partial enumeration would resume the binding with objects still
		// carrying the old fingerprint — invisible to this cluster ever after.
		return 0, fmt.Errorf("enumerate prefix %d: %w", b.PrefixID, err)
	}

	rewritten := 0
	for _, ip := range addrs {
		cf, uuid, mac, ok := parseIdentity(ip.Identity)
		if !ok || cf != b.ClusterFingerprint {
			// Malformed, another cluster's, or already rewritten by an earlier
			// run of this same re-key. The pin is what says which are ours.
			continue
		}
		if err := s.netbox.SetIPIdentity(ctx, ip.ID, netbox.Identity(newFP, uuid, mac)); err != nil {
			s.nbMetrics().IncAPIError(netbox.Classify(err))
			return rewritten, fmt.Errorf("rewrite identity on address %s (id %d) after %d rewrites; "+
				"the binding stays suspended, re-run to finish: %w",
				ip.Address, ip.ID, rewritten, err)
		}
		rewritten++
	}

	// A re-key answers exactly ONE reason a binding suspends: the fingerprint
	// pin. Resuming here on the strength of that alone would lift a suspension
	// this operation did nothing about — and on a re-CIDRed prefix that is not
	// merely premature, it is silently destructive. Allocation would resume from
	// the NEW NetBox range while the row still records the OLD ObservedCIDR, and
	// both the sweeper and lease repair enumerate by ObservedCIDR: every address
	// claimed from the new range is invisible to the reclaim proof.
	//
	// So re-run the whole predicate with the new fingerprint as the pin. Only
	// what a re-key fixed is fixed; anything else keeps the binding suspended,
	// now under the reason an operator has to act on.
	next := b
	next.ClusterFingerprint = newFP
	if reason := s.bindingDrift(ctx, next, newFP); reason != "" {
		if err := corrosion.SuspendBinding(ctx, s.db, b.PrefixID, reason); err != nil {
			return rewritten, fmt.Errorf("suspend binding %d after re-key: %w", b.PrefixID, err)
		}
		slog.Warn("netbox binding re-keyed but still drifted", "network", b.Network,
			"prefix", b.PrefixID, "addresses_rewritten", rewritten, "reason", reason)
		return rewritten, stillDriftedError{reason: reason}
	}

	next.Suspended = false
	next.SuspendReason = ""
	if err := corrosion.UpsertBinding(ctx, s.db, next); err != nil {
		return rewritten, fmt.Errorf("resume binding for prefix %d: %w", b.PrefixID, err)
	}
	slog.Info("netbox binding re-keyed", "network", b.Network, "prefix", b.PrefixID,
		"addresses_rewritten", rewritten, "fingerprint", newFP)
	return rewritten, nil
}

// ── the resume ──────────────────────────────────────────────────────────────

// ResumeBinding lifts a suspension whose cause has been repaired in NetBox.
//
// Suspension is sticky by design, so every drift needs a way out. A re-key is
// the way out of ONE of them (the fingerprint pin) and rewrites objects to get
// there; the others — a re-CIDR, a move to the global table, a VRF that stopped
// enforcing uniqueness — are repaired in NetBox by an operator, and all that is
// left is to re-check and clear the flag. That is this call, and it re-runs the
// full bind-time predicate rather than trusting the operator's word for it.
//
// RESUME NEVER ACCEPTS A CIDR CHANGE. It re-validates against the PINNED
// ObservedCIDR and writes it back unchanged, so a prefix that NetBox now
// reports under a different CIDR stays suspended. Re-CIDRing a bound prefix is
// a v1 limitation: revert the CIDR in NetBox, or delete and recreate the
// litevirt network (which releases the binding and re-claims it against the new
// range).
func (s *Server) ResumeBinding(ctx context.Context, req *pb.ResumeBindingRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.GetNetwork() == "" {
		return nil, status.Error(codes.InvalidArgument, "network is required")
	}
	if s.netbox == nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this node has no netbox configuration; run the resume on a node that does")
	}
	if s.db == nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this node has no cluster database; run the resume on a node that does")
	}
	b, err := corrosion.GetBindingByNetwork(ctx, s.db, req.GetNetwork())
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"read binding for network %q: %v", req.GetNetwork(), err)
	}
	if b == nil {
		return nil, status.Errorf(codes.NotFound,
			"network %q is not bound to a NetBox prefix", req.GetNetwork())
	}
	if !b.Suspended {
		// Idempotent: resuming a live binding is the state the caller asked for.
		s.audit(ctx, "netbox.resume", req.GetNetwork(),
			fmt.Sprintf("prefix=%d already-live", b.PrefixID), "ok")
		return &emptypb.Empty{}, nil
	}

	// The LIVE fingerprint, so a CA replacement is still caught here and routed
	// to the re-key that actually fixes it — the reason string already names it.
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive cluster fingerprint: %v", err)
	}
	if reason := s.bindingDrift(ctx, *b, fp); reason != "" {
		s.audit(ctx, "netbox.resume", req.GetNetwork(),
			fmt.Sprintf("prefix=%d refused: %s", b.PrefixID, reason), "error")
		return nil, status.Errorf(codes.FailedPrecondition,
			"network %q stays suspended: %s", req.GetNetwork(), reason)
	}

	// Everything the pin records is written back UNCHANGED. Resume clears a
	// flag; it never re-observes the prefix into the binding, because that would
	// turn "the drift is gone" into "adopt whatever NetBox says now" — the very
	// silent re-identification the pin exists to prevent.
	next := *b
	next.Suspended = false
	next.SuspendReason = ""
	if err := corrosion.UpsertBinding(ctx, s.db, next); err != nil {
		s.audit(ctx, "netbox.resume", req.GetNetwork(),
			fmt.Sprintf("prefix=%d", b.PrefixID), "error")
		return nil, status.Errorf(codes.Internal,
			"resume binding for network %q: %v", req.GetNetwork(), err)
	}
	slog.Info("netbox binding resumed", "network", b.Network, "prefix", b.PrefixID)
	s.audit(ctx, "netbox.resume", req.GetNetwork(),
		fmt.Sprintf("prefix=%d", b.PrefixID), "ok")
	return &emptypb.Empty{}, nil
}
