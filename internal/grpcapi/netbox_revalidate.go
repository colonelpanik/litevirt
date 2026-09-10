package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/netboxsync"
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
// the binding, and only an operator says otherwise: `lv netbox resume` for a
// binding that re-validates cleanly again, or `lv netbox rekey` when the
// cluster's identity fingerprint has moved away from the binding's pin and the
// objects carrying the old one have to be re-stamped (resume refuses that case
// and names rekey).
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
	// The `netbox.cluster_name` uniformity finding, from the rows just read.
	//
	// HERE rather than in the sweep, because this pass runs on every configured
	// node and the sweep runs only on the leader — and the node whose config
	// disagrees is precisely the one that may never lead. It raises a health
	// condition and nothing else: the refusal itself lives at the mirror's
	// per-pass gate, and suspending a BINDING over it would be wrong in both
	// directions (it would stop allocation, which the mismatch does not
	// endanger, and it would do so cluster-wide over one node's config).
	//
	// Before the drift loop, so a node that cannot mirror says so on the same
	// pass whatever the drift check goes on to decide.
	s.evaluateNetBoxClusterPin(ctx, bindings)

	// Whether THIS host could provision each bound network at all. Same
	// placement: this pass runs on every configured node, and the fact is
	// host-local bridge state — so the node that cannot place a VM on a bound
	// network is the node that has to say so, and it may never lead.
	s.evaluateNetBoxDHCPConflicts(ctx, bindings)

	// The other half of the same enforcement: what this node's LIVE PEERS
	// published, which is the only uniformity evidence a cluster with no bound
	// network has. Also where this node PUBLISHES its own resolved name, so a
	// configured node contributes its opinion whether or not it ever mirrors.
	s.evaluateNetBoxClusterUniformity(ctx)

	// The IP scanner's refusals, from this node's own runtime. Reported here for
	// the same reason the two above are: this pass runs on every configured
	// node, and the observation is host-local — the scanner that made it runs on
	// whichever host the guest is on, which is not necessarily the leader.
	s.evaluateNetBoxDiscoveryRefusals(ctx)

	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return fmt.Errorf("derive cluster fingerprint: %w", err)
	}
	for _, b := range bindings {
		if b.Suspended {
			// The ONE suspension this pass may lift by itself. Everything else
			// records a repair an operator has to make, and lifting one of those
			// would declare a repair the pass never performed.
			if isUnhydratedSuspension(b.SuspendReason) {
				s.resumeUnhydratedBinding(ctx, b, fp)
			}
			continue
		}
		reason, derr := s.bindingDrift(ctx, b, fp)
		if derr != nil {
			// THE ONE PLACE THE UNKNOWN ANSWER IS TOLERATED, and it is tolerated
			// because this pass only ever makes a binding LESS trusted. A
			// suspension is sticky, so suspending on a NetBox maintenance window
			// would turn a transient into a network that refuses every create
			// until a human intervenes, with nothing actually having changed.
			// Preserving state is the conservative direction HERE and only here
			// — every path that makes a binding LIVE must refuse this answer, and
			// each of them does.
			slog.Warn("netbox: binding could not be re-validated; it is left exactly as it is",
				"network", b.Network, "prefix", b.PrefixID, "error", derr)
			continue
		}
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

// resumeUnhydratedBinding re-runs the adoption a bind could not, and resumes the
// binding once it completes.
//
// THIS IS THE CONVERGENT HALF of the uncorroborated-empty-read decision
// (corroborateEmptyVMRead). A bind that could not tell "this cluster has no VMs"
// from "this node has not replicated yet" left the binding SUSPENDED rather than
// live, which serves no claim; without this it would stay that way until an
// operator noticed. A refusal never converges; a pass does.
//
// ORDER: drift first, then adoption, then a FRESH drift re-check, then the
// activation — the same order the re-key's tail and ResumeBinding both use, and
// for the same reason. A binding waiting for its inventory can ALSO have been
// re-CIDRed or moved out of its VRF while it waited, and resuming on the
// strength of the adoption alone would lift a suspension over a prefix that no
// longer validates. A drift REPLACES the reason, which is what takes the binding
// out of the self-lifting class and puts it in front of an operator.
//
// THE FIRST CHECK IS THE CHEAP ONE, NOT THE PREMISE. It refuses before the
// adoption spends up to 256 NetBox POSTs on a binding that already cannot go
// live. The premise the activation rests on is the SECOND check, which
// activateBinding makes after the last of those POSTs — because the adoption's
// own requests are a window across which the answer to the first one can change.
//
// NO LEADER LEASE, and no nbPassMu of its own. Both follow the rule
// adoptExistingAddresses already states: adoption's exclusion is nbPassMu, which
// netboxMaintenanceTick holds for the whole of this pass, and adoption may not
// require cluster leadership. The cross-node consequence is that every configured
// node can run this for the same binding, which is safe rather than merely
// tolerated: the claim path recovers its own object by identity, so a second
// node's POST resolves to the first node's object and persists the same lease.
//
// IT COSTS NOTHING ON THE PASSES THAT CANNOT ACT. The corroboration is one local
// read, and the 2N+3-query enumeration behind adoptExistingAddresses only runs
// once it succeeds — so a binding waiting on a hydrating node does not re-scan
// the whole cluster's NICs every fifteen minutes.
//
// It returns nothing. Every outcome is either a state change on the row or a log
// line: a pass that cannot resume this binding has no bearing on the rest of
// revalidation, and returning an error would skip the orphan sweep behind it.
func (s *Server) resumeUnhydratedBinding(ctx context.Context, b corrosion.BindingRecord, fp string) {
	reason, derr := s.bindingDrift(ctx, b, fp)
	if derr != nil {
		// AN ACTIVATION PATH, so the unknown answer is a refusal. This function
		// ends in a resume, and the enclosing pass's tolerance for an unreadable
		// NetBox is a statement about leaving a binding ALONE — it cannot carry
		// over to lifting a suspension, which is the one thing here that makes a
		// binding serve claims again. Nothing changes: the reason stands, and the
		// next pass asks again.
		slog.Warn("netbox: binding stays suspended — its preconditions could not be "+
			"re-checked, so the adoption that would resume it was not attempted",
			"network", b.Network, "prefix", b.PrefixID, "error", derr)
		return
	}
	if reason != "" {
		slog.Warn("netbox binding suspended", "network", b.Network,
			"prefix", b.PrefixID, "reason", reason)
		if err := corrosion.SuspendBinding(ctx, s.db, b.PrefixID, reason); err != nil {
			slog.Error("netbox: could not re-state why a binding stays suspended",
				"network", b.Network, "prefix", b.PrefixID, "error", err)
			return
		}
		s.nbMetrics().IncBindingSuspended()
		return
	}

	adopted, aerr := s.activateBinding(ctx, b, nil)
	if ref, refused := activationRefused(aerr); refused {
		// THE FINAL GATE refused, having adopted everything. It owns the row: a
		// drift it READ is already written there (which takes this binding out
		// of the self-lifting class, correctly — that one needs an operator),
		// and an answer it could NOT read leaves the reason untouched so the
		// next pass asks again. Either way the adopted claims stand.
		if ref.reason != "" {
			slog.Warn("netbox: adopted every existing address, but the post-adoption "+
				"revalidation refused to activate the binding", "network", b.Network,
				"prefix", b.PrefixID, "adopted", adopted, "reason", ref.reason)
			return
		}
		slog.Warn("netbox: adopted every existing address, but the binding stays suspended — "+
			"its preconditions could not be re-checked AFTER the adoption, so activation was "+
			"refused; the next pass asks again", "network", b.Network, "prefix", b.PrefixID,
			"adopted", adopted, "error", ref.unread)
		return
	}
	if np, notPersisted := activationNotPersisted(aerr); notPersisted {
		// EVERYTHING WORKED EXCEPT THE WRITE. The addresses are adopted, the
		// preconditions were re-read after the last of them and they hold, and
		// the only step that failed is the one that records the flag.
		//
		// The row is left EXACTLY as it is, which is what keeps this binding in
		// the self-lifting class: re-stating the reason as owed adoption — which
		// is what a generic error here used to do — would move a suspension that
		// heals on the next pass into the class that waits for an operator, over
		// a transient this pass has already survived the hard part of.
		slog.Warn("netbox: adopted every existing address and re-validated cleanly, but the "+
			"activation could not be written down; the binding stays suspended under the reason "+
			"it already carries and the next pass retries",
			"network", b.Network, "prefix", b.PrefixID, "adopted", adopted, "error", np.cause)
		return
	}
	if errors.Is(aerr, errAdoptionUncorroborated) {
		// Still no standing to enumerate. Nothing changes — not the row, not the
		// reason — so the next pass asks again. INFO rather than WARN: the bind
		// already warned, the row already says so, and this repeats every
		// fifteen minutes for as long as the node is catching up.
		slog.Info("netbox: binding stays suspended — this node still cannot corroborate its VM "+
			"inventory", "network", b.Network, "prefix", b.PrefixID)
		return
	}
	if aerr != nil {
		// A real adoption failure. Re-state the reason with what is actually
		// outstanding, which also takes the binding out of the self-lifting
		// class: this one needs an operator.
		reason := fmt.Sprintf(
			"adoption of existing addresses on network %s is incomplete after adopting %d: %v",
			b.Network, adopted, aerr)
		slog.Warn("netbox: could not finish the adoption a bind left owed",
			"network", b.Network, "prefix", b.PrefixID, "adopted", adopted, "error", aerr)
		if err := corrosion.SuspendBinding(ctx, s.db, b.PrefixID, reason); err != nil {
			slog.Error("netbox: could not record why an adoption stopped; the binding stays "+
				"suspended under its previous reason",
				"network", b.Network, "prefix", b.PrefixID, "error", err)
			return
		}
		s.nbMetrics().IncBindingSuspended()
		return
	}
	s.audit(ctx, "netbox.adopt", b.Network,
		fmt.Sprintf("prefix=%d adopted=%d revalidation-resume", b.PrefixID, adopted), "ok")
	slog.Info("netbox binding resumed after a revalidation pass corroborated this node's "+
		"inventory and adopted what it found",
		"network", b.Network, "prefix", b.PrefixID, "adopted", adopted)
}

// bindingDrift re-runs every bind-time precondition and returns THREE
// distinguishable answers, never two.
//
//	("", nil)        every precondition was READ and holds.
//	(reason, nil)    a precondition was READ and does NOT hold.
//	("", err)        a precondition could not be read at all.
//
// At most one of the two is ever non-zero, and the third answer is the whole
// point of the signature. It used to be absent: a NetBox read failure returned
// the same empty string as a clean re-validation, which is "I could not look"
// reported as "nothing is wrong". The periodic pass reads that as "leave the
// binding alone", which is right, and every path that makes a binding LIVE read
// it as permission to resume — so a resume succeeded against an unreachable
// NetBox while the VRF's uniqueness enforcement was still switched off, which is
// the precise condition the binding had been suspended for.
//
// So the error is now unignorable at the type level, and the callers divide on
// it: the periodic pass tolerates it (it can only ever suspend, and suspension
// is sticky, so a maintenance window must not brick a network), while the resume,
// the re-key's tail and the automatic unhydrated completion all REFUSE it. A
// binding may go live only on preconditions somebody actually read.
//
// The API-error metric is counted here, because a failed NetBox read is a fact
// about NetBox whichever caller asked. The LOG line is not: what a failure means
// — "left as it is" or "stays suspended" — is the caller's, and only the caller
// knows which.
func (s *Server) bindingDrift(ctx context.Context, b corrosion.BindingRecord, liveFingerprint string) (string, error) {
	// The PIN, not a recomputation. Recomputing here would compare a value with
	// itself, never disagree, and quietly leave every existing NetBox object
	// stranded under an identity this cluster no longer recognises as its own.
	//
	// What this branch is NOT is a CA-replacement detector. The fingerprint is
	// minted once by corrosion.EnsureClusterRecord and deliberately never tracks
	// `ca.crt`; nothing in production rewrites `cluster.ca_cert` afterwards. So a
	// disagreement here means the replicated `cluster` row itself moved out of
	// band — an operator edit, or a restore carrying another installation's CA —
	// and the reason string says that rather than naming a cause an operator
	// mid-incident would go looking for and never find.
	if b.ClusterFingerprint != liveFingerprint {
		return fmt.Sprintf(
			"cluster identity fingerprint moved: this binding is pinned to %s and the cluster "+
				"now derives %s from its replicated `cluster` row; run `lv netbox rekey %s` to "+
				"re-stamp the objects still carrying the old one",
			b.ClusterFingerprint, liveFingerprint, b.Network), nil
	}

	p, err := s.netbox.GetPrefix(ctx, b.PrefixID)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		return "", fmt.Errorf("read prefix %d from NetBox: %w", b.PrefixID, err)
	}
	if p.Prefix != b.ObservedCIDR {
		// The addresses already handed out do NOT move with the prefix, so the
		// binding now names a range litevirt's leases are not inside.
		return fmt.Sprintf("prefix re-CIDRed from %s to %s", b.ObservedCIDR, p.Prefix), nil
	}
	if p.VRFID == 0 {
		// The same refusal bind makes: NetBox does not expose the global
		// ENFORCE_GLOBAL_UNIQUE setting, so uniqueness is unverifiable here.
		return "prefix moved to the global table, where uniqueness is not verifiable", nil
	}
	// THE SAME VRF, not merely a VRF that happens to share its policy.
	//
	// The uniqueness read below asks whether the prefix's CURRENT VRF enforces
	// uniqueness. On its own that is a weaker fact standing in for the one the
	// binding needs: a prefix moved between two uniqueness-enforcing VRFs passes
	// it, while the binding goes on carrying the OLD vrf_id as its allocation
	// scope. Everything downstream then works in a scope nothing has re-proved —
	// a dynamic claim fails the returned-VRF validation, and an explicit one is
	// still addressed to the VRF the prefix has left.
	//
	// REJECTED, NEVER REPINNED, and that is the deliberate half. Writing the new
	// id onto the row would move the allocation scope without establishing one
	// thing inside it: uniqueness within the new VRF says nothing about whether
	// the addresses this binding's guests already hold are unique THERE, and
	// those leases were proved against the old one. It is the same class of error
	// as resuming on a precondition nobody read. Moving a scope is an operator's
	// decision, so this states it and stops.
	if p.VRFID != b.VRFID {
		return fmt.Sprintf(
			"prefix moved out of VRF %d into VRF %d: the binding's allocation scope is pinned "+
				"to VRF %d, and re-pinning it would move that scope without re-proving the "+
				"addresses this network's guests already hold are unique inside the new one. "+
				"Move the prefix back in NetBox, or delete and recreate the litevirt network "+
				"to bind it against VRF %d",
			b.VRFID, p.VRFID, b.VRFID, p.VRFID), nil
	}

	unique, err := s.netbox.VRFEnforcesUnique(ctx, p.VRFID)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		return "", fmt.Errorf("read whether VRF %d enforces uniqueness: %w", p.VRFID, err)
	}
	if !unique {
		return fmt.Sprintf("VRF %d no longer enforces uniqueness", p.VRFID), nil
	}
	return "", nil
}

// ── the CA re-key ───────────────────────────────────────────────────────────

// RekeyBinding rewrites the identities a bound network owns in NetBox under the
// cluster's CURRENT fingerprint, then resumes the binding IF nothing else is
// wrong with it.
//
// A pinned fingerprint with no re-stamping path is an outage waiting for the
// first fingerprint move, so this is the operation that turns one into a chore.
// It answers the fingerprint pin and only that: a binding that had also drifted in
// NetBox stays suspended under the remaining reason, for `lv netbox resume`
// once an operator has repaired it.
//
// An EMPTY network is the cluster-scoped, INVENTORY-ONLY form — see
// rekeyInventoryOnly. It exists because a cluster can run the inventory mirror
// with no bound network at all (StartNetBoxMirror asks for a NetBox client and
// nothing else), and the per-network form has no pin to look up there.
func (s *Server) RekeyBinding(ctx context.Context, req *pb.RekeyBindingRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if s.netbox == nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this node has no netbox configuration; run the re-key on a node that does")
	}
	if s.db == nil {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this node has no cluster database; run the re-key on a node that does")
	}
	// The INTRA-node exclusion, before either form runs. The `netbox` leader
	// lease below is the cross-node half and cannot be this one: it names the
	// NODE, so on the node that holds it the re-key merely RENEWS the same
	// holder and this node's own mirror sweep and orphan sweep read "ours"
	// throughout the rewrite. Held for the whole operation, released when it
	// returns.
	//
	// A refusal, not a wait: a re-key can run for as long as NetBox takes, so an
	// operator queued behind a sweep would see a hang with nothing to read. The
	// retry this one advises is a real one — a maintenance or mirror pass ends
	// on its own, unlike a lease the holder renews forever.
	if !s.nbPassMu.TryLock() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"a NetBox maintenance or inventory pass is already running on this node, so "+
				"nothing was rewritten; the pass ends on its own — run the re-key again in a moment")
	}
	defer s.nbPassMu.Unlock()
	// `netbox.cluster_name` agreement, before either form does anything.
	//
	// A re-key resolves the SAME NetBox cluster object the mirror writes into and
	// then rewrites every identity under it. Run on a node whose configuration
	// disagrees with the cluster's pinned name, it would re-stamp objects in the
	// wrong cluster — or create that cluster and strand the real inventory — and
	// report success while doing it. That is strictly worse than a sweep, which
	// is why this refuses LOUDLY where the mirror declines in silence: an
	// operator is waiting on the answer and is the only one who can fix it.
	//
	// Both forms, including the inventory-only one. It resolves the same name and
	// enumerates the same cluster; a mirror-only installation simply has no
	// binding to compare against, so the check passes there and says so.
	if err := s.requireNetBoxClusterAgreement(ctx); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
	}
	if req.GetNetwork() == "" {
		return s.rekeyInventoryOnly(ctx)
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
	counts, err := s.rekeyBinding(ctx, *b)
	detail := fmt.Sprintf("prefix=%d rewritten=%d vms=%d interfaces=%d refs=%d",
		b.PrefixID, counts.addresses, counts.vms, counts.interfaces, counts.refs)
	if err != nil {
		// Audited on BOTH outcomes: a re-key that failed partway has still
		// rewritten objects in NetBox, so "nothing happened" is exactly the
		// wrong thing for the audit trail to imply.
		s.audit(ctx, "netbox.rekey", req.GetNetwork(), detail, "error")
		return nil, status.Errorf(rekeyCode(err), "re-key network %q: %v", req.GetNetwork(), err)
	}
	s.audit(ctx, "netbox.rekey", req.GetNetwork(), detail, "ok")
	return &emptypb.Empty{}, nil
}

// stillDriftedError is a re-key that rewrote every identity and then found the
// binding still invalid for a reason a re-key does not address.
type stillDriftedError struct{ reason string }

func (e stillDriftedError) Error() string {
	// NOT "run `lv netbox resume`": resume re-validates first and refuses a
	// binding whose identity pin is stale, telling the operator to re-key —
	// which is the command that just produced this error. Pointing at resume
	// sends them round that loop. The re-key is what re-pins the fingerprint,
	// so it is the re-key that has to be run again once NetBox is repaired.
	return fmt.Sprintf("identities re-keyed, but the binding remains suspended: %s"+
		" — repair it in NetBox, then run `lv netbox rekey` again once the drift is repaired", e.reason)
}

// leaseRefusedError is a re-key that could not take the `netbox` leader lease
// and therefore rewrote NOTHING. It is the fail-closed refusal, and it costs
// the operator a retry.
type leaseRefusedError struct{ holder string }

func (e leaseRefusedError) Error() string {
	if e.holder == "" {
		// The row is absent, unreadable, or already expired but not yet taken
		// by anyone. Naming a holder we cannot prove would be worse than
		// naming none — and here a retry genuinely can win, because no live
		// lease is standing in the way.
		return "could not take the netbox leader lease, so nothing was rewritten;" +
			" retry in a few minutes"
	}
	// NOT "retry": the holder RENEWS on every tick with a TTL of twice its
	// interval, and acquireNetBoxLease refuses to steal an unexpired lease, so
	// this refusal is permanent for as long as that node is up. Retrying here is
	// waiting for something that does not happen — and this is the only
	// re-stamping path there is, so while it is blocked every binding stays
	// suspended and
	// every create on a bound network refuses. The name is only useful if the
	// message says to go and use it.
	return fmt.Sprintf("the netbox leader lease is held by %q, so nothing was rewritten;"+
		" run the re-key on %s — that node renews the lease on every sweep, so waiting"+
		" here will not release it", e.holder, e.holder)
}

// leaseLostError is a re-key that HELD the lease and lost it partway, and so
// stopped rather than write on without it.
type leaseLostError struct{ holder string }

func (e leaseLostError) Error() string {
	if e.holder == "" {
		return "the netbox leader lease was lost mid-re-key"
	}
	return fmt.Sprintf("the netbox leader lease was lost mid-re-key and is now held by %q", e.holder)
}

// rekeyCode is the gRPC code a re-key failure deserves.
//
// FailedPrecondition for everything an OPERATOR can act on — a rewrite that
// finished and left the binding drifted for a reason a re-key does not address,
// and a lease this node could not take or did not keep. None of those is a bug
// in the daemon and all of them are answered by a retry, so reporting them as
// Internal would send an operator looking for one.
func rekeyCode(err error) codes.Code {
	var (
		drifted stillDriftedError
		refused leaseRefusedError
		lost    leaseLostError
	)
	if errors.As(err, &drifted) || errors.As(err, &refused) || errors.As(err, &lost) {
		return codes.FailedPrecondition
	}
	return codes.Internal
}

// rekeyCounts is what one re-key touched, for the audit trail. A re-key that
// failed partway has still rewritten some of it, so the numbers are recorded on
// both outcomes.
type rekeyCounts struct {
	addresses  int // ipam.ip-address objects
	vms        int // virtualization.virtual_machine objects
	interfaces int // virtualization.vminterface objects
	refs       int // local netbox_objects index rows
}

// ── the leader lease ────────────────────────────────────────────────────────

// A re-key is the THIRD writer under the `netbox` leader_election key, and it
// has to be, because it rewrites the very objects the other two act on.
//
// The orphan sweeper and the inventory mirror already share that one key so
// that neither can reclaim an address while the other rewrites the inventory
// naming it. The re-key rewrites both sets of identities at once, and a mirror
// sweep running alongside it sees a half-rewritten cluster: BuildActual filters
// actual state on the LIVE fingerprint, so a not-yet-rewritten VM is invisible,
// Diff emits a create for it, and NetBox's cluster-scoped VM-name uniqueness
// refuses that create — taking the whole sweep down. Nothing is corrupted (the
// failed create never reaches recordRef) and the next sweep converges once the
// re-key finishes, but a failed sweep is a false alarm an operator has to read.
//
// Taking the lease is also what makes the re-key STOP a sweep already in
// flight: the mirror re-validates the lease before every write batch, so an
// outgoing writer halts at its next boundary instead of racing on.

// rekeyLeaseInterval sizes the lease ONE re-key holds. acquireNetBoxLease
// writes an expiry of 2x whatever it is handed, so the re-key holds the lease
// for two minutes at a time and renews once half of that has gone.
//
// Deliberately NOT the sweep cadence, and deliberately renewed rather than
// sized to cover the operation: how long a re-key runs is a function of how
// much inventory NetBox holds, which nothing knows at acquire time, so any TTL
// "large enough" is a guess that fails in exactly the case that motivates it. A
// SHORT TTL is what keeps the other direction safe — the conditional upsert in
// acquireNetBoxLease refuses to steal an UNEXPIRED lease, so a re-key whose
// node dies mid-operation locks the mirror out for one TTL and no longer.
const rekeyLeaseInterval = time.Minute

// rekeyLease is the `netbox` leader lease held for the duration of one re-key.
type rekeyLease struct {
	s       *Server
	renewAt time.Time
}

// takeRekeyLease acquires the lease, or refuses having written nothing.
//
// acquireNetBoxLease is a conditional upsert plus a read-back: a losing acquire
// writes nothing at all and the read-back is what makes the loss observable
// rather than assumed. So a refusal here is proof this node does not lead, not
// an inference from one.
func (s *Server) takeRekeyLease(ctx context.Context) (*rekeyLease, error) {
	if !s.acquireNetBoxLease(ctx, rekeyLeaseInterval) {
		return nil, leaseRefusedError{holder: s.netBoxLeaseHolder(ctx)}
	}
	return &rekeyLease{s: s, renewAt: time.Now().Add(rekeyLeaseInterval)}, nil
}

// check re-proves the lease immediately before one more object is rewritten,
// renewing it when the TTL is half gone.
//
// The renewal cannot paper over a steal: it goes through the same conditional
// upsert, which writes nothing when a peer holds an unexpired lease, and the
// read-back then reports the loss. Between renewals the check is the READ
// alone, so a lease lost for any reason — a peer that took an expired row, a
// hand-edited row, a clock that moved — stops the rewrite at the very next
// object rather than at the next renewal.
//
// A local query per rewritten object is not a cost worth optimising: every one
// of those objects is an HTTP round trip to NetBox.
func (l *rekeyLease) check(ctx context.Context) error {
	if time.Now().Before(l.renewAt) {
		if l.s.holdsLeaderLease(ctx) {
			return nil
		}
		return leaseLostError{holder: l.s.netBoxLeaseHolder(ctx)}
	}
	if !l.s.acquireNetBoxLease(ctx, rekeyLeaseInterval) {
		return leaseLostError{holder: l.s.netBoxLeaseHolder(ctx)}
	}
	l.renewAt = time.Now().Add(rekeyLeaseInterval)
	return nil
}

// netBoxLeaseHolder names the node the `netbox` lease row records, for an
// operator-facing message and nothing else — never as a decision input, which
// is holdsLeaderLease's job.
//
// An EXPIRED row names nobody: it records who led last, not who leads, and
// putting that name in a refusal would send an operator to a node that has
// nothing to do with it. Same for an absent or unreadable row.
func (s *Server) netBoxLeaseHolder(ctx context.Context) string {
	if s.db == nil {
		return ""
	}
	rows, err := s.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election WHERE key = ?`, netBoxLeaseKey)
	if err != nil || len(rows) == 0 {
		return ""
	}
	expiresAt, err := time.Parse(time.RFC3339, rows[0].String("expires_at"))
	if err != nil || !time.Now().UTC().Before(expiresAt) {
		return ""
	}
	return rows[0].String("holder")
}

// rekeyBinding is the re-key itself: rewrite, then re-validate, then resume —
// never any other order.
//
// SCOPE: every object whose identity carries the cluster fingerprint. That is
// the bound prefix's `ipam.ip-address` objects, and — cluster-wide — the
// `virtual_machine` and `vminterface` objects the inventory mirror writes, and
// the local `netbox_objects` index whose litevirt_key IS the identity string.
// Leaving any of them behind strands it under a fingerprint this cluster no
// longer recognises as its own: the next sweep would find no inventory, emit a
// create for all of it, and be refused by NetBox's per-cluster VM-name
// uniqueness.
//
// ORDER, and it is not interchangeable: NetBox first, the local index second.
// NetBox rewritten with a stale local index is a LEAK — parentVMID prefers the
// parent id read from actual state, so parenting still resolves and the next
// adopt re-records the row under the new identity. The other way round is a
// COLLISION: the sweep looks for objects under an identity NetBox does not carry
// yet, finds nothing, and its create is refused by a name the cluster already
// holds. Leak over collision, every time.
//
// It is idempotent and RESUMABLE. Objects already carrying the new fingerprint
// no longer match the binding's (old) pin and are skipped, so a re-run finishes
// exactly the work a failed run left. What it is not is safe to interleave with
// a SECOND fingerprint move: objects stamped with an intermediate fingerprint
// match neither the old pin nor the new one. Finish a re-key before the
// fingerprint moves again.
func (s *Server) rekeyBinding(ctx context.Context, b corrosion.BindingRecord) (rekeyCounts, error) {
	var counts rekeyCounts
	newFP, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return counts, fmt.Errorf("derive cluster fingerprint: %w", err)
	}

	// The lease before ANY write, the suspend below included. A re-key that
	// cannot prove it leads the cluster must leave the binding exactly as it
	// found it — suspending a binding it is then not going to repair would take
	// a network out of service for nothing.
	lease, err := s.takeRekeyLease(ctx)
	if err != nil {
		return counts, err
	}

	// Suspend FIRST when the pin is already stale. Every claim stamps the LIVE
	// fingerprint, so a binding left allocating during a partial rewrite would
	// keep minting objects under a fingerprint its own pin does not cover. This
	// is also what revalidation would do on its next pass; doing it here makes
	// the re-key safe to run on its own, before any pass has noticed.
	if b.ClusterFingerprint != newFP && !b.Suspended {
		reason := fmt.Sprintf(
			"cluster identity fingerprint moved; re-key in progress for %s", b.Network)
		if err := corrosion.SuspendBinding(ctx, s.db, b.PrefixID, reason); err != nil {
			return counts, fmt.Errorf("suspend binding %d before re-key: %w", b.PrefixID, err)
		}
	}

	addrs, err := s.netbox.ListIPsByPrefix(ctx, b.ObservedCIDR, b.VRFID)
	if err != nil {
		// A partial enumeration would resume the binding with objects still
		// carrying the old fingerprint — invisible to this cluster ever after.
		return counts, fmt.Errorf("enumerate prefix %d: %w", b.PrefixID, err)
	}

	for _, ip := range addrs {
		cf, uuid, mac, ok := parseIdentity(ip.Identity)
		if !ok || cf != b.ClusterFingerprint {
			// Malformed, another cluster's, or already rewritten by an earlier
			// run of this same re-key. The pin is what says which are ours.
			continue
		}
		if err := lease.check(ctx); err != nil {
			return counts, fmt.Errorf("re-key address %s (id %d) after %d rewrites; "+
				"the binding stays suspended, re-run to finish: %w",
				ip.Address, ip.ID, counts.addresses, err)
		}
		if err := s.netbox.SetIPIdentity(ctx, ip.ID, netbox.Identity(newFP, uuid, mac)); err != nil {
			s.nbMetrics().IncAPIError(netbox.Classify(err))
			return counts, fmt.Errorf("rewrite identity on address %s (id %d) after %d rewrites; "+
				"the binding stays suspended, re-run to finish: %w",
				ip.Address, ip.ID, counts.addresses, err)
		}
		counts.addresses++
	}

	// The inventory objects the mirror owns, then the local index — in that
	// order, and both BEFORE the resume below. See the ordering note on this
	// function: a binding resumed over a half-rewritten inventory is live with
	// objects it can no longer name.
	if err := s.rekeyInventory(ctx, lease, b.ClusterFingerprint, newFP, &counts); err != nil {
		return counts, err
	}
	if err := s.rekeyObjectIndex(ctx, lease, b.ClusterFingerprint, newFP, &counts); err != nil {
		return counts, err
	}

	// A proof before the tail below starts writing. What follows is the drift
	// re-check (which can SUSPEND), the adoption (which can POST up to 256
	// times), and finally the resume — and each of those is a write that may not
	// rest on a lease this node stopped holding somewhere in the rewrite above.
	// Returning here leaves the binding suspended and the operation re-runnable,
	// which is the contract every error in this function already promises.
	//
	// It is the FIRST of three proofs in this tail, not the only one: the
	// adoption re-proves before every claim of its own, and the resume re-proves
	// again immediately before it writes. One proof here would cover the drift
	// check and then be separated from the resume by every one of those round
	// trips.
	if err := lease.check(ctx); err != nil {
		return counts, fmt.Errorf("re-validate before resuming the binding for prefix %d; "+
			"it stays suspended, re-run to finish: %w", b.PrefixID, err)
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
	reason, derr := s.bindingDrift(ctx, next, newFP)
	if derr != nil {
		// AN ACTIVATION PATH: this tail ends in a resume, so a precondition that
		// could not be READ is a refusal, not a pass. The identities have already
		// been rewritten and that work is kept — the binding simply stays
		// suspended under its existing reason, and the re-key is re-runnable
		// exactly as every other error in this function promises.
		return counts, fmt.Errorf(
			"identities re-keyed, but the binding for prefix %d cannot be resumed because its "+
				"NetBox preconditions could not be re-checked; it stays suspended, re-run to "+
				"finish: %w", b.PrefixID, derr)
	}
	if reason != "" {
		if err := corrosion.SuspendBinding(ctx, s.db, b.PrefixID, reason); err != nil {
			return counts, fmt.Errorf("suspend binding %d after re-key: %w", b.PrefixID, err)
		}
		slog.Warn("netbox binding re-keyed but still drifted", "network", b.Network,
			"prefix", b.PrefixID, "addresses_rewritten", counts.addresses,
			"vms_rewritten", counts.vms, "interfaces_rewritten", counts.interfaces,
			"index_rows_rewritten", counts.refs, "reason", reason)
		return counts, stillDriftedError{reason: reason}
	}

	// A re-key RESUMES, and every resume has to pass the same gate: a binding
	// may not go live over an address its guests hold that NetBox has not been
	// told about. Without this, `lv netbox rekey` would be a second door around
	// the adoption gate — a bind whose adoption stopped partway leaves the
	// binding suspended, bindingDrift finds nothing wrong with it (the pin is
	// current), and this tail would resume it over the un-adopted remainder.
	//
	// It ADOPTS rather than merely refusing, so the re-key finishes the job like
	// the resume does. Under the NEW fingerprint, which is what `next` carries
	// and what the rewrite above has just stamped on everything else.
	//
	// UNDER THE LEASE, which the loop inside re-proves before every claim. This
	// step is up to 256 NetBox round trips against a one-minute lease, so it is
	// the longest stretch in the whole re-key and the one most likely to outlive
	// a handover; leaving it unproven would also separate the resume below from
	// its last proof by all of them.
	//
	// NOT "a few local reads" on a binding with nothing owed, which is what this
	// used to claim. It re-plans the adoption unconditionally, which is 2N+3
	// local queries for a cluster of N VMs — every VM's two NIC tables, before
	// anything can be known to be owed (planAdoption states the figure). A
	// re-key that is only answering a fingerprint move pays all of it. That is
	// accepted here rather than optimised: a re-key is an operator command, it
	// already spends one NetBox round trip per object it rewrites, and the scan
	// is what makes the resume below unable to be a second door around the
	// adoption gate.
	// THE ACTIVATION GATE owns everything from here: the adoption, the FRESH
	// post-adoption re-check the activation actually rests on, the last lease
	// proof, and the write that lifts the flag. The drift check above is the
	// cheap refusal that keeps a doomed re-key from POSTing 256 times; it is not
	// the premise, because the adoption's own requests are exactly the window
	// across which its answer can change. See activateBinding.
	adopted, aerr := s.activateBinding(ctx, next, lease)
	if ref, refused := activationRefused(aerr); refused {
		if ref.reason != "" {
			// The gate has already re-stated the suspension under the drift it
			// READ. Reported as stillDriftedError so `lv netbox rekey` names the
			// same class of outcome it does for a pre-adoption drift: the
			// rewrite finished, the binding did not go live, and the remaining
			// reason is an operator's to repair.
			slog.Warn("netbox binding re-keyed but its post-adoption revalidation refused "+
				"activation", "network", b.Network, "prefix", b.PrefixID,
				"adopted", adopted, "reason", ref.reason)
			return counts, stillDriftedError{reason: ref.reason}
		}
		slog.Warn("netbox binding re-keyed but not activated — its preconditions could not be "+
			"re-checked after the adoption", "network", b.Network, "prefix", b.PrefixID,
			"adopted", adopted, "error", ref.unread)
		return counts, fmt.Errorf(
			"identities re-keyed and every existing address adopted, but the binding for "+
				"prefix %d was not activated; it stays suspended, re-run to finish: %w",
			b.PrefixID, aerr)
	}
	if np, notPersisted := activationNotPersisted(aerr); notPersisted {
		// The gate passed and the write did not land — the lease lapsed across
		// the adoption's round trips, or the local upsert failed. The adoption is
		// NOT owed, so the reason on the row is not re-stated: re-run the re-key
		// and it activates.
		slog.Warn("netbox binding re-keyed and re-validated, but the activation could not be "+
			"written down; it stays suspended under the reason it already carries",
			"network", b.Network, "prefix", b.PrefixID, "adopted", adopted, "error", np.cause)
		return counts, fmt.Errorf(
			"identities re-keyed and every existing address adopted, but the binding for "+
				"prefix %d was not activated; it stays suspended, re-run to finish: %w",
			b.PrefixID, aerr)
	}
	if aerr != nil {
		reason := fmt.Sprintf(
			"identities re-keyed, but the addresses this network's guests already hold are not "+
				"all recorded in NetBox (adopted %d this pass): %v", adopted, aerr)
		if serr := corrosion.SuspendBinding(ctx, s.db, b.PrefixID, reason); serr != nil {
			return counts, fmt.Errorf("suspend binding %d after re-key: %w", b.PrefixID, serr)
		}
		slog.Warn("netbox binding re-keyed but its existing addresses are not all adopted",
			"network", b.Network, "prefix", b.PrefixID, "adopted", adopted, "error", aerr)
		return counts, stillDriftedError{reason: reason}
	}
	slog.Info("netbox binding re-keyed", "network", b.Network, "prefix", b.PrefixID,
		"addresses_rewritten", counts.addresses, "vms_rewritten", counts.vms,
		"interfaces_rewritten", counts.interfaces, "index_rows_rewritten", counts.refs,
		"fingerprint", newFP)
	return counts, nil
}

// ── the inventory half ──────────────────────────────────────────────────────

// The netbox_objects kinds the inventory mirror records under. They are a
// REPLICATED column value, so they live here as literals matching
// internal/netboxsync's rather than as an import that could be renamed on one
// side of a mixed-version cluster.
const (
	rekeyRefKindVM  = "vm"
	rekeyRefKindNIC = "nic"
)

// rekeyInventoryDetail is the audit detail every outcome of the cluster-scoped
// re-key records — refusal, no-op, partial failure and success alike — so the
// shape an operator greps for is written in one place rather than three.
func rekeyInventoryDetail(pins, rows int, counts rekeyCounts) string {
	return fmt.Sprintf("inventory pins=%d rows=%d vms=%d interfaces=%d refs=%d",
		pins, rows, counts.vms, counts.interfaces, counts.refs)
}

// rekeyInventoryTarget is what the audit trail names for the cluster-scoped
// form. Parenthesised because a network name never can be, so it can never be
// confused with a per-network re-key of a network someone called "inventory".
const rekeyInventoryTarget = "(inventory)"

// rekeyInventoryOnly is the CLUSTER-SCOPED re-key: no network, no binding, no
// resume — just the inventory objects and the local index that names them.
//
// It exists because a cluster can use NetBox purely for INVENTORY.
// StartNetBoxMirror asks for a NetBox client and nothing else, so a cluster with
// no bound network is a supported configuration — and one the per-network form
// cannot serve, because it takes its old-fingerprint pin from a binding row that
// does not exist. A fingerprint move there leaves every virtual_machine and
// vminterface carrying a fingerprint the cluster no longer answers to, and the
// next sweep tries to duplicate the whole inventory into a NetBox cluster whose
// VM names are already taken.
//
// WHERE THE PIN COMES FROM, which is the whole safety argument: the LOCAL INDEX.
// `netbox_objects.litevirt_key` IS the identity string, and those rows are
// written only by this cluster's own mirror into this cluster's own replicated
// database — so any fingerprint appearing in one is provably ours, and needs no
// binding to vouch for it. A fingerprint move does not disturb the index either;
// nothing rewrites it but recordRef and rekeyObjectIndex.
//
// What it must NEVER do is fall back to "rewrite anything that is not the
// current fingerprint". ListVMsByCluster hands this cluster every object in a
// NetBox cluster it may be SHARING with a second installation, and that rule
// would stamp the co-tenant's inventory with this cluster's identity — leaving
// them to find nothing of their own and be refused by the names they already
// hold. No derivable pin means no re-key.
//
// NO BINDING MEANS NO RESUME, and therefore no resume gate. The per-network form
// leans on that gate to make a partial re-key visible and re-runnable; here the
// visible artefact is the audit row and the error, and re-runnability comes from
// the pin filter alone — an object already carrying the new fingerprint no
// longer matches, so a re-run finishes exactly the work a failed run left.
//
// Bound networks are NOT covered. This rewrites no `ipam.ip-address` object and
// resumes no binding, so a cluster that has both still runs `lv netbox rekey
// <network>` for each of them; that run finds the inventory already done and
// costs two list calls.
func (s *Server) rekeyInventoryOnly(ctx context.Context) (*emptypb.Empty, error) {
	newFP, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive cluster fingerprint: %v", err)
	}
	pins, rows, err := s.inventoryPins(ctx, newFP)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive the re-key pin: %v", err)
	}
	if rows == 0 {
		// FAIL CLOSED. An empty index records no earlier fingerprint at all, so
		// there is nothing to derive a pin from — and reporting success would be
		// worse than refusing: an operator whose index was lost while NetBox
		// still holds stranded inventory would be told the re-key worked.
		s.audit(ctx, "netbox.rekey", rekeyInventoryTarget,
			rekeyInventoryDetail(0, 0, rekeyCounts{}), "error")
		return nil, status.Errorf(codes.FailedPrecondition,
			"the local identity index holds no rows, so nothing records the fingerprint this "+
				"cluster's NetBox objects carry; re-stamping everything that is not the current "+
				"fingerprint would seize a second installation's objects out of a shared NetBox. "+
				"If NetBox holds inventory under an identity this cluster no longer recognises, "+
				"remove it there by hand and let the mirror rebuild it")
	}
	if len(pins) == 0 {
		// Already consistent: every row the index holds is under the live
		// fingerprint. Nothing to rewrite, and — deliberately — no other rule to
		// fall back on. This is also what makes a second run of a completed
		// re-key a no-op.
		slog.Info("netbox re-key: every local index row already carries the live fingerprint",
			"rows", rows, "fingerprint", newFP)
		s.audit(ctx, "netbox.rekey", rekeyInventoryTarget,
			rekeyInventoryDetail(0, rows, rekeyCounts{}), "ok")
		return &emptypb.Empty{}, nil
	}

	// The lease, and only now: neither answer above writes anything, and taking
	// the lease to refuse or to no-op would lock the inventory mirror out of a
	// sweep for nothing. Everything below this line rewrites.
	lease, err := s.takeRekeyLease(ctx)
	if err != nil {
		// Audited like every other outcome, because an operator has to be able
		// to see that the command ran and declined.
		s.audit(ctx, "netbox.rekey", rekeyInventoryTarget,
			rekeyInventoryDetail(len(pins), rows, rekeyCounts{}), "error")
		return nil, status.Errorf(rekeyCode(err), "re-key inventory: %v", err)
	}

	// One pass per stale fingerprint. More than one means a rotation was
	// interrupted and then rotated again; all of them are ours by construction,
	// so each is re-keyed in turn rather than guessed between.
	var counts rekeyCounts
	var failed error
	for _, oldFP := range pins {
		// NetBox first, the local index second — the same order and the same
		// reason as the per-network form. Leak over collision, every time.
		if failed = s.rekeyInventory(ctx, lease, oldFP, newFP, &counts); failed != nil {
			break
		}
		if failed = s.rekeyObjectIndex(ctx, lease, oldFP, newFP, &counts); failed != nil {
			break
		}
	}

	detail := rekeyInventoryDetail(len(pins), rows, counts)
	if failed != nil {
		// Audited on BOTH outcomes, as the per-network form is: a re-key that
		// failed partway has still rewritten objects, so "nothing happened" is
		// the wrong thing for the audit trail to imply.
		s.audit(ctx, "netbox.rekey", rekeyInventoryTarget, detail, "error")
		return nil, status.Errorf(rekeyCode(failed), "re-key inventory: %v", failed)
	}
	slog.Info("netbox inventory re-keyed", "pins", len(pins), "index_rows", rows,
		"vms_rewritten", counts.vms, "interfaces_rewritten", counts.interfaces,
		"index_rows_rewritten", counts.refs, "fingerprint", newFP)
	s.audit(ctx, "netbox.rekey", rekeyInventoryTarget, detail, "ok")
	return &emptypb.Empty{}, nil
}

// inventoryPins reads the local index and returns the distinct fingerprints in
// it that are NOT the live one, plus how many rows it holds at all.
//
// The row count is returned separately because "no stale fingerprints" and "no
// index" are different states with different answers: the first is a converged
// cluster, the second is one this command must refuse. A single empty slice
// cannot tell them apart, and conflating them is precisely how a refusal turns
// into a silent success.
//
// Sorted, so a multi-pin re-key rewrites in the same order every run and a
// failure partway is reproducible rather than depending on map iteration.
func (s *Server) inventoryPins(ctx context.Context, liveFP string) (pins []string, rows int, err error) {
	seen := map[string]bool{}
	for _, kind := range []string{rekeyRefKindVM, rekeyRefKindNIC} {
		refs, err := corrosion.ListObjectRefs(ctx, s.db, kind)
		if err != nil {
			return nil, 0, fmt.Errorf("list %s index rows: %w", kind, err)
		}
		rows += len(refs)
		for _, ref := range refs {
			// splitIdentity, not parseIdentity: a VM row's key is
			// Identity(fp, uuid, "") and carries an EMPTY mac, which
			// parseIdentity refuses. Reading only NIC rows would still derive
			// the right pin today, but a cluster whose VMs alone were stranded
			// would silently get none.
			cf, _, _, ok := splitIdentity(ref.LitevirtKey)
			if !ok || cf == liveFP || seen[cf] {
				continue
			}
			seen[cf] = true
			pins = append(pins, cf)
		}
	}
	sort.Strings(pins)
	return pins, rows, nil
}

// rekeyInventory re-stamps this cluster's `virtual_machine` and `vminterface`
// objects, which carry the same fingerprint every address does.
//
// CLUSTER-SCOPED inside a PER-BINDING operation, deliberately. The resume gate
// is what makes a partial re-key visible and re-runnable, and that gate lives on
// the binding — so the inventory rewrite has to sit inside it, before the
// re-validate. Running it once per bound network costs two extra list calls per
// network after the first, because the old-fingerprint pin filter then matches
// nothing; that is cheap, and the alternative — resuming a binding while the
// inventory it shares with every other binding is half-rewritten — is not.
//
// The pin filter is `== oldFP`, never `!= newFP`. Two litevirt installations can
// share one NetBox and, mirroring under the same cluster name, one NetBox
// cluster object — so this enumeration hands one cluster's re-key the OTHER
// cluster's inventory, and only the fingerprint says which rows are ours.
func (s *Server) rekeyInventory(ctx context.Context, lease *rekeyLease, oldFP, newFP string, counts *rekeyCounts) error {
	if oldFP == newFP {
		// Nothing to match. Without this a redundant re-key would PATCH every
		// object in the cluster to the value it already holds.
		//
		// It also means a binding whose pin was already advanced by a re-key
		// that did NOT rewrite inventory (a pre-P2 build) can never be repaired
		// through this path: the fingerprint those objects carry is no longer
		// recorded anywhere, and rewriting whatever is not newFP would stamp a
		// second installation's objects with this cluster's identity.
		return nil
	}
	clusterID, err := s.netboxClusterID(ctx)
	if err != nil {
		return err
	}
	if clusterID == 0 {
		// No cluster object means no inventory in it. Not an error, and not a
		// reason to refuse the re-key of the addresses that did get rewritten.
		slog.Info("netbox re-key: no cluster object, so no inventory to re-stamp")
		return nil
	}

	vms, err := s.netbox.ListVMsByCluster(ctx, clusterID)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		// A partial enumeration would resume the binding over inventory still
		// carrying the old fingerprint, which is the whole failure this exists
		// to prevent.
		return fmt.Errorf("enumerate VMs in cluster %d for re-key; the binding stays suspended, "+
			"re-run to finish: %w", clusterID, err)
	}
	for _, vm := range vms {
		cf, uuid, _, ok := splitIdentity(vm.Identity)
		if !ok || cf != oldFP {
			continue
		}
		// The VM form of an identity carries NO MAC. Rebuilding it with the one
		// splitIdentity returned would work only because it is empty; passing ""
		// says so.
		if err := lease.check(ctx); err != nil {
			return fmt.Errorf("re-key VM %d after %d addresses and %d VMs; the binding stays "+
				"suspended, re-run to finish: %w", vm.ID, counts.addresses, counts.vms, err)
		}
		if err := s.netbox.SetVMIdentity(ctx, vm.ID, netbox.Identity(newFP, uuid, "")); err != nil {
			s.nbMetrics().IncAPIError(netbox.Classify(err))
			return fmt.Errorf("rewrite identity on VM %d after %d addresses and %d VMs; "+
				"the binding stays suspended, re-run to finish: %w",
				vm.ID, counts.addresses, counts.vms, err)
		}
		counts.vms++
	}

	ifaces, err := s.netbox.ListInterfacesByCluster(ctx, clusterID)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		return fmt.Errorf("enumerate interfaces in cluster %d for re-key; the binding stays "+
			"suspended, re-run to finish: %w", clusterID, err)
	}
	for _, i := range ifaces {
		cf, uuid, mac, ok := splitIdentity(i.Identity)
		if !ok || cf != oldFP {
			continue
		}
		if err := lease.check(ctx); err != nil {
			return fmt.Errorf("re-key interface %d after %d VMs and %d interfaces; the binding "+
				"stays suspended, re-run to finish: %w", i.ID, counts.vms, counts.interfaces, err)
		}
		if err := s.netbox.SetInterfaceIdentity(ctx, i.ID, netbox.Identity(newFP, uuid, mac)); err != nil {
			s.nbMetrics().IncAPIError(netbox.Classify(err))
			return fmt.Errorf("rewrite identity on interface %d after %d VMs and %d interfaces; "+
				"the binding stays suspended, re-run to finish: %w",
				i.ID, counts.vms, counts.interfaces, err)
		}
		counts.interfaces++
	}
	return nil
}

// netboxClusterID resolves the NetBox cluster this litevirt cluster mirrors
// into, WITHOUT creating it — see netbox.FindCluster.
//
// The name comes from netboxsync, which owns it. Deriving it here instead would
// put a second copy of the placeholder fallback in the tree, and a re-key
// looking at a different cluster than the mirror writes to would report zero
// objects rewritten and resume the binding over inventory it never touched.
func (s *Server) netboxClusterID(ctx context.Context) (int, error) {
	name, err := netboxsync.ClusterName(ctx, s.db, s.netboxClusterName)
	if err != nil {
		return 0, fmt.Errorf("read cluster name for re-key: %w", err)
	}
	id, err := s.netbox.FindCluster(ctx, name)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		return 0, fmt.Errorf("resolve NetBox cluster %q for re-key; the binding stays suspended, "+
			"re-run to finish: %w", name, err)
	}
	return id, nil
}

// rekeyObjectIndex re-stamps the LOCAL identity map, whose litevirt_key is the
// identity string itself.
//
// Stranded rows here are not cosmetic. GetObjectRef is keyed on that string, so
// a NIC's parent lookup finds nothing under the new identity, and every adopt
// re-searches NetBox instead of resolving the id it already recorded.
//
// LAST, after NetBox. A row rewritten ahead of the object it names points at an
// identity NetBox does not carry, and the sweep that trusts it then behaves as
// if the object were absent.
//
// Each row is written under its NEW key BEFORE the old one is tombstoned,
// keeping the netbox_id mapped throughout: the crash window leaves a harmless
// duplicate pointing at the same object rather than a moment with no row at all.
// Both writes are the same replicated statements the mirror already uses — the
// key is part of the primary key, so this is an insert and a tombstone, never an
// update of it.
func (s *Server) rekeyObjectIndex(ctx context.Context, lease *rekeyLease, oldFP, newFP string, counts *rekeyCounts) error {
	if oldFP == newFP {
		return nil
	}
	for _, kind := range []string{rekeyRefKindVM, rekeyRefKindNIC} {
		refs, err := corrosion.ListObjectRefs(ctx, s.db, kind)
		if err != nil {
			return fmt.Errorf("list %s index rows for re-key; the binding stays suspended, "+
				"re-run to finish: %w", kind, err)
		}
		for _, ref := range refs {
			cf, uuid, mac, ok := splitIdentity(ref.LitevirtKey)
			if !ok || cf != oldFP {
				// Same pin as the NetBox side, and for the same reason: a row
				// under an intermediate fingerprint belongs to a re-key that was
				// interrupted by a second fingerprint move, and guessing at it
				// would orphan the object it names.
				continue
			}
			if err := lease.check(ctx); err != nil {
				return fmt.Errorf("re-key %s index row after %d rows; the binding stays "+
					"suspended, re-run to finish: %w", kind, counts.refs, err)
			}
			next := ref
			next.LitevirtKey = netbox.Identity(newFP, uuid, mac)
			if err := corrosion.PutObjectRef(ctx, s.db, next); err != nil {
				return fmt.Errorf("re-key %s index row after %d rows; the binding stays "+
					"suspended, re-run to finish: %w", kind, counts.refs, err)
			}
			if err := corrosion.DeleteObjectRef(ctx, s.db, kind, ref.LitevirtKey); err != nil {
				return fmt.Errorf("retire the old %s index row after %d rows; the binding stays "+
					"suspended, re-run to finish: %w", kind, counts.refs, err)
			}
			counts.refs++
		}
	}
	return nil
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

	// THE INTRA-NODE EXCLUSION. A resume finishes any owed adoption below, which
	// POSTs to NetBox, so this RPC is a NetBox WRITE PASS — and nbPassMu admits
	// one at a time on this node (server.go). It was a read-and-clear-a-flag call
	// when that rule was written and is not any more; without this it could run
	// its claims straight through a re-key rewriting the very identities those
	// claims are stamped with, on this same node, where the `netbox` leader lease
	// cannot separate them because it names the node.
	//
	// Taken AFTER the idempotent early-out above, so resuming an already-live
	// binding never contends, and held for the whole of the rest of the call: the
	// drift re-check, the adoption, and the write that lifts the flag.
	//
	// A refusal, not a wait — an operator queued behind a sweep would see a hang
	// with nothing to read, and the suspension is sticky, so retrying costs
	// nothing.

	if !s.nbPassMu.TryLock() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"a NetBox maintenance or inventory pass is already running on this node, so "+
				"network %q stays suspended and nothing was written; the pass ends on its own "+
				"— run the resume again in a moment", req.GetNetwork())
	}
	defer s.nbPassMu.Unlock()

	// The LIVE fingerprint, so a moved fingerprint is still caught here and routed
	// to the re-key that actually fixes it — the reason string already names it.
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "derive cluster fingerprint: %v", err)
	}
	reason, derr := s.bindingDrift(ctx, *b, fp)
	if derr != nil {
		// A RESUME MAY NOT REST ON A VALIDATION THAT DID NOT HAPPEN.
		//
		// This is the door the empty-string-on-failure predicate walked straight
		// through: NetBox unreachable, both reads failed, no reason came back, and
		// the resume read that as "the drift is gone" and lifted a suspension
		// whose cause — a VRF that had stopped enforcing uniqueness — was still
		// there. An operator's word is not the premise this call rests on; the
		// re-read is, and a re-read that failed is not one.
		//
		// FailedPrecondition, not Internal: nothing is broken here, the answer is
		// simply not available yet, and the retry once NetBox answers is the same
		// command.
		s.audit(ctx, "netbox.resume", req.GetNetwork(),
			fmt.Sprintf("prefix=%d refused: preconditions unread: %v", b.PrefixID, derr), "error")
		return nil, status.Errorf(codes.FailedPrecondition,
			"network %q stays suspended: its NetBox preconditions could not be re-checked, so "+
				"nothing was resumed and nothing was written — a resume re-proves the binding "+
				"rather than taking the repair on trust. Run it again once NetBox answers: %v",
			req.GetNetwork(), derr)
	}
	if reason != "" {
		s.audit(ctx, "netbox.resume", req.GetNetwork(),
			fmt.Sprintf("prefix=%d refused: %s", b.PrefixID, reason), "error")
		return nil, status.Errorf(codes.FailedPrecondition,
			"network %q stays suspended: %s", req.GetNetwork(), reason)
	}

	// FINISH ANY OWED ADOPTION before the flag comes off, and refuse the resume
	// if it cannot be finished.
	//
	// This is the other half of the resume GATE, and without it the gate is
	// fail-OPEN. A bind whose adoption stopped partway leaves the binding
	// suspended precisely so that the un-adopted remainder cannot be handed to
	// anybody; a resume that only cleared the flag would make the binding live
	// over exactly that remainder, and NetBox would offer a running guest's
	// address to the next VM. It is also what makes "re-run to finish" true:
	// the resume is the operator's re-run.
	//
	// It makes no NetBox request when nothing is owed, so an ordinary resume of
	// a drift suspension writes nothing remote — but it is NOT cheap, which is
	// what this used to say. Establishing that nothing is owed means re-planning
	// the adoption: 2N+3 local queries for a cluster of N VMs, every VM's two
	// NIC tables, on every `lv netbox resume` whatever the suspension was for
	// (planAdoption states the figure and why it is not bounded). Accepted for
	// the same reason as the re-key's: this is an operator command, not a
	// periodic pass.
	//
	// No leader lease: a resume must not require cluster leadership, so this
	// door's exclusion is the nbPassMu above and nothing else. See
	// adoptExistingAddresses.
	// Everything the pin records is written back UNCHANGED. An activation clears
	// a flag; it never re-observes the prefix into the binding, because that
	// would turn "the drift is gone" into "adopt whatever NetBox says now" — the
	// very silent re-identification the pin exists to prevent. activateBinding
	// upserts the record it is HANDED for exactly that reason.
	adopted, aerr := s.activateBinding(ctx, *b, nil)
	if ref, refused := activationRefused(aerr); refused {
		s.audit(ctx, "netbox.resume", req.GetNetwork(),
			fmt.Sprintf("prefix=%d adopted=%d refused: post-adoption revalidation", b.PrefixID, adopted), "error")
		// FailedPrecondition for BOTH halves. A drift the gate READ is an
		// operator's repair; an answer it could not read is a retry of this same
		// command. Neither is a fault in the daemon, and Internal would send
		// someone hunting one.
		return nil, status.Errorf(codes.FailedPrecondition,
			"network %q stays suspended: %v", req.GetNetwork(), ref)
	}
	if _, notPersisted := activationNotPersisted(aerr); notPersisted {
		// The gate passed; the write did not land. Reported as what it is rather
		// than as owed adoption — Internal, because a local write that failed is
		// a fault to fix and not a precondition to repair — and the row keeps the
		// reason it already carries, so a self-lifting suspension stays one.
		s.audit(ctx, "netbox.resume", req.GetNetwork(),
			fmt.Sprintf("prefix=%d adopted=%d not-persisted", b.PrefixID, adopted), "error")
		return nil, status.Errorf(codes.Internal,
			"network %q stays suspended: %v", req.GetNetwork(), aerr)
	}
	if aerr != nil {
		s.audit(ctx, "netbox.resume", req.GetNetwork(),
			fmt.Sprintf("prefix=%d adopted=%d", b.PrefixID, adopted), "error")
		code := codes.Internal
		if adoptionRefused(aerr) {
			code = codes.FailedPrecondition
		}
		return nil, status.Errorf(code,
			"network %q stays suspended: the addresses its guests already hold are not all "+
				"recorded in NetBox (adopted %d this pass): %v",
			req.GetNetwork(), adopted, aerr)
	}
	slog.Info("netbox binding resumed", "network", b.Network, "prefix", b.PrefixID,
		"adopted", adopted)
	s.audit(ctx, "netbox.resume", req.GetNetwork(),
		fmt.Sprintf("prefix=%d adopted=%d", b.PrefixID, adopted), "ok")
	return &emptypb.Empty{}, nil
}
