package grpcapi

import (
	"context"
	"fmt"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/netboxsync"
	"github.com/litevirt/litevirt/internal/network"
)

// validateAndBindPrefix runs every bind-time precondition and records the
// binding. Each check fails closed with an operator-actionable message.
//
// def is the network definition the bind is FOR, not a copy of anything already
// persisted — nothing is persisted yet, and check 2b needs it. It is passed
// explicitly rather than defaulted, because a default would be a value for the
// hazard input: a fixture that quietly supplied a subnet-less def would make
// every caller look safe and check 2b reachable by nothing.
func (s *Server) validateAndBindPrefix(ctx context.Context, netName string, prefixID int, def compose.NetworkDef) error {
	if s.netbox == nil {
		return fmt.Errorf("binding a NetBox prefix requires netbox configuration on this node")
	}

	// 1. The latch, DURABLY. A latch that is only in-memory would not survive a
	//    restart — this node could come back up, momentarily believe the fleet
	//    doesn't support netbox_ipam_v1 yet, and an older peer that never parses
	//    NetBoxPrefixID would then allocate from the builtin allocator across an
	//    already-bound prefix. DurablyLatched requires the persisted marker, not
	//    just the in-memory flag.
	if s.gate == nil || !s.gate.DurablyLatched(capabilities.NetBoxIPAMV1) {
		return fmt.Errorf("%s is not durably latched cluster-wide — enable netbox on every node first", capabilities.NetBoxIPAMV1)
	}

	// 2. The prefix exists, and we record its CIDR as the drift baseline.
	p, err := s.netbox.GetPrefix(ctx, prefixID)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		return fmt.Errorf("read NetBox prefix %d: %w", prefixID, err)
	}

	// 2b. litevirt's own DHCP server must not be a second allocator over this
	//     prefix. Where dnsmasq serves, it derives the gateway as network+1 and
	//     leases a pool spanning essentially the whole subnet — none of it a
	//     database row, so nothing adopts or reserves any of it, and NetBox's
	//     /available-ips/ will hand the same addresses (the gateway included) to
	//     the next VM.
	//
	//     Refusing rather than reserving: the gateway is one address and could
	//     be reserved the way adoption reserves the addresses guests already
	//     hold, but the POOL cannot — it is dynamic and spans the prefix, so
	//     reserving it would leave NetBox nothing to allocate. See
	//     internal/network/dhcp_gate.go, which owns the predicate that
	//     provisioning starts dnsmasq from, and docs/networking.md for what this
	//     still does not cover.
	//
	//     Placed here, immediately after the prefix read it needs and before the
	//     VRF round-trip, so the cheapest refusal costs the fewest NetBox calls.
	if err := network.CheckDHCPBindConflict(def, p.Prefix, s.bridgeExistsHere(def.Interface)); err != nil {
		return err
	}

	// 3. It must live in a VRF. NetBox does not expose the global
	//    ENFORCE_GLOBAL_UNIQUE setting through a supported API, so a global-table
	//    prefix cannot be validated — and without uniqueness enforcement every
	//    conflict guarantee in the claim path evaporates.
	if p.VRFID == 0 {
		return fmt.Errorf("NetBox prefix %d is in the global table; bind requires a prefix in a VRF with enforce_unique set, because the global uniqueness setting is not readable through the API", prefixID)
	}
	unique, err := s.netbox.VRFEnforcesUnique(ctx, p.VRFID)
	if err != nil {
		s.nbMetrics().IncAPIError(netbox.Classify(err))
		return fmt.Errorf("read NetBox VRF %d: %w", p.VRFID, err)
	}
	if !unique {
		return fmt.Errorf("NetBox VRF %d does not set enforce_unique; litevirt cannot guarantee address uniqueness without it", p.VRFID)
	}

	// 4. One litevirt network per prefix. ip_allocations is keyed on the LITEVIRT
	//    network name, so two networks sharing a prefix allocate independently.
	existing, err := corrosion.GetBindingByPrefix(ctx, s.db, prefixID)
	if err != nil {
		return fmt.Errorf("check existing binding: %w", err)
	}
	if existing != nil && existing.Network != netName {
		return fmt.Errorf("NetBox prefix %d is already bound to network %q", prefixID, existing.Network)
	}

	// 5. …and one prefix per litevirt network, the other direction of the same
	//    1:1. netbox_bindings.network carries no UNIQUE constraint, so nothing
	//    below stops a network that already holds prefix 7 from also claiming
	//    prefix 8 — and GetBindingByNetwork, which returns a single row, could
	//    not then say which prefix the network allocates from.
	bound, err := corrosion.GetBindingByNetwork(ctx, s.db, netName)
	if err != nil {
		return fmt.Errorf("check existing binding for network %q: %w", netName, err)
	}
	if bound != nil && bound.PrefixID != prefixID {
		return fmt.Errorf("network %q is already bound to NetBox prefix %d", netName, bound.PrefixID)
	}

	// 6. Pin the fingerprint. Pinned, not recomputed: a fingerprint that moved
	//    must SUSPEND the binding rather than silently re-identify every object
	//    litevirt already wrote under the old one.
	fp, err := corrosion.ClusterFingerprint(ctx, s.db)
	if err != nil {
		return fmt.Errorf("derive cluster fingerprint: %w", err)
	}

	// 6b. Pin the NetBox CLUSTER NAME this node resolves, for the same reason and
	//     in the same place. `netbox.cluster_name` has to be identical on every
	//     node — the mirror sweep runs on whichever node holds the `netbox`
	//     leader lease, so a disagreement moves the whole inventory between two
	//     `virtualization.cluster` objects as leadership moves — and it is the
	//     one setting no capability latch can make uniform, because a token
	//     carries a name and not a value. Pinning it here is what lets every
	//     other node discover that its own configuration disagrees (see
	//     netbox_cluster_pin.go).
	//
	//     The RESOLVED name, not the raw config value: unset resolves to the
	//     local cluster name, so pinning "" would make "every node left it
	//     unset" (agreement) indistinguishable from "this node set it and that
	//     one did not" (the hazard).
	//
	//     A resolution failure REFUSES the bind. It is one local read of the
	//     `cluster` row — the same row step 6 just read a fingerprint from — so
	//     failing here means the row is unreadable, and a binding pinned to no
	//     name would silently opt out of the uniformity check for the life of
	//     the cluster.
	nbCluster, err := netboxsync.ClusterName(ctx, s.db, s.netboxClusterName)
	if err != nil {
		return fmt.Errorf("resolve the NetBox cluster name to pin on the binding: %w", err)
	}

	rec := corrosion.BindingRecord{
		Network:            netName,
		PrefixID:           prefixID,
		ObservedCIDR:       p.Prefix,
		VRFID:              p.VRFID,
		ClusterFingerprint: fp,
		NetBoxCluster:      nbCluster,
	}

	// 7. The addresses litevirt is ALREADY handing to guests inside this prefix.
	//    Checks 1-6 are all about the prefix; none of them looks at what is
	//    already inside it, and NetBox has never been told — `/available-ips/`
	//    means "no ip_address object exists", so every one of those addresses is
	//    one NetBox will offer to the next VM on this network. See
	//    netbox_adopt.go.
	//
	//    PLANNED here, before the claim, so every refusal it can make from local
	//    rows alone — a container lease, a template, a lease litevirt cannot
	//    account for, the per-bind cap — costs a refused bind that claimed
	//    NOTHING, exactly like checks 1-6. The adoption itself runs after the
	//    network row lands (see CreateNetwork), because a refusal there has to
	//    leave a binding an operator can resume.
	plan, err := s.planAdoption(ctx, rec)
	if err != nil {
		return err
	}

	won, err := corrosion.ClaimBinding(ctx, s.db, rec)
	if err != nil {
		return err
	}
	if !won {
		// Another bind won the race between our check above and this insert.
		return fmt.Errorf("NetBox prefix %d was bound to another network concurrently", prefixID)
	}
	pending := plan.candidates
	// WHY THE BINDING MIGHT NOT GO LIVE, in the two cases that exist.
	//
	// THE UNCORROBORATED CASE IS TESTED FIRST, and the order is load-bearing: a
	// partially hydrated node has BOTH — a list of candidates it can see and no
	// standing to call that list complete — and only the uncorroborated reason is
	// in the class the revalidation pass lifts by itself (isUnhydratedSuspension).
	// Writing the adoption reason over it would leave the binding waiting for an
	// operator who has nothing to repair, while the adoption it names refuses on
	// the sentinel anyway.
	suspendReason := ""
	switch {
	case plan.uncorroborated:
		// Nothing corroborates that this node's VM list is the cluster's, so
		// what it does not name is unknown rather than absent. Live would be a
		// binding allocating across a prefix whose occupants are unknown; a
		// REFUSAL would refuse the first bind on a young multi-node cluster with
		// no way out. Suspended is neither: no claim is served, and the
		// revalidation pass re-runs adoption and resumes it with no operator
		// action. See corroborateAdoptionInventory.
		suspendReason = unhydratedSuspendReason(netName)
	case len(pending) > 0:
		suspendReason = adoptionSuspendReason(netName, len(pending))
	default:
		// Nothing to adopt and a corroborated inventory to say so: the binding is
		// live immediately, which is both the pre-adoption behaviour and the
		// common case. No NetBox address request is made at all.
		return nil
	}

	// SUSPEND before anything can allocate from it. A binding that served claims
	// while its existing addresses were still unknown to NetBox would hand one of
	// them straight out, which is the defect this whole step closes.
	//
	// A separate write rather than a suspended ClaimBinding, and the window
	// between them is provably unusable: this function is reached only from
	// CreateNetwork, which refuses a network that already exists, so no
	// `networks` row for netName exists yet — and every allocation path resolves
	// the network to a host device before it ever asks for an allocator. There is
	// no VM that can be created on this network until CreateNetwork persists it,
	// below.
	if serr := corrosion.SuspendBinding(ctx, s.db, prefixID, suspendReason); serr != nil {
		// The binding is LIVE and un-adopted, which is the one state that must
		// not survive. Release the prefix so nothing can allocate from it, and
		// say so if even that fails — a prefix left bound refuses every future
		// bind of it.
		if rerr := corrosion.DeleteBinding(ctx, s.db, prefixID); rerr != nil {
			return fmt.Errorf(
				"could not suspend the binding for prefix %d (%s) (%v), and releasing it also "+
					"failed (%v); prefix %d STAYS BOUND and must be released by hand before it "+
					"can be bound again",
				prefixID, suspendReason, serr, rerr, prefixID)
		}
		return fmt.Errorf(
			"could not suspend the binding for prefix %d (%s), so the prefix was released and "+
				"nothing was bound: %w",
			prefixID, suspendReason, serr)
	}
	// Deliberately NOT counted on litevirt_netbox_bindings_suspended_total. This
	// suspension is TRANSIENT by design — the adoption below lifts it within the
	// same RPC on every successful bind — and an operator alerting on that
	// counter's rate would be paged by a bind that worked. Only an adoption that
	// FAILS leaves a binding out of service, and that is where it is counted
	// (finishAdoptionAndResume). The live gauge,
	// litevirt_netbox_bindings_suspended, reads the rows directly and so shows
	// this one for as long as it lasts, which is what a gauge is for.
	return nil
}
