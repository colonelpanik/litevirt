package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
)

// DISCOVERY: recording an address a guest is USING, which litevirt did not
// allocate.
//
// Four paths do it — the IP scanner's 30-second tick, the LB render, and (a read
// RPC persisting on the side) ListVMs and GetVM — and all four wrote
// `vm_interfaces.ip` through corrosion.UpdateVMInterfaceIP with no gate of any
// kind. On a NetBox-bound network that is the same write SetVMIP was hardened to
// refuse, for the same reason it was hardened: the row would describe an address
// litevirt does not hold, and every other reader (cloud-init's static
// network-config, the inventory mirror, the orphan proof) then treats it as one
// litevirt DOES hold. The difference is only that the operator-facing RPC asks
// first and an automated tick did not.
//
// The rule here is one sentence: on a bound network a discovered address is
// recorded ONLY once NetBox has granted it to this NIC. Discovery becomes a
// claim rather than a bypass.
//
// WHO MAY CLAIM. Only the background passes. A read RPC that POSTed to NetBox
// would make `lv ls` as slow and as failure-prone as the external API — and
// would do it once per undiscovered NIC, in a loop over every VM in the cluster.
// It buys nothing either: both read paths only discover for a RUNNING VM on
// THIS host, which is exactly the population the IP scanner sweeps every 30
// seconds on that same host. So they record on an unbound network as before, and
// on a bound one they display the address without recording it and leave the
// claim to the tick.
//
// WHAT A REFUSAL MEANS. A discovered address NetBox will not grant is not a
// litevirt bug and not a transient: it means a guest is using an address that
// NetBox says belongs to something else — the collision this whole feature
// exists to prevent, arriving from the one direction litevirt cannot stop
// (an external DHCP server). It cannot be repaired here, so it is surfaced:
// ERROR log plus litevirt_netbox_unclaimable_discoveries_total, and the row is
// left empty rather than made to assert something false.

// discoveryRefusal is the BOUNDED reason label for
// litevirt_netbox_unclaimable_discoveries_total. Bounded because the detail
// (which VM, which address, which identity) is unbounded and goes to the log —
// a Prometheus label with unbounded cardinality is a cluster-wide memory bug.
const (
	// discoveryRefusedNotOurs: NetBox holds this address under another identity,
	// or under none. The definite one, and the one that means two guests.
	discoveryRefusedNotOurs = "not_ours"
	// discoveryRefusedUnknown: the claim's outcome could not be established —
	// NetBox unreachable, or a response lost. May resolve on the next tick.
	discoveryRefusedUnknown = "unknown"
	// discoveryRefusedNoAllocator: litevirt could not even decide who owns these
	// addresses — the binding is suspended, the node has no NetBox client, the
	// network's config disagrees with its binding, or the read failed.
	discoveryRefusedNoAllocator = "no_allocator"
	// discoveryRefusedNoIdentity: no NetBox identity can be minted for this NIC
	// (no MAC, no incarnation uuid, no cluster fingerprint), so a claim could
	// only produce an object no lookup and no sweep could ever resolve.
	discoveryRefusedNoIdentity = "no_identity"
)

// discoverNICAddress asks THIS host where a MAC is answering: the ARP cache
// first, then libvirt's dnsmasq leases.
//
// One implementation for all four discovery paths, which each had their own
// copy of the same two-line fallback, and the seam that lets a test drive
// discovery without a guest (see SetNICIPDiscovery).
func (s *Server) discoverNICAddress(mac string) string {
	if s.nicIPDiscovery != nil {
		return s.nicIPDiscovery(mac)
	}
	if ip := lv.GetIPFromARP(mac); ip != "" {
		return ip
	}
	return lv.GetIPFromDHCPLeases("/var/lib/libvirt/dnsmasq", mac)
}

// SetNICIPDiscovery replaces the ARP / dnsmasq-lease lookup behind
// discoverNICAddress.
//
// Test-only seam, nil in production. It is the only way to reach the discovery
// gate at all without a real guest answering ARP on the test host: every path
// that records a discovered address starts from that lookup, so with no seam the
// whole gate is unreachable and would be pinned by nothing.
func (s *Server) SetNICIPDiscovery(fn func(mac string) string) { s.nicIPDiscovery = fn }

// claimAndRecordDiscoveredVMIP records a discovered address, claiming it from
// NetBox first if the network is bound. For the BACKGROUND passes only.
func (s *Server) claimAndRecordDiscoveredVMIP(ctx context.Context, vm *corrosion.VMRecord, netName, mac, ip string) bool {
	return s.recordDiscoveredVMIP(ctx, vm, netName, mac, ip, true)
}

// recordDiscoveredVMIPIfUnbound records a discovered address only where nothing
// external owns the address space. On a bound network it records NOTHING and
// makes no NetBox request. For the READ RPCs — see "WHO MAY CLAIM" above.
func (s *Server) recordDiscoveredVMIPIfUnbound(ctx context.Context, vm *corrosion.VMRecord, netName, mac, ip string) {
	s.recordDiscoveredVMIP(ctx, vm, netName, mac, ip, false)
}

// recordDiscoveredVMIP is the single gate every discovery write passes. It
// reports whether the address was RECORDED.
//
// The bool is not an error and no caller has to check it: a refusal has already
// disposed of itself (ERROR log plus counter), and a read RPC's answer must not
// depend on whether a side-effect landed. It exists for the one caller with a
// DEPENDENT write — the IP scanner's DNS record, which asserts the same address
// to a second reader and must not be published for an address the NIC row was
// not allowed to carry.
func (s *Server) recordDiscoveredVMIP(ctx context.Context, vm *corrosion.VMRecord, netName, mac, ip string, mayClaim bool) bool {
	if vm == nil || ip == "" {
		return false
	}

	// Asked through allocatorFor, exactly as SetVMIP asks: the binding row alone
	// is not the whole question. A network whose CONFIG names a prefix while no
	// binding exists is a disagreement it refuses loudly, and a direct read would
	// answer "nil, so unbound" and let the write through across a space someone
	// believes is externally managed. A suspended binding and a missing NetBox
	// client are refused there too, and both mean the addresses are still
	// NetBox's.
	//
	// FAIL CLOSED on the read. "Could not read the record" is not "the record
	// names no prefix" — that swallow is what made the container guard fail-open
	// once.
	alloc, binding, err := s.allocatorFor(ctx, "vm", netName)
	if err != nil {
		s.refuseDiscovery(discoveryRefusedNoAllocator, vm.Name, netName, ip,
			"litevirt cannot tell who owns the addresses on this network", err)
		return false
	}
	if alloc == nil {
		// UNBOUND. Nothing external owns these addresses, VMs allocate nothing
		// here, and recording what a guest picked up by DHCP is the whole point
		// of discovery. This is the pre-existing behaviour, byte for byte, and it
		// is the overwhelmingly common path.
		return s.persistDiscoveredVMIP(ctx, vm.Name, netName, ip)
	}
	if binding == nil {
		// An allocator with no binding is the fail-closed impossibility CreateVM
		// and the hotplug attach both refuse; this is not the call site that
		// should be the one to allow it.
		s.refuseDiscovery(discoveryRefusedNoAllocator, vm.Name, netName, ip,
			"an address allocator was selected for a VM with no NetBox binding", nil)
		return false
	}

	// Outside the bound prefix: not this prefix's authority and not a collision
	// risk, because `/available-ips/` can only ever offer an address the prefix
	// contains. The litevirt network's subnet and the bound prefix need not be
	// identical, so this is ordinary configuration — the same tolerance
	// bind-time adoption applies to a VM address outside the prefix.
	inside, perr := addressInPrefix(binding.ObservedCIDR, ip)
	if perr != nil {
		s.refuseDiscovery(discoveryRefusedNoAllocator, vm.Name, netName, ip,
			"the bound prefix or the discovered address is unparseable", perr)
		return false
	}
	if !inside {
		return s.persistDiscoveredVMIP(ctx, vm.Name, netName, ip)
	}

	if !mayClaim {
		// A read RPC. The address is still returned to the caller — the guest
		// really is using it, and hiding it would be worse than not recording it
		// — but nothing is written and NetBox is not touched. The IP scanner on
		// this same host claims it within 30 seconds.
		slog.Debug("netbox: not recording a discovered address from a read path; the IP scanner claims it",
			"vm", vm.Name, "network", netName, "ip", ip, "prefix", binding.PrefixID)
		return false
	}

	identity, ierr := s.nicIdentity(ctx, vm, mac)
	if ierr != nil {
		s.refuseDiscovery(discoveryRefusedNoIdentity, vm.Name, netName, ip,
			"no NetBox identity can be minted for this NIC", ierr)
		return false
	}

	// The ordinary explicit-claim path, reused verbatim — so this inherits
	// validateClaim's scope checks, the guarded lease upsert with its read-back,
	// and the provenance rule that decides whether a failed persist may delete
	// the remote object. A second claim path here would be a second place for
	// those to be got wrong.
	//
	// The address is claimed with the mask of the BOUND PREFIX, not as a bare
	// host: NetBox's ip-address objects carry a mask, and a bare address becomes
	// a /32 that would not match the objects an ordinary claim produces.
	ones, merr := prefixOnes(binding.ObservedCIDR)
	if merr != nil {
		s.refuseDiscovery(discoveryRefusedNoAllocator, vm.Name, netName, ip,
			"the bound prefix is unparseable", merr)
		return false
	}
	if _, cerr := alloc.Claim(ctx, network.ClaimRequest{
		Network:    netName,
		MAC:        mac,
		OwnerKind:  "vm",
		OwnerHost:  "", // VM names are cluster-global
		Name:       vm.Name,
		Identity:   identity,
		ExplicitIP: fmt.Sprintf("%s/%d", ip, ones),
		PrefixID:   binding.PrefixID,
		VRFID:      binding.VRFID,
		PrefixCIDR: binding.ObservedCIDR,
	}); cerr != nil {
		// NOT enqueued for the orphan sweep on an unknown outcome, unlike a
		// failed claim during a create. There the identity may name an object
		// nothing references; here a guest is holding the address right now, so
		// the object is not an orphan — it is what the next tick adopts by
		// recovery lookup. Naming it would send the sweeper after something it
		// must never reclaim.
		reason := discoveryRefusedUnknown
		if errors.Is(cerr, network.ErrAddressNotOurs) {
			reason = discoveryRefusedNotOurs
		}
		s.refuseDiscovery(reason, vm.Name, netName, ip,
			"a guest is using an address NetBox will not grant it; the address is NOT recorded",
			cerr)
		return false
	}
	// The claim was GRANTED, so whatever this VM was refused for is over. Cleared
	// before the row write rather than after it: the finding is about NetBox
	// declining the address, and a failed local write is a different fault with
	// its own log line, which the next tick retries.
	s.clearDiscoveryRefusal(vm.Name)
	return s.persistDiscoveredVMIP(ctx, vm.Name, netName, ip)
}

// persistDiscoveredVMIP writes the NIC row. Ordered AFTER the claim on a bound
// network, deliberately: a row written first would describe an address litevirt
// might then fail to obtain, and every reader of that row treats it as held. The
// reverse gap — a granted claim whose row write fails — self-heals, because the
// next tick discovers the same address and the claim path recovers its own
// object by identity.
func (s *Server) persistDiscoveredVMIP(ctx context.Context, vmName, netName, ip string) bool {
	if err := corrosion.UpdateVMInterfaceIP(ctx, s.db, vmName, netName, ip); err != nil {
		slog.Warn("could not record a discovered VM address; it will be re-discovered",
			"vm", vmName, "network", netName, "ip", ip, "error", err)
		return false
	}
	return true
}

// refuseDiscovery is the disposition of every address discovery litevirt
// declines to record: one ERROR log carrying the unbounded detail, one counter
// carrying the bounded reason, and one durable health finding.
//
// ERROR rather than WARN because nothing repairs it automatically and the
// operator-visible consequence is real: a guest is using an address the cluster
// will not record, so it is missing from cloud-init, from the inventory mirror,
// and from every "is this address free" answer.
//
// THE HEALTH FINDING is why a log line and a counter were not enough. This is
// the one NetBox failure that means two things are probably using one address,
// and both of its existing surfaces are opt-in: the log has to be watched, and
// the counter has to be scraped. `lv health` is what an operator actually reads
// during an incident, and it said nothing at all. See
// evaluateNetBoxDiscoveryRefusals.
func (s *Server) refuseDiscovery(reason, vmName, netName, ip, what string, err error) {
	slog.Error("netbox: refusing to record a discovered address — "+what,
		"reason", reason, "vm", vmName, "network", netName, "ip", ip, "error", err)
	s.nbMetrics().IncUnclaimableDiscovery(reason)
	s.noteDiscoveryRefusal(vmName, fmt.Sprintf(
		"%s on network %s is using %s, which NetBox will not grant it (%s): %s. The address is "+
			"NOT recorded, so it is missing from cloud-init, from the inventory mirror and from "+
			"every \"is this address free\" answer — and something else may be using it",
		vmName, netName, ip, reason, what))
}

// noteDiscoveryRefusal records one refused discovery for the health evaluator.
func (s *Server) noteDiscoveryRefusal(vmName, detail string) {
	if vmName == "" {
		return
	}
	s.nbDiscMu.Lock()
	defer s.nbDiscMu.Unlock()
	if s.nbDiscRefused == nil {
		s.nbDiscRefused = map[string]string{}
	}
	s.nbDiscRefused[vmName] = detail
}

// clearDiscoveryRefusal forgets a VM whose address litevirt has now recorded.
//
// Called on the SUCCESS of the same write the refusal blocked, not on a timer:
// the scanner re-attempts every 30 seconds, so a refusal that has resolved
// clears itself on the next tick, and one that has not stays until it does. A
// time-based expiry would clear a live collision while it was still live.
func (s *Server) clearDiscoveryRefusal(vmName string) {
	s.nbDiscMu.Lock()
	defer s.nbDiscMu.Unlock()
	delete(s.nbDiscRefused, vmName)
}

// discoveryRefusals is a copy of the current set, for the evaluator.
func (s *Server) discoveryRefusals() map[string]string {
	s.nbDiscMu.Lock()
	defer s.nbDiscMu.Unlock()
	out := make(map[string]string, len(s.nbDiscRefused))
	for k, v := range s.nbDiscRefused {
		out[k] = v
	}
	return out
}

// addressInPrefix reports whether a bare address falls inside a CIDR.
func addressInPrefix(cidr, ip string) (bool, error) {
	_, prefix, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, fmt.Errorf("parse bound prefix %q: %w", cidr, err)
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false, fmt.Errorf("discovered address %q is unparseable", ip)
	}
	return prefix.Contains(addr), nil
}

// prefixOnes is the mask length of a bound prefix.
func prefixOnes(cidr string) (int, error) {
	_, prefix, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, fmt.Errorf("parse bound prefix %q: %w", cidr, err)
	}
	ones, _ := prefix.Mask.Size()
	return ones, nil
}
