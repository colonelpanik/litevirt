package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
	"github.com/litevirt/litevirt/internal/network"
)

// Bind-time ADOPTION: teaching NetBox about the addresses litevirt's own guests
// already hold inside a prefix, as part of binding it.
//
// WHY IT HAS TO EXIST. The seven bind-time checks all look at the PREFIX — that
// it exists, that its VRF enforces uniqueness, that nothing else claims it. None
// of them looks at the addresses litevirt is already handing to guests inside
// it, and nothing else ever teaches NetBox about one: the inventory mirror only
// assigns and clears objects that already carry a NetBox id, and those ids come
// only from the allocator at claim time. So an address a guest held before the
// bind stays invisible to NetBox permanently — and `/available-ips/`, whose
// notion of "available" is "no ip_address object exists", offers it to the next
// VM created on that network. Two guests, one address.
//
// WHERE THE ADDRESS ACTUALLY LIVES, which is the part worth being explicit
// about. It is on the NIC ROWS (`vm_interfaces` / `vm_nics`, read through
// MergedVMNICs), not in `ip_allocations`. On an unbound network VMs never
// allocate at all — allocatorFor hands a VM no allocator there, which is why
// `network.AllocateIPFor` has only ever been reached by containers — so the
// lease table holds nothing for them. What holds their address is the NIC row:
// written from an explicit `Ip` on the attachment, or discovered from DHCP by
// the IP scanner and the guest agent. Adoption therefore enumerates NICs and
// treats `ip_allocations` as the record of what litevirt has ALREADY accounted
// for, which is the reverse of the obvious reading and the only one that reaches
// the guests this exists to protect.
//
// ORDERING. The binding is created SUSPENDED whenever there is anything to
// adopt, adoption runs, and only a pass that adopted EVERY address resumes it. A
// binding that went live half-adopted would leave the un-adopted remainder
// exactly as collision-prone as before, which is the whole defect. A partial
// pass leaves the binding suspended under a reason naming what is left, and
// `lv netbox resume` finishes it — the same contract the CA re-key already
// promises, through the same gate.

// adoptionCap bounds how many addresses ONE bind will adopt.
//
// The unit of cost is one PENDING adoption: a POST to NetBox, plus up to two
// recovery GETs when that POST is refused, all sequential inside one RPC. The
// cap exists so a prefix holding thousands of guests refuses in a message an
// operator can read instead of running for minutes with nothing to look at.
//
// 256 is chosen against the shape of the thing being bound, not the shape of the
// timeout. A binding is 1:1 with a litevirt network and a litevirt network is
// VLAN-shaped, so the prefix on the other end of one is a /24 in practice, whose
// 254 usable hosts this covers COMPLETELY — a fully-populated subnet adopts in a
// single bind, and the cap only bites on something larger, where an operator
// genuinely should be asked whether one RPC is the right place for it. The
// runtime that buys is bounded too: 256 round trips is seconds on a LAN and tens
// of seconds against a slow NetBox, either way not minutes.
//
// It is counted over what is PENDING, not over what exists. Already-adopted
// addresses cost nothing (they are skipped before any request), so counting them
// would refuse a re-run that has nothing left to do — turning the cap into a
// permanent block on the one operation that recovers from it.
const adoptionCap = 256

// adoptionRefusedError is a bind-time adoption litevirt declined to perform.
//
// Distinguished from an ordinary failure so the RPC can report it as
// FailedPrecondition: every one of these is a state an OPERATOR repairs (move a
// container off, delete a foreign object in NetBox, retire a stale lease) and
// none of them is a bug in the daemon. Reporting them as Internal would send
// someone looking for one.
type adoptionRefusedError struct{ msg string }

func (e adoptionRefusedError) Error() string { return e.msg }

func adoptRefusef(format string, args ...any) error {
	return adoptionRefusedError{msg: fmt.Sprintf(format, args...)}
}

// adoptionRefused reports whether an adoption failure is one an OPERATOR
// repairs, and so deserves FailedPrecondition rather than Internal.
//
// It covers the local-row refusals this package makes AND the claim-path's
// definite "this address is not litevirt's" — a foreign identity, or an object
// with none. That second class comes back through the allocator, so it cannot be
// one of this package's own error types, and reporting it as Internal would send
// an operator hunting a daemon bug over an object they can see in NetBox.
func adoptionRefused(err error) bool {
	var refused adoptionRefusedError
	return errors.As(err, &refused) || errors.Is(err, network.ErrAddressNotOurs)
}

// adoptCandidate is one address a guest already holds that NetBox has to be
// told about.
type adoptCandidate struct {
	// IP is the address in canonical BARE form — the `ip_allocations` key.
	IP string
	// AddressCIDR is the same address in the "host/prefixlen" form NetBox
	// stores, with the mask of the BOUND PREFIX. NetBox's ip-address objects
	// carry a mask, and a bare address would be recorded as a /32: it would
	// still be inside the prefix, so nothing would refuse it, but it would not
	// match the objects an ordinary claim produces and the two would drift apart
	// for the same address.
	AddressCIDR string
	MAC         string
	VMName      string
	Identity    string
}

// adoptExistingAddresses adopts every address a guest already holds inside the
// bound prefix, and reports how many it adopted.
//
// The count is returned ALONGSIDE an error, never instead of one: a pass that
// failed partway has still created objects in NetBox, and the caller has to be
// able to say so in the audit trail rather than imply nothing happened.
func (s *Server) adoptExistingAddresses(ctx context.Context, b corrosion.BindingRecord) (int, error) {
	cands, err := s.planAdoption(ctx, b)
	if err != nil {
		return 0, err
	}
	if len(cands) == 0 {
		return 0, nil
	}
	if s.netbox == nil {
		return 0, adoptRefusef(
			"network %q has %d existing address(es) to adopt into NetBox prefix %d, but this "+
				"node has no netbox configuration; bind from a node that does",
			b.Network, len(cands), b.PrefixID)
	}

	// Constructed directly rather than through allocatorFor, which is the right
	// selector everywhere else and the wrong one here: it refuses a SUSPENDED
	// binding, and the binding is suspended for the whole of this pass by
	// design. The allocator itself is the ordinary one — adoption is an explicit
	// claim for an address litevirt already holds, so it inherits validateClaim's
	// scope checks, the guarded lease upsert with its read-back, and the
	// provenance rule that decides whether a failed persist may delete the remote
	// object.
	alloc := network.NewNetBoxAllocator(s.db, s.netbox, s.nbMetrics())

	adopted := 0
	for _, c := range cands {
		if _, cerr := alloc.Claim(ctx, network.ClaimRequest{
			Network:    b.Network,
			MAC:        c.MAC,
			OwnerKind:  "vm",
			OwnerHost:  "", // VM names are cluster-global
			Name:       c.VMName,
			Identity:   c.Identity,
			ExplicitIP: c.AddressCIDR,
			PrefixID:   b.PrefixID,
			VRFID:      b.VRFID,
			PrefixCIDR: b.ObservedCIDR,
		}); cerr != nil {
			// Deliberately NOT enqueued for the orphan sweep, unlike a failed
			// claim during a create. There the identity may name an object
			// nothing references; here the address is held by a guest whose NIC
			// row still names it, so the object is not an orphan at all — it is
			// the object the NEXT adoption pass adopts by recovery lookup.
			// Naming it would send the sweeper after something it must never
			// reclaim, and the sweeper's own live-claimant proof would refuse it
			// anyway.
			return adopted, fmt.Errorf(
				"adopt %s (held by %s) into NetBox prefix %d after adopting %d of %d: %w",
				c.IP, c.VMName, b.PrefixID, adopted, len(cands), cerr)
		}
		adopted++
	}
	slog.Info("netbox: adopted existing addresses into a bound prefix",
		"network", b.Network, "prefix", b.PrefixID, "adopted", adopted)
	return adopted, nil
}

// planAdoption reads the whole cluster's view of one network and returns every
// address that still has to be adopted, in a stable order.
//
// It is FAIL-CLOSED throughout: every state it cannot account for refuses the
// bind rather than being stepped over, because stepping over one leaves exactly
// the invisible address the whole operation exists to remove. Every read failure
// is returned for the same reason — an unreadable NIC list is not an empty one.
//
// It runs BEFORE the prefix is claimed as well as during the adoption itself.
// The refusals it can make from local rows alone — a container lease, a
// template, the cap — therefore cost a refused bind that claimed nothing, and
// only the refusals that need NetBox leave a binding behind to resume.
func (s *Server) planAdoption(ctx context.Context, b corrosion.BindingRecord) ([]adoptCandidate, error) {
	if b.ClusterFingerprint == "" {
		// Every identity is built from it, and an identity without one names
		// nothing: the object would be unfindable by the recovery lookup and
		// unreclaimable by the sweep.
		return nil, adoptRefusef(
			"network %q: no cluster identity fingerprint, so no NetBox identity can be minted", b.Network)
	}
	_, prefix, perr := net.ParseCIDR(b.ObservedCIDR)
	if perr != nil {
		return nil, adoptRefusef("network %q: bound prefix %q is unparseable: %v",
			b.Network, b.ObservedCIDR, perr)
	}
	ones, _ := prefix.Mask.Size()

	// What litevirt has ALREADY accounted for on this network, plus the one
	// class of lease that refuses the bind outright.
	leases, err := corrosion.ListLeasesByNetwork(ctx, s.db, b.Network)
	if err != nil {
		return nil, fmt.Errorf("read existing address leases on network %q: %w", b.Network, err)
	}
	byIP := make(map[string]corrosion.LeaseRecord, len(leases))
	var containers []string
	for _, l := range leases {
		if l.OwnerKind != "vm" {
			// Adopting a container's address would manufacture a state the rest
			// of the system rejects: allocatorFor refuses containers on a bound
			// network, so the container would hold a lease it can never
			// renegotiate — it could not be migrated, re-addressed or recreated
			// on this network again. Refuse the BIND instead, and name them, so
			// the operator moves them first.
			containers = append(containers,
				fmt.Sprintf("%s on %s holds %s", l.VMName, l.OwnerHost, l.IP))
			continue
		}
		byIP[l.IP] = l
	}
	if len(containers) > 0 {
		sort.Strings(containers)
		return nil, adoptRefusef(
			"network %q holds %d container address lease(s) — %v — and containers are not "+
				"supported on a network bound to NetBox; move them to another network (or delete "+
				"them) before binding prefix %d",
			b.Network, len(containers), containers, b.PrefixID)
	}

	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return nil, fmt.Errorf("list VMs to find existing addresses on network %q: %w", b.Network, err)
	}
	var cands []adoptCandidate
	seen := make(map[string]string) // bare address -> the VM already claiming it
	for _, vm := range vms {
		nics, nerr := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
		if nerr != nil {
			return nil, fmt.Errorf("read NICs of VM %s: %w", vm.Name, nerr)
		}
		for _, nic := range nics {
			if nic.NetworkName != b.Network || nic.IP == "" {
				continue
			}
			addr := net.ParseIP(nic.IP)
			if addr == nil {
				// Fail closed. An address we cannot parse is one we cannot test
				// for containment, so we cannot say whether NetBox is about to
				// hand it out again.
				return nil, adoptRefusef(
					"network %q: VM %s records an unparseable address %q; correct or clear it before binding",
					b.Network, vm.Name, nic.IP)
			}
			if !prefix.Contains(addr) {
				// Outside the bound prefix, so not this prefix's authority and
				// not a collision risk: NetBox will never offer this address.
				// The litevirt network's subnet and the bound prefix need not be
				// identical, so this is an ordinary configuration, not a fault.
				continue
			}
			if vm.IsTemplate {
				// A template is invisible to the inventory mirror (desiredState
				// skips it), so an address adopted for one would be an object no
				// inventory names — and refuseTemplateIfBound already refuses to
				// CREATE that state from the other direction, by declining to
				// convert a bound-network VM into a template. Manufacturing it
				// here through the back door would be the same trap with no
				// command to undo it.
				return nil, adoptRefusef(
					"network %q: template %s holds %s inside NetBox prefix %d; a template is "+
						"invisible to the inventory mirror, so its address would be held by nothing "+
						"and reclaimable by neither the mirror nor the sweep. Detach that NIC, or "+
						"revert the template to a VM, before binding",
					b.Network, vm.Name, nic.IP, b.PrefixID)
			}
			bare := addr.String()
			if lease, held := byIP[bare]; held {
				if lease.NetBoxIPID != 0 && lease.NetBoxPrefix == b.PrefixID {
					// ALREADY ADOPTED, against THIS prefix. Both halves are
					// required: an id alone can name an object in a prefix this
					// network used to be bound to, and skipping on that would
					// leave the address unknown to the prefix being bound now.
					continue
				}
				return nil, adoptRefusef(
					"network %q: %s is held by VM %s and already carries a lease litevirt cannot "+
						"account for (netbox object %d in prefix %d, binding prefix %d); retire that "+
						"lease before binding",
					b.Network, bare, vm.Name, lease.NetBoxIPID, lease.NetBoxPrefix, b.PrefixID)
			}
			if nic.MAC == "" {
				return nil, adoptRefusef(
					"network %q: VM %s holds %s on a NIC with no MAC, so no NetBox identity can "+
						"be minted for it", b.Network, vm.Name, bare)
			}
			uuid, uerr := vmSpecUUID(vm.Spec)
			if uerr != nil {
				return nil, adoptRefusef(
					"network %q: VM %s holds %s but %v, so no NetBox identity can be minted for it",
					b.Network, vm.Name, bare, uerr)
			}
			if other, dup := seen[bare]; dup {
				// Two NICs naming one address is a duplicate litevirt already
				// has, locally. `ip_allocations` is keyed (network, ip) so only
				// one of them could ever hold the lease, and adopting one would
				// silently pick a winner and tell NetBox it is the owner.
				return nil, adoptRefusef(
					"network %q: %s is recorded on two NICs (VMs %s and %s); resolve the duplicate "+
						"before binding prefix %d", b.Network, bare, other, vm.Name, b.PrefixID)
			}
			seen[bare] = vm.Name
			cands = append(cands, adoptCandidate{
				IP:          bare,
				AddressCIDR: fmt.Sprintf("%s/%d", bare, ones),
				MAC:         nic.MAC,
				VMName:      vm.Name,
				Identity:    netbox.Identity(b.ClusterFingerprint, uuid, nic.MAC),
			})
		}
	}
	if len(cands) > adoptionCap {
		return nil, adoptRefusef(
			"network %q has %d existing addresses to adopt into NetBox prefix %d, over the "+
				"per-bind limit of %d; a bind adopts each one with a separate NetBox request, so "+
				"this one would run for minutes. Move workloads off the network, or bind a smaller "+
				"prefix",
			b.Network, len(cands), b.PrefixID, adoptionCap)
	}
	// Sorted by ADDRESS so a pass that fails partway fails reproducibly, and so
	// a re-run picks up where it left off rather than in an order ListVMs and
	// map iteration happened to produce. Compared as bytes, not as text, so
	// .100 does not sort before .2.
	sort.Slice(cands, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(cands[i].IP), net.ParseIP(cands[j].IP)) < 0
	})
	return cands, nil
}

// adoptionSuspendReason is the reason a binding carries while adoption is owed.
// It names the count, so an operator reading the row knows what is outstanding
// rather than only that something is.
func adoptionSuspendReason(network string, pending int) string {
	return fmt.Sprintf(
		"adopting %d existing address(es) on network %s into NetBox; the binding serves no "+
			"claims until every one of them is recorded", pending, network)
}

// finishAdoptionAndResume adopts what a bind left owed and resumes the binding.
//
// It is a NO-OP on a binding that is not suspended, which is the common case: a
// bind of a network with no existing guests leaves the binding live and this
// costs one local read and nothing else. That is deliberate — the ordinary bind
// must not become a slow path, and in particular must not reach NetBox's address
// endpoints at all.
//
// RESUME LAST, and only on a pass that adopted everything. Everything before the
// resume is safe to interrupt: the binding stays suspended, no claim is served,
// and the addresses already adopted are recorded on their leases so a re-run
// skips them. The resume is the single step that makes the binding live, so it
// may not rest on a pass that did not finish.
func (s *Server) finishAdoptionAndResume(ctx context.Context, netName string, prefixID int) error {
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, prefixID)
	if err != nil {
		return fmt.Errorf("read binding for prefix %d: %w", prefixID, err)
	}
	if b == nil {
		// Nothing to finish. A released binding is not this function's problem —
		// its caller's compensation already dealt with it.
		return nil
	}
	if !b.Suspended {
		return nil
	}

	adopted, aerr := s.adoptExistingAddresses(ctx, *b)
	detail := fmt.Sprintf("prefix=%d adopted=%d", prefixID, adopted)
	if aerr != nil {
		// Audited on BOTH outcomes, the way a re-key is: a pass that failed
		// partway has still created objects in NetBox, so "nothing happened" is
		// the wrong thing for the trail to imply.
		s.audit(ctx, "netbox.adopt", netName, detail, "error")
		// Re-state the suspension with what is actually outstanding. The bind
		// wrote a reason from the PRE-claim plan; by now some of it is done, and
		// a reason naming the original count would send an operator looking for
		// work that is finished.
		reason := fmt.Sprintf(
			"adoption of existing addresses on network %s is incomplete after adopting %d: %v",
			netName, adopted, aerr)
		if serr := corrosion.SuspendBinding(ctx, s.db, prefixID, reason); serr != nil {
			slog.Error("netbox: could not record why an adoption stopped; the binding stays suspended under its previous reason",
				"network", netName, "prefix", prefixID, "error", serr)
		}
		s.nbMetrics().IncBindingSuspended()
		return aerr
	}

	next := *b
	next.Suspended = false
	next.SuspendReason = ""
	if uerr := corrosion.UpsertBinding(ctx, s.db, next); uerr != nil {
		s.audit(ctx, "netbox.adopt", netName, detail, "error")
		return fmt.Errorf(
			"every existing address on network %s was adopted (%d), but resuming the binding "+
				"failed: %w — re-run `lv netbox resume %s`", netName, adopted, uerr, netName)
	}
	s.audit(ctx, "netbox.adopt", netName, detail, "ok")
	slog.Info("netbox binding resumed after adopting existing addresses",
		"network", netName, "prefix", prefixID, "adopted", adopted)
	return nil
}
