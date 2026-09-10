package grpcapi

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
// WHAT IS NOT ADOPTED, which is the other half of being explicit about it:
//
//   - A CONTAINER's address, on any of the three tables that can hold one. It is
//     not adopted at all — it REFUSES the bind — because a container is
//     unsupported on a bound network, so an adopted container lease could never
//     be renegotiated.
//   - An address litevirt has not RECORDED. There is nothing to claim, so a NIC
//     with no address refuses the bind while its guest is not provably stopped,
//     and is stepped over when it is. See the empty-IP branch in planAdoption.
//   - A legacy raw-bridge CONTAINER NIC, which is genuinely invisible: it names
//     a host DEVICE rather than a litevirt network, so it has no
//     container_interfaces row and no lease, and a DHCP one records its address
//     nowhere at all. The narrow reason that is acceptable: a raw bridge that
//     resolves to exactly one managed network is PROMOTED to a managed NIC by
//     resolveContainerNICs, which gives it a row and puts it behind
//     allocatorFor's refusal — so what is left is a NIC on a device litevirt
//     cannot attribute to this network, in the same class as any non-litevirt
//     host on the same L2. NetBox is the authority for those, and it excludes
//     them from `/available-ips/` by holding an ip_address object for each. The
//     two signals that could be guessed from instead are both unsound: bridge
//     names are host-local (br0 on two hosts is two L2s), and matching on the
//     address alone would refuse a bind over a container on an unrelated L2
//     whose private range happens to overlap.
//
// ORDERING. The binding is created SUSPENDED whenever there is anything to
// adopt, adoption runs, and only a pass that adopted EVERY address resumes it. A
// binding that went live half-adopted would leave the un-adopted remainder
// exactly as collision-prone as before, which is the whole defect. A partial
// pass leaves the binding suspended under a reason naming what is left, and
// `lv netbox resume` finishes it — the same contract the CA re-key already
// promises, through the same gate.

// SetOnInventoryRead installs a hook that runs immediately AFTER planAdoption's
// local VM enumeration and before the plan is corroborated.
//
// It exists so a scenario can replicate a row into the exact window the plan's
// snapshot binding defends — a `vms` or NIC row arriving after the enumeration
// the candidate list came from — which nothing above the server can otherwise
// reach: the window is inside one function, between two local reads. nil in
// production.
func (s *Server) SetOnInventoryRead(fn func()) { s.onInventoryRead = fn }

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
// cause, when set, is a sentinel a caller matches with errors.Is — the refusals
// that a background pass has to TELL APART rather than merely report. Most
// refusals carry none: they are read by an operator, not branched on.
type adoptionRefusedError struct {
	msg   string
	cause error
}

func (e adoptionRefusedError) Error() string { return e.msg }
func (e adoptionRefusedError) Unwrap() error { return e.cause }

func adoptRefusef(format string, args ...any) error {
	return adoptionRefusedError{msg: fmt.Sprintf(format, args...)}
}

// adoptRefuseCausef is adoptRefusef for a refusal a caller branches on. The
// message is written out in full rather than assembled from cause, so the
// operator-facing sentence stays one readable string.
func adoptRefuseCausef(cause error, format string, args ...any) error {
	return adoptionRefusedError{msg: fmt.Sprintf(format, args...), cause: cause}
}

// adoptionRefused reports whether an adoption failure is one an OPERATOR
// repairs, and so deserves FailedPrecondition rather than Internal.
//
// It covers the local-row refusals this package makes AND the claim-path's
// definite "this address is not litevirt's" — a foreign identity, or an object
// with none. That second class comes back through the allocator, so it cannot be
// one of this package's own error types, and reporting it as Internal would send
// an operator hunting a daemon bug over an object they can see in NetBox.
//
// THE FINAL GATE'S REFUSAL IS IN HERE TOO, both halves of it. A drift the gate
// read after the adoption is a repair an operator makes in NetBox; an answer it
// could not read is a retry of the same command once NetBox answers. Neither is
// a fault in the daemon, so neither may be reported as one — and keeping it in
// this one predicate is what stops the four doors from disagreeing about the
// code they return for the identical outcome.
func adoptionRefused(err error) bool {
	var (
		refused     adoptionRefusedError
		unactivated activationRefusedError
	)
	return errors.As(err, &refused) || errors.As(err, &unactivated) ||
		errors.Is(err, network.ErrAddressNotOurs)
}

// errAdoptionUncorroborated is the sentinel for the one adoption that cannot be
// performed because litevirt cannot ENUMERATE what needs performing: nothing
// corroborates that the local VM list is the cluster's, so what it does not name
// is unknown rather than absent (see corroborateAdoptionInventory).
//
// It lives on adoptExistingAddresses rather than on each of the three resume
// doors, because that function's contract is "adopt EVERY address a guest already
// holds", and every door that resumes a binding goes through it. One branch there
// makes the bind's own finisher, `lv netbox resume` and the re-key's tail all fail
// closed; a check per door would be three places to forget it.
//
// Wrapped in an adoptionRefusedError so the RPCs report FailedPrecondition: this
// is a state of the cluster, not a fault in the daemon.
var errAdoptionUncorroborated = errors.New(
	"this node's VM inventory could not be corroborated, so the addresses guests already hold " +
		"inside the prefix cannot be enumerated")

// adoptionPlan is what planAdoption decided from local rows alone.
type adoptionPlan struct {
	// candidates is every address that still has to be adopted, in a stable
	// order.
	candidates []adoptCandidate
	// uncorroborated records that nothing corroborated this node's VM inventory
	// as the cluster's, so `candidates` may be a proper subset of what actually
	// needs adopting.
	//
	// It is NOT mutually exclusive with a non-empty candidates — a partially
	// hydrated node has both — so every caller must prefer it: the candidates it
	// found are real, but adopting only them and going live is exactly the
	// half-adopted binding this whole step exists to prevent.
	uncorroborated bool
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
//
// LEASE. `lease` is the `netbox` leader lease when the caller holds one, and it
// is re-proved before EVERY claim — one HTTP round trip each, against a lease
// whose TTL is a minute, so a pass that proved it once at the top would go on
// writing under a lease another node had taken. That is the discipline the
// re-key's address-rewrite loop already keeps, and this is the same kind of step
// sitting inside the same operation.
//
// A NIL lease is not a relaxation of that rule; it means the caller holds no
// leader lease AT ALL, and only two callers may be in that position:
// CreateNetwork's bind and `lv netbox resume`. Neither may require cluster
// leadership — the mirror and the sweeper are periodic passes that can wait for
// their next tick, an operator binding or resuming a network cannot, and a bind
// refused because some other node leads would be unusable. Their exclusion is
// nbPassMu, taken by each of those doors.
func (s *Server) adoptExistingAddresses(ctx context.Context, b corrosion.BindingRecord, lease *rekeyLease) (int, error) {
	plan, err := s.planAdoption(ctx, b)
	if err != nil {
		return 0, err
	}
	if plan.uncorroborated {
		// Nothing to adopt AND no standing to say so. Every caller of this
		// function goes on to resume the binding, and a resume on the strength
		// of an empty read this node cannot corroborate is exactly the live,
		// un-adopted binding the suspension exists to prevent.
		return 0, adoptRefuseCausef(errAdoptionUncorroborated,
			"network %q: %v; the binding for prefix %d stays suspended and a NetBox "+
				"revalidation pass resumes it automatically once this node's inventory can be "+
				"corroborated",
			b.Network, errAdoptionUncorroborated, b.PrefixID)
	}
	cands := plan.candidates
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
		if lease != nil {
			// Before the WRITE, not after it, and before each one. A lease lost
			// for any reason — a peer that took an expired row, a hand-edited
			// row, a clock that moved — stops the pass at the very next address
			// rather than at the next renewal, and the caller's own error
			// handling leaves the binding suspended and the operation
			// re-runnable.
			if lerr := lease.check(ctx); lerr != nil {
				return adopted, fmt.Errorf(
					"adopt %s (held by %s) into NetBox prefix %d after adopting %d of %d: %w",
					c.IP, c.VMName, b.PrefixID, adopted, len(cands), lerr)
			}
		}
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
// The refusals it can make from local rows alone — a container NIC or lease, a
// template, an unrecorded address on a live guest, the cap — therefore cost a
// refused bind that claimed nothing, and only the refusals that need NetBox
// leave a binding behind to resume.
//
// That pre-claim ordering is load-bearing for the unrecorded-address refusal in
// particular. The remedy for it is usually "wait for the address to be
// discovered", and discovery can only record an address while the network is
// UNBOUND: on a bound network recording becomes a claim, and on a SUSPENDED one
// allocatorFor refuses outright. A refusal that left a suspended binding behind
// would therefore be a deadlock — the resume waiting for an address discovery
// was no longer permitted to write.
//
// WHAT IT COSTS, stated in numbers because three comments elsewhere used to
// describe it as "a few local reads". It is 2N+3 local queries for a cluster of
// N VMs, all synchronous and all BEFORE the cap is evaluated:
// ListLeasesByNetwork, ListContainerInterfacesByNetwork and ListVMs, then
// MergedVMNICs per VM — and MergedVMNICs is TWO queries, one per NIC table
// (internal/corrosion/hardware.go). On a 500-VM cluster that is a little over a
// thousand queries. It scans EVERY VM in the cluster, not only the ones on this
// network, because the NIC tables are keyed by VM and the merge that decides
// what a NIC actually IS is per-VM; a network-scoped read would have to
// reimplement that resolution.
//
// The inventory SAMPLE at the top adds one more read of a different shape: a
// whole-database table digest, the same computation anti-entropy runs on its own
// tick. It is taken before the refusals rather than after, because a sample
// taken after a read is a sample that cannot certify it — so a bind refused for
// a container on the network now pays for one digest it does not use. That is a
// few milliseconds against an operation that already scans every VM in the
// cluster.
//
// IT IS DELIBERATELY NOT BOUNDED, and the cap is not what would bound it — the
// cap counts adoption CANDIDATES, so it is evaluated after the scan and cannot
// shorten it. The reason is that every caller is either interactive and rare or
// once-per-binding: a bind (one `lv network create`), `lv netbox resume`, a
// re-key, and the revalidation pass's re-adoption, which runs only for a binding
// suspended on an uncorroborated inventory and only on the pass that can finally
// act — after which the binding is live and never scanned again. A thousand
// local SQLite reads is tens of milliseconds; a periodic per-binding scan of the
// whole fleet's NICs would not be, and that is the shape this avoids.
func (s *Server) planAdoption(ctx context.Context, b corrosion.BindingRecord) (adoptionPlan, error) {
	if b.ClusterFingerprint == "" {
		// Every identity is built from it, and an identity without one names
		// nothing: the object would be unfindable by the recovery lookup and
		// unreclaimable by the sweep.
		return adoptionPlan{}, adoptRefusef(
			"network %q: no cluster identity fingerprint, so no NetBox identity can be minted", b.Network)
	}
	_, prefix, perr := net.ParseCIDR(b.ObservedCIDR)
	if perr != nil {
		return adoptionPlan{}, adoptRefusef("network %q: bound prefix %q is unparseable: %v",
			b.Network, b.ObservedCIDR, perr)
	}
	ones, _ := prefix.Mask.Size()

	// THE SNAPSHOT THIS PLAN IS BOUND TO, sampled BEFORE the first read that
	// goes into it.
	//
	// The plan is a claim about the whole cluster — "these are all the addresses
	// guests already hold inside this prefix" — assembled from the local reads
	// below, and the corroboration at the bottom is what turns those reads into
	// a statement about the cluster. It therefore has to certify THESE reads.
	// Sampling the digests part-way through, which is where this check used to
	// sit, certified a read the candidate list had already been enumerated from
	// something older than: a `vms` row arriving between the enumeration and the
	// sample was absent from the candidates and PRESENT in the digest every peer
	// then agreed with, so the bind went live over an address it had not seen —
	// the same defect the inventory mirror was found to have, reached from the
	// other side.
	//
	// An unreadable digest is recorded as uncorroborated rather than returned as
	// an error, matching corroborateAdoptionInventory's own read failure: the
	// remedy for both is a later pass, not an operator.
	bound, berr := s.localTableDigests(ctx, adoptionInventoryTables())
	if berr != nil {
		slog.Warn("netbox: could not sample this node's inventory digests before planning an "+
			"adoption; the plan cannot be corroborated and the binding stays suspended",
			"network", b.Network, "prefix", b.PrefixID, "error", berr)
	}

	// What litevirt has ALREADY accounted for on this network, plus the one
	// class of lease that refuses the bind outright.
	leases, err := corrosion.ListLeasesByNetwork(ctx, s.db, b.Network)
	if err != nil {
		return adoptionPlan{}, fmt.Errorf("read existing address leases on network %q: %w", b.Network, err)
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

	// The lease table is not the only place a container's address lives, and for
	// the shape an operator is most likely to bind it is not the place at all: a
	// SUBNET-LESS network is DHCP, so the create path takes no lease ("blank IP,
	// no lease" — resolveContainerNICs) and the live address is persisted by the
	// IP scanner into `container_interfaces.ip` alone. A refusal that read only
	// the leases called that address free while a row still named it, the bind
	// went live, and NetBox handed the container's address to the next VM.
	//
	// This is the third of the three tables nicClaimTables (netbox_proof.go)
	// enumerates as recording a NIC's MAC and IP, for exactly this reason. The
	// other two — vm_nics and vm_interfaces — are the VM side, read below through
	// MergedVMNICs.
	//
	// Refused on the ROW, not on its address, and so deliberately WITHOUT the
	// `prefix.Contains` test the VM path applies:
	//
	//   - a container is unsupported on a bound network at ANY address
	//     (allocatorFor refuses it outright), so its address is not what makes
	//     this a problem — its presence is. The VM path tolerates an
	//     out-of-prefix address because a VM on this network is legitimate and
	//     NetBox will never offer an address the prefix does not contain; there
	//     is no equivalent "legitimate" reading for a container.
	//   - a row whose `ip` is still empty is a container whose DHCP has not been
	//     discovered YET. The guest may already hold an address; the scanner
	//     writes it on its next 30-second tick. Gating on the recorded address
	//     would make this refusal a race against that tick.
	ctNICs, cerr := corrosion.ListContainerInterfacesByNetwork(ctx, s.db, b.Network)
	if cerr != nil {
		return adoptionPlan{}, fmt.Errorf("read container NICs on network %q: %w", b.Network, cerr)
	}
	for _, nic := range ctNICs {
		held := nic.IP
		if held == "" {
			held = "an address litevirt has not discovered yet"
		}
		containers = append(containers,
			fmt.Sprintf("%s on %s holds %s", nic.CtName, nic.HostName, held))
	}
	if len(containers) > 0 {
		// Deduplicated: a container with BOTH a lease and a NIC row (the
		// subnet-ful case) is named by both reads, and a refusal that listed it
		// twice would read as two containers to move.
		sort.Strings(containers)
		containers = slices.Compact(containers)
		return adoptionPlan{}, adoptRefusef(
			"network %q holds %d container NIC(s)/address lease(s) — %v — and containers are not "+
				"supported on a network bound to NetBox; move them to another network (or delete "+
				"them) before binding prefix %d",
			b.Network, len(containers), containers, b.PrefixID)
	}

	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return adoptionPlan{}, fmt.Errorf("list VMs to find existing addresses on network %q: %w", b.Network, err)
	}
	if s.onInventoryRead != nil {
		// A TEST SEAM, and the window it opens is the one the snapshot binding
		// above defends: a replicated row landing after the enumeration this
		// plan is built from. nil in production. See SetOnInventoryRead.
		s.onInventoryRead()
	}

	plan := adoptionPlan{}
	var cands []adoptCandidate
	seen := make(map[string]string) // bare address -> the VM already claiming it
	for _, vm := range vms {
		nics, nerr := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
		if nerr != nil {
			return adoptionPlan{}, fmt.Errorf("read NICs of VM %s: %w", vm.Name, nerr)
		}
		for _, nic := range nics {
			if nic.NetworkName != b.Network {
				continue
			}
			if nic.IP == "" {
				// The one state that was stepped over, and the one that matters
				// most: an address litevirt has NOT recorded is exactly the
				// address NetBox is about to hand out, because `/available-ips/`
				// means "no ip_address object exists" and nothing here can say
				// otherwise. On an unbound network this population is large
				// rather than exceptional — allocatorFor gives a VM no allocator
				// there, so every VM created without an explicit address has an
				// empty NIC IP.
				//
				// There is genuinely nothing to ADOPT: no address to claim, and
				// an identity claiming nothing would be worse than no object.
				// So the bind refuses, unless the guest is provably holding
				// nothing.
				//
				// "Provably stopped", not "not running". A stopped VM's guest
				// holds no address right now, so a bind over one collides with
				// nothing and proceeding keeps the feature usable on a real
				// cluster — refusing on every stopped VM with an unrecorded
				// address would refuse nearly every bind. Every OTHER state is
				// refused, including `error`, `migrating` and `unknown`: a
				// migrating guest is certainly up, and the rest are the absence
				// of a statement rather than a statement of absence.
				//
				// What covers the stopped VM afterwards is the discovery gate
				// (netbox_discovery.go): when it is next started and its address
				// is discovered, recording it becomes a CLAIM, and a claim NetBox
				// will not grant is refused and surfaced instead of written.
				if vm.State == "stopped" {
					continue
				}
				return adoptionPlan{}, adoptRefusef(
					"network %q: VM %s (state %q) has a NIC (%s) on this network with no address "+
						"recorded, so litevirt cannot tell NetBox what that guest is using — and "+
						"NetBox would offer the same address to the next VM created here. Let the "+
						"address be discovered (or record it, stop the VM, or detach the NIC) "+
						"before binding prefix %d",
					b.Network, vm.Name, vm.State, nic.MAC, b.PrefixID)
			}
			addr := net.ParseIP(nic.IP)
			if addr == nil {
				// Fail closed. An address we cannot parse is one we cannot test
				// for containment, so we cannot say whether NetBox is about to
				// hand it out again.
				return adoptionPlan{}, adoptRefusef(
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
				return adoptionPlan{}, adoptRefusef(
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
				return adoptionPlan{}, adoptRefusef(
					"network %q: %s is held by VM %s and already carries a lease litevirt cannot "+
						"account for (netbox object %d in prefix %d, binding prefix %d); retire that "+
						"lease before binding",
					b.Network, bare, vm.Name, lease.NetBoxIPID, lease.NetBoxPrefix, b.PrefixID)
			}
			if nic.MAC == "" {
				return adoptionPlan{}, adoptRefusef(
					"network %q: VM %s holds %s on a NIC with no MAC, so no NetBox identity can "+
						"be minted for it", b.Network, vm.Name, bare)
			}
			uuid, uerr := vmSpecUUID(vm.Spec)
			if uerr != nil {
				return adoptionPlan{}, adoptRefusef(
					"network %q: VM %s holds %s but %v, so no NetBox identity can be minted for it",
					b.Network, vm.Name, bare, uerr)
			}
			if other, dup := seen[bare]; dup {
				// Two NICs naming one address is a duplicate litevirt already
				// has, locally. `ip_allocations` is keyed (network, ip) so only
				// one of them could ever hold the lease, and adopting one would
				// silently pick a winner and tell NetBox it is the owner.
				return adoptionPlan{}, adoptRefusef(
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
		return adoptionPlan{}, adoptRefusef(
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
	plan.candidates = cands

	// THE ONE THING THIS FUNCTION CANNOT FAIL CLOSED ON FROM ITS OWN READS, and
	// it is asked LAST, about the snapshot taken FIRST.
	//
	// Recorded on the plan rather than acted on here, because what it costs is
	// decided by the caller: a bind SUSPENDS, and an adoption that is meant to
	// finish a suspension REFUSES. See corroborateAdoptionInventory.
	//
	// On EVERY bind, not only an empty read. An empty list is the loudest shape
	// of an unreplicated inventory but not the only one, and it is not even the
	// dangerous one: a node that has received SOME rows and not the target
	// network's guests enumerates a plausible-looking list, adopts what is in it,
	// binds live having adopted nothing that matters, and hands the incumbent's
	// address to the next VM created there. Gating the check on `len(vms) == 0`
	// let exactly that through — one unrelated VM was enough to skip it.
	//
	// ASKED HERE, not part-way up, and that is the second finding on this line.
	// Every read this plan rests on is now inside the window the proof covers:
	// the leases, the container NICs, the VM enumeration and each VM's merged
	// NICs. Asked before those reads finished, the proof certified an inventory
	// the candidate list had not been built from — and a row that arrived in
	// between was missing from the list while being present in the digest every
	// peer agreed with, which is a live binding over an address nobody adopted.
	plan.uncorroborated = !s.corroborateAdoptionInventory(ctx, b, bound)
	return plan, nil
}

// corroborateAdoptionInventory decides the one thing planAdoption cannot fail
// closed on from its own read, and reports whether this node's inventory of the
// addresses guests ALREADY hold is CORROBORATED as the cluster's.
//
// corrosion.ListVMs and the NIC reads beside it answer from local rows alone,
// and nothing in the schema records how much of a table this node has actually
// received. So what they return is indistinguishable from the cluster's whole
// inventory — whether it came back empty on a node hydrating after a database
// loss, or came back with three VMs on a node that has not yet received the
// fourth, which is the one holding the address inside the prefix about to be
// bound.
//
// THE SECOND SIGNAL IS THE CLUSTER ITSELF, ASKED. The question goes to the other
// nodes: do your address-bearing tables say the same as mine? Every host agrees,
// or nothing is corroborated. That is the orphan sweeper's negative-proof
// discipline applied to a different absence, and it reuses the sweeper's own
// machinery rather than inventing a second one: closedInventoryCorroborationPeers
// for the participant universe — which deliberately keeps offline, fenced,
// tombstoned and WITNESS hosts in (a host that cannot be reached still HOLDS its
// rows, and a witness holds every one of them while hosting nothing) and is
// CLOSED over every participant's own membership view, `hosts` rows and gossip
// members alike, so a host only a peer has a row for, or only a peer's gossip
// names, is asked too — dialPeer for the transport, and one bounded timeout each.
//
// THE SET IT ASKS IS THE CORROBORATION SET AND NOT THE RUNTIME-PROOF SET, which
// is a distinction this check got wrong once. The sweeper's set excuses a witness
// because a witness has no domain to scan; this check wants the ROWS, which a
// witness has in full. Reading the sweeper's set here meant a witness holding the
// only replicated copy of an incumbent's VM and NIC rows was never asked, the
// remaining nodes' equally short inventories agreed, and the bind went live over
// a held address.
//
// THE SAME CLOSURE, NOT A SUBSET OF IT. Every membership check the sweeper makes
// before it reclaims, this makes before it goes live, because
// closedParticipantSets is the only way either of them reaches a peer set — each
// through the accessor named for the set it needs. That is not symmetry for its
// own sake: a bind that adopts nothing because it could not see a holder hands
// that holder's address to the next guest created, which is the same collision
// the sweeper's proof exists to prevent — reached from the other side. A period
// when the bind skipped the corroboration the sweeper ran is exactly how a
// tombstoned holder stayed invisible to one and not the other.
//
// The peer's answer is its digest of every table in adoptionInventoryTables,
// from GetStateDigest: an RPC that already exists for anti-entropy, so nothing
// new goes on the wire and one call carries them all, read by exactly the
// predicate anti-entropy repairs on (corrosion.TableDigestsAgree). Each digest
// covers the whole of its table, TOMBSTONES INCLUDED, on both sides.
//
// AGREEMENT, NOT A COUNT RELATIONSHIP. An earlier round of this accepted a peer
// holding STRICTLY FEWER rows, reasoning that a lagging peer cannot be why our
// list is short. Fewer rows do not make a subset: a peer holding one incumbent
// VM and a binder holding two unrelated ones compare as "the peer is behind",
// and the incumbent's address is then handed to the next VM created there. No
// relation between two cardinalities means "nothing you hold is missing here",
// so the only sound reading of a peer that does not AGREE is that this node's
// inventory is not the cluster's.
//
// DROPPING THAT RELAXATION IS AFFORDABLE BECAUSE THE BIND IS CONVERGENT. A bind
// that cannot corroborate is not refused: it is recorded SUSPENDED under
// unhydratedSuspendReason, the one class isUnhydratedSuspension lets the
// periodic revalidation pass lift by ITSELF. So a lagging peer DELAYS a bind, it
// never fails one, and nobody has to run a command to finish it. That is what
// buys the strictness — the check can ask for the strongest property rows can
// support instead of the weakest one that still lets a bind through.
//
// FAIL CLOSED at every branch. An unreachable host, a peer that answers without
// one of the digests, an unreadable local digest, a participant set that cannot
// be closed, any disagreement — none of them is a corroborated inventory. What
// that costs is a suspension that lifts itself on the next pass; what fail-open
// would cost is a live binding over addresses running guests hold.
//
// IT CERTIFIES THE SNAPSHOT THE PLAN WAS BUILT FROM, not the inventory as it
// stands when the question is asked. planAdoption samples the digests before its
// first read and hands them in here; this re-reads them and requires them
// IDENTICAL (inventoryMoved) before comparing anything with a peer, and it is
// the BOUND digests the peers are compared against. Both halves are load-bearing
// and neither is enough alone: without the binding, a row arriving mid-plan is
// absent from the candidate list and present in the digest every peer agrees
// with — a live binding over an address nobody adopted; without the peer
// agreement, an unhydrated node's short read is confirmed by nothing but itself.
//
// A CHANGE DISCARDS THE PLAN. The bind suspends under the self-lifting
// unhydrated reason, and the revalidation pass re-derives the plan from a fresh
// snapshot on its next pass — a re-plan with no retry loop, no second code path
// and no NetBox requests spent on a premise that has already moved.
//
// WHAT IT STILL CANNOT SEE: an inventory that is identical on every host in the
// closed participant set and wrong on all of them. Agreement across the cluster
// is the strongest statement replicated rows can support; no proof can invent a
// row nobody holds.
func (s *Server) corroborateAdoptionInventory(ctx context.Context, b corrosion.BindingRecord,
	bound map[string]corrosion.TableDigest) bool {
	if len(bound) == 0 {
		slog.Warn("netbox: no inventory sample was taken before this adoption plan was built, "+
			"so there is nothing to corroborate it against; treating it as uncorroborated",
			"network", b.Network, "prefix", b.PrefixID)
		return false
	}
	local, err := s.localTableDigests(ctx, adoptionInventoryTables())
	if err != nil {
		slog.Warn("netbox: could not read this node's own inventory digests while binding a "+
			"prefix; treating it as uncorroborated",
			"network", b.Network, "prefix", b.PrefixID, "error", err)
		return false
	}
	if moved := inventoryMoved(bound, local); moved != "" {
		// THE PLAN'S OWN INPUTS MOVED WHILE IT WAS BEING BUILT. Discarded, not
		// re-planned: the caller suspends the binding under the self-lifting
		// unhydrated reason and the revalidation pass re-derives the whole plan
		// from a fresh snapshot, which is a re-plan with none of the machinery.
		slog.Warn("netbox: this node's inventory changed while an adoption plan was being "+
			"built, so the plan does not describe the read the cluster can confirm; the "+
			"binding stays suspended and a revalidation pass re-plans it",
			"network", b.Network, "prefix", b.PrefixID, "reason", moved)
		return false
	}
	proven, why, perr := s.proveNoPeerHoldsInventoryRowsWeLack(ctx, bound)
	if perr != nil {
		slog.Warn("netbox: could not establish whether any peer holds an inventory record this "+
			"node has not received while binding a prefix; treating it as uncorroborated",
			"network", b.Network, "prefix", b.PrefixID, "error", perr)
		return false
	}
	if proven {
		return true
	}
	// Two shapes, reported apart, because the remedies read differently and an
	// operator seeing the first has a much better guess at what is happening: an
	// EMPTY local table on a multi-node cluster is a node that has replicated
	// nothing at all, while a populated one that the cluster does not confirm is
	// a node that is part-way there.
	if local[vmsTableName].Count == 0 {
		slog.Warn("netbox: uncorroborated empty VM inventory — this node's local database holds "+
			"no VM record of any kind and the cluster could not confirm that it holds none "+
			"either, which a node that has not finished replicating looks exactly like; a "+
			"binding made now is created SUSPENDED and a revalidation pass resumes it once the "+
			"read can be corroborated",
			"network", b.Network, "prefix", b.PrefixID, "reason", why)
		return false
	}
	slog.Warn("netbox: uncorroborated VM inventory — this node holds guest records but the "+
		"cluster could not confirm they are ALL of them, and the guests this node has not "+
		"received are exactly the ones whose addresses would go unadopted; a binding made now "+
		"is created SUSPENDED and a revalidation pass resumes it once the inventory can be "+
		"corroborated",
		"network", b.Network, "prefix", b.PrefixID, "local_vms", local[vmsTableName].Count,
		"reason", why)
	return false
}

// adoptionInventoryTables lists every replicated table adoption reads to find an
// address a guest ALREADY holds. It is the whole of what corroboration has to
// cover, because a table left OUT is a table whose absent rows corroborate
// perfectly: identical `vms` tables with the incumbent's NIC rows missing here
// agreed on the only table an earlier round compared, and the bind went live
// having seen nothing.
//
// DERIVED, not written out a second time. `vms` is the enumeration adoption
// starts from, and nicClaimTables (netbox_proof.go) is this package's single
// registry of the tables that record a NIC's MAC and IP — vm_nics and
// vm_interfaces for the VM side (the v42 hardware model dual-writes them, and a
// VM created through the plain InsertVM path has only vm_interfaces rows), and
// container_interfaces for the container side, which is where a subnet-less
// container's address lives and NOWHERE else. The orphan proof reads exactly
// that registry, so a table added there is covered here without anybody
// remembering to — which is the property that was missing while this check
// covered `vms` alone and the addresses lived on the NIC rows.
//
// ip_allocations is deliberately NOT here, and saying so is part of the set
// being deliberate: adoption does read it, but only to learn what it has ALREADY
// accounted for. A lease row this node has not received makes adoption re-adopt
// an address it already owns — a duplicate NetBox object, which the POST's own
// conflict-recovery path resolves — and never a collision. The tables above are
// the ones whose missing rows make a held address INVISIBLE.
func adoptionInventoryTables() []string {
	tables := make([]string, 0, len(nicClaimTables)+1)
	tables = append(tables, vmsTableName)
	for _, t := range nicClaimTables {
		tables = append(tables, t.name)
	}
	return tables
}

// corroborateMirrorInventory is the SECOND caller of the proof above, and it is
// deliberately the same proof rather than a second one.
//
// WHO ASKS AND WHY. The inventory mirror's removal-evidence policy has one
// record that identifies an incarnation without saying whether it stopped
// existing: its own `netbox_objects` mapping row, which is exactly what a node
// holds for an incarnation whose `vms` row has not replicated here and whose VM
// may be live on a peer. The mirror will not conclude an absence from it until
// the read that absence is measured against is corroborated as the cluster's —
// which is the identical property the prefix bind refuses to hand out addresses
// without, reached from the other side. A bind that adopted nothing because it
// could not see a holder, and a mirror that deleted a holder's inventory object
// because it could not see the holder, are one condition.
//
// SO IT IS ONE MECHANISM, NOT TWO. Same table set (adoptionInventoryTables),
// same predicate (corrosion.TableDigestsAgree over every one of them), same
// closed participant universe with witnesses in and nobody excused. The mirror
// reaches it through a function value threaded into netboxsync.Options, because
// that package cannot import this one — see netboxsync.Options.
//
// IT ANSWERS FOR THE SNAPSHOT IT IS GIVEN, WHICH IS THE WHOLE OF THE SECOND
// FINDING HERE. The mirror does not ask this until it has read its desired
// state, diffed it against NetBox and classified its removal evidence — so by
// the time the question arrives, the read the absence is measured against is
// already several reads old. An earlier round reused the bind's predicate as it
// stood, which samples its digests when called. That is right for the bind,
// which proves and then acts on one read, and wrong here: it certified the
// inventory as it was at the END of the pass and stamped the answer on a
// conclusion drawn at the start. A live VM's object was deleted through that gap
// — the target's `vms` row replicated mid-pass, both peers agreed about the
// now-complete inventory, and the OLD plan executed with a successful proof
// attached. A separately sampled boolean cannot establish a relationship to a
// plan it never saw.
//
// So the caller samples FIRST (netboxsync.Options.InventorySnapshot) and this
// answers about THAT sample, in two halves that are both required:
//
//  1. THE SAMPLE IS STILL THIS NODE'S OWN READ. Re-read the digests and require
//     them identical (inventoryMoved). Without it a peer that has not yet
//     received the row agrees with a sample this node has already moved past —
//     the proof succeeds while the local database itself now contradicts the
//     conclusion.
//  2. EVERY PARTICIPANT AGREES WITH THE SAMPLE — the bind's own fan-out, handed
//     the BOUND digests rather than freshly sampled ones, so what is proven
//     whole is the read the plan came from.
//
// A CHANGE DISCARDS, it does not retry. The pass withholds the removals it
// cannot prove, reports unconverged, stamps no success and re-derives everything
// on the next tick; nothing about the withheld object is remembered. Recomputing
// inside the pass would mean re-reading both sides — the desired state AND
// NetBox — in a loop a busy cluster's write rate could keep alive, inside a
// one-minute leader lease and while holding this node's NetBox critical section.
// Withholding costs one interval of a leaked NetBox object; leak over collision.
//
// FAIL CLOSED at every branch, with the reason returned rather than logged here:
// the mirror puts it on its own withheld-removal warning, beside the objects it
// withheld, which is the line an operator reads.
//
// WHAT IT COSTS. On a cluster with rows in flight the digests disagree until
// replication settles, so a removal resting on a mapping row alone is DELAYED —
// the mirror stalls for that one object, logs why, and does not stamp its
// success gauge. The binding check widens that from "settled at this instant" to
// "unchanged across the pass's own reads", which is the same direction and the
// same self-clearing delay. And the same limitation the bind documents holds: a
// PERMANENTLY lost host can never produce a digest, so a removal that needs one
// keeps withholding and the object is one to remove in NetBox by hand. See
// docs/networking.md.
func (s *Server) corroborateMirrorInventory(ctx context.Context, bound map[string]corrosion.TableDigest) (bool, string) {
	if len(bound) == 0 {
		// No sample means no conclusion to certify: the sampler failed, or a
		// caller passed nothing. Either way this cannot answer for a read it was
		// never given, and answering about a fresh one is the defect.
		return false, "this pass carries no inventory sample, so the read its conclusions " +
			"were drawn from cannot be corroborated"
	}
	now, err := s.localTableDigests(ctx, adoptionInventoryTables())
	if err != nil {
		return false, fmt.Sprintf(
			"this node's own inventory digests could not be read (%v)", err)
	}
	if moved := inventoryMoved(bound, now); moved != "" {
		return false, moved
	}
	proven, why, perr := s.proveNoPeerHoldsInventoryRowsWeLack(ctx, bound)
	if perr != nil {
		return false, fmt.Sprintf(
			"whether any peer holds an inventory record this node has not received could "+
				"not be established (%v)", perr)
	}
	if proven {
		return true, ""
	}
	return false, why
}

// inventoryMoved reports the table whose digest changed between the sample a
// conclusion was computed from and the sample taken while proving it, or "" when
// every table is identical.
//
// THE ONE COPY, shared by both consumers of the inventory proof, because both
// have the same shape: read the inventory, conclude something from it, prove the
// conclusion. Two spellings of "did our read move?" would be a second notion of
// a whole read, which is the mistake this file has already made three times in
// the peer-set direction.
//
// SCOPED TO THE INVENTORY TABLES, and deliberately no wider. These are the
// tables whose rows decide the conclusions — whether a guest already holds an
// address (the bind) and whether any host holds a row for an incarnation (the
// mirror). `ip_allocations`, `netbox_objects` and every other replicated table
// are excluded for the reason adoptionInventoryTables states: a row arriving
// there cannot make an absent VM present or an unrecorded address held. Widening
// this to the whole database would withhold on writes that cannot change the
// answer — the mirror's own mapping-row write is one of them — and a busy
// cluster would never prove a mapping-only removal again. That is a liveness
// regression bought for nothing.
//
// STRICT EQUALITY, both hashes and the count. A count that matches under a
// different hash is a row that was REPLACED, which moves the read as surely as
// one that was added; and the v1/v2 hash pair is compared whole because a
// digest_v2 flip mid-pass is itself a change in what the sample means. The
// comparison is local-to-local — one node's own two reads — so there is no
// pairwise negotiation to do and nothing corrosion.TableDigestsAgree would add:
// that predicate answers the DIFFERENT question of whether two NODES agree, and
// borrowing it here is how one question grows two answers.
//
// WHAT IT CANNOT SEE: a change that lands and is undone inside the window,
// restoring an identical digest. Row PRESENCE is monotone across a window this
// short — litevirt soft-deletes, so an arrival leaves a row that is still there
// at the second sample and the count cannot come back down — so no ARRIVAL can
// hide here, and an arrival is what every conclusion on this path turns on. A
// row updated away and back would hide, and costs nothing: both conclusions rest
// on a row existing, not on its contents.
func inventoryMoved(bound, now map[string]corrosion.TableDigest) string {
	// Walked in adoptionInventoryTables order so two runs over one change name
	// the same table rather than whichever the map yielded first.
	for _, table := range adoptionInventoryTables() {
		was, ok := bound[table]
		if !ok {
			return fmt.Sprintf(
				"the inventory sample this conclusion was drawn from carries no %s digest, "+
					"so there is nothing to corroborate it against", table)
		}
		is, ok := now[table]
		if !ok {
			return fmt.Sprintf("this node no longer reports a %s digest, so the read this "+
				"conclusion was drawn from cannot be confirmed as still its own", table)
		}
		if was != is {
			return fmt.Sprintf(
				"this node's %s rows changed while the proof was being taken (%d row(s) in "+
					"the read this conclusion was drawn from, %d now), so what the cluster "+
					"agrees about is no longer the read that produced it; the conclusion is "+
					"discarded and the next pass re-derives it",
				table, was.Count, is.Count)
		}
	}
	return ""
}

// proveNoPeerHoldsInventoryRowsWeLack asks every host in the CLOSED participant
// universe for its digest of each address-bearing table and reports whether they
// ALL AGREE with this node's.
//
// One shape is accepted, and only one: corrosion.TableDigestsAgree on every
// table — same count, same content hash — for every participant. Nothing any of
// them holds is then missing here. Everything else says our inventory is not the
// cluster's, and the bind must not go live on it. See
// corroborateAdoptionInventory for why that strictness is affordable (the bind
// suspends, and the revalidation pass finishes it) and why no relation between
// two row counts can replace it.
//
// The second return is the operator-facing reason a negative answer is negative
// — which host, which table, and what it said — because "we could not prove it"
// with nothing attached is the log line nobody can act on.
//
// Errors are RETURNED only for the failures that are about this node (no
// database, an unreadable host table). A peer that cannot be reached, or a
// participant set that cannot be closed, is part of the ANSWER, not an error: it
// is an inventory that could not be read, and the proof simply does not hold.
//
// MACHINE EVIDENCE IS THE ONLY WAY TO SATISFY THIS PREMISE. There is no grant,
// manifest or attestation an operator can record that excuses a participant from
// producing its digest — a prerelease permanent-loss exception did exactly that
// and was removed. The consequence is a real, documented limitation rather than
// an oversight: a PERMANENTLY lost host can never produce a digest, so a bind or
// adoption that needs one keeps withholding indefinitely and there is currently
// no operator remedy. See docs/networking.md ("Permanent host loss") and the
// frozen recovery contract in
// docs/reviews/2026-09-08-trust-lifecycle-followup-scope.md.
func (s *Server) proveNoPeerHoldsInventoryRowsWeLack(ctx context.Context, local map[string]corrosion.TableDigest) (bool, string, error) {
	if s.db == nil {
		return false, "", fmt.Errorf("no cluster database")
	}
	peers, unclosed, err := s.closedInventoryCorroborationPeers(ctx)
	if err != nil {
		return false, "", err
	}
	if unclosed != "" {
		// The set of hosts that could be holding rows is not even known yet, so
		// there is nobody for the digests below to have proved anything about.
		return false, unclosed, nil
	}
	if len(peers) == 0 {
		// This node stands alone, so its local database IS the cluster's. Not a
		// vacuous proof: the local read that got us here already answered for
		// this host.
		return true, "", nil
	}

	tables := adoptionInventoryTables()
	for _, a := range s.gatherTableDigests(ctx, peers, tables) {
		if a.err != nil {
			return false, fmt.Sprintf("host %s could not be asked (%v)", a.host, a.err), nil
		}
		// Walked in adoptionInventoryTables order, so which table a suspension
		// names does not depend on map iteration: two runs over one divergence
		// report the same reason.
		for _, table := range tables {
			remote, found := a.digests[table]
			if !found {
				// An older peer, or one whose digest set does not carry the
				// table. Silence about a table is not a statement about what it
				// holds.
				return false, fmt.Sprintf("host %s reported no %s digest", a.host, table), nil
			}
			if !corrosion.TableDigestsAgree(local[table], remote) {
				return false, fmt.Sprintf(
					"host %s holds a different set of %s rows than this node (%d there, %d here)",
					a.host, table, remote.GetCount(), local[table].Count), nil
			}
		}
	}
	return true, "", nil
}

// localTableDigest reads THIS node's digest for one table, from the same
// computation GetStateDigest serves to a peer — so the two sides of every
// comparison are produced by one piece of code rather than by a local row count
// that would have to be kept in step with it by hand.
func (s *Server) localTableDigest(ctx context.Context, table string) (corrosion.TableDigest, error) {
	digests, err := s.localTableDigests(ctx, []string{table})
	if err != nil {
		return corrosion.TableDigest{}, err
	}
	return digests[table], nil
}

// localTableDigests reads THIS node's digests for several tables out of ONE
// StateDigest call, so a proof spanning four tables compares four digests taken
// from a single read rather than four reads a write could land between.
//
// A table this node cannot digest is reported as an ERROR rather than omitted,
// so every caller fails closed instead of comparing against a zero-valued
// digest — which would read as "empty, and agreeing with nobody".
func (s *Server) localTableDigests(ctx context.Context, tables []string) (map[string]corrosion.TableDigest, error) {
	if s.db == nil {
		return nil, fmt.Errorf("no cluster database")
	}
	digests, err := s.db.StateDigest(ctx)
	if err != nil {
		return nil, fmt.Errorf("read local table digests: %w", err)
	}
	byName := make(map[string]corrosion.TableDigest, len(digests))
	for _, d := range digests {
		byName[d.Name] = d
	}
	out := make(map[string]corrosion.TableDigest, len(tables))
	for _, t := range tables {
		d, ok := byName[t]
		if !ok {
			return nil, fmt.Errorf("this node reported no %s digest", t)
		}
		out[t] = d
	}
	return out, nil
}

// digestAnswer is one participant's reply about the tables it was asked for.
type digestAnswer struct {
	host string
	// digests carries ONLY the tables the peer actually reported, so a caller
	// can tell "it holds no rows" from "it said nothing about that table" —
	// which are the same number and opposite claims.
	digests map[string]*pb.TableDigest
	err     error
}

// gatherTableDigests asks each peer for its digest of several tables, over the
// bounded worker pool and per-peer timeout the sweeper's proof fan-out already
// uses. One GetStateDigest carries every table, so asking for four costs one
// round trip per peer — and all four come from one snapshot of that peer.
func (s *Server) gatherTableDigests(ctx context.Context, peers []string, tables []string) []digestAnswer {
	want := make(map[string]bool, len(tables))
	for _, t := range tables {
		want[t] = true
	}
	answers := make([]digestAnswer, len(peers))
	var wg sync.WaitGroup
	sem := make(chan struct{}, orphanProofWorkers)
	for i, h := range peers {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, h string) {
			defer wg.Done()
			defer func() { <-sem }()
			answers[i] = digestAnswer{host: h}
			pctx, cancel := context.WithTimeout(ctx, orphanProofTimeout)
			defer cancel()
			client, closeConn, derr := s.dialPeer(pctx, h)
			if derr != nil {
				answers[i].err = derr
				return
			}
			resp, rerr := client.GetStateDigest(pctx, &emptypb.Empty{})
			closeConn()
			if rerr != nil {
				answers[i].err = rerr
				return
			}
			got := make(map[string]*pb.TableDigest, len(tables))
			for _, td := range resp.GetTables() {
				if want[td.GetName()] {
					got[td.GetName()] = td
				}
			}
			answers[i].digests = got
		}(i, h)
	}
	wg.Wait()
	return answers
}

// vmsTableName is the table the inventory corroboration starts from. A literal
// rather than an import: it is matched against a name a PEER put on the wire,
// and on a mixed-version cluster the two sides are different builds.
//
// There is no `hosts` counterpart any more. Membership was once compared as a
// `hosts` DIGEST and then read out of a `hosts` state dump; both are gone —
// GetMembershipView asks each node for its own universe directly, so nothing
// here compares that table.
const vmsTableName = "vms"

// unhydratedSuspendPrefix is the head of the reason a bind writes when it could
// not corroborate an empty VM inventory, and the whole of how the revalidation
// pass RECOGNISES that suspension later.
//
// A prefix match on a sentence rather than a column, because `netbox_bindings`
// is a replicated table and a new column on it is a mixed-version cost with
// nothing to buy here: the reason string already replicates, already reaches the
// operator through `lv health`, and this is the only consumer that has to branch
// on it. The sentence therefore has to stay the literal head of what
// unhydratedSuspendReason produces — pinned by
// TestUnhydratedSuspensionIsToldFromEveryOtherSuspension, which asserts the
// predicate matches its own writer's output and no other suspension's.
const unhydratedSuspendPrefix = "this node could not corroborate its VM inventory when NetBox " +
	"prefix was bound"

// unhydratedSuspendReason is the suspension a bind writes over an empty VM read
// it cannot corroborate.
//
// It states the automatic resume, because this is the ONE suspension an operator
// must not go looking for a repair for: nothing is broken, and the pass lifts it
// on its own. It also names the manual finisher, because the pass is 15 minutes
// away by default and `lv netbox resume` is the same re-run every other adoption
// suspension advises.
func unhydratedSuspendReason(network string) string {
	return fmt.Sprintf(
		"%s, so the addresses guests already hold inside it could not be enumerated; the "+
			"binding serves no claims until a NetBox revalidation pass re-runs adoption, which "+
			"happens automatically once this node's inventory can be corroborated. To finish it "+
			"now, run `lv netbox resume %s` from a node that has been up and replicating",
		unhydratedSuspendPrefix, network)
}

// isUnhydratedSuspension reports whether a suspension is the one the periodic
// revalidation pass may lift by itself.
//
// Exactly one class, deliberately. Every other suspension records something an
// operator has to change — a re-CIDRed prefix, a VRF that stopped enforcing
// uniqueness, a moved fingerprint, an adoption that failed against NetBox — and
// a pass that lifted one of those would be declaring a repair it never made.
func isUnhydratedSuspension(reason string) bool {
	return strings.HasPrefix(reason, unhydratedSuspendPrefix)
}

// adoptionSuspendReason is the reason a binding carries while adoption is owed.
// It names the count, so an operator reading the row knows what is outstanding
// rather than only that something is.
func adoptionSuspendReason(network string, pending int) string {
	return fmt.Sprintf(
		"adopting %d existing address(es) on network %s into NetBox; the binding serves no "+
			"claims until every one of them is recorded", pending, network)
}

// ── THE FINAL ACTIVATION GATE ───────────────────────────────────────────────
//
// activateBinding is the ONE door onto a live binding, and the only place in
// this tree that clears a suspension.
//
// WHY IT EXISTS AT ALL, stated precisely because a previous round audited this
// and left it alone on reasoning that turned out to be wrong. Every activation
// path used to validate the binding, then adopt, then resume — and the argument
// for that order was "the premise is the bind's own validation in the same RPC".
// Same RPC does not mean unchanged external state. Adoption itself performs
// intervening NetBox requests: up to 256 POSTs, each a round trip an operator or
// another system can act across. Disabling a VRF's uniqueness enforcement during
// an adoption POST therefore left the binding LIVE on every one of the four
// doors — the precise condition each of them had just checked for.
//
// So the premise an activation rests on is re-read AFTER the last adoption
// write, and this function owns that ordering. It is the ADOPTION WINDOW that
// closes here.
//
// WHAT THIS DOES NOT BUY, and nothing in it should be read as implying
// otherwise: it does NOT make NetBox changes atomic with local activation. There
// is no transaction spanning the two, and there cannot be — NetBox is a separate
// system with no lock this daemon can hold. Uniqueness enforcement switched off
// one millisecond after the revalidation read returns still leaves the binding
// live, and the periodic revalidation pass is what catches that (it suspends,
// which is the one direction that pass is allowed to move). What closes here is
// the window with a KNOWN, BOUNDED duration and a KNOWN cause: the adoption's
// own requests, which are this daemon's doing and can be read across.
//
// ONE GATE, NOT FOUR CHECKS THAT AGREE. Four call sites are how this diverged in
// the first place, and an earlier round already had to unify the bind and the
// sweeper for the same reason. So all four paths — the bind's own finisher,
// `lv netbox resume`, the re-key's tail, and the automatic unhydrated completion
// — call THIS, and none of them writes `Suspended = false` itself. That is
// pinned structurally (TestOnlyTheActivationGateClearsASuspension and
// TestTheActivationGateRevalidatesAfterItAdopts), the same way the
// activation-door guard pins the unread drift answer.
//
// FAIL CLOSED, AND KEEP THE WORK. Drift that was READ re-states the suspension
// under the current cause. Drift that could NOT be read leaves the row exactly
// as it is. In both cases the adopted claims STAND — the NetBox objects and the
// local leases behind them are not rolled back, because adoption is the work a
// retry must not have to redo and discarding it would hand a running guest's
// address back to `/available-ips/`. Refusing to activate is not a reason to
// un-adopt.
//
// The count is returned ALONGSIDE the error for the same reason
// adoptExistingAddresses returns one: a pass that stopped here has still created
// objects in NetBox, and the audit trail may not imply nothing happened.
func (s *Server) activateBinding(ctx context.Context, b corrosion.BindingRecord, lease *rekeyLease) (int, error) {
	adopted, aerr := s.adoptExistingAddresses(ctx, b, lease)
	if aerr != nil {
		// The adoption's own failure, returned unwrapped so every caller's
		// existing branch still reads it: errAdoptionUncorroborated for the
		// automatic path, adoptionRefused for the RPC codes.
		return adopted, aerr
	}

	// NO NETBOX, NO ACTIVATION. bindingDrift reads the prefix and its VRF
	// through s.netbox and would dereference a nil one; every door onto this
	// function establishes that it is non-nil, and the adoption itself refuses
	// without it — but a binding may not go live on a check that could not be
	// made, and a nil client is the most complete version of "could not be
	// made". Fail closed rather than trust the callers to keep doing it.
	if s.netbox == nil {
		return adopted, activationRefusedError{
			network: b.Network, prefixID: b.PrefixID, adopted: adopted,
			unread: fmt.Errorf(
				"this node has no netbox configuration, so the binding's preconditions cannot "+
					"be re-checked; activate it from a node that does, with "+
					"`lv netbox resume %s`", b.Network),
		}
	}

	// THE FRESH REVALIDATION, after the last adoption write and before anything
	// that could be mistaken for one.
	//
	// The LIVE fingerprint, derived here rather than taken from the caller, so a
	// fingerprint that moved DURING the adoption is caught too — that is the
	// same class of intervening change as the VRF, and a caller-supplied value
	// read before the adoption would be exactly the stale premise this function
	// exists to remove.
	fp, ferr := corrosion.ClusterFingerprint(ctx, s.db)
	if ferr != nil {
		return adopted, activationRefusedError{
			network: b.Network, prefixID: b.PrefixID, adopted: adopted,
			unread: fmt.Errorf("derive cluster fingerprint: %w", ferr),
		}
	}
	reason, derr := s.bindingDrift(ctx, b, fp)
	if derr != nil {
		// AN UNREADABLE ANSWER IS NOT A CLEAN ONE. The row is left untouched —
		// not re-stated, not re-suspended — because nothing was learned: a
		// binding waiting on its inventory stays in the class the revalidation
		// pass lifts by itself, and every other suspension keeps the reason an
		// operator is already acting on.
		return adopted, activationRefusedError{
			network: b.Network, prefixID: b.PrefixID, adopted: adopted, unread: derr,
		}
	}
	if reason != "" {
		// READ, and it does not hold. Re-state the suspension under the CURRENT
		// cause: the reason on the row was written before the adoption and now
		// names something that may no longer be the problem. This also takes an
		// unhydrated suspension out of the self-lifting class, which is correct
		// — a VRF that stopped enforcing uniqueness is an operator's repair, not
		// a pass's.
		if serr := corrosion.SuspendBinding(ctx, s.db, b.PrefixID, reason); serr != nil {
			slog.Error("netbox: could not re-state why a binding stays suspended after its "+
				"post-adoption revalidation refused activation; it stays suspended under its "+
				"previous reason",
				"network", b.Network, "prefix", b.PrefixID, "reason", reason, "error", serr)
		} else {
			s.nbMetrics().IncBindingSuspended()
		}
		return adopted, activationRefusedError{
			network: b.Network, prefixID: b.PrefixID, adopted: adopted, reason: reason,
		}
	}

	// THE LAST LEASE PROOF, immediately before the write and after the
	// revalidation's round trips.
	//
	// The re-key is the only caller that holds one, and its own comments state
	// why this belongs here: the adoption above may have spent tens of seconds
	// in NetBox against a lease with a one-minute TTL, and the revalidation has
	// just added two more reads on top. A proof taken before either is not a
	// statement about now, and a binding activated under a lease another node
	// holds is live while that node may be partway through a rewrite of its own.
	if lease != nil {
		if lerr := lease.check(ctx); lerr != nil {
			return adopted, activationNotPersistedError{
				network: b.Network, prefixID: b.PrefixID, adopted: adopted, cause: lerr,
			}
		}
	}

	next := b
	next.Suspended = false
	next.SuspendReason = ""
	if uerr := corrosion.UpsertBinding(ctx, s.db, next); uerr != nil {
		// A POST-ADOPTION OPERATIONAL FAILURE, not an adoption failure, and the
		// distinction is the whole of activationNotPersistedError. Everything
		// this binding was waiting for happened: the addresses are adopted, the
		// preconditions were re-read and hold. The only thing that did not is
		// the local write, and the caller must not describe that as owed
		// adoption — see there.
		return adopted, activationNotPersistedError{
			network: b.Network, prefixID: b.PrefixID, adopted: adopted, cause: uerr,
		}
	}
	return adopted, nil
}

// activationRefusedError is an adoption that SUCCEEDED and an activation the
// final gate then refused.
//
// A distinct type because the two halves of the outcome have to be reported
// together and each caller says so differently: the adopted claims STAND, and
// the binding did NOT go live. Read as an ordinary failure it would suggest the
// adoption is owed again, which would send an operator looking for work that is
// already done.
//
// reason and unread are mutually exclusive, and which one is set is the whole
// distinction the callers act on: a reason is a repair an operator makes, and an
// unread answer is a retry.
type activationRefusedError struct {
	network  string
	prefixID int
	adopted  int
	reason   string
	unread   error
}

func (e activationRefusedError) Error() string {
	if e.unread != nil {
		return fmt.Sprintf(
			"the addresses network %s's guests already hold were adopted (%d this pass) and "+
				"those claims stand, but the binding for prefix %d was NOT activated: its "+
				"NetBox preconditions could not be re-checked AFTER the adoption, and an "+
				"activation may not rest on a validation the adoption's own requests could "+
				"have outlived. It stays suspended — re-run once NetBox answers: %v",
			e.network, e.adopted, e.prefixID, e.unread)
	}
	return fmt.Sprintf(
		"the addresses network %s's guests already hold were adopted (%d this pass) and those "+
			"claims stand, but the binding for prefix %d was NOT activated: re-checked after "+
			"the adoption, %s",
		e.network, e.adopted, e.prefixID, e.reason)
}

func (e activationRefusedError) Unwrap() error { return e.unread }

// activationRefused reports whether an error is the final gate's refusal, and
// returns it.
//
// Callers use it to keep their OWN suspension reason off the row: the gate has
// already written the one that names the current cause, and re-stating it as
// "the adoption is incomplete" would be false — the adoption finished.
func activationRefused(err error) (activationRefusedError, bool) {
	var ref activationRefusedError
	ok := errors.As(err, &ref)
	return ref, ok
}

// activationNotPersistedError is an adoption that succeeded, a post-adoption
// revalidation that HELD, and an activation that could not be written down.
//
// A THIRD OUTCOME, not a variant of the refusal above, and the reason it is its
// own type is what happened to the binding before it existed. Every path here
// used to return a plain error for the two ways activation fails after passing
// its gate — a lease that lapsed across the adoption's round trips, and a local
// UpsertBinding that failed — and the callers read any non-refusal as a failed
// ADOPTION. So they replaced the reason on the row with "adoption … is
// incomplete". For the ONE self-lifting suspension in this tree (see
// isUnhydratedSuspension) that is not merely inaccurate: it takes the binding out
// of the class the revalidation pass completes by itself, so a single transient
// write failure converted a suspension that heals in fifteen minutes into one
// that waits for an operator — with the reason text itself recording that
// adoption and revalidation had both succeeded.
//
// NOTHING IS OWED AND NOTHING IS WRONG, which is why the correct handling is to
// leave the row exactly as it is. The adopted claims stand, the preconditions
// were read and held, and the next pass through the same gate re-reads them and
// writes the flag again. Re-stating the reason is the only thing that can make
// this permanent, so no caller does it.
//
// It is NOT in adoptionRefused: a local write that failed is a fault to fix, not
// a precondition an operator repairs, so the RPCs keep reporting Internal for it.
type activationNotPersistedError struct {
	network  string
	prefixID int
	adopted  int
	cause    error
}

func (e activationNotPersistedError) Error() string {
	return fmt.Sprintf(
		"every existing address on network %s was adopted (%d this pass) and the binding for "+
			"prefix %d re-validated cleanly, but activating it could not be persisted; it stays "+
			"suspended under the reason it already carries and the next pass retries: %v",
		e.network, e.adopted, e.prefixID, e.cause)
}

func (e activationNotPersistedError) Unwrap() error { return e.cause }

// activationNotPersisted reports whether an error is that third outcome.
func activationNotPersisted(err error) (activationNotPersistedError, bool) {
	var np activationNotPersistedError
	ok := errors.As(err, &np)
	return np, ok
}

// adoptionOwed reports whether an activateBinding failure leaves ADOPTION
// outstanding — which is the only case a caller may re-state the row's
// suspension reason for.
//
// ONE PREDICATE FOR ALL FOUR DOORS. The gate has three failure outcomes and only
// one of them means "the addresses guests hold are not all in NetBox"; the other
// two happen AFTER the adoption finished, and describing either as owed adoption
// is a false operator claim — and, on the self-lifting suspension, a permanent
// one. Asking here rather than at each door is what stops a fourth outcome from
// being handled correctly in three places and wrongly in the fourth, which is
// exactly how this defect reached two of them.
func adoptionOwed(err error) bool {
	if err == nil {
		return false
	}
	if _, refused := activationRefused(err); refused {
		return false
	}
	if _, notPersisted := activationNotPersisted(err); notPersisted {
		return false
	}
	return true
}

// finishAdoptionAndResume adopts what a bind left owed and resumes the binding.
//
// It is a NO-OP on a binding that is not suspended, which is the common case: a
// bind of a network with no existing guests leaves the binding live, and this
// then costs the one GetBindingByPrefix below and nothing else. That is
// deliberate — the ordinary bind must not become a slow path, and in particular
// must not reach NetBox's address endpoints at all.
//
// On a binding that IS suspended it costs 2N+3 more local queries for a cluster
// of N VMs, because it re-plans the adoption (see planAdoption, which states the
// figure and why it is not bounded). That is the same scan the bind itself just
// performed; it is repeated rather than carried across, because the plan is only
// valid against the rows as they are now and the binding is persisted in between.
//
// RESUME LAST, and only on a pass that adopted everything AND re-validated
// afterwards. Everything before the activation is safe to interrupt: the binding
// stays suspended, no claim is served, and the addresses already adopted are
// recorded on their leases so a re-run skips them. Activation is the single step
// that makes the binding live, so it may not rest on a pass that did not finish
// — nor on the bind's own validation, which the adoption's NetBox requests are
// interleaved with. Both rules live in activateBinding, which this calls.
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
	if isUnhydratedSuspension(b.SuspendReason) {
		// The bind decided, from the same reads this call would repeat, that it
		// cannot enumerate what needs adopting. Nothing has changed since —
		// this runs in the same RPC — so there is no point taking nbPassMu or
		// reaching NetBox, and no point rewriting the reason: the revalidation
		// pass recognises exactly this one, and a reason restated as "adoption
		// is incomplete" would take the binding out of the only class of
		// suspension that lifts itself.
		return adoptRefuseCausef(errAdoptionUncorroborated,
			"the binding for prefix %d is suspended because %s. It resumes automatically once "+
				"this node's inventory can be corroborated; `lv netbox resume %s` from a node "+
				"that has been up and replicating finishes it now",
			prefixID, unhydratedSuspendPrefix, netName)
	}

	// THE INTRA-NODE EXCLUSION, and only now that there is provably something
	// to adopt. Past this point the pass POSTs to NetBox, and nbPassMu is what
	// admits one NetBox write pass at a time on this node (see server.go) — the
	// same gate its two siblings take, the maintenance pass and RekeyBinding.
	//
	// Taken AFTER the suspended check, deliberately. A bind with nothing owed
	// makes no NetBox request at all, so gating it would refuse an ordinary
	// `lv network create` whenever a 15-minute mirror sweep happened to overlap
	// it — a refusal over an operation that was never going to write.
	//
	// A refusal, not a wait: an operator queued behind a sweep would see a hang
	// with nothing to read, and the binding is left suspended and resumable, so
	// the retry this advises is a real one.

	if !s.nbPassMu.TryLock() {
		return adoptRefusef(
			"a NetBox maintenance or inventory pass is already running on this node, so the "+
				"existing addresses on network %s were not adopted and the binding stays "+
				"suspended; the pass ends on its own — finish with `lv netbox resume %s` in a moment",
			netName, netName)
	}
	defer s.nbPassMu.Unlock()

	// No leader lease. Neither of the two doors that reach this function may
	// require cluster leadership — see adoptExistingAddresses.
	adopted, aerr := s.activateBinding(ctx, *b, nil)
	detail := fmt.Sprintf("prefix=%d adopted=%d", prefixID, adopted)
	if aerr != nil {
		// Audited on BOTH outcomes, the way a re-key is: a pass that failed
		// partway has still created objects in NetBox, so "nothing happened" is
		// the wrong thing for the trail to imply.
		s.audit(ctx, "netbox.adopt", netName, detail, "error")
		if !adoptionOwed(aerr) {
			// THE ADOPTION FINISHED. Either the gate refused — it owns the reason
			// on the row, the drift it read or the previous one when it could not
			// read at all — or the activation passed its gate and could not be
			// written down, which leaves the reason already there correct and the
			// retry automatic. Nothing is re-stated for either: calling the
			// adoption "incomplete" would be false and would send an operator to
			// finish work that is finished.
			return aerr
		}
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

	s.audit(ctx, "netbox.adopt", netName, detail, "ok")
	slog.Info("netbox binding resumed after adopting existing addresses",
		"network", netName, "prefix", prefixID, "adopted", adopted)
	return nil
}
