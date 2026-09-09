// Package netboxsync mirrors litevirt inventory into NetBox.
//
// The reconciler is a DESIRED-STATE DIFF, not an event replay. The
// netbox_sync_queue table is a latency optimisation only: correctness must hold
// with the queue empty or lost, because a node that dies mid-create never
// enqueues anything. The periodic full sweep is what makes the mirror right.
package netboxsync

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/netbox"
)

// DesiredVM is litevirt's view of one VM.
type DesiredVM struct {
	Name     string
	Host     string
	UUID     string
	Status   string
	VCPUs    int
	MemoryMB int
	// DiskMB is the total provisioned disk in NetBox's unit for the field it
	// is mirrored into: DECIMAL megabytes. Not gibibytes, and not the quota
	// helper's GiB-rounded figure — see netbox.DiskMBFromBytes.
	DiskMB   int
	DeviceID int // resolved DCIM device for Host; 0 when the host is not modelled
	NICs     []DesiredNIC
}

// DesiredNIC is one NIC. NetBoxIPID is 0 when the address did not come from a
// bound network.
type DesiredNIC struct {
	Name       string
	MAC        string
	IP         string
	NetBoxIPID int
}

// Action is one unit of work for the applier.
//
// Key is an IDENTITY, never a name. NetBoxID is carried because a delete action
// has no other way to name its target: the identity has already been resolved
// against actual state here, and re-resolving it in the applier would be a
// second round trip that could observe different state.
type Action struct {
	Kind     string // "vm" | "nic"
	Op       string // "create" | "update" | "delete" | "assign" | "clear" | "replace" | "park"
	Key      string // identity
	NetBoxID int    // 0 for create; the target object for every other op

	// ParentNetBoxID is the owning VM's NetBox id, carried on every "nic"
	// action and read from ACTUAL state.
	//
	// Phase ordering alone cannot establish it: if the VM already exists in
	// NetBox but its netbox_objects row was lost, Diff emits no VM action at
	// all, so the VM phase records nothing and the NIC phase's mapping lookup
	// finds nothing. Reading it from actual state closes that hole.
	ParentNetBoxID int

	// IPID is the address this action assigns or clears.
	//
	// ClearIPAssignment takes the ADDRESS id, not the interface id, so an
	// interface id alone cannot clear anything. It is populated for a clear only
	// when litevirt owns that address — an operator-owned one is never carried,
	// so the applier cannot clear it even by mistake.
	IPID int

	// FreesName is the VM name this action clears the way for: the name a
	// "replace" removes an object from, or the name a "park" moves one off.
	// Record only — neither applier proof consults it — but it is what makes
	// the log line and the refusals legible.
	FreesName string
}

// ── vm/replace: the superseded incarnation of a reused name ─────────────────
//
// WHAT IT IS FOR. A VM deleted and recreated under the same name before the next
// sweep has a new UUID, so a new identity, so the diff calls for a create — and
// NetBox enforces one VM name per cluster, so that create is a 400 for as long
// as the old object holds the name. The old object IS in this sweep's delete set,
// but deletes run in the LAST phase and creates in the first, so the pass aborts
// on the 400 before ever reaching it. Three consecutive passes fail identically:
// a permanent stall on an ordinary operation.
//
// A CREATE IS NOT THE ONLY WAY TO NEED A NAME, which is the half this originally
// missed. NetBox's rule constrains the NAME, so a PATCH that moves an existing
// object onto a taken name gets the same 400. Rename a VM to something else,
// delete it, and rename a second VM into the name it vacated — all within one
// sweep interval, which is minutes by default — and the survivor needs an
// UPDATE. Applying the proof only ahead of creates left that case stalling
// exactly as before, so it is applied ahead of a name-changing update too, from
// the same function under the same proof (freeReusedName).
//
// WHY NOT SIMPLY RUN DELETES FIRST. That ordering is load-bearing — a VM delete
// cascades its interfaces, and an address must be released before anything
// claims it — and reordering it wholesale would undo reasons earlier rounds
// established. This moves exactly ONE removal, of ONE object, proven to be a
// superseded incarnation of the exact name the upsert needs — and, with it, the
// interfaces NetBox cascades away under that object, which the same removal now
// owns rather than leaving to a separate action in a later phase.
//
// THE PROOF, and every clause is load-bearing — the same one whether a create or
// a rename is what needs the name (see supersededIncarnation, which makes it,
// and Reconciler.replaceSuperseded, which makes it again from the applier's own
// index before it touches anything):
//
//   - the occupying object carries THIS cluster's identity fingerprint, and
//   - the UUID in that identity is NOT in the desired set.
//
// Ours, and gone. A FOREIGN fingerprint is another installation's object and
// untouchable at any cost; an identity that IS in the desired set is a LIVE VM,
// which is the one thing freeing a name may never remove.
//
// IT IS A DESTRUCTIVE ACTION and passes both withholding gates as one: the
// desired-set-absence half of the proof is only as good as the desired read is
// whole, so a sweep that cannot prove its read whole withholds this exactly as
// it withholds every delete. The create then collides as it does today — the
// mirror stays stalled for that VM rather than replacing an object on evidence
// it has just admitted is partial.
const opReplace = "replace"

// ── vm/park: breaking a rename cycle through a name we control ──────────────
//
// WHAT IT IS FOR. Two VMs SWAPPING names — or any permutation of names among
// live VMs — has no safe starting point. Each object's occupant is another LIVE
// VM of this cluster, so the replace above refuses both (correctly: an identity
// in the desired set may never be removed to free a name), and each rename is
// refused by NetBox for as long as the other has not landed. Neither can go
// first, so WAITING DOES NOT RESOLVE IT: every sweep computes the same two
// updates and every sweep gets the same two 400s, for as long as both VMs exist.
// That is a permanent stall on an operation an operator reaches with two ordinary
// renames.
//
// THE ONLY WAY OUT OF A PERMUTATION IS A NAME OUTSIDE IT. So one object of the
// cycle is PATCHED onto a temporary name this mirror derives and owns
// (parkedName), which turns the cycle into a chain — and a chain converges,
// because its head is unblocked. Nothing is deleted and no identity is touched:
// a park changes the one field the mirror rewrites on every rename anyway, and
// the object it changes is a live VM of ours whose desired name the very next
// sweep writes.
//
// LEAK OVER COLLISION, which is the same direction every other decision in this
// package takes. The leak is visible — an object sitting under
// `litevirt-renaming-<uuid>` for one sweep interval, self-describing so an
// operator reading NetBox knows what it is — and the alternative was a mirror
// that could not represent a state the cluster reaches on its own. Resolving the
// collision by DELETING either object was never available: both identities are
// in the desired set.
//
// EXACTLY ONE PER CYCLE, chosen by lowest identity so repeated sweeps pick the
// same one instead of parking a different member each pass. And only when the
// temporary name is provably free of every name in play — our own objects, a
// co-tenant's, and every desired name — because a park onto a taken name is the
// same 400 it is there to avoid.
//
// IT IS NOT DESTRUCTIVE and the withholding gates deliberately keep it, with the
// creates and updates. A partial desired read can only REMOVE edges from the
// blocked-by graph — every edge requires the holder's identity to be in the
// desired set — so it can make a cycle disappear, never appear. The worst a
// partial read costs here is an object under a temporary name that a later pass
// renames, which is the additive direction; withholding it instead would keep
// the permanent stall the park exists to end.
const opPark = "park"

// parkedNamePrefix heads every temporary name the cycle-breaker writes.
//
// Self-describing on purpose: it is read by an operator looking at NetBox during
// the one sweep interval an object sits under it, and it has to say what it is
// and that it is transient. Nothing branches on it — the park is planned from
// the blocked-by graph, never from a name — so it is a label, not a marker.
const parkedNamePrefix = "litevirt-renaming-"

// parkedName is the temporary NetBox name for one parked identity.
//
// ONE SPELLING for the planner and the applier both, because they have to agree
// exactly: the planner is what proves the name is free, and a name derived twice
// is a name that can be derived two ways. Keyed on the incarnation uuid, so it is
// stable across sweeps (a park re-planned before the previous one converged
// writes the identical name) and unique per object (NetBox's rule is per name,
// and two objects parked under one name would collide with each other).
func parkedName(identity string) string {
	return parkedNamePrefix + netbox.IdentityVMUUID(identity)
}

// Actual is what NetBox currently holds for THIS cluster, keyed by identity.
//
// Keyed by identity, never by name. Two litevirt clusters can hold same-named
// VMs in one NetBox; a name-keyed map would make one cluster's sweep see the
// other's VM as "not in my desired set" and delete it.
type Actual struct {
	VMs  map[string]netbox.VirtualMachine
	NICs map[string]netbox.VMInterface

	// ForeignVMNames are the virtual_machine names this NetBox cluster already
	// holds under something that is NOT this cluster's identity — a co-tenant
	// installation's object, or one an operator made by hand.
	//
	// It exists because a NetBox cluster is the scope in which NetBox enforces
	// one VM name per cluster, and that rule reaches across identities: a create
	// for a name already taken is a 400 whoever holds it. Identity keeps the
	// DELETE half safe, and can do nothing at all for the create half.
	//
	// Names, not identities, because the constraint is on the name. An empty
	// identity counts as foreign for the same reason: an operator's own VM holds
	// the name just as firmly as a co-tenant's.
	ForeignVMNames map[string]bool

	// OwnedIPsByIface maps a NetBox interface id to the litevirt-owned addresses
	// currently assigned to it.
	//
	// Assignment is modelled from the IP OBJECT's assigned_object_id, not as a
	// synthetic field on the interface: a NetBox interface can carry several
	// addresses, and only those whose identity proves litevirt ownership may be
	// cleared. Anything not in this map is operator-owned and untouchable.
	OwnedIPsByIface map[int][]netbox.IPAddress
}

// ActualLister is the subset of the NetBox client BuildActual reads through.
//
// An interface rather than *netbox.Client so the reconciler can pass the same
// client abstraction its other calls go through, and so a fleet fake satisfies
// it without a second collection path existing to drift from this one.
type ActualLister interface {
	ListVMsByCluster(ctx context.Context, clusterID int) ([]netbox.VirtualMachine, error)
	ListInterfacesByCluster(ctx context.Context, clusterID int) ([]netbox.VMInterface, error)
	ListOwnedIPsForInterfaces(ctx context.Context, ifaceIDs []int) ([]netbox.IPAddress, error)
}

// BuildActual reads NetBox's current view of one cluster and keys it by
// identity.
//
// It is the reconciler's ONLY collection path — Reconciler.actualState calls
// this rather than carrying a second copy of the filtering, because a second
// copy is a second place for the fingerprint guard to be dropped.
//
// Every object whose identity fingerprint is not ours is DISCARDED here. That
// filter is what stops one cluster's sweep from deleting another cluster's
// inventory out of a shared NetBox; Diff's own fingerprint check on deletes is
// the second, independent guard.
func BuildActual(ctx context.Context, c ActualLister, clusterID int, fingerprint string) (Actual, error) {
	out := Actual{
		VMs:             map[string]netbox.VirtualMachine{},
		NICs:            map[string]netbox.VMInterface{},
		ForeignVMNames:  map[string]bool{},
		OwnedIPsByIface: map[int][]netbox.IPAddress{},
	}

	vms, err := c.ListVMsByCluster(ctx, clusterID)
	if err != nil {
		return Actual{}, fmt.Errorf("netboxsync: list VMs in cluster %d: %w", clusterID, err)
	}
	for _, v := range vms {
		if !ownedBy(v.Identity, fingerprint) {
			// Discarded from the diff — but its NAME is recorded, because
			// NetBox's uniqueness rule does not care whose object holds it.
			out.ForeignVMNames[v.Name] = true
			continue
		}
		out.VMs[v.Identity] = v
	}

	ifaces, err := c.ListInterfacesByCluster(ctx, clusterID)
	if err != nil {
		return Actual{}, fmt.Errorf("netboxsync: list interfaces in cluster %d: %w", clusterID, err)
	}
	ifaceIDs := make([]int, 0, len(ifaces))
	for _, i := range ifaces {
		if !ownedBy(i.Identity, fingerprint) {
			continue
		}
		out.NICs[i.Identity] = i
		ifaceIDs = append(ifaceIDs, i.ID)
	}
	if len(ifaceIDs) == 0 {
		return out, nil
	}

	// The surviving interface set IS the cluster scope: NetBox's address filter
	// set has no cluster filter, so there is no single query for "every address
	// in this cluster".
	ips, err := c.ListOwnedIPsForInterfaces(ctx, ifaceIDs)
	if err != nil {
		return Actual{}, fmt.Errorf("netboxsync: list owned addresses in cluster %d: %w", clusterID, err)
	}
	for _, ip := range ips {
		// An unassigned address belongs to no interface, and one carrying
		// someone else's identity — an operator's blank one included — is not
		// ours to detach. Neither may enter the map the clear path reads.
		if ip.AssignedObjectID == 0 || !ownedBy(ip.Identity, fingerprint) {
			continue
		}
		out.OwnedIPsByIface[ip.AssignedObjectID] = append(out.OwnedIPsByIface[ip.AssignedObjectID], ip)
	}
	return out, nil
}

// Diff computes the minimal action set over VMs AND their NICs.
//
// It emits an update ONLY when a mirrored field actually differs; an
// unconditional PATCH per sweep would bury NetBox's changelog in noise.
func Diff(desired []DesiredVM, actual Actual, fingerprint string) []Action {
	var out []Action
	seenVM := make(map[string]bool, len(desired))
	seenNIC := map[string]bool{}

	// The desired identity set and the owned-object-by-name index, both needed
	// BEFORE the loop below: a superseded incarnation is proven from the WHOLE
	// desired set, and the loop reaches each VM one at a time.
	desiredIDs := make(map[string]bool, len(desired))
	for _, d := range desired {
		desiredIDs[netbox.Identity(fingerprint, d.UUID, "")] = true
	}
	ownedByName := ownedVMsByName(actual)
	// The identities a create or a rename is taking over from, so the delete
	// half below does not ALSO emit a delete for them. One removal, one owner.
	replaced := map[string]bool{}

	// WHOSE NAME EACH UPSERT IS WAITING ON, and which of those waits a cycle
	// makes permanent. Both are needed BEFORE the loop, for the same reason the
	// desired set is: a cycle is a property of the whole graph, and the loop
	// reaches one VM at a time. See opPark.
	blockedBy := renameBlockers(desired, actual, ownedByName, desiredIDs, fingerprint)
	parked := renameCycleParks(blockedBy, desired, actual, fingerprint)

	for _, d := range desired {
		vmID := netbox.Identity(fingerprint, d.UUID, "")
		seenVM[vmID] = true

		if parked[vmID] {
			// THE CYCLE-BREAKER. This object moves to a temporary name in the
			// FIRST phase, which frees the name the VM behind it in the cycle is
			// waiting on. Its own desired name is still held by a live VM, so it
			// is not written this pass — the next sweep, with the cycle now a
			// chain, converges it.
			//
			// SEEN, including its NICs, exactly as the foreign-name branch below
			// is: taking them out of the desired set would have the delete half
			// reap the objects of a VM that is very much alive.
			out = append(out, Action{
				Kind: "vm", Op: opPark, Key: vmID,
				NetBoxID: actual.VMs[vmID].ID, FreesName: actual.VMs[vmID].Name,
			})
			for _, n := range d.NICs {
				seenNIC[netbox.Identity(fingerprint, d.UUID, n.MAC)] = true
			}
			continue
		}
		if blocker, blocked := blockedBy[vmID]; blocked && !parked[blocker] {
			// THE NAME IS HELD BY A LIVE VM THAT IS ITSELF MOVING, and not one
			// this pass frees. Writing the upsert anyway is a 400 that fails the
			// whole sweep — including the work it had already done — over a wait
			// of one interval, so nothing is emitted for this VM and the pass
			// reports itself unconverged (see unconvergedRenames).
			//
			// Not a stall: the holder is renaming away by construction, since
			// desired names are unique and it is in the desired set under a
			// different one. A chain drains from its head, one link per sweep,
			// and a CYCLE has no head — which is what the park above supplies.
			//
			// Seen, for the reason the branch above states.
			for _, n := range d.NICs {
				seenNIC[netbox.Identity(fingerprint, d.UUID, n.MAC)] = true
			}
			continue
		}

		if actual.ForeignVMNames[d.Name] {
			// Somebody else's object holds this name in this NetBox cluster, so
			// a create or a rename onto it is a 400 — and one 400 fails the
			// whole sweep, on every pass, for as long as both VMs exist. Emit
			// nothing for this VM rather than post a write we can prove will be
			// rejected.
			//
			// SEEN FIRST, including its NICs. Skipping without marking them
			// would take the objects we may already hold for this VM out of the
			// desired set, and the delete half would then reap them — turning a
			// name collision into a deletion, which is the one outcome worse
			// than not mirroring.
			for _, n := range d.NICs {
				seenNIC[netbox.Identity(fingerprint, d.UUID, n.MAC)] = true
			}
			continue
		}

		a, ok := actual.VMs[vmID]
		switch {
		case !ok:
			// A SUPERSEDED INCARNATION of this name, if there is one: ours, and
			// with a UUID this cluster no longer has. Emitted BEFORE the create
			// in the list and, more importantly, in an earlier PHASE — see
			// opReplace for why this one removal moves and no other does.
			out = freeReusedName(out, replaced, d.Name, ownedByName, desiredIDs, fingerprint)
			out = append(out, Action{Kind: "vm", Op: "create", Key: vmID})
		case vmDiffers(d, a):
			// A NAME-CHANGING UPDATE NEEDS THE SAME NAME FREED, and needs it in
			// the same earlier phase.
			//
			// NetBox's one-VM-name-per-cluster rule is a constraint on the NAME,
			// not on the operation, so a PATCH that moves an object onto a taken
			// name is the identical 400 a create gets — and the object holding
			// it is in this sweep's delete set, which runs four phases later.
			// The shape is ordinary: rename a VM to something else, delete it,
			// and rename a second VM into the name it vacated, all inside one
			// sweep interval. The survivor then needs an UPDATE, not a create,
			// and without this the pass fails on that 400 every time — a
			// permanent stall, exactly the one the create half already fixed.
			//
			// Gated on the name actually changing. An update that only moves a
			// CPU count or a host link cannot collide with anything, so paying
			// for the proof there would be a removal considered over an
			// operation that could never need one.
			if d.Name != a.Name {
				out = freeReusedName(out, replaced, d.Name, ownedByName, desiredIDs, fingerprint)
			}
			out = append(out, Action{Kind: "vm", Op: "update", Key: vmID, NetBoxID: a.ID})
		}

		// NICs are first-class: without these actions, hotplug attach and detach
		// never converge and interface drift is invisible.
		for _, n := range d.NICs {
			nicID := netbox.Identity(fingerprint, d.UUID, n.MAC)
			seenNIC[nicID] = true
			an, ok := actual.NICs[nicID]
			if !ok {
				// ParentNetBoxID comes from ACTUAL state, so a NIC create works
				// even when the VM exists in NetBox with no local mapping. It is
				// 0 only when the VM is also being created this sweep, in which
				// case the VM phase has recorded its mapping by the time this
				// runs.
				out = append(out, Action{
					Kind: "nic", Op: "create", Key: nicID, ParentNetBoxID: a.ID,
				})
				continue
			}
			if nicDiffers(n, an) {
				out = append(out, Action{
					Kind: "nic", Op: "update", Key: nicID,
					NetBoxID: an.ID, ParentNetBoxID: a.ID,
				})
			}
			// Assignment drift, over a SET.
			//
			// A NetBox interface can hold several addresses, so picking one
			// arbitrarily is not well defined: [desired, stale] would look
			// correct and leave the stale one forever, [stale, desired] would
			// emit a needless clear, and API ordering could change the action
			// set between sweeps for identical state.
			//
			// Set semantics instead: attach the desired address if it is not
			// already there, and clear every OTHER litevirt-owned address on the
			// interface. Operator-owned addresses are not in this set at all —
			// BuildActual never admits them — so they are structurally
			// untouchable.
			owned := actual.OwnedIPsByIface[an.ID]
			var hasDesired bool
			var stale []int
			for _, ip := range owned {
				switch {
				case n.NetBoxIPID != 0 && ip.ID == n.NetBoxIPID:
					hasDesired = true
				default:
					stale = append(stale, ip.ID)
				}
			}
			if n.NetBoxIPID != 0 && !hasDesired {
				out = append(out, Action{
					Kind: "nic", Op: "assign", Key: nicID,
					NetBoxID: an.ID, ParentNetBoxID: a.ID, IPID: n.NetBoxIPID,
				})
			}
			// Sorted so identical state always produces an identical action
			// list, whatever order the API returned.
			sort.Ints(stale)
			for _, id := range stale {
				out = append(out, Action{
					Kind: "nic", Op: "clear", Key: nicID,
					NetBoxID: an.ID, ParentNetBoxID: a.ID, IPID: id,
				})
			}
		}
	}

	// Deletes are filtered by fingerprint DEFENSIVELY, even though BuildActual
	// already scopes what it admits. Two litevirt clusters can share one NetBox,
	// and a mis-scoped read reaching here must not become a delete of another
	// cluster's inventory. Two independent guards, because this one is
	// irreversible.
	//
	// Identities are sorted so a sweep over identical state yields an identical
	// list; map iteration order would otherwise reshuffle it every time.
	for _, id := range sortedIdentities(actual.VMs) {
		if seenVM[id] || !ownedBy(id, fingerprint) {
			continue
		}
		if replaced[id] {
			// A vm/replace above has taken this removal over, because this
			// object's name is what a create needs. Emitting a delete for it as
			// well would give one object two owners in two phases, and the two
			// gates would then have to keep them in step — one withheld and the
			// other kept is a delete that runs without freeing anything.
			continue
		}
		out = append(out, Action{Kind: "vm", Op: "delete", Key: id, NetBoxID: actual.VMs[id].ID})
	}
	// The NetBox objects a vm/replace is removing. Their interfaces go with them,
	// so the replace owns those removals too — see the loop below.
	replacedObjects := make(map[int]bool, len(replaced))
	for id := range replaced {
		replacedObjects[actual.VMs[id].ID] = true
	}
	for _, id := range sortedIdentities(actual.NICs) {
		if seenNIC[id] || !ownedBy(id, fingerprint) {
			continue
		}
		n := actual.NICs[id]
		if replacedObjects[n.VMID] {
			// A vm/replace ALREADY REMOVES THIS, by cascade. DeleteVM takes
			// every vminterface under it, and the replace runs in the FIRST
			// phase — so by the time nic-delete phase came round this action's
			// target would be gone and it would be asking NetBox to delete an
			// object twice.
			//
			// The inversion is what makes this different from an ordinary VM
			// delete, where the child delete IS wanted: there the parent goes
			// LAST, and detaching children before it is the documented ordering.
			// A replace puts the parent first, so the ordinary ordering does not
			// apply and the cascade is the removal.
			//
			// It is not merely redundant, which is the reason it has to be
			// skipped rather than tolerated. A nic delete carries its OWN,
			// weaker evidence question — the local database's record for
			// (owning VM name, MAC), where the name comes from the NetBox object
			// — and a replaced object is exactly the case where that name can be
			// stale: rename-then-delete leaves NetBox holding the pre-rename
			// name while the local tombstone carries the post-rename one, so the
			// evidence lookup misses and the removal is withheld. A withheld
			// delete escalates to withholding every destructive action in the
			// pass, the proven vm/replace included — which puts the mirror back
			// in the permanent collision stall the replace exists to end, over
			// an object the cascade was going to remove anyway.
			continue
		}
		out = append(out, Action{
			Kind: "nic", Op: "delete", Key: id,
			NetBoxID: n.ID, ParentNetBoxID: n.VMID,
		})
	}
	return out
}

// freeReusedName appends the one removal that frees `name` for the VM about to
// take it, when — and only when — the occupant is provably a superseded
// incarnation of this cluster's own.
//
// ONE SPELLING FOR BOTH CALLERS, which is the point of it being a function. The
// create half and the name-changing-update half need the identical removal under
// the identical proof, and two copies of it is how one of them would come to
// accept an occupant the other refuses. It records `replaced` for the same
// reason the create half always has: one object, one removal, one owner — the
// delete half below skips whatever is in there, so an object cannot be taken
// away by two actions in two phases with two gates deciding independently
// whether to withhold them.
//
// The proof itself is supersededIncarnation's and is not restated here.
func freeReusedName(out []Action, replaced map[string]bool, name string,
	ownedByName map[string][]netbox.VirtualMachine, desiredIDs map[string]bool,
	fingerprint string) []Action {
	occ, proven := supersededIncarnation(name, ownedByName, desiredIDs, fingerprint)
	if !proven {
		return out
	}
	out = append(out, Action{
		Kind: "vm", Op: opReplace, Key: occ.Identity,
		NetBoxID: occ.ID, FreesName: name,
	})
	replaced[occ.Identity] = true
	return out
}

// renameBlockers maps each desired identity whose upsert needs a name to the
// LIVE object of ours still holding it.
//
// The edges of the blocked-by graph, and every clause of what makes an edge is
// load-bearing:
//
//   - THE UPSERT MUST ACTUALLY NEED A NAME. An object already under its desired
//     name is waiting for nothing, whatever else about it differs.
//   - EXACTLY ONE OF OUR OBJECTS HOLDS IT. Zero means the name is free. More
//     than one contradicts NetBox's own uniqueness rule, so the read cannot be
//     trusted to say who holds what, and no edge is drawn on it.
//   - THE HOLDER'S IDENTITY IS IN THE DESIRED SET. That is what makes it a LIVE
//     VM rather than a superseded incarnation: a superseded one is removed by
//     the vm/replace in the first phase, so the upsert behind it is not blocked
//     at all. This is also why a PARTIAL desired read can only lose edges — a
//     missing row means a missing identity means no edge — so it can make a
//     cycle vanish and never invent one.
//   - A FOREIGN NAME DRAWS NO EDGE. Diff emits nothing for such a VM and the
//     collision is reported rather than resolved; a co-tenant's object is not
//     something this mirror can move out of the way.
//
// A HOLDER THAT DRAWS AN EDGE IS ALWAYS ITSELF RENAMING, which is what makes a
// chain finite: desired names are unique (they are the local `vms` primary key),
// so a live holder in the desired set under a name someone else wants is in the
// desired set under a DIFFERENT one.
func renameBlockers(desired []DesiredVM, actual Actual, ownedByName map[string][]netbox.VirtualMachine,
	desiredIDs map[string]bool, fingerprint string) map[string]string {
	out := map[string]string{}
	for _, d := range desired {
		if actual.ForeignVMNames[d.Name] {
			continue
		}
		vmID := netbox.Identity(fingerprint, d.UUID, "")
		if a, ok := actual.VMs[vmID]; ok && a.Name == d.Name {
			continue
		}
		holders := ownedByName[d.Name]
		if len(holders) != 1 {
			continue
		}
		h := holders[0]
		if h.Identity == vmID || !desiredIDs[h.Identity] {
			continue
		}
		out[vmID] = h.Identity
	}
	return out
}

// renameCycleParks picks the ONE identity per cycle whose object is moved to a
// temporary name, breaking the cycle. See opPark for why a permutation needs one
// and why nothing else can supply it.
//
// A functional graph — each node has at most one outgoing edge, because a name is
// held by at most one object — so a cycle is found by walking and no general
// cycle enumeration is needed. Walked from SORTED starts, and the member with the
// lowest identity is the one chosen, so a condition lasting several sweeps parks
// the same object every time instead of moving a different member each pass.
//
// A PARK IS ONLY PLANNED WHEN ITS TEMPORARY NAME IS PROVABLY FREE — of every
// desired name, every name our own objects hold, and every name a co-tenant
// holds. NetBox's rule is per name whoever is writing, so a park onto a taken
// name is the identical 400 it exists to avoid, and planning one anyway would
// trade a stall for a failed sweep. Refusing leaves the cycle exactly as it was,
// which the pass reports (unconvergedRenames).
func renameCycleParks(blockedBy map[string]string, desired []DesiredVM,
	actual Actual, fingerprint string) map[string]bool {
	if len(blockedBy) == 0 {
		return nil
	}
	starts := make([]string, 0, len(blockedBy))
	for id := range blockedBy {
		starts = append(starts, id)
	}
	sort.Strings(starts)

	settled := map[string]bool{}
	out := map[string]bool{}
	for _, start := range starts {
		if settled[start] {
			continue
		}
		// position on the CURRENT walk, so a node met again is told from a node
		// settled by an earlier walk.
		at := map[string]int{}
		var path []string
		node := start
		for {
			if _, onPath := at[node]; onPath {
				// The cycle is the tail of the path from where it re-enters.
				cycle := path[at[node]:]
				if pick := lowestIdentity(cycle); pick != "" {
					out[pick] = true
				}
				break
			}
			if settled[node] {
				// An earlier walk already resolved everything downstream — and
				// if that walk found a cycle, this path leads INTO it and adds
				// nothing.
				break
			}
			at[node] = len(path)
			path = append(path, node)
			next, ok := blockedBy[node]
			if !ok {
				break // a chain's head: unblocked, so it drains on its own
			}
			node = next
		}
		for _, n := range path {
			settled[n] = true
		}
	}
	if len(out) == 0 {
		return nil
	}
	// The temporary-name safety check, last, over every name in play.
	taken := namesInPlay(desired, actual)
	for id := range out {
		if taken[parkedName(id)] {
			delete(out, id)
		}
	}
	return out
}

// lowestIdentity is the smallest identity in a set, or "" for an empty one.
func lowestIdentity(ids []string) string {
	var out string
	for _, id := range ids {
		if out == "" || id < out {
			out = id
		}
	}
	return out
}

// namesInPlay is every VM name this NetBox cluster's namespace currently holds
// or is about to: our own objects', a co-tenant's, and every desired name.
//
// All three, because NetBox's one-name-per-cluster rule does not care who holds
// the name or whether the holder has landed yet — a temporary name that collides
// with any of them is refused exactly as the original collision was.
func namesInPlay(desired []DesiredVM, actual Actual) map[string]bool {
	out := make(map[string]bool, len(desired)+len(actual.VMs)+len(actual.ForeignVMNames))
	for _, d := range desired {
		out[d.Name] = true
	}
	for _, v := range actual.VMs {
		out[v.Name] = true
	}
	for n := range actual.ForeignVMNames {
		out[n] = true
	}
	return out
}

// unconvergedRenames is the desired VM names this pass deliberately left
// unwritten because another LIVE VM of ours still holds the name, sorted.
//
// Read off the ACTION LIST rather than counted inside the loop, the same way
// withheldReplacements is: the loop has three reasons to emit no upsert for a VM,
// and asking the list what actually went is one answer instead of three places to
// keep in step.
//
// A VM belongs here when this pass carries no create and no update for its
// identity and NetBox does not already hold it under its desired name. BOTH
// deferrals are covered, and the second is easy to miss: a blocked CREATE has no
// object at all, so a predicate that only compared names against an existing
// object would report the parked and blocked renames and silently pass a
// suppressed create as converged.
//
// A PARK COUNTS AS UNCONVERGED. It writes — to a temporary name — which is
// progress and not the desired state, so the pass must not stamp the success
// gauge on the strength of having made it.
//
// A FOREIGN-NAME COLLISION IS EXCLUDED. Diff emits nothing for those VMs either,
// but the cause is another installation's object and collidingNames already
// reports it with that cause; naming them here as well would tell an operator
// their own live VM is in the way.
func unconvergedRenames(desired []DesiredVM, actual Actual, actions []Action, fingerprint string) []string {
	writes := map[string]bool{}
	for _, a := range actions {
		if a.Kind == "vm" && (a.Op == "create" || a.Op == "update") {
			writes[a.Key] = true
		}
	}
	var out []string
	for _, d := range desired {
		id := netbox.Identity(fingerprint, d.UUID, "")
		if writes[id] || actual.ForeignVMNames[d.Name] {
			continue
		}
		if a, ok := actual.VMs[id]; ok && a.Name == d.Name {
			continue
		}
		out = append(out, d.Name)
	}
	sort.Strings(out)
	return out
}

// ownedVMsByName indexes this cluster's OWN objects by NetBox name.
//
// Only actual.VMs, which BuildActual has already filtered to our fingerprint —
// a foreign object's name lives in ForeignVMNames and is a different answer
// entirely (nothing may be replaced there; see Diff's earlier branch).
//
// A slice per name, not one object. NetBox enforces one VM name per cluster, so
// a second entry means the read is not what this code believes it to be, and
// supersededIncarnation refuses on it rather than picking one.
func ownedVMsByName(actual Actual) map[string][]netbox.VirtualMachine {
	out := make(map[string][]netbox.VirtualMachine, len(actual.VMs))
	for _, v := range actual.VMs {
		out[v.Name] = append(out[v.Name], v)
	}
	return out
}

// supersededIncarnation resolves the one object a create may replace, or reports
// that there is none.
//
// THE PROOF, in full, and every clause of it is load-bearing:
//
//   - EXACTLY ONE of our objects holds the name. Zero means the name is free and
//     the create needs no help. More than one contradicts NetBox's own
//     uniqueness rule, so the read cannot be trusted to say which is superseded.
//   - ITS IDENTITY IS OURS. Re-tested here even though actual.VMs is already
//     filtered, because this is the irreversible direction and the delete half
//     of Diff takes its fingerprint guard twice for the same reason. An object
//     under another installation's fingerprint is untouchable at any cost: the
//     collision it causes is reported and lived with, never resolved by
//     deleting somebody else's VM.
//   - ITS IDENTITY IS NOT IN THE DESIRED SET. This is what makes it SUPERSEDED
//     rather than merely in the way. An identity in the desired set is a LIVE
//     VM of this cluster's own — a rename in flight, say — and removing it to
//     free a name would destroy a mirrored VM to mirror another.
//
// Nothing here consults the reason the name is taken. The proof is about the
// OCCUPANT's identity, which is a fact this sweep has read on both sides, rather
// than about an error string NetBox returned.
func supersededIncarnation(name string, ownedByName map[string][]netbox.VirtualMachine,
	desiredIDs map[string]bool, fingerprint string) (netbox.VirtualMachine, bool) {
	holders := ownedByName[name]
	if len(holders) != 1 {
		return netbox.VirtualMachine{}, false
	}
	occ := holders[0]
	if !ownedBy(occ.Identity, fingerprint) {
		return netbox.VirtualMachine{}, false
	}
	if desiredIDs[occ.Identity] {
		return netbox.VirtualMachine{}, false
	}
	return occ, true
}

// collidingNames returns the desired VM names this NetBox cluster already holds
// under a foreign identity, sorted.
//
// Diff acts on the same predicate and needs no list; the sweep needs the list,
// to name the VMs in the warning and to report the pass as unconverged. One
// predicate, read twice, so the two cannot disagree about what a collision is.
func collidingNames(desired []DesiredVM, actual Actual) []string {
	var out []string
	for _, d := range desired {
		if actual.ForeignVMNames[d.Name] {
			out = append(out, d.Name)
		}
	}
	sort.Strings(out)
	return out
}

// sortedIdentities returns a map's identity keys in a stable order.
func sortedIdentities[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ownedBy reports whether an identity belongs to this cluster.
func ownedBy(identity, fingerprint string) bool {
	parts := strings.SplitN(identity, ":", 3)
	return len(parts) >= 2 && parts[0] == "lv" && parts[1] == fingerprint
}

// vmDiffers compares every mirrored VM field.
//
// DeviceID is included so a MIGRATION converges: the address and interface stay
// put, but the host link must follow the VM. Name is included because a rename
// keeps the object — identity-keying guarantees that — so nothing else would
// ever carry the new name across. Every field here must be populated by
// vmJSON.toVM, or it differs on every sweep.
// VCPUs is compared NUMERICALLY, against NetBox's decimal rather than against an
// int. litevirt's desired value is a whole count and NetBox returns it as `2.0`,
// so an identity comparison between two different types would either not compile
// or, if the decode had rounded, hide a genuinely fractional NetBox value: 2.5
// would round to 2, compare equal to a desired 2, and never be patched back.
// Widened, `2.0 == 2` agrees and emits no PATCH, and 2.5 differs and converges
// to the integer.
//
// Disk is compared in ONE unit on both sides — megabytes, as NetBox holds it —
// so a value that is already correct cannot produce a PATCH. Comparing a
// desired gibibyte figure against an actual megabyte one differs on every sweep
// for every VM, which is write-on-change defeated at the only place it is
// decided.
func vmDiffers(d DesiredVM, a netbox.VirtualMachine) bool {
	return d.Name != a.Name ||
		netbox.VCPUs(d.VCPUs) != a.VCPUs ||
		d.MemoryMB != a.MemoryMB ||
		d.DiskMB != a.DiskMB ||
		d.Status != a.Status ||
		d.DeviceID != a.DeviceID
}

// nicDiffers compares the mirrored interface fields. The MAC comparison is
// case-insensitive because NetBox echoes it upper-cased.
func nicDiffers(d DesiredNIC, a netbox.VMInterface) bool {
	return d.Name != a.Name || !strings.EqualFold(d.MAC, a.MAC)
}

// Phase orders actions so a parent never runs after its child, and so no
// assignment can be undone by a concurrent clear.
//
// The applier uses a worker pool, so without phases: a NIC create can run before
// its VM exists, and a VM delete can cascade-delete an interface while a
// concurrent DeleteInterface gets a 404.
//
// CLEARS GET THEIR OWN PHASE, strictly before every assignment. Consider an
// address moved from NIC A to NIC B: A emits clear 41 and B emits assign 41. In
// one shared phase the pool can run the assign first, and the clear then
// detaches the address that was just correctly attached — leaving B unassigned
// until some later sweep. Sorting the action list makes it deterministic; it
// does not order EXECUTION. Only a phase boundary does.
//
// Within a phase, actions are independent and may run in parallel.
// THE FIRST PHASE IS THE ONLY ONE AHEAD OF THE UPSERTS, and it is there because
// neither a create nor a rename can use a name another object still holds. It
// admits exactly two action shapes, and they are the two ways a name is freed:
// vm/replace, whose target is proven twice over to be a superseded incarnation
// of this cluster's own, and vm/park, which moves a LIVE object of ours to a
// temporary name to break a rename cycle. Every delete other than the replace
// stays in the last two phases where the cascade and the address-release
// ordering need it.
//
// The two cannot contend for one name: a replace targets an occupant whose
// identity is NOT in the desired set and a park one whose identity IS, so for
// any given name at most one of them is planned.
const (
	PhaseVMSupersede = 0 // free a reused name: replace a superseded incarnation, or park a live one
	PhaseVMUpsert    = 1 // parents first
	PhaseIPClear     = 2 // release addresses before anyone claims them
	PhaseNICUpsert   = 3 // create/update interfaces and assign addresses
	PhaseNICDelete   = 4 // detach children before their parent goes
	PhaseVMDelete    = 5 // last; it cascades
	phaseCount       = 6
)

// Phase reports which phase one action belongs to.
func Phase(a Action) int {
	switch {
	case a.Kind == "vm" && (a.Op == opReplace || a.Op == opPark):
		return PhaseVMSupersede
	case a.Kind == "vm" && (a.Op == "create" || a.Op == "update"):
		return PhaseVMUpsert
	case a.Kind == "nic" && a.Op == "clear":
		return PhaseIPClear
	case a.Kind == "nic" && a.Op != "delete":
		return PhaseNICUpsert
	case a.Kind == "nic" && a.Op == "delete":
		return PhaseNICDelete
	default:
		// Everything left is a VM delete, and anything unrecognised lands here
		// too — the last phase is the only bucket where an action nobody
		// planned for cannot run ahead of something that depends on it.
		return PhaseVMDelete
	}
}

// Phases groups actions into dependency-ordered buckets.
func Phases(actions []Action) [][]Action {
	out := make([][]Action, phaseCount)
	for _, a := range actions {
		p := Phase(a)
		out[p] = append(out[p], a)
	}
	return out
}
