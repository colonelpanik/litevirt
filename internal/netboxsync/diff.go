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
	Op       string // "create" | "update" | "delete" | "assign" | "clear"
	Key      string // identity
	NetBoxID int    // 0 for create; the target object for update, delete, assign, clear

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

	for _, d := range desired {
		vmID := netbox.Identity(fingerprint, d.UUID, "")
		seenVM[vmID] = true

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
		if !ok {
			out = append(out, Action{Kind: "vm", Op: "create", Key: vmID})
		} else if vmDiffers(d, a) {
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
		out = append(out, Action{Kind: "vm", Op: "delete", Key: id, NetBoxID: actual.VMs[id].ID})
	}
	for _, id := range sortedIdentities(actual.NICs) {
		if seenNIC[id] || !ownedBy(id, fingerprint) {
			continue
		}
		n := actual.NICs[id]
		out = append(out, Action{
			Kind: "nic", Op: "delete", Key: id,
			NetBoxID: n.ID, ParentNetBoxID: n.VMID,
		})
	}
	return out
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
const (
	PhaseVMUpsert  = 0 // parents first
	PhaseIPClear   = 1 // release addresses before anyone claims them
	PhaseNICUpsert = 2 // create/update interfaces and assign addresses
	PhaseNICDelete = 3 // detach children before their parent goes
	PhaseVMDelete  = 4 // last; it cascades
	phaseCount     = 5
)

// Phase reports which phase one action belongs to.
func Phase(a Action) int {
	switch {
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
