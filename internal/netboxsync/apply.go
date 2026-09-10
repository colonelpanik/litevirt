package netboxsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// The two identity-map kinds, and the NetBox object each maps to. They are
// constants because "vm" and "nic" identities share a key space — a VM identity
// is its NIC identity with an empty MAC — so a mistyped kind would silently read
// or tombstone the wrong row.
const (
	kindVM  = "vm"
	kindNIC = "nic"

	netboxKindVM  = "virtual_machine"
	netboxKindNIC = "vminterface"
)

// workers bounds concurrency against the NetBox API within one batch.
//
// Parallelism is safe INSIDE a batch only because Phases has already separated
// the dependent work: a batch never holds a NIC create and the VM it hangs off,
// nor a clear and the assign that reclaims the same address.
const workers = 4

// netboxWriter is the NetBox surface the reconciler drives.
//
// It embeds ActualLister rather than leaving the reads on a separate value, so
// the writes and the collection path cannot be satisfied by two different fakes
// that drift apart — Reconciler.actualState reads through this same client.
type netboxWriter interface {
	ActualLister

	FindVMByIdentity(ctx context.Context, identity string) ([]netbox.VirtualMachine, error)
	CreateVM(ctx context.Context, vm netbox.VirtualMachine) (netbox.VirtualMachine, error)
	UpdateVM(ctx context.Context, id int, vm netbox.VirtualMachine) error
	DeleteVM(ctx context.Context, id int) error

	FindInterfaceByIdentity(ctx context.Context, identity string) ([]netbox.VMInterface, error)
	CreateInterface(ctx context.Context, i netbox.VMInterface) (netbox.VMInterface, error)
	UpdateInterface(ctx context.Context, id int, i netbox.VMInterface) error
	DeleteInterface(ctx context.Context, id int) error

	AssignIPToInterface(ctx context.Context, ipID, ifaceID int) error
	ClearIPAssignment(ctx context.Context, ipID int) error

	FindDeviceByName(ctx context.Context, name string) (int, error)

	// The cluster every mirrored VM hangs off, resolved once per sweep. Both
	// halves are here because a cluster cannot be created without its type, and
	// NetBox does not create one implicitly.
	EnsureClusterType(ctx context.Context, name string) (int, error)
	EnsureCluster(ctx context.Context, name string, typeID int) (int, error)
}

// The operation vocabulary of litevirt_netbox_mirror_objects_total, in the PAST
// tense on purpose: they name what the mirror actually wrote to NetBox, not what
// the diff asked for. An adopted object satisfies a vm/create action without any
// write, and a delete of an object already gone writes nothing either — neither
// is counted, because the counter's job is to tell a converged mirror apart from
// one that is churning.
const (
	opCreated = "created"
	opUpdated = "updated"
	opDeleted = "deleted"
)

// The sweep-result vocabulary of litevirt_netbox_mirror_sweeps_total.
const (
	sweepOK    = "ok"
	sweepError = "error"
)

// mirrorMetrics is the counter sink the mirror emits into. An interface so the
// package does not import internal/metrics — whose counters are process-global
// Prometheus state a test cannot assert on.
type mirrorMetrics interface {
	// IncDuplicateObject counts one NetBox object found duplicated for a single
	// litevirt identity, and deleted by the sweep.
	IncDuplicateObject()
	// IncMirrorObject counts one NetBox object this mirror WROTE. kind is the
	// NetBox object kind (netboxKindVM / netboxKindNIC), op one of the three
	// above. Both vocabularies are closed: they become Prometheus labels.
	IncMirrorObject(kind, op string)
	// IncMirrorSweep counts one sweep that ran to a conclusion, ok or error. A
	// pass that never took the lease is neither — see SyncOnce.
	IncMirrorSweep(result string)
	// SetMirrorLastSuccess records when a sweep last SUCCEEDED. It is the
	// staleness signal an operator alerts on ("the mirror has not converged in
	// N minutes"), so only a sweep that genuinely reconciled may advance it.
	SetMirrorLastSuccess(t time.Time)
}

// noopMetrics is the sink used when none is wired. Metrics must never be a
// reason the mirror panics.
type noopMetrics struct{}

func (noopMetrics) IncDuplicateObject()            {}
func (noopMetrics) IncMirrorObject(_, _ string)    {}
func (noopMetrics) IncMirrorSweep(string)          {}
func (noopMetrics) SetMirrorLastSuccess(time.Time) {}

// Reconciler mirrors litevirt inventory into NetBox.
//
// It is deliberately small: the sweep loop, the leader lease and the desired /
// actual collection hang off this same value, so every NetBox call the mirror
// makes goes through one client and one identity map.
type Reconciler struct {
	nb      netboxWriter
	db      *corrosion.Client
	metrics mirrorMetrics

	// clusterName overrides the NetBox cluster name (config
	// `netbox.cluster_name`); empty means the local cluster name. See
	// Options.ClusterName.
	clusterName string

	// clusterID is the NetBox cluster every mirrored VM belongs to, resolved
	// once per sweep before any action runs. It is not on Action because every
	// action in a sweep shares it.
	clusterID int

	// interval is the sweep cadence Run ticks on; pollInterval is the faster
	// cadence on which the node already holding the lease looks for queued work.
	// Only the sweep acquires — see Run.
	interval     time.Duration
	pollInterval time.Duration
	// sweepPhase delays the first sweep tick, holding this loop's schedule away
	// from the maintenance loop it shares a per-node gate with. See
	// Options.SweepPhase.
	sweepPhase time.Duration

	// acquireLease takes or renews the leader lease; holdsLease is the READ
	// alone, re-run before every write batch.
	//
	// They are function values rather than SQL of their own because the lease
	// they gate on is the ORPHAN SWEEPER's, `leader_election` key "netbox",
	// which lives in internal/grpcapi. A second key would let the sweeper and
	// the mirror each believe it leads the cluster, and a copy of the same SQL
	// under the same key is one edit away from becoming a second key.
	//
	// Both are nil-safe in the FAIL-CLOSED direction: an unwired reconciler
	// holds no lease and writes nothing (see holdsLeader).
	acquireLease func(context.Context) bool
	holdsLease   func(context.Context) bool

	// latched is the cluster-wide capability predicate, re-read on every pass.
	// See Options.Latched.
	latched func(context.Context) bool

	// inventorySnapshot samples the inventory a pass's conclusions are read
	// from and hands back the corroboration BOUND to that exact sample, for the
	// one removal record that cannot say so by itself. Nil never corroborates.
	// See Options.InventorySnapshot and vmRemovalProven.
	inventorySnapshot func(context.Context) InventoryProof

	// exclusive is the caller's INTRA-NODE critical section around one pass.
	// Nil runs the pass directly. See Options.Exclusive.
	exclusive func(context.Context, func(context.Context) error) error
}

// sink returns the metrics sink, never nil.
func (r *Reconciler) sink() mirrorMetrics {
	if r.metrics == nil {
		return noopMetrics{}
	}
	return r.metrics
}

// desiredIndex resolves an Action.Key to what should exist.
//
// BOTH maps are needed. A NIC action's Key is a NIC identity, which the VM index
// cannot resolve, and a NIC create also needs its parent VM's identity for the
// netbox_objects lookup — which the NIC alone does not carry.
type desiredIndex struct {
	VMs  map[string]DesiredVM  // keyed by VM identity
	NICs map[string]desiredNIC // keyed by NIC identity
}

// desiredNIC is one NIC plus the parent it must be attached to.
type desiredNIC struct {
	NIC    DesiredNIC
	VMKey  string // parent VM identity, for the netbox_objects lookup
	VMUUID string // parent VM UUID, for rebuilding this NIC's own identity
}

// indexDesired keys the desired set by IDENTITY, the same key Action.Key and the
// netbox_objects litevirt_key column carry. A name-keyed map would not resolve
// against identity-keyed actions at all.
func indexDesired(desired []DesiredVM, fingerprint string) desiredIndex {
	idx := desiredIndex{
		VMs:  make(map[string]DesiredVM, len(desired)),
		NICs: map[string]desiredNIC{},
	}
	for _, d := range desired {
		vmKey := netbox.Identity(fingerprint, d.UUID, "")
		idx.VMs[vmKey] = d
		for _, n := range d.NICs {
			idx.NICs[netbox.Identity(fingerprint, d.UUID, n.MAC)] = desiredNIC{
				NIC: n, VMKey: vmKey, VMUUID: d.UUID,
			}
		}
	}
	return idx
}

// apply executes one batch of actions.
//
// The batch runs on a bounded worker pool. Actions within a batch are
// INDEPENDENT — Phases guarantees that — so one failing action does not skip the
// rest; the first error is returned once the batch has drained, and the caller
// abandons the sweep rather than continuing into a phase whose predecessor did
// not fully converge.
func (r *Reconciler) apply(ctx context.Context, actions []Action, idx desiredIndex, fingerprint string) error {
	if len(actions) == 0 {
		return nil
	}
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		firstErr error
	)
	work := make(chan Action)
	for range min(workers, len(actions)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range work {
				if err := r.applyOne(ctx, a, idx, fingerprint); err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
				}
			}
		}()
	}
	for _, a := range actions {
		work <- a
	}
	close(work)
	wg.Wait()
	return firstErr
}

// applyOne dispatches one action.
//
// An unrecognised action is an ERROR rather than a skip: a silently dropped op
// is a mirror that never converges and never says why.
func (r *Reconciler) applyOne(ctx context.Context, a Action, idx desiredIndex, fingerprint string) error {
	switch {
	case a.Kind == kindVM && a.Op == opReplace:
		return r.replaceSuperseded(ctx, a, idx, fingerprint)
	case a.Kind == kindVM && a.Op == opPark:
		return r.parkForRenameCycle(ctx, a, idx, fingerprint)
	case a.Kind == kindVM && a.Op == "create":
		return r.createVM(ctx, a, idx, fingerprint)
	case a.Kind == kindVM && a.Op == "update":
		return r.updateVM(ctx, a, idx)
	case a.Kind == kindNIC && a.Op == "create":
		return r.createNIC(ctx, a, idx, fingerprint)
	case a.Kind == kindNIC && a.Op == "update":
		return r.updateNIC(ctx, a, idx)
	case a.Kind == kindNIC && a.Op == "assign":
		// One address per action, so the set case needs no handling here: Diff
		// emits one assign for the desired address plus one clear per stale
		// litevirt-owned address.
		return r.nb.AssignIPToInterface(ctx, a.IPID, a.NetBoxID)
	case a.Kind == kindNIC && a.Op == "clear":
		// IPID is only ever a litevirt-owned address — BuildActual admits no
		// other into the set Diff clears from — so this branch cannot detach an
		// operator's address even by mistake.
		return r.nb.ClearIPAssignment(ctx, a.IPID)
	case a.Op == "delete":
		return r.deleteObject(ctx, a)
	default:
		return fmt.Errorf("netboxsync: unhandled action %s/%s for %s", a.Kind, a.Op, a.Key)
	}
}

// createVM creates or ADOPTS one virtual machine.
//
// It creates the VM ONLY — never its NICs. Phase 2 owns every interface and Diff
// already emits a nic/create for each one; creating them here too would double
// the work and split interface ownership across two phases, so a bug in either
// path would be masked by the other.
func (r *Reconciler) createVM(ctx context.Context, a Action, idx desiredIndex, fingerprint string) error {
	d, ok := idx.VMs[a.Key]
	if !ok {
		return fmt.Errorf("netboxsync: vm/create %s has no desired VM", a.Key)
	}
	identity := netbox.Identity(fingerprint, d.UUID, "")

	// SEARCH BEFORE CREATE. NetBox has no idempotency key, so a timeout after
	// creation but before the identity-map write leaves an object nothing points
	// at; a create that did not look first would duplicate it on every retry.
	found, err := r.nb.FindVMByIdentity(ctx, identity)
	if err != nil {
		return fmt.Errorf("netboxsync: search VM %s: %w", identity, err)
	}
	ids := make([]int, 0, len(found))
	for _, v := range found {
		ids = append(ids, v.ID)
	}
	id, err := r.keepOldest(ctx, ids, r.nb.DeleteVM)
	if err != nil {
		return fmt.Errorf("netboxsync: de-duplicate VM %s: %w", identity, err)
	}
	if id == 0 {
		vm, err := r.nb.CreateVM(ctx, netbox.VirtualMachine{
			Name:      d.Name,
			ClusterID: r.clusterID,
			DeviceID:  r.deviceID(ctx, d),
			VCPUs:     netbox.VCPUs(d.VCPUs),
			MemoryMB:  d.MemoryMB,
			DiskMB:    d.DiskMB,
			Status:    d.Status,
			Identity:  identity,
		})
		if err != nil {
			return fmt.Errorf("netboxsync: create VM %s: %w", identity, err)
		}
		// Counted on the WRITE, not on the action: the adopt branch above
		// reaches this same recordRef having created nothing.
		r.sink().IncMirrorObject(netboxKindVM, opCreated)
		id = vm.ID
	}
	return r.recordRef(ctx, kindVM, identity, netboxKindVM, id)
}

// replaceSuperseded removes the superseded incarnation holding a name a create
// needs, then retires its mapping. See opReplace for what it is for and why one
// removal — and only this one — runs ahead of the creates.
//
// IT RE-PROVES BOTH REFUSALS BEFORE IT TOUCHES ANYTHING, from the applier's own
// desired index rather than from the fact that Diff emitted the action. Same
// two-independent-guards rule the delete path follows, and for the same reason:
// this is the irreversible direction, and a proof made in one function and acted
// on in another is one refactor away from being a proof of nothing.
//
//   - AN IDENTITY IN THE DESIRED SET IS A LIVE VM, and freeing a name may never
//     remove one. A create that cannot be made is a stalled mirror, which the
//     next sweep can still fix; a mirrored VM deleted out of NetBox is gone. So
//     this refuses and the sweep fails LOUDLY rather than proceeding.
//   - A FOREIGN FINGERPRINT is another installation's object, or an operator's.
//     Diff's foreign-name branch emits nothing at all for such a VM, so an
//     action carrying one means something upstream is wrong — and the answer to
//     that is to stop, never to delete somebody else's inventory.
//
// The mapping is retired HERE because this action owns the removal: Diff emits no
// separate delete for a replaced identity, so nothing else would prune the row.
// A NetBox object already gone (404) still reaches that retirement, exactly as
// deleteObject does, because a stranded mapping is how a re-created object comes
// to adopt a dead id.
func (r *Reconciler) replaceSuperseded(ctx context.Context, a Action, idx desiredIndex, fingerprint string) error {
	if _, live := idx.VMs[a.Key]; live {
		return fmt.Errorf(
			"netboxsync: vm/replace %s would free the name %q, but that identity IS in this "+
				"sweep's desired set — it is a live VM of this cluster, not a superseded "+
				"incarnation, and freeing a name may never remove one",
			a.Key, a.FreesName)
	}
	if !ownedBy(a.Key, fingerprint) {
		return fmt.Errorf(
			"netboxsync: vm/replace %s does not carry this cluster's identity fingerprint — "+
				"another installation's object, or an operator's, and not this mirror's to "+
				"remove at any cost to free the name %q",
			a.Key, a.FreesName)
	}
	if a.NetBoxID == 0 {
		return fmt.Errorf("netboxsync: vm/replace %s carries no NetBox object to remove", a.Key)
	}
	err := r.nb.DeleteVM(ctx, a.NetBoxID)
	switch {
	case err == nil:
		r.sink().IncMirrorObject(netboxKindVM, opDeleted)
	case isNotFound(err):
		// Already gone IS the end state this action wants, so it falls through
		// to the mapping retirement below.
		slog.Info("netbox mirror: the superseded incarnation was already absent; retiring its mapping",
			"identity", a.Key, "netbox_id", a.NetBoxID)
	default:
		return fmt.Errorf(
			"netboxsync: replace the superseded incarnation %s (netbox id %d) holding the name "+
				"%q: %w", a.Key, a.NetBoxID, a.FreesName, err)
	}
	if err := corrosion.DeleteObjectRef(ctx, r.db, kindVM, a.Key); err != nil {
		return fmt.Errorf("netboxsync: retire mapping %s/%s: %w", kindVM, a.Key, err)
	}
	slog.Info("netbox mirror: replaced the superseded incarnation of a reused VM name",
		"identity", a.Key, "netbox_id", a.NetBoxID, "name", a.FreesName)
	return nil
}

// parkForRenameCycle moves ONE object of a rename cycle onto a temporary name
// this mirror derives, so the cycle becomes a chain and converges. See opPark for
// why a permutation of names has no other way out and why nothing is deleted.
//
// IT RE-PROVES ITS PREMISE BEFORE IT WRITES, from the applier's own desired index
// rather than from the fact that Diff emitted the action — the same
// two-independent-guards rule replaceSuperseded follows, and the guards are the
// EXACT INVERSE of that one's:
//
//   - THE IDENTITY MUST BE IN THE DESIRED SET. A park is only ever applied to a
//     live VM of this cluster's own, because its whole justification is that the
//     object may not be removed. An identity absent from desired is a superseded
//     incarnation, and the answer to one of those is the replace, which deletes
//     it — so parking one would leave a stray object under a temporary name that
//     no later sweep has a reason to touch.
//   - THE FINGERPRINT MUST BE OURS. Another installation's object is not this
//     mirror's to rename any more than it is to delete.
//
// It writes the DESIRED fields with the temporary name, not a name-only patch:
// the object's other drift is converged in the same request, so the pass that
// parks it leaves nothing but the name outstanding. The mapping is re-recorded
// for the reason updateVM re-records it — a lost netbox_objects row heals on the
// next write rather than only on a delete and re-create.
func (r *Reconciler) parkForRenameCycle(ctx context.Context, a Action, idx desiredIndex, fingerprint string) error {
	d, live := idx.VMs[a.Key]
	if !live {
		return fmt.Errorf(
			"netboxsync: vm/park %s would move an object off the name %q, but that identity is "+
				"NOT in this sweep's desired set — a park is only ever applied to a live VM of "+
				"this cluster, and a superseded incarnation is the replace's to remove",
			a.Key, a.FreesName)
	}
	if !ownedBy(a.Key, fingerprint) {
		return fmt.Errorf(
			"netboxsync: vm/park %s does not carry this cluster's identity fingerprint — "+
				"another installation's object, or an operator's, and not this mirror's to "+
				"rename to free the name %q",
			a.Key, a.FreesName)
	}
	if a.NetBoxID == 0 {
		return fmt.Errorf("netboxsync: vm/park %s carries no NetBox object to move", a.Key)
	}
	// The temporary name is DERIVED from the incarnation uuid, so an identity
	// that carries none would park every such object onto one shared name — a
	// collision manufactured by the thing that exists to avoid one. Diff cannot
	// produce that (desiredState skips a VM with no uuid), which is exactly why
	// it is checked here rather than trusted.
	if netbox.IdentityVMUUID(a.Key) == "" {
		return fmt.Errorf(
			"netboxsync: vm/park %s carries no incarnation uuid, so no temporary name can be "+
				"derived for it", a.Key)
	}
	temp := parkedName(a.Key)
	if err := r.nb.UpdateVM(ctx, a.NetBoxID, netbox.VirtualMachine{
		Name:      temp,
		ClusterID: r.clusterID,
		DeviceID:  d.DeviceID,
		VCPUs:     netbox.VCPUs(d.VCPUs),
		MemoryMB:  d.MemoryMB,
		DiskMB:    d.DiskMB,
		Status:    d.Status,
		Identity:  a.Key,
	}); err != nil {
		return fmt.Errorf("netboxsync: park VM %d onto %q to free the name %q: %w",
			a.NetBoxID, temp, a.FreesName, err)
	}
	r.sink().IncMirrorObject(netboxKindVM, opUpdated)
	slog.Info("netbox mirror: parked one object of a rename cycle on a temporary name, which "+
		"frees the name the rename behind it needs; the next sweep writes this object's own "+
		"desired name",
		"identity", a.Key, "netbox_id", a.NetBoxID, "freed_name", a.FreesName,
		"temporary_name", temp, "desired_name", d.Name)
	return r.recordRef(ctx, kindVM, a.Key, netboxKindVM, a.NetBoxID)
}

// updateVM patches the object the diff resolved.
//
// It re-records the mapping, so a VM whose netbox_objects row was lost heals on
// the next field change rather than only on a delete and re-create.
func (r *Reconciler) updateVM(ctx context.Context, a Action, idx desiredIndex) error {
	d, ok := idx.VMs[a.Key]
	if !ok {
		return fmt.Errorf("netboxsync: vm/update %s has no desired VM", a.Key)
	}
	if err := r.nb.UpdateVM(ctx, a.NetBoxID, netbox.VirtualMachine{
		Name:      d.Name,
		ClusterID: r.clusterID,
		// VERBATIM, never re-resolved: the diff compared THIS id, so a second
		// lookup here could write back the very link the diff decided to clear,
		// and the next sweep would diff it again — forever.
		DeviceID: d.DeviceID,
		VCPUs:    netbox.VCPUs(d.VCPUs),
		MemoryMB: d.MemoryMB,
		DiskMB:   d.DiskMB,
		Status:   d.Status,
		Identity: a.Key,
	}); err != nil {
		return fmt.Errorf("netboxsync: update VM %d: %w", a.NetBoxID, err)
	}
	r.sink().IncMirrorObject(netboxKindVM, opUpdated)
	return r.recordRef(ctx, kindVM, a.Key, netboxKindVM, a.NetBoxID)
}

// createNIC creates or ADOPTS one interface, then assigns its address.
//
// The assignment is part of the create because Diff emits no separate assign for
// a NIC that does not yet exist. Without it a newly created NIC stays unassigned
// until some later sweep notices the drift — a VM would boot holding an address
// NetBox does not show as assigned to it.
func (r *Reconciler) createNIC(ctx context.Context, a Action, idx desiredIndex, fingerprint string) error {
	dn, ok := idx.NICs[a.Key]
	if !ok {
		return fmt.Errorf("netboxsync: nic/create %s has no desired NIC", a.Key)
	}
	identity := netbox.Identity(fingerprint, dn.VMUUID, dn.NIC.MAC)

	parent, err := r.parentVMID(ctx, a, dn)
	if err != nil {
		return err
	}
	if parent == 0 {
		// Refused rather than posted with virtual_machine 0: NetBox would reject
		// that anyway, with an error that says nothing about why.
		return fmt.Errorf("netboxsync: nic/create %s: no NetBox id for parent VM %s", identity, dn.VMKey)
	}

	found, err := r.nb.FindInterfaceByIdentity(ctx, identity)
	if err != nil {
		return fmt.Errorf("netboxsync: search interface %s: %w", identity, err)
	}
	ids := make([]int, 0, len(found))
	for _, i := range found {
		ids = append(ids, i.ID)
	}
	id, err := r.keepOldest(ctx, ids, r.nb.DeleteInterface)
	if err != nil {
		return fmt.Errorf("netboxsync: de-duplicate interface %s: %w", identity, err)
	}
	if id == 0 {
		iface, err := r.nb.CreateInterface(ctx, netbox.VMInterface{
			VMID:     parent,
			Name:     dn.NIC.Name,
			MAC:      dn.NIC.MAC,
			Identity: identity,
		})
		if err != nil {
			return fmt.Errorf("netboxsync: create interface %s: %w", identity, err)
		}
		// Counted BEFORE the MAC echo check below, which refuses an object
		// NetBox has nonetheless created. The counter reports what was written,
		// and an interface abandoned right after a successful POST is still an
		// interface this mirror put there.
		r.sink().IncMirrorObject(netboxKindNIC, opCreated)
		// FAIL CLOSED on the echoed MAC.
		//
		// DRF silently IGNORES a write field its serializer does not know, so a
		// NetBox that has moved MACs to their own object model accepts
		// `mac_address`, drops it, and returns 201. Every interface would then be
		// created MAC-less while this code believed otherwise — and the MAC is
		// what the identity is derived from, so nothing downstream could notice.
		// Refusing here is the only place the discrepancy is visible.
		//
		// Compared case-INSENSITIVELY: NetBox echoes a MAC upper-cased, and a
		// case-sensitive check would refuse every create against a real server.
		if !strings.EqualFold(iface.MAC, dn.NIC.MAC) {
			return fmt.Errorf(
				"netboxsync: create interface %s: NetBox echoed mac_address %q for the %q it was sent — "+
					"this NetBox does not accept a MAC on a vminterface write",
				identity, iface.MAC, dn.NIC.MAC)
		}
		id = iface.ID
	}
	if err := r.recordRef(ctx, kindNIC, identity, netboxKindNIC, id); err != nil {
		return err
	}
	if dn.NIC.NetBoxIPID == 0 {
		return nil
	}
	if err := r.nb.AssignIPToInterface(ctx, dn.NIC.NetBoxIPID, id); err != nil {
		return fmt.Errorf("netboxsync: assign address %d to interface %d: %w", dn.NIC.NetBoxIPID, id, err)
	}
	return nil
}

// updateNIC patches the interface the diff resolved. The identity is not
// rewritten: it is derived from the MAC, so an interface whose MAC changed is a
// different object, not an update.
func (r *Reconciler) updateNIC(ctx context.Context, a Action, idx desiredIndex) error {
	dn, ok := idx.NICs[a.Key]
	if !ok {
		return fmt.Errorf("netboxsync: nic/update %s has no desired NIC", a.Key)
	}
	// The parent link is deliberately NOT passed: UpdateInterface never sends
	// virtual_machine, so an assignment here would be silently dropped while
	// reading like a re-parent. A NIC that moved to another VM has a different
	// identity anyway — that is a create plus a delete, not an update.
	if err := r.nb.UpdateInterface(ctx, a.NetBoxID, netbox.VMInterface{
		ID:       a.NetBoxID,
		Name:     dn.NIC.Name,
		MAC:      dn.NIC.MAC,
		Identity: a.Key,
	}); err != nil {
		return fmt.Errorf("netboxsync: update interface %d: %w", a.NetBoxID, err)
	}
	r.sink().IncMirrorObject(netboxKindNIC, opUpdated)
	return r.recordRef(ctx, kindNIC, a.Key, netboxKindNIC, a.NetBoxID)
}

// deleteObject removes the object the ACTION names, then tombstones its
// mapping.
//
// The id comes from the action rather than a fresh lookup by identity, so the
// delete targets exactly the object the diff decided on. A second round trip
// could observe different state — and this is the irreversible direction.
func (r *Reconciler) deleteObject(ctx context.Context, a Action) error {
	var kind, netboxKind string
	var err error
	switch a.Kind {
	case kindVM:
		kind, netboxKind, err = kindVM, netboxKindVM, r.nb.DeleteVM(ctx, a.NetBoxID)
	case kindNIC:
		kind, netboxKind, err = kindNIC, netboxKindNIC, r.nb.DeleteInterface(ctx, a.NetBoxID)
	default:
		return fmt.Errorf("netboxsync: delete of unknown kind %q for %s", a.Kind, a.Key)
	}
	switch {
	case err == nil:
		// Only a delete that actually removed something is counted; the 404
		// below removed nothing, and counting it would report churn on a mirror
		// that is merely retiring a stale mapping.
		r.sink().IncMirrorObject(netboxKind, opDeleted)
	case isNotFound(err):
		// Already gone IS the desired end state, so this falls through to the
		// tombstone. Aborting here would strand the mapping PERMANENTLY: the
		// next sweep finds no such object in actual state, so it emits no
		// delete, and nothing else prunes a netbox_objects row.
		slog.Info("netbox: object already absent; retiring its mapping",
			"kind", a.Kind, "netbox_id", a.NetBoxID)
	default:
		return fmt.Errorf("netboxsync: delete %s %d: %w", a.Kind, a.NetBoxID, err)
	}
	// Tombstoned under the SAME identity the object was recorded under, so a
	// re-created object is synced afresh instead of adopting the dead id.
	if err := corrosion.DeleteObjectRef(ctx, r.db, kind, a.Key); err != nil {
		return fmt.Errorf("netboxsync: retire mapping %s/%s: %w", kind, a.Key, err)
	}
	return nil
}

// isNotFound reports whether NetBox answered 404. Only an APIError carries a
// status: a transport failure is an AMBIGUOUS outcome, not a proven absence.
func isNotFound(err error) bool {
	var ae *netbox.APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

// parentVMID resolves the VM a NIC hangs off.
//
// ParentNetBoxID FIRST, the netbox_objects row second. Phase ordering alone is
// not sufficient: it establishes the mapping only when phase 0 actually ran a
// vm/create. If the VM already exists in NetBox and its object-ref row was lost,
// Diff emits no VM action, nothing is recorded, and the fallback finds nothing —
// which is exactly the case ParentNetBoxID, read from actual state, covers.
//
// The fallback is still needed for the opposite case: a VM created THIS sweep
// was absent from actual state, so its actions carry no parent id and the row
// phase 0 wrote is the only link.
func (r *Reconciler) parentVMID(ctx context.Context, a Action, dn desiredNIC) (int, error) {
	if a.ParentNetBoxID != 0 {
		return a.ParentNetBoxID, nil
	}
	ref, err := corrosion.GetObjectRef(ctx, r.db, kindVM, dn.VMKey)
	if err != nil {
		return 0, fmt.Errorf("netboxsync: read mapping for parent VM %s: %w", dn.VMKey, err)
	}
	if ref == nil {
		return 0, nil
	}
	return ref.NetBoxID, nil
}

// keepOldest resolves a search result to the one object to adopt.
//
// Exactly one match is adopted. More than one is the transient duplicate NetBox
// has no idempotency key to prevent, and the sweep is authoritative about it:
// keep the LOWEST id — NetBox ids are monotonic, so that is the oldest object,
// the one anything else may already reference — and delete the rest.
//
// Zero matches returns 0, meaning "create it".
func (r *Reconciler) keepOldest(ctx context.Context, ids []int, del func(context.Context, int) error) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	sort.Ints(ids)
	for _, dup := range ids[1:] {
		if err := del(ctx, dup); err != nil {
			return 0, fmt.Errorf("delete duplicate %d: %w", dup, err)
		}
		r.sink().IncDuplicateObject()
	}
	return ids[0], nil
}

// recordRef records the identity -> NetBox id mapping. Every create and adopt
// goes through here, under the SAME identity the action carries.
func (r *Reconciler) recordRef(ctx context.Context, kind, identity, netboxKind string, id int) error {
	if err := corrosion.PutObjectRef(ctx, r.db, corrosion.ObjectRef{
		LitevirtKind: kind,
		LitevirtKey:  identity,
		NetBoxKind:   netboxKind,
		NetBoxID:     id,
	}); err != nil {
		return fmt.Errorf("netboxsync: record mapping %s/%s -> %d: %w", kind, identity, id, err)
	}
	return nil
}

// deviceID resolves the DCIM device this VM's host is modelled as.
//
// desiredState resolves it for the diff; this is the CREATE-path fallback for a
// desired record that names a host but carries no resolved id — a first mirror
// has no prior link to preserve. The UPDATE path must not use it, or it writes
// back a link the diff decided to clear; see updateVM.
//
// Best-effort in BOTH directions: a lookup failure and a host that is simply not
// modelled both mean "no link", and the write body then sends device: null. An
// operator who does not model hosts in NetBox must still get a working mirror,
// so this can never return an error.
func (r *Reconciler) deviceID(ctx context.Context, d DesiredVM) int {
	if d.DeviceID != 0 || d.Host == "" {
		return d.DeviceID
	}
	id, err := r.nb.FindDeviceByName(ctx, d.Host)
	if err != nil {
		slog.Debug("netbox: host device lookup failed; mirroring without the link", "error", err)
		return 0
	}
	return id
}
