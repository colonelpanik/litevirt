package netboxsync

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// QueueKind is the netbox_sync_queue kind the mirror owns.
//
// Exported because the producers live outside this package: every consumer of
// the queue drains ONLY its own kind (see corrosion.DrainSyncQueue), so a
// producer that enqueued under a different string would have its items skipped
// by the sweeper AND never drained by the mirror — they would accumulate
// forever with nothing reporting it.
const QueueKind = "mirror"

// batchSize is how many actions run under one leader-lease check.
const batchSize = 20

// queueBatch is how many of its own items one pass drains. It matches the
// sweeper's, so neither consumer can starve the other by draining more slowly
// than the other produces.
const queueBatch = 100

// defaultInterval is the sweep cadence when none is configured. It matches the
// orphan sweeper's, because both are gated on the SAME leader lease and a lease
// sized for one cadence must not be handed away between the other's passes.
const defaultInterval = 15 * time.Minute

// defaultPollInterval is how often the node that ALREADY holds the lease looks
// for queued work between sweeps.
//
// It is not a second sweep cadence: a poll is one local read, and it reaches the
// sweep only when the queue is non-empty, so an idle cluster pays one SELECT per
// node per minute and writes nothing. What it buys is latency — without it a
// delete waits out a whole defaultInterval before NetBox stops advertising a VM
// that no longer exists, and every enqueue a lifecycle path makes is a
// replicated write that changes nothing.
const defaultPollInterval = 60 * time.Second

// clusterTypeName is the NetBox cluster-type every litevirt cluster registers
// under. A constant, not a config key: it names the SOFTWARE, so an operator
// choosing it per-cluster would fragment the type list for no gain.
const clusterTypeName = "litevirt"

// fallbackClusterName names the NetBox cluster when the local `cluster` row
// carries no name. Mirroring under a placeholder is better than not mirroring:
// the name is a label, and identity — which does all the scoping — is the
// fingerprint carried in the custom field.
const fallbackClusterName = "litevirt"

// Options is everything the reconciler needs. The daemon fills it from config;
// see internal/grpcapi's mirror wiring, which is the only production caller.
type Options struct {
	// NetBox is the REST client. *netbox.Client satisfies it.
	NetBox netboxWriter
	// DB is the local corrosion handle every read and every identity-map write
	// goes through.
	DB *corrosion.Client
	// Metrics may be nil — a metrics sink must never be why a mirror panics.
	Metrics mirrorMetrics
	// Interval is the sweep cadence; <= 0 means defaultInterval.
	Interval time.Duration
	// PollInterval is how often the node holding the lease checks the queue
	// between sweeps; <= 0 means defaultPollInterval. Anything LARGER than
	// Interval is clamped to it — a poll slower than the sweep it exists to
	// anticipate would never be the thing that noticed a change.
	PollInterval time.Duration
	// AcquireLease and HoldsLease gate the sweep on the cluster's `netbox`
	// leader lease. Leaving either nil makes this reconciler write NOTHING —
	// the fail-closed direction, so an incomplete wiring is inert rather than
	// an ungated second writer.
	AcquireLease func(context.Context) bool
	HoldsLease   func(context.Context) bool
}

// New builds a Reconciler.
func New(o Options) *Reconciler {
	interval := o.Interval
	if interval <= 0 {
		interval = defaultInterval
	}
	poll := o.PollInterval
	if poll <= 0 {
		poll = defaultPollInterval
	}
	if poll > interval {
		poll = interval
	}
	return &Reconciler{
		nb:           o.NetBox,
		db:           o.DB,
		metrics:      o.Metrics,
		interval:     interval,
		pollInterval: poll,
		acquireLease: o.AcquireLease,
		holdsLease:   o.HoldsLease,
	}
}

// Run drives the reconciler until ctx ends.
//
// TWO cadences, and only one of them can change who leads. The sweep tick is the
// authority — it acquires the lease and reconciles everything, queue or no queue
// — and the poll tick only accelerates the node ALREADY holding that lease. So
// leadership handover happens at exactly the cadence it did before the poll
// existed, and a queue that is empty, lost or unreadable costs the mirror
// nothing but latency.
//
// There is deliberately no pass at startup, matching the orphan sweeper: the
// first pass lands one interval in, so a node that has just restarted — or a
// cluster mid-rolling-upgrade — is not writing inventory while its own view of
// the fleet is still assembling. The poll cannot pull that forward either: it
// takes no lease, so before the first sweep tick there is none to hold.
func (r *Reconciler) Run(ctx context.Context) {
	sweep := time.NewTicker(r.interval)
	defer sweep.Stop()
	poll := time.NewTicker(r.pollInterval)
	defer poll.Stop()
	r.run(ctx, sweep.C, poll.C)
}

// run is Run over its two tick sources.
//
// Split out so a test can fire exactly ONE tick of either kind and know when it
// has been processed, instead of sleeping on a real minute. Driving the loop
// itself matters: calling pollQueue directly would leave the wiring — which tick
// runs which pass — asserted by nothing.
func (r *Reconciler) run(ctx context.Context, sweepTick, pollTick <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweepTick:
			if err := r.SyncOnce(ctx); err != nil {
				slog.Warn("netbox mirror: sync failed", "error", err)
			}
		case <-pollTick:
			if err := r.pollQueue(ctx); err != nil {
				slog.Warn("netbox mirror: queued sync failed", "error", err)
			}
		}
	}
}

// pollQueue sweeps early IF this node leads and something is waiting.
//
// The order of the three questions is the whole design, and each one stops the
// pass:
//
//  1. Do we hold the lease? A READ (holdsLeader), never an acquire. A non-leader
//     has to reach the end of this having written NOTHING — not a lease renewal,
//     not a queue ack — or every configured node would be contending for
//     leadership on the fast cadence instead of the sweep's.
//  2. Is anything queued? A peek, not a drain: corrosion.DrainSyncQueue is a
//     plain SELECT and acking is a separate call, so this observes the queue
//     without consuming it. Nothing is acked here — Sync does that, and only
//     once its sweep has succeeded.
//  3. Only then, the full sweep — Sync, NOT SyncOnce. The lease is already held;
//     re-acquiring it on every poll is precisely the replicated-write
//     amplification this path exists to avoid.
//
// A queue this node cannot read is not an error: the sweep tick covers
// everything the queue could have named, so a failed peek is logged and the poll
// simply does nothing this minute.
func (r *Reconciler) pollQueue(ctx context.Context) error {
	if !r.holdsLeader(ctx) {
		return nil
	}
	// Limit 1: the poll only needs to know whether the queue is EMPTY. Sync
	// re-reads it in full to decide what to ack.
	items, err := corrosion.DrainSyncQueue(ctx, r.db, QueueKind, 1)
	if err != nil {
		slog.Warn("netbox mirror: queue poll failed; the next full sweep still covers it", "error", err)
		return nil
	}
	if len(items) == 0 {
		return nil
	}
	return r.Sync(ctx)
}

// SyncOnce is ONE leader-gated pass.
//
// Leader-gated: five masterless nodes must not all mirror inventory, and NetBox
// has no idempotency key that would make concurrent writers merge. Every
// configured node runs this — the gate, not the caller, decides which one
// writes — so a node that loses the race does nothing and reports nothing.
//
// It exists as its own method so a test can drive a pass deterministically
// instead of waiting on the ticker, through the SAME gate the loop uses.
func (r *Reconciler) SyncOnce(ctx context.Context) error {
	if !r.acquireLeader(ctx) {
		return nil
	}
	return r.Sync(ctx)
}

// acquireLeader takes or renews the lease. An unwired reconciler never leads.
func (r *Reconciler) acquireLeader(ctx context.Context) bool {
	return r.acquireLease != nil && r.acquireLease(ctx)
}

// holdsLeader re-reads the lease WITHOUT renewing it, so it can be called
// immediately before each write batch without extending a lease this node may
// already have lost. An unwired reconciler never leads.
func (r *Reconciler) holdsLeader(ctx context.Context) bool {
	return r.holdsLease != nil && r.holdsLease(ctx)
}

// Sync reconciles litevirt state into NetBox.
//
// The queue is a latency optimisation; the full diff below runs regardless of
// what the queue held, because a node that died mid-create never enqueued
// anything and a peer that drained an item may have died before acting on it.
// Nothing in the sweep branches on what the peek returned.
//
// Read first, ack LAST. The items are only tombstoned once the sweep they were
// read before has succeeded, so a sweep that fails partway leaves its triggers
// in place and the next poll retries immediately. Acking first would throw the
// trigger away on exactly the passes that did not do the work, and the change
// would then wait out a full sweep interval.
//
// Both counters are emitted HERE rather than in SyncOnce, so a node that never
// took the lease records nothing at all: every configured node runs the loop,
// and a skipped pass counted as ok would put a fresh success timestamp on all of
// them — while counted as an error it would raise one on every node but the
// leader. The success stamp is set on exactly the path the ack is on, because
// the two mean the same thing: this sweep converged.
func (r *Reconciler) Sync(ctx context.Context) error {
	queued := r.peekQueue(ctx)
	converged, err := r.sweep(ctx)
	if err != nil {
		r.sink().IncMirrorSweep(sweepError)
		return err
	}
	if !converged {
		// The pass RAN — every non-delete phase applied — but its desired-state
		// read was not whole enough to authorize a delete, so NetBox may still
		// be advertising objects this sweep could not account for. That is not a
		// converged mirror and must not read as one: the success stamp is the
		// staleness signal an operator alerts on, and the queued items are
		// triggers a later, whole pass still owes an answer to.
		//
		// No error is returned. The condition is a property of the local
		// database, not a failure of this pass, and the next sweep re-evaluates
		// it from scratch.
		r.sink().IncMirrorSweep(sweepError)
		return nil
	}
	r.sink().IncMirrorSweep(sweepOK)
	// Wall clock, not the HLC: this is read as `time() - <gauge>` against
	// Prometheus's own clock, and a logical timestamp there is meaningless.
	r.sink().SetMirrorLastSuccess(time.Now())
	r.ackQueued(ctx, queued)
	return nil
}

// sweep is the reconciliation itself: read both sides, diff, apply in phases.
//
// It reports whether the pass CONVERGED. A pass that withheld its deletes —
// see deleteBlocker — returns (false, nil): it did every piece of work it could
// prove was right, and none that it could not.
func (r *Reconciler) sweep(ctx context.Context) (bool, error) {
	fp, err := corrosion.ClusterFingerprint(ctx, r.db)
	if err != nil {
		return false, fmt.Errorf("cluster fingerprint: %w", err)
	}
	// BEFORE the reads: actualState is scoped to this cluster id, and
	// createVM/updateVM write it onto every object.
	clusterID, err := r.ensureCluster(ctx)
	if err != nil {
		return false, fmt.Errorf("ensure cluster: %w", err)
	}
	r.clusterID = clusterID

	desired, skipped, err := r.desiredState(ctx)
	if err != nil {
		return false, fmt.Errorf("read desired state: %w", err)
	}
	actual, err := r.actualState(ctx, fp)
	if err != nil {
		return false, fmt.Errorf("read actual state: %w", err)
	}

	actions := Diff(desired, actual, fp)
	converged := true
	if why := deleteBlocker(desired, skipped, actual); why != "" {
		kept, withheld := withoutDeletes(actions)
		slog.Warn("netbox mirror: withholding this sweep's deletes — the desired state is not whole",
			"reason", why, "withheld_deletes", withheld,
			"desired_vms", len(desired), "skipped_records", skipped,
			"netbox_vms", len(actual.VMs), "netbox_interfaces", len(actual.NICs))
		actions, converged = kept, false
	}

	if err := r.applyPhases(ctx, actions, indexDesired(desired, fp), fp); err != nil {
		return false, err
	}
	return converged, nil
}

// deleteBlocker reports WHY this sweep may not delete, or "" when its evidence
// is whole.
//
// A delete is the only irreversible thing the mirror does: DeleteVM cascades
// away every vminterface under it, and the NetBox object ids other systems
// reference do not come back. So it may rest only on a desired state that is
// provably complete — and desiredState has two ways of being silently
// incomplete, NEITHER of which is an error:
//
//  1. An EMPTY read. corrosion.ListVMs answers ([], nil) for a table that is
//     empty because this node is hydrating after a database loss or a fresh
//     join, exactly as it does for a cluster that genuinely holds no VMs.
//     Nothing here can tell those apart — but against a NetBox that still holds
//     objects for this cluster only one of them is plausible, and acting on the
//     wrong one deletes the operator's inventory. P1's orphan sweeper states
//     the same rule about proofs: an empty universe makes every proof vacuously
//     complete, which is the one shape that must never authorize a delete.
//
//  2. A SKIPPED record. A VM whose spec carries no uuid, or a NIC with no MAC,
//     is dropped by the reader with a warning. For an object that has never
//     been mirrored that is harmless — no object of ours carries an identity
//     naming it. For one that HAS been (a spec rewritten without its uuid, a
//     MAC cleared) the skip is indistinguishable from the workload being gone,
//     and the object is destroyed.
//
// Non-delete work is unaffected: this is about never deleting on thin evidence,
// not about halting the mirror.
func deleteBlocker(desired []DesiredVM, skipped int, actual Actual) string {
	if skipped > 0 {
		return fmt.Sprintf("%d local record(s) could not be read", skipped)
	}
	if len(desired) == 0 && (len(actual.VMs) > 0 || len(actual.NICs) > 0) {
		return "the local inventory read returned no VMs while NetBox still holds objects for this cluster"
	}
	return ""
}

// withoutDeletes returns the actions that are not deletes, and how many it
// dropped.
//
// It filters the ACTION LIST rather than skipping the delete PHASES: a phase is
// a scheduling boundary, and one skipped by a flag is one a later ordering
// change can quietly reintroduce. An action that does not exist cannot run,
// whatever the phase runner does with it.
func withoutDeletes(actions []Action) ([]Action, int) {
	kept := make([]Action, 0, len(actions))
	for _, a := range actions {
		if a.Op == "delete" {
			continue
		}
		kept = append(kept, a)
	}
	return kept, len(actions) - len(kept)
}

// peekQueue reads this mirror's own queued items WITHOUT consuming them.
//
// DrainSyncQueue is a plain SELECT — acking is AckSyncItem, a separate call — so
// this is side-effect free and safe to run before a sweep that may fail.
//
// It resolves nothing from what it read: the full diff covers every object the
// queue could name, so the read exists only to decide which rows the sweep has
// earned the right to tombstone. A failure is logged and swallowed for the same
// reason — a queue this component cannot read is not a reason to skip a sweep
// that does not depend on it.
func (r *Reconciler) peekQueue(ctx context.Context) []corrosion.QueueItem {
	items, err := corrosion.DrainSyncQueue(ctx, r.db, QueueKind, queueBatch)
	if err != nil {
		slog.Warn("netbox mirror: queue read failed; the full sweep still runs", "error", err)
		return nil
	}
	return items
}

// ackQueued tombstones the items a SUCCEEDED sweep has covered.
//
// Called only after Sync's sweep returned nil, so an item is never thrown away
// by a pass that did not do its work. Every ack failure is logged and swallowed:
// the row is a trigger, not state, and the worst a surviving one costs is one
// redundant sweep on the next poll.
func (r *Reconciler) ackQueued(ctx context.Context, items []corrosion.QueueItem) {
	for _, it := range items {
		if err := corrosion.AckSyncItem(ctx, r.db, it.ID); err != nil {
			slog.Warn("netbox mirror: ack queue item", "id", it.ID, "error", err)
		}
	}
}

// applyPhases is the production phase runner.
//
// It exists as its own method so the ordering regression can exercise the REAL
// orchestration. A test that loops over Phases() itself and calls apply cannot
// detect this function flattening the list, skipping a boundary, or running two
// phases concurrently — the test would be guaranteeing the very ordering it is
// supposed to verify.
func (r *Reconciler) applyPhases(ctx context.Context, actions []Action, idx desiredIndex, fp string) error {
	// PHASES, not one flat list. apply runs a worker pool, so a flat list lets a
	// NIC create race ahead of its VM, lets a clear undo a concurrent assign,
	// and lets a VM delete cascade away an interface a concurrent
	// DeleteInterface is still deleting.
	//
	// Parallelism stays INSIDE a phase, where actions are independent. Each
	// phase must fully drain before the next begins.
	for phase, phaseActions := range Phases(actions) {
		if len(phaseActions) == 0 {
			continue // a quiet sweep stays cheap
		}
		for start := 0; start < len(phaseActions); start += batchSize {
			// Re-validated before EACH batch, not once per sweep, so an outgoing
			// leader stops rather than racing the incoming one through a long
			// sweep. A sweep over a large cluster is many seconds of writes; a
			// single check at the top says nothing about the lease at the end.
			if !r.holdsLeader(ctx) {
				return fmt.Errorf("netboxsync: leader lease lost mid-sweep in phase %d after %d actions",
					phase, start)
			}
			end := min(start+batchSize, len(phaseActions))
			if err := r.apply(ctx, phaseActions[start:end], idx, fp); err != nil {
				return fmt.Errorf("netboxsync: phase %d: %w", phase, err)
			}
		}
	}
	return nil
}

// ClusterName is the NetBox cluster name this litevirt cluster mirrors under,
// placeholder included.
//
// Exported because the CA re-key — in internal/grpcapi, which owns the operation
// but not the mirror — has to resolve the SAME cluster object the mirror writes
// into, to enumerate the inventory it must re-stamp. A second copy of the
// fallback would strand every object a mirror wrote under the placeholder the
// moment the two strings diverged, with nothing failing to say so.
func ClusterName(ctx context.Context, db *corrosion.Client) (string, error) {
	name, err := corrosion.ClusterName(ctx, db)
	if err != nil {
		return "", err
	}
	if name == "" {
		return fallbackClusterName, nil
	}
	return name, nil
}

// ensureCluster resolves the NetBox cluster every mirrored VM belongs to,
// creating the cluster and its type on first use.
//
// Named after the operator's own cluster name, never after the fingerprint: the
// fingerprint is derived from the CA certificate, so a CA replacement would
// point the mirror at a NEW cluster object and orphan everything under the old
// one. Two installations sharing a name therefore share a cluster object, which
// is harmless — every object is still scoped by the identity fingerprint, and
// that is what BuildActual and Diff filter on.
func (r *Reconciler) ensureCluster(ctx context.Context) (int, error) {
	typeID, err := r.nb.EnsureClusterType(ctx, clusterTypeName)
	if err != nil {
		return 0, fmt.Errorf("cluster type %q: %w", clusterTypeName, err)
	}
	name, err := ClusterName(ctx, r.db)
	if err != nil {
		return 0, err
	}
	id, err := r.nb.EnsureCluster(ctx, name, typeID)
	if err != nil {
		return 0, fmt.Errorf("cluster %q: %w", name, err)
	}
	if id == 0 {
		// NetBox answered without an id. Continuing would list "cluster 0" —
		// which has no filter meaning — and diff every object in the install
		// against this cluster's desired set.
		return 0, fmt.Errorf("netboxsync: NetBox returned no id for cluster %q", name)
	}
	return id, nil
}

// actualState is the reconciler's only NetBox read path.
//
// One line on purpose: BuildActual holds the identity-fingerprint filter that
// stops one cluster's sweep from deleting another's inventory out of a shared
// NetBox, and a second collection path here would be a second place for that
// filter to be dropped.
func (r *Reconciler) actualState(ctx context.Context, fingerprint string) (Actual, error) {
	return BuildActual(ctx, r.nb, r.clusterID, fingerprint)
}

// vmSpecFields is the slice of the stored VM spec the mirror reads. The spec is
// the marshalled pb.VMSpec, so these tags are the wire names.
type vmSpecFields struct {
	UUID      string `json:"uuid"`
	CPU       int    `json:"cpu"`
	MemoryMiB int    `json:"memory_mib"`
}

// desiredState is litevirt's own inventory, in the shape Diff compares.
//
// Every read failure is RETURNED, never skipped past. Desired state is what the
// delete half of the diff is computed against, so a VM missing from it because
// a query failed is a VM the sweep would delete from NetBox.
// It also returns how many records it SKIPPED — a VM with no uuid, a NIC with
// no MAC. A skip is not an error and does not stop the read, but it does make
// the answer partial, and the caller has to know: see deleteBlocker.
func (r *Reconciler) desiredState(ctx context.Context) ([]DesiredVM, int, error) {
	vms, err := corrosion.ListVMs(ctx, r.db, "", "")
	if err != nil {
		return nil, 0, fmt.Errorf("list VMs: %w", err)
	}
	leases, err := corrosion.ListNetBoxLeases(ctx, r.db)
	if err != nil {
		return nil, 0, fmt.Errorf("list NetBox leases: %w", err)
	}
	byAddress := make(map[string]int, len(leases))
	for _, l := range leases {
		byAddress[leaseKey(l.Network, l.IP)] = l.NetBoxIPID
	}

	// One device lookup per HOST, not per VM: a sweep over a large cluster
	// otherwise issues one NetBox request per VM to resolve the same handful of
	// hosts.
	devices := map[string]int{}

	out := make([]DesiredVM, 0, len(vms))
	skipped := 0
	for _, v := range vms {
		if v.IsTemplate {
			// A template is a disk image, never a running machine. Mirroring one
			// would put a permanently-offline virtual_machine in NetBox for every
			// image an operator keeps.
			continue
		}
		var spec vmSpecFields
		if err := json.Unmarshal([]byte(v.Spec), &spec); err != nil || spec.UUID == "" {
			// The uuid is what makes an identity incarnation-unique, so a VM
			// without one cannot be named in NetBox at all.
			//
			// COUNTED, not merely logged. A VM that has never been mirrored is
			// harmless to omit — no object of ours carries an identity naming
			// it. But one whose spec LOST its uuid HAS been mirrored, and to the
			// diff its absence from this list is indistinguishable from the VM
			// having been destroyed. The count is what stops the sweep acting on
			// that difference (see deleteBlocker).
			slog.Warn("netbox mirror: skipping a VM whose spec carries no uuid",
				"vm", v.Name, "error", err)
			skipped++
			continue
		}

		nics, err := corrosion.MergedVMNICs(ctx, r.db, v.Name)
		if err != nil {
			return nil, 0, fmt.Errorf("read NICs of VM %s: %w", v.Name, err)
		}
		disks, err := corrosion.GetVMDisks(ctx, r.db, v.Name)
		if err != nil {
			return nil, 0, fmt.Errorf("read disks of VM %s: %w", v.Name, err)
		}

		deviceID, ok := devices[v.HostName]
		if !ok && v.HostName != "" {
			deviceID = r.lookupDevice(ctx, v.HostName)
			devices[v.HostName] = deviceID
		}

		nicSet, nicsSkipped := desiredNICs(nics, byAddress)
		skipped += nicsSkipped
		out = append(out, DesiredVM{
			Name:     v.Name,
			Host:     v.HostName,
			UUID:     spec.UUID,
			Status:   netboxStatus(v.State),
			VCPUs:    orSpec(v.CPUActual, spec.CPU),
			MemoryMB: orSpec(v.MemActual, spec.MemoryMiB),
			DiskGB:   totalDiskGiB(disks),
			DeviceID: deviceID,
			NICs:     nicSet,
		})
	}
	// Sorted so a sweep over identical state produces an identical action list;
	// ListVMs imposes no order of its own.
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, skipped, nil
}

// lookupDevice resolves one host's DCIM device id, or 0.
//
// Best-effort in BOTH directions: a lookup failure and a host that is simply
// not modelled both mean "no link". An operator who does not model hosts in
// NetBox must still get a working mirror, so this never fails a sweep.
func (r *Reconciler) lookupDevice(ctx context.Context, host string) int {
	id, err := r.nb.FindDeviceByName(ctx, host)
	if err != nil {
		slog.Debug("netbox mirror: host device lookup failed; mirroring without the link",
			"host", host, "error", err)
		return 0
	}
	return id
}

// desiredNICs maps litevirt NIC rows onto the mirror's NIC shape, resolving each
// one's NetBox address object through the lease index. It also returns how many
// NICs it skipped — see desiredState.
func desiredNICs(nics []corrosion.NICRecord, byAddress map[string]int) ([]DesiredNIC, int) {
	// Ordered before naming, because the names are derived positionally on a
	// collision and map/query order must not decide them.
	sort.Slice(nics, func(i, j int) bool {
		if nics[i].Ordinal != nics[j].Ordinal {
			return nics[i].Ordinal < nics[j].Ordinal
		}
		return nics[i].MAC < nics[j].MAC
	})
	out := make([]DesiredNIC, 0, len(nics))
	used := make(map[string]bool, len(nics))
	skipped := 0
	for _, n := range nics {
		if n.MAC == "" {
			// The identity is MAC-derived, so a NIC without one cannot be named
			// in NetBox at all. Mirroring it under an empty MAC would collide
			// with its own VM's identity (a VM identity IS a NIC identity with an
			// empty MAC).
			//
			// Counted for the same reason a uuid-less VM is: an interface whose
			// MAC was cleared has already been mirrored, and dropping it here
			// leaves the diff unable to tell that from a detached NIC.
			slog.Warn("netbox mirror: skipping a NIC with no MAC", "vm", n.VMName, "nic", n.ID)
			skipped++
			continue
		}
		out = append(out, DesiredNIC{
			Name:       nicName(n, used),
			MAC:        strings.ToLower(n.MAC),
			IP:         n.IP,
			NetBoxIPID: byAddress[leaseKey(n.NetworkName, n.IP)],
		})
	}
	return out, skipped
}

// nicName is the interface name NetBox shows, derived from the NIC's ordinal.
//
// NetBox requires interface names to be unique WITHIN a virtual machine, so a
// duplicate ordinal — which a legacy vm_interfaces row that never carried one
// can produce — would make the second create a 400 and abort the sweep. The
// collision suffix is the MAC, which is unique by construction and is already
// this NIC's identity component.
func nicName(n corrosion.NICRecord, used map[string]bool) string {
	name := "eth" + strconv.Itoa(n.Ordinal)
	if used[name] {
		name += "-" + strings.ReplaceAll(strings.ToLower(n.MAC), ":", "")
	}
	used[name] = true
	return name
}

// leaseKey is the (network, ip) primary key of an ip_allocations row, which is
// how a NIC finds the NetBox address object it holds.
func leaseKey(network, ip string) string { return network + "\x00" + ip }

// netboxStatus maps a litevirt VM state onto NetBox's status choice.
//
// Only "running" is active. Every other state — stopped, migrating, error, a
// state this version does not know — is offline, because NetBox's remaining
// choices ("planned", "staged", "failed", "decommissioning") describe an
// operator's INTENT for a machine, not a hypervisor's runtime, and writing one
// would overwrite what an operator put there.
func netboxStatus(state string) string {
	if state == "running" {
		return "active"
	}
	return "offline"
}

// orSpec prefers the live-resized actual and falls back to what the spec asked
// for. A VM that has never been resized carries a zero actual.
func orSpec(actual int, spec int) int {
	if actual > 0 {
		return actual
	}
	return spec
}

// totalDiskGiB sums a VM's disks, rounding each up exactly as project quota
// does, so the two never disagree about the same VM.
//
// The value goes onto NetBox's `virtual_machine.disk`. That field's unit has
// varied across NetBox releases, so what makes the mirror stable is not the
// unit but the ROUND TRIP: whatever is written must read back equal, or the
// diff sees drift on unchanged state and PATCHes forever. The fleet's
// second-sweep-issues-no-PATCHes scenario is what pins that.
func totalDiskGiB(disks []corrosion.DiskRecord) int {
	total := 0
	for _, d := range disks {
		total += corrosion.DiskQuotaGiB(d.SizeBytes)
	}
	return total
}
