package netboxsync

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
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

// InventoryProof is a corroboration BOUND to one sampled inventory: the answer
// to "is the read these conclusions were computed from the CLUSTER's?", asked
// about that read and not about whatever the tables hold by the time the
// question is put.
//
// The binding is what makes the answer mean anything. The mirror reads its
// desired state and its removal evidence, diffs them against NetBox, and only
// then discovers that one removal rests on a mapping row alone — the record that
// cannot justify an absence by itself. Everything before that sentence took
// time, and replication does not stop while it passes. A proof sampled at the
// end certifies the inventory as it is then; the plan came from the inventory as
// it was, and the two are the same only by luck. A live VM's NetBox object was
// deleted through precisely that gap: the target's `vms` row landed after the
// plan was built, both peers agreed on the now-complete inventory, and the OLD
// plan executed with a fresh proof stamped on it.
//
// So an implementation must answer for the SAMPLE, which entails both halves:
// every participant agrees with the sampled digests, AND this node's own rows
// still are those digests. The second half is not redundant — a peer that has
// not yet received a row agrees with a sample this node has already moved past,
// and the conclusion drawn from the sample is then contradicted by the local
// database itself.
type InventoryProof interface {
	// Corroborated reports whether the bound sample is corroborated as the
	// cluster's inventory and, when it is not, the operator-facing reason.
	//
	// Called at most once per pass (see removalCorroboration): it is a peer
	// fan-out, and two answers to one question can straddle a write.
	Corroborated(ctx context.Context) (bool, string)
}

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
	// SweepPhase delays the FIRST sweep tick, shifting this loop's whole
	// schedule away from another periodic loop it shares an exclusion with.
	//
	// It exists because the mirror and the orphan sweeper's maintenance loop run
	// on the SAME configured cadence and serialise on the SAME per-node gate,
	// and both are started from the same function microseconds apart. Two
	// tickers of equal period created together stay in lockstep for the life of
	// the process, so whichever loop reaches the gate second finds it held and
	// declines — every interval, indefinitely.
	//
	// That is not a lost tick. The mirror's sweep is the ONLY thing that
	// acquires the leader lease, and the queue poll acts solely on a lease
	// already held, so a sweep that never wins the gate means no node ever
	// leads, the poll can never pull work forward either, and the inventory
	// mirror does not run at all. Half an interval of skew leaves the two
	// schedules maximally far apart, and a pass slower than that hits the gate
	// on the merits — which is what declining is for.
	//
	// <= 0 means no delay, and the first sweep lands one interval in as before.
	SweepPhase time.Duration
	// ClusterName overrides the NetBox cluster this mirror writes into. Empty
	// means "the local cluster name", which is the default every
	// single-installation deployment runs.
	ClusterName string
	// AcquireLease and HoldsLease gate the sweep on the cluster's `netbox`
	// leader lease. Leaving either nil makes this reconciler write NOTHING —
	// the fail-closed direction, so an incomplete wiring is inert rather than
	// an ungated second writer.
	AcquireLease func(context.Context) bool
	HoldsLease   func(context.Context) bool
	// Latched reports whether the cluster-wide capability contract this mirror
	// depends on has DURABLY formed.
	//
	// It is a function, not a bool, because it is asked ONCE PER PASS: a latch
	// closes while the daemon runs — it is what the last node of a rolling
	// upgrade completes — and nothing restarts this loop when it does. Sampling
	// it at construction would leave a correctly-configured mirror inert for the
	// life of the process.
	//
	// Nil is "not latched", matching the lease functions above: an incomplete
	// wiring must be inert rather than an ungated writer.
	Latched func(context.Context) bool

	// InventorySnapshot samples the inventory this pass reads its conclusions
	// from, and returns the corroboration BOUND to that exact sample.
	//
	// It is the second half of the removal-evidence policy for the one record
	// that cannot supply it: the mirror's own mapping row, which identifies an
	// incarnation without saying anything about whether it stopped existing. See
	// vmRemovalProven.
	//
	// TWO CALLS, NOT ONE PREDICATE, and the split is the whole point. A pass
	// concludes an absence from rows it read at the START of the sweep and asks
	// about it LATER, after a diff and several NetBox round trips. A predicate
	// that sampled its own digests when asked would therefore certify a
	// DIFFERENT state from the one that supplied the conclusion — peers agreeing
	// about the inventory as it is now says nothing about the plan computed from
	// the inventory as it was, and a live VM's object was deleted through exactly
	// that gap. So the sample is taken BEFORE the reads and the proof is bound to
	// it: see InventoryProof.
	//
	// THREADED IN rather than implemented here, exactly as the lease and the
	// latch are, because the answer needs the cluster: it is a fan-out over the
	// closed participant universe comparing every address-bearing table's digest
	// with this node's, and that machinery lives beside the prefix bind that
	// already depends on it. Reimplementing a second notion of a whole read in
	// this package is how two proofs of one property came to differ before.
	//
	// Nil is "not corroborated", matching every other predicate here: an
	// incomplete wiring withholds a removal rather than authorizing one. So is a
	// nil InventoryProof, which is what a sampler that could not read its own
	// digests returns.
	InventorySnapshot func(context.Context) InventoryProof

	// Exclusive runs one pass inside the caller's INTRA-NODE critical section,
	// and may decline to run it at all.
	//
	// The leader lease this mirror already takes is the CROSS-node half of the
	// exclusion. It cannot be the whole of it, because it names the NODE: on the
	// node that holds it, a CA re-key renews the very same holder, so the
	// per-batch lease read still says "ours" and a sweep runs straight through a
	// rewrite of the identities it filters actual state on. Which of this node's
	// NetBox operations may run is not something this package can know — the
	// re-key does not live here — so the decision is the caller's, threaded in
	// exactly as the lease is.
	//
	// Nil runs the pass directly. That is the right default for a reconciler
	// wired on its own: with no other writer on the node there is nothing to
	// exclude.
	Exclusive func(ctx context.Context, pass func(context.Context) error) error
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
		sweepPhase:   o.SweepPhase,
		clusterName:  o.ClusterName,
		acquireLease: o.AcquireLease,
		holdsLease:   o.HoldsLease,
		latched:      o.Latched,
		exclusive:    o.Exclusive,

		inventorySnapshot: o.InventorySnapshot,
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
// SweepPhase is the skew this reconciler was built with.
//
// It exists so the WIRING can be asserted where the value is decided. The skew
// is the only thing keeping the mirror's sweep off the maintenance loop's tick,
// and a mirror built with a zero one is starved completely rather than visibly
// broken — nothing errors, no inventory is written, and the loop that would have
// reported it never acquires a lease. Run's own behaviour under a phase is
// testable in this package; that the daemon PASSES one is not.
func (r *Reconciler) SweepPhase() time.Duration { return r.sweepPhase }

func (r *Reconciler) Run(ctx context.Context) {
	// The phase delay is taken BEFORE the sweep ticker is created, because a
	// ticker's schedule is fixed from the moment it is made: creating it now and
	// dropping its first tick would leave it in the very lockstep the delay
	// exists to break. Waiting first puts every later tick half an interval off
	// the maintenance loop's, for the life of the process.
	if r.sweepPhase > 0 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.sweepPhase):
		}
	}
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
	if !r.capabilityLatched(ctx) {
		return nil
	}
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
	// The capability gate comes FIRST, ahead of the lease. Acquiring the lease
	// is itself a replicated write and it enters the cluster's leadership race,
	// and a node that may not mirror has no business doing either.
	if !r.capabilityLatched(ctx) {
		return nil
	}
	if !r.acquireLeader(ctx) {
		return nil
	}
	return r.Sync(ctx)
}

// capabilityLatched reports whether the cluster-wide contract that authorizes
// mirroring has durably formed. An unwired predicate never authorizes anything.
//
// Read on EVERY pass. A latch closes while the daemon runs — it is the last act
// of a rolling upgrade — and nothing restarts this loop when it does, so a
// value sampled at construction would leave a correctly-configured mirror inert
// for the life of the process. The read is a cheap in-memory one; it dials no
// peer.
func (r *Reconciler) capabilityLatched(ctx context.Context) bool {
	return r.latched != nil && r.latched(ctx)
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
// The capability gate is NOT re-read here. Both entry points — SyncOnce and
// pollQueue — ask before they call this, exactly once per pass, and asking
// twice would make "the latch formed between these two passes" mean something
// different depending on which read observed the flip.
//
// Both counters are emitted HERE rather than in SyncOnce, so a node that never
// took the lease records nothing at all: every configured node runs the loop,
// and a skipped pass counted as ok would put a fresh success timestamp on all of
// them — while counted as an error it would raise one on every node but the
// leader. The success stamp is set on exactly the path the ack is on, because
// the two mean the same thing: this sweep converged.
// Every entry point reaches the pass through here — SyncOnce, pollQueue, and a
// test driving one directly — so this is where the caller's INTRA-NODE critical
// section goes. Putting it in the two entry points instead would leave the
// exclusion one new caller away from being bypassed, and the leader lease has
// already shown what an exclusion with a hole in it is worth.
func (r *Reconciler) Sync(ctx context.Context) error {
	if r.exclusive != nil {
		return r.exclusive(ctx, r.syncPass)
	}
	return r.syncPass(ctx)
}

// syncPass is Sync's body: everything a pass does once it has been admitted.
//
// Both counters live here rather than in Sync, so a pass the caller's exclusion
// DECLINED records nothing at all — a declined pass is not a failed sweep, and
// counting it as one would raise the staleness signal an operator alerts on
// every time a re-key ran normally.
func (r *Reconciler) syncPass(ctx context.Context) error {
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

	// THE SNAPSHOT THIS PASS'S CONCLUSIONS ARE BOUND TO, sampled BEFORE the
	// reads that produce them and not when the proof is finally needed.
	//
	// Everything below — the desired state, the diff, the removal evidence — is
	// read from the local inventory tables, and the one conclusion that needs
	// the cluster ("no host holds a row for this incarnation") is a statement
	// about THIS read. Sampling the digests later would prove a different read
	// whole and stamp the answer on this one: that is how a live VM's object
	// came to be deleted, with the target's row already replicated and both
	// peers agreeing about it. See InventoryProof.
	//
	// Unconditional, unlike the fan-out it feeds. The sample is local — a table
	// digest, no peer dialled, the same computation anti-entropy already runs
	// every tick — and it has to be taken before anything is read, which is
	// exactly when a pass cannot yet know whether some removal will need it. So
	// the leader pays one digest per sweep; the fan-out itself stays lazy (see
	// removalCorroboration), and a pass whose every removal rests on a tombstone
	// still asks no peer.
	proof := r.bindInventory(ctx)

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
	if collided := collidingNames(desired, actual); len(collided) > 0 {
		// Diff has already withheld every action for these VMs. What is left is
		// to say so: the mirror cannot represent them, and it will not be able
		// to until the operator gives one of the two installations a NetBox
		// cluster of its own — or, if these objects are this cluster's own
		// stranded under a fingerprint it has moved away from, until
		// `lv netbox rekey` re-stamps them.
		slog.Warn("netbox mirror: skipping VMs whose names this NetBox cluster already holds "+
			"under another identity; set netbox.cluster_name to give this installation a "+
			"cluster of its own, or run `lv netbox rekey` if they are this cluster's own "+
			"objects left under a fingerprint it has moved away from",
			"vms", collided, "netbox_cluster", r.clusterID)
		converged = false
	}
	// A RENAME THIS PASS DELIBERATELY DID NOT WRITE.
	//
	// Diff emits no upsert for a VM whose desired name a LIVE VM of ours still
	// holds — writing it is a 400 that fails the whole sweep over a wait of one
	// interval — and it breaks a rename CYCLE by parking one member on a
	// temporary name, which is progress rather than convergence. Both leave
	// NetBox not matching desired state, so both have to be said out loud and
	// neither may stamp the success gauge.
	//
	// A condition that persists past a few sweeps is not the chain draining: it
	// is a park that could not be planned because its temporary name is taken,
	// which is the one case the cycle-breaker refuses (see renameCycleParks).
	if pending := unconvergedRenames(desired, actual, actions, fp); len(pending) > 0 {
		slog.Warn("netbox mirror: these VMs keep their previous NetBox name for now — each one's "+
			"desired name is still held by another live VM of this cluster that is itself being "+
			"renamed. A chain of renames lands one link per sweep; a cycle is broken by moving "+
			"one member onto a temporary name, which this pass does. Nothing is removed either "+
			"way. A condition that outlasts a few sweeps means the temporary name was itself "+
			"taken — free a name in NetBox by hand",
			"vms", pending, "netbox_vms", len(actual.VMs))
		converged = false
	}
	// What a withholding gate took away from THIS pass, kept so the collision it
	// causes can be reported with its cause rather than on its own. See
	// withheldReplacementCause.
	planned := actions
	var partialRead string
	if why := r.deleteBlocker(ctx, desired, skipped, actual); why != "" {
		kept, withheld := withoutDestructive(actions)
		slog.Warn("netbox mirror: withholding this sweep's deletes — the desired state is not whole",
			"reason", why, "withheld_actions", withheld,
			"desired_vms", len(desired), "skipped_records", skipped,
			"netbox_vms", len(actual.VMs), "netbox_interfaces", len(actual.NICs))
		actions, converged, partialRead = kept, false, why
	} else if kept, unprovenDeletes, unprovenClears := r.withoutUnprovenRemovals(ctx, actions, actual, proof); unprovenDeletes+unprovenClears > 0 {
		// The whole-pass gate above answers "is this read whole?", which a
		// PARTIALLY hydrated database passes: some of the cluster's rows are
		// here, so the read is neither empty nor short of a record it tried to
		// parse. The per-object rule below is what covers that — see
		// withoutUnprovenRemovals.
		if unprovenDeletes > 0 {
			// A withheld DELETE is positive proof that this node's INVENTORY
			// read is partial: NetBox holds an object whose VM or NIC the local
			// database has no row for, tombstone included. The clear branch
			// resolves its addresses through that same inventory read — a NIC
			// the read has not caught up on resolves to address 0, which reads
			// as "holds no address" — so a pass that has just proven the read
			// partial may not run the destructive half of it on the strength of
			// the address evidence alone. Withholding the delete and clearing
			// anyway is the contradiction: the pass would detach addressing on
			// exactly the sweep that admitted it could not be trusted to.
			//
			// A withheld CLEAR does NOT reach here. That one is proven per
			// object and its blast radius is one address; escalating it to the
			// whole list would let a single unprovable address — an object an
			// operator hand-copied, say — withhold every clear in the cluster
			// for as long as it exists.
			kept, _ = withoutDestructive(kept)
		}
		actions, converged = kept, false
		partialRead = fmt.Sprintf(
			"this node holds no local record — tombstone included — for %d of the NetBox "+
				"object(s) this sweep would have removed, so its view of the cluster is partial",
			unprovenDeletes+unprovenClears)
	}

	// THE CAUSE OF A WITHHELD REPLACEMENT, said out loud.
	//
	// Withholding it is right (see destructive), but the operator-visible
	// consequence is a NetBox 400 on a name they can see is free — and the
	// collision error alone names neither the withheld replacement nor the
	// partial read behind it. Reported here as its own condition, so it is on
	// the record whatever the apply below then does.
	withheldNames := withheldReplacements(planned, actions)
	if len(withheldNames) > 0 {
		slog.Warn("netbox mirror: WITHHOLDING the replacement of the superseded NetBox "+
			"object(s) holding these names, because this pass could not prove its own view of "+
			"the cluster is whole. Every create or rename onto one of them will be refused by "+
			"NetBox until the replacement can be proven — the mirror stalls for those VMs "+
			"rather than removing an object on partial evidence. It clears itself once the "+
			"local database has replicated the missing rows; a condition that persists past a "+
			"few sweeps is an object to remove in NetBox by hand",
			"names", withheldNames, "cause", partialRead,
			"desired_vms", len(desired), "netbox_vms", len(actual.VMs))
	}

	if err := r.applyPhases(ctx, actions, indexDesired(desired, fp), fp); err != nil {
		return false, withheldReplacementCause(err, withheldNames, partialRead)
	}
	return converged, nil
}

// withheldReplacements is the desired names whose vm/replace a withholding gate
// dropped from this pass, sorted.
//
// Diffed from the two action lists rather than counted inside the gates: both
// gates drop a replace through the same `destructive` filter, and asking the
// lists what actually went is one answer instead of two places to keep in step.
func withheldReplacements(planned, kept []Action) []string {
	if len(planned) == len(kept) {
		return nil
	}
	survived := make(map[string]bool, len(kept))
	for _, a := range kept {
		if a.Op == opReplace {
			survived[a.Key] = true
		}
	}
	var out []string
	for _, a := range planned {
		if a.Op == opReplace && !survived[a.Key] {
			out = append(out, a.FreesName)
		}
	}
	sort.Strings(out)
	return out
}

// withheldReplacementCause annotates a NetBox name collision with the reason the
// replacement that would have cleared it was withheld.
//
// An operator reading the raw failure sees `HTTP 400: a virtual machine with
// this name already exists in this cluster` for a name that is, as far as
// litevirt is concerned, free — and nothing connecting it to the partial read
// that is the actual cause. The stall is deliberate and stays; what it needed
// was to say why.
//
// Only a NAME refusal is annotated. Wrapping every failure of a pass that
// happened to withhold a replacement would attach the explanation to unrelated
// errors, which is how an accurate message becomes a misleading one. The log
// line in sweep carries the condition unconditionally, so nothing is lost if
// NetBox ever words this differently.
func withheldReplacementCause(err error, names []string, why string) error {
	if len(names) == 0 || !nameAlreadyTaken(err) {
		return err
	}
	return fmt.Errorf("%w — this sweep withheld the replacement of the superseded object(s) "+
		"holding %v, because %s. The name cannot be freed until that removal can be proven "+
		"from the local database, so this VM stays unmirrored rather than having an object "+
		"removed on evidence the pass has already admitted is partial",
		err, names, why)
}

// nameAlreadyTaken reports whether a NetBox refusal is the one-VM-name-per-
// cluster rule.
//
// A 400 (NetBox ANSWERED, and said no) whose body names the `name` field. Not
// matched on the sentence, which is a NetBox release's wording, and not on the
// status alone, which every other validation refusal shares.
func nameAlreadyTaken(err error) bool {
	var ae *netbox.APIError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Status == 400 && strings.Contains(ae.Body, `"name"`)
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
//     join, exactly as it does for a cluster that genuinely holds no VMs. Left
//     there the two are indistinguishable, and acting on the wrong one deletes
//     the operator's inventory — P1's orphan sweeper states the same rule about
//     proofs: an empty universe makes every proof vacuously complete, which is
//     the one shape that must never authorize a delete.
//
//     So an empty read must be CORROBORATED, and corrosion.HasVMRecords is what
//     corroborates it: a VM that was deleted leaves a tombstone behind, and a
//     database that has never been read holds no row of any kind. That keeps the
//     ordinary case working — deleting the last VM in a cluster still retires
//     its NetBox object — while an unhydrated node still deletes nothing.
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
func (r *Reconciler) deleteBlocker(ctx context.Context, desired []DesiredVM, skipped int, actual Actual) string {
	if skipped > 0 {
		return fmt.Sprintf("%d local record(s) could not be read", skipped)
	}
	if len(desired) != 0 || (len(actual.VMs) == 0 && len(actual.NICs) == 0) {
		return "" // nothing to corroborate: either side is non-empty
	}
	// Desired is empty and NetBox is not. Only positive local evidence that
	// this database holds VM history can tell an empty cluster from an empty
	// read, and a read that FAILS is no evidence at all.
	seen, err := corrosion.HasVMRecords(ctx, r.db)
	if err != nil {
		return fmt.Sprintf("the local VM history could not be read: %v", err)
	}
	if !seen {
		return "the local database holds no VM record of any kind, tombstones included, " +
			"while NetBox still holds objects for this cluster"
	}
	return ""
}

// withoutUnprovenRemovals drops the deletes AND clears this pass cannot PROVE,
// and reports how many of each it dropped.
//
// deleteBlocker asks whether the desired read is WHOLE, and a partially
// hydrated database answers yes to every question it poses: the table is not
// empty, so the empty-read corroboration never runs, and nothing was skipped,
// so the partial-read counter is zero. A node holding one of the cluster's VMs
// therefore diffs the other N-1 to "litevirt no longer holds these" and retires
// them from NetBox — the operator's source of truth — and the same applies one
// level down, where a `vms` row that replicated ahead of its `vm_interfaces`
// rows leaves a mirrored VM with every interface deleted out from under it.
//
// Nothing else stands in the way, either — only a DELAY. Such a node derives a
// fingerprint from the locally-healed cluster record and re-latches the
// capability on its own, and the lease is no obstacle: it is a shared lease any
// configured node may take, and this one takes it on its FIRST SWEEP TICK, one
// interval after start (15 minutes by default; see Run, which deliberately runs
// no pass at startup, and pollQueue, which acquires nothing at all). A wait is
// not a proof — it is the same duration whether the database has hydrated or
// not, and a node slow enough to still be replicating at the next tick gets no
// second grace period.
//
// So the rule the empty read already obeys is applied PER OBJECT: a removal needs
// positive local evidence that the thing it takes away is genuinely gone, and the
// evidence is the record the local database holds for it — live or TOMBSTONED.
// litevirt soft-deletes, so a destroyed workload leaves one; a row that has not
// replicated leaves nothing. See corrosion.MirrorEvidence.
//
// BOTH destructive ops are covered, not just the delete. A `clear` unassigns an
// address rather than destroying it, but it is reached by the same partial read
// and by a shape the repair mechanism itself produces: anti-entropy repairs per
// TABLE, so "`vms` and `vm_interfaces` repaired, `ip_allocations` not yet" is
// ordinary. In that state every NIC resolves to address 0 — "this NIC holds no
// address" — and every litevirt-owned address in the cluster routes into the
// clear branch. Its evidence is a lease row of any kind naming the address
// (MirrorEvidence.KnowsAddress), which is complete because nothing hard-deletes
// one: ReleaseLease tombstones the row and retains netbox_ip_id, so requiring
// the proof cannot strand a genuinely stale assignment.
//
// This is deliberately NOT a replication-freshness gate, which is what it might
// look like it should be. There is no local signal in this tree that proves a
// node's replicated view is caught up: `mutation_log` and every
// `replication_watermarks`-derived gauge measure what THIS node owes its PEERS,
// so the rebuilt node that has written nothing and holds nothing reads as
// maximally healthy by all of them — the gate would be green on precisely the
// node it exists to stop. Per-object evidence needs no such signal, and it
// degrades the right way: it withholds exactly the deletes it cannot support and
// lets every other one through, so a bulk teardown whose tombstones have all
// arrived still converges in one pass.
//
// A partial pass is NOT an error. It reports unconverged — the caller withholds
// the success stamp — and the next sweep re-derives everything from scratch.
func (r *Reconciler) withoutUnprovenRemovals(ctx context.Context, actions []Action, actual Actual,
	proof InventoryProof) ([]Action, int, int) {
	if !hasRemovals(actions) {
		// The evidence read costs five table scans, so a pass with nothing to
		// prove does not pay for them.
		return actions, 0, 0
	}
	known, err := corrosion.ReadMirrorEvidence(ctx, r.db)
	if err != nil {
		// A read that FAILED is no evidence at all, so nothing is proven and
		// every removal goes. Same direction as deleteBlocker's own failed read.
		kept, withheld := withoutDestructive(actions)
		slog.Warn("netbox mirror: withholding this sweep's deletes and clears — the local "+
			"record history could not be read, so neither can be proven",
			"error", err, "withheld_actions", withheld)
		// Counted as withheld DELETES: nothing at all is proven here, which is
		// the whole-read failure the escalation in sweep exists for, not the
		// one-address case.
		return kept, withheld, 0
	}

	// The owning VM's NAME, by NetBox object id: a nic delete carries its
	// parent's id (read from actual state) and the evidence is keyed on the
	// litevirt name.
	nameByID := make(map[int]string, len(actual.VMs))
	for _, v := range actual.VMs {
		nameByID[v.ID] = v.Name
	}

	// The inventory corroboration, ASKED AT MOST ONCE for the whole pass and only
	// if some removal's evidence actually needs it. It is a peer fan-out — see
	// removalCorroboration — and a healthy pass whose every removal rests on a
	// tombstone must not pay for one.
	corr := r.removalCorroboration(ctx, proof)

	kept := make([]Action, 0, len(actions))
	var unprovenVMs, unprovenNICs []string
	var unprovenAddrs []int
	for _, a := range actions {
		if !destructive(a) || provenRemovable(a, actual, nameByID, known, corr) {
			kept = append(kept, a)
			continue
		}
		switch {
		case a.Op == "clear":
			unprovenAddrs = append(unprovenAddrs, a.IPID)
		case a.Kind == "vm":
			unprovenVMs = append(unprovenVMs, actual.VMs[a.Key].Name)
		default:
			unprovenNICs = append(unprovenNICs, actual.NICs[a.Key].MAC)
		}
	}
	deletes := len(unprovenVMs) + len(unprovenNICs)
	if deletes > 0 {
		// Sorted, so a condition that lasts several sweeps logs the same list
		// each time instead of reshuffling it.
		sort.Strings(unprovenVMs)
		sort.Strings(unprovenNICs)
		slog.Warn("netbox mirror: withholding deletes for NetBox objects whose removal this "+
			"node cannot conclude from its own records — it holds no record of the incarnation, "+
			"tombstone included; or it holds one that says the incarnation still EXISTS; or all "+
			"it holds is its own mapping row, which proves the object was mirrored and not that "+
			"the workload is gone, and the cluster could not confirm this node's inventory read "+
			"is whole. The next sweep re-evaluates",
			"vms", unprovenVMs, "interface_macs", unprovenNICs,
			"netbox_vms", len(actual.VMs), "netbox_interfaces", len(actual.NICs),
			"withheld_deletes", deletes, "inventory_corroboration", corr.reason())
	}
	if len(unprovenAddrs) > 0 {
		sort.Ints(unprovenAddrs)
		slog.Warn("netbox mirror: withholding address detachments this node holds no lease "+
			"record of, tombstone included — `ip_allocations` has not replicated them, or the "+
			"address belongs to something this cluster has never leased; the next sweep "+
			"re-evaluates. A condition that persists is an object to remove in NetBox by hand",
			"netbox_address_ids", unprovenAddrs,
			"netbox_interfaces", len(actual.NICs),
			"withheld_clears", len(unprovenAddrs))
	}
	return kept, deletes, len(unprovenAddrs)
}

// destructive reports whether an action TAKES something away. Three ops do: the
// delete, the clear, and the replace.
//
// This is the ONLY spelling of that set: hasRemovals, withoutUnprovenRemovals
// and withoutDestructive all call it rather than re-testing the ops, so the
// per-object gate and the whole-list drop cannot come to disagree about what
// they cover. A fourth destructive op therefore reaches both gates the moment it
// is added here — and provenRemovable fails it closed until someone gives it an
// evidence question.
//
// THE REPLACE IS IN HERE, and it is the reason this comment says three. It reads
// like part of a create — it exists to free a name a create needs — but it
// deletes a NetBox object, and half of its proof is that the object's UUID is
// absent from the DESIRED set. That premise is only as good as the desired read
// is whole, which is exactly the question both gates ask. So a sweep that cannot
// prove its read whole withholds the replace with the deletes; the create then
// collides as it did before the replace existed, which leaves the mirror stalled
// for that one VM rather than removing an object on evidence just admitted to be
// partial.
func destructive(a Action) bool {
	return a.Op == "delete" || a.Op == "clear" || a.Op == opReplace
}

// provenRemovable reports whether this node can CONCLUDE, from records it holds
// itself, that the thing this destructive action would take away is one the
// mirror must no longer hold.
//
// Not "holds a record of", which is what it used to say and what its VM half
// used to implement. A record can just as easily say the thing is still there,
// or say only that the mirror once created an object for it. Which record it is
// decides the answer — see vmRemovalProven.
//
// A CLEAR asks about the ADDRESS, not the interface. The interface is in the
// desired set by construction (Diff only computes a clear for a NIC it is
// mirroring), so a NIC-keyed question here would be answered yes every time and
// would prove nothing at all. What is unproven is the claim "no lease of ours
// names this address", and the lease row — live or tombstoned — is the evidence
// for it.
//
// BOTH VM REMOVALS ASK ONE QUESTION, and it is vmRemovalProven's. The vm/delete
// and the vm/replace differ in when they run and in what they unblock, never in
// what would make removing a VM object justified, and the two rounds of findings
// here were both a path answering it its own way: the replace on a NAME (proved
// by the beneficiary of the removal), then the delete on a NAME (proved by
// whichever incarnation last held it). So neither branch below has an evidence
// question of its own — they share one, and a change to the policy cannot reach
// one path and miss the other.
//
// An op or Kind it does not recognise is NOT proven. A third of either added
// without a matching evidence question must fail closed rather than inherit a
// permissive default.
func provenRemovable(a Action, actual Actual, nameByID map[int]string,
	known corrosion.MirrorEvidence, corr *removalCorroboration) bool {
	if a.Op == "clear" {
		return known.KnowsAddress(a.IPID)
	}
	if a.Op == opReplace {
		// Kind is checked, not assumed: Diff only ever builds a vm/replace, and
		// a NIC-kinded one reaching here would be asking a VM question about an
		// interface identity.
		if a.Kind != "vm" {
			return false
		}
		return vmRemovalProven(a.Key, known, corr)
	}
	if a.Op != "delete" {
		return false
	}
	switch a.Kind {
	case "vm":
		return vmRemovalProven(a.Key, known, corr)
	case "nic":
		n := actual.NICs[a.Key]
		return known.KnowsNIC(nameByID[n.VMID], n.MAC)
	default:
		return false
	}
}

// vmRemovalProven is THE removal-evidence policy for a VM object, and the only
// one: both the ordinary vm/delete and the vm/replace reach it.
//
// TWO REQUIREMENTS, NOT ONE. That is the whole of it, and each was a separate
// finding when it was missing:
//
//  1. INCARNATION-SPECIFIC EVIDENCE, never the name. `identity` carries the
//     incarnation uuid, and every record corrosion classifies is keyed on it, so
//     no row of a different VM sharing the name can answer for it. A name-keyed
//     premise fails in both directions — the replace's name is held by the VM
//     the replace is FOR, and the delete's name is held by whichever incarnation
//     used it last.
//  2. A JUSTIFIED CONCLUSION that the mirror must no longer represent this
//     incarnation. Being able to NAME the incarnation is not that conclusion,
//     which is exactly the step the previous round skipped: it asked for
//     incarnation-specific evidence, got incarnation-specific IDENTIFICATION,
//     and treated it as authorization.
//
// WHAT SATISFIES THE SECOND REQUIREMENT, per record:
//
//   - A TOMBSTONE for this exact incarnation justifies absence on its own.
//     litevirt soft-deletes, so this is what a destroyed incarnation leaves, and
//     no peer can be running a VM whose row this cluster has tombstoned.
//   - A LIVE row that is a TEMPLATE justifies the removal WITHOUT justifying
//     absence, and it is the one record of that shape. The incarnation exists,
//     and the mirror deliberately does not represent it — desiredState skips a
//     template because a template is a disk image, not a running machine — so
//     this node can read the reason its object is unwanted straight off the row
//     it holds. Every OTHER live row is the opposite answer.
//   - A LIVE row that is not a template means THE INCARNATION EXISTS, so no
//     removal. Reaching here on one means the desired read and the evidence read
//     disagree about the same row, and the safe reading of a contradiction is to
//     act on neither half of it.
//   - A MAPPING ROW ALONE justifies NOTHING about absence. It proves this node's
//     mirror created that object for that incarnation — replication is per
//     TABLE, so it is precisely what a node holds for an incarnation whose `vms`
//     row has not arrived and whose VM may be live on a peer. It becomes a
//     justified absence only when THE INVENTORY READ IT IS ABSENT FROM — that
//     read, not a later one — is corroborated as the cluster's: every
//     participant's address-bearing tables agreeing with the sample this pass
//     was computed from means no host holds a row for this uuid, and a VM nobody
//     holds a row for is not running anywhere. See removalCorroboration, which
//     asks a proof BOUND to that sample and reuses the bind path's own machinery
//     rather than inventing a second notion of a whole read.
//   - NO RECORD withholds, as it always has.
//
// The corroboration is asked ONLY on the mapping-only branch. It is a peer
// fan-out, and every other branch is answered from a local row.
func vmRemovalProven(identity string, known corrosion.MirrorEvidence, corr *removalCorroboration) bool {
	switch known.VMRemoval(identity, netbox.IdentityVMUUID(identity)) {
	case corrosion.VMRemovalRetired, corrosion.VMRemovalLiveTemplate:
		return true
	case corrosion.VMRemovalMirroredOnly:
		return corr.corroborated()
	default:
		// VMRemovalLive — it exists — and VMRemovalNoRecord, which is the
		// unhydrated node. A record class added to corrosion without a decision
		// here lands on this branch and withholds.
		return false
	}
}

// removalCorroboration is this pass's answer to "is this node's inventory read
// the CLUSTER's?", asked at most once and only if a removal actually needs it.
//
// WHY THE QUESTION EXISTS. One removal record — the mirror's own mapping row —
// identifies an incarnation without saying whether it stopped existing, and the
// gap between those two is where a deletion of a live peer's VM object fitted.
// What closes it is not a stronger local read: replication is per TABLE, and
// nothing in the schema records how much of a table this node has received, so
// no local signal can tell "no row for this uuid" from "that row has not arrived
// yet". The second signal has to be the cluster, asked.
//
// WHAT IT ASKS IS THE PREFIX BIND'S OWN PROOF, unchanged and not a second
// notion of the same thing: every host in the closed participant universe —
// offline, fenced, tombstoned and witness hosts included, because a host that
// cannot be reached still HOLDS its rows — is asked for its digest of every
// address-bearing table, and they must all AGREE with this node's. Two
// mechanisms answering one question is how several findings on this path
// survived, so there is one, wired in from where it already lives.
//
// ASKED LAZILY, AND ONCE. It dials peers, so a pass whose every removal rests on
// a tombstone must not pay for it — and two candidates in one pass must not each
// pay, nor be allowed to get different answers from two fan-outs a write could
// land between.
//
// ASKED LATE, ABOUT AN INVENTORY SAMPLED EARLY. Lazy is right for the fan-out
// and wrong for the SAMPLE: by the time a mapping-only removal turns up, the
// read that removal is measured against is already several reads and several
// NetBox round trips old. So the pass hands in an InventoryProof bound to the
// inventory it read, taken before it read anything, and this asks that proof.
// Sampling here instead would answer about the inventory as it is now — a
// different state from the one that produced the conclusion, which is how a live
// VM's object was once deleted on a perfectly successful proof.
//
// FAIL CLOSED, including the unwired case: no asker is not a corroborated
// inventory, and the removal is withheld. The reason is kept for the log line,
// because "not corroborated" with nothing attached is what an operator cannot
// act on.
type removalCorroboration struct {
	ask  func() (bool, string)
	done bool
	ok   bool
	why  string
}

// bindInventory samples the inventory this pass will read its conclusions from,
// and returns the proof bound to that sample.
//
// Nil in, nil out, and a sampler that could not read its own digests returns nil
// too: every one of those is "not corroborated" at the point the question is
// asked (see removalCorroboration), so an unwired or unreadable mirror withholds
// a mapping-only removal rather than authorizing one.
func (r *Reconciler) bindInventory(ctx context.Context) InventoryProof {
	if r.inventorySnapshot == nil {
		return nil
	}
	return r.inventorySnapshot(ctx)
}

// removalCorroboration binds this pass's corroboration to its context and to the
// SNAPSHOT the pass's conclusions were read from.
//
// The proof is taken by the caller before any read (see sweep) and passed in
// here, so nothing on this path can reach a corroboration of a different read:
// there is no sampler to call late. That is the structural half of the fix — the
// proof's own binding check is the other, and neither is enough alone.
//
// The context is captured here rather than stored on the value: the fan-out
// belongs to ONE pass, and a struct carrying a context is one refactor away from
// being reused across two.
func (r *Reconciler) removalCorroboration(ctx context.Context, proof InventoryProof) *removalCorroboration {
	return &removalCorroboration{ask: func() (bool, string) {
		if proof == nil {
			return false, "this mirror has no inventory proof for the read this pass was " +
				"computed from, so no absence can be concluded from a mapping row alone"
		}
		return proof.Corroborated(ctx)
	}}
}

// corroborated answers the question, asking at most once per pass.
func (c *removalCorroboration) corroborated() bool {
	if !c.done {
		c.done = true
		c.ok, c.why = c.ask()
	}
	return c.ok
}

// reason is what to tell an operator about a corroboration that came back
// negative, or "" when it was never needed or came back positive.
//
// "not asked" and "asked and agreed" are deliberately the same empty answer:
// both mean the corroboration is not why anything was withheld.
func (c *removalCorroboration) reason() string {
	if !c.done || c.ok {
		return ""
	}
	if c.why == "" {
		return "this node's inventory read could not be corroborated as the cluster's"
	}
	return c.why
}

// hasRemovals reports whether the list holds any destructive action at all.
func hasRemovals(actions []Action) bool {
	for _, a := range actions {
		if destructive(a) {
			return true
		}
	}
	return false
}

// withoutDestructive returns the actions that TAKE nothing away, and how many
// it dropped.
//
// Both destructive ops go, not just the delete. A `clear` is bounded — it
// unassigns an address rather than destroying it, and the next healthy sweep
// re-assigns — but it is still the mirror removing something on evidence it has
// just admitted is partial, and the shape that reaches it is common: an
// unhydrated `ip_allocations` resolves EVERY NIC to address 0, which reads as
// "this NIC holds no address" and routes every litevirt-owned address in the
// cluster into the clear branch. Withholding the delete while letting that
// through would detach the whole fleet's addressing on the pass that proved it
// could not be trusted to.
//
// Creates, updates, assigns and PARKS are kept deliberately. They are additive,
// so the worst a partial read costs there is an object or an assignment that a
// later pass reconciles — leak over collision, the same direction every other
// fail-closed decision in this package takes. The one create that is NOT purely
// additive — the one whose name is held by a superseded incarnation — does not
// carry the removal itself: that is a separate vm/replace action, which
// destructive covers and this therefore drops.
//
// The park stays for the same reason an update does, and its own premise cannot
// be weakened by a partial read: every edge of the blocked-by graph requires the
// holder's identity to be IN the desired set, so a read missing rows loses edges
// and can only make a cycle vanish. What it writes is a name on a live object of
// ours that the next pass renames again — see opPark.
//
// It filters the ACTION LIST rather than skipping the destructive PHASES: a
// phase is a scheduling boundary, and one skipped by a flag is one a later
// ordering change can quietly reintroduce. An action that does not exist cannot
// run, whatever the phase runner does with it.
//
// It calls destructive rather than re-spelling the op pair, so the whole-list
// drop and the per-object gate cannot disagree about what "destructive" means:
// an op added to one and not the other is how this gate would develop a hole
// that every test still passes over.
func withoutDestructive(actions []Action) ([]Action, int) {
	kept := make([]Action, 0, len(actions))
	for _, a := range actions {
		if destructive(a) {
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

// ClusterName is the NetBox cluster name this litevirt cluster mirrors under —
// the configured override, the local cluster name, or the placeholder, in that
// order.
//
// Exported because the CA re-key — in internal/grpcapi, which owns the operation
// but not the mirror — has to resolve the SAME cluster object the mirror writes
// into, to enumerate the inventory it must re-stamp. A second copy of this
// precedence would strand every object a mirror wrote the moment the two
// resolutions diverged, with nothing failing to say so.
//
// The override short-circuits the read: an operator who has named the cluster
// explicitly has said everything there is to say, and a `cluster` row that
// cannot be read must not change which objects a re-key can find.
func ClusterName(ctx context.Context, db *corrosion.Client, override string) (string, error) {
	if override != "" {
		return override, nil
	}
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
// Named after the operator's own cluster name, never after the fingerprint: a
// fingerprint that moved would point the mirror at a NEW cluster object and
// orphan everything under the old one. (The fingerprint is minted once and does
// not track `ca.crt` — see corrosion.EnsureClusterRecord — so replacing the CA
// is not what moves it.) Two installations sharing a name therefore share a cluster object, and that
// is NOT harmless: a NetBox cluster is the scope in which NetBox enforces one VM
// name per cluster, so the two share the namespace their VM names live in. The
// delete half is safe — every object is scoped by the identity fingerprint,
// which is what BuildActual and Diff filter on — but a create is not, and the
// collision is what `netbox.cluster_name` and Diff's name guard exist for.
func (r *Reconciler) ensureCluster(ctx context.Context) (int, error) {
	typeID, err := r.nb.EnsureClusterType(ctx, clusterTypeName)
	if err != nil {
		return 0, fmt.Errorf("cluster type %q: %w", clusterTypeName, err)
	}
	name, err := ClusterName(ctx, r.db, r.clusterName)
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
	byLease, ambiguous := indexLeases(leases)

	// One device lookup per HOST, not per VM: a sweep over a large cluster
	// otherwise issues one NetBox request per VM to resolve the same handful of
	// hosts.
	devices := map[string]int{}

	out := make([]DesiredVM, 0, len(vms))
	// An ambiguous lease key is a partial read exactly as an unreadable spec is:
	// it leaves the mirror unable to say which address a NIC holds. It is
	// counted here so ONE rule covers both — see deleteBlocker.
	skipped := ambiguous
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

		nicSet, nicsSkipped := desiredNICs(nics, byLease)
		skipped += nicsSkipped
		out = append(out, DesiredVM{
			Name:     v.Name,
			Host:     v.HostName,
			UUID:     spec.UUID,
			Status:   netboxStatus(v.State),
			VCPUs:    orSpec(v.CPUActual, spec.CPU),
			MemoryMB: orSpec(v.MemActual, spec.MemoryMiB),
			DiskMB:   totalDiskMB(disks),
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
func desiredNICs(nics []corrosion.NICRecord, byLease map[string]int) ([]DesiredNIC, int) {
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
			NetBoxIPID: byLease[leaseKey(n.NetworkName, strings.ToLower(n.MAC))],
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

// indexLeases builds the (network, MAC) -> NetBox address id index the desired
// side resolves each NIC's address through, and reports how many lease rows it
// could NOT place.
//
// A duplicate key is the whole reason this is a function rather than a two-line
// loop. `leaseKey` is not a uniqueness constraint anywhere in litevirt: the
// `ip_allocations` primary key is (network, ip), and the only MAC-collision
// check on the attach path is per-VM — so two VMs given the same MAC on one
// bound network leave two LIVE leases under one key, each naming a different
// address object. ListNetBoxLeases has no ORDER BY, so which of them a plain
// `m[k] = v` loop would keep is not even stable between sweeps.
//
// Whichever it kept, the other NIC would resolve to it: the mirror would attach
// one workload's address to the other's interface and detach it from the one
// that holds the lease, while both `ip_allocations` rows stayed live so the
// orphan sweeper could never see the stranding.
//
// So the group is DROPPED, not resolved. There is no winner to pick — the two
// rows are equally real, and picking either one drives a write on ownership the
// mirror cannot establish. Dropping it leaves both NICs resolving to address 0,
// which is "this NIC holds no NetBox address": no assign is computed for either,
// and the count returned here withholds the destructive half of the pass (see
// deleteBlocker), so the address the mirror could not resolve is not detached
// either. The duplicate is left for an operator, named in the log.
func indexLeases(leases []corrosion.LeaseRecord) (map[string]int, int) {
	grouped := make(map[string][]corrosion.LeaseRecord, len(leases))
	for _, l := range leases {
		k := leaseKey(l.Network, l.MAC)
		grouped[k] = append(grouped[k], l)
	}
	out := make(map[string]int, len(grouped))
	var ambiguousKeys []string
	dropped := 0
	for k, group := range grouped {
		if len(group) == 1 {
			out[k] = group[0].NetBoxIPID
			continue
		}
		ambiguousKeys = append(ambiguousKeys, k)
		// Every row in the group is a record this read could not use, not just
		// the ones after the first: with no way to tell which NIC owns which
		// address, none of them resolves.
		dropped += len(group)
	}
	// Sorted, so a cluster carrying more than one duplicate logs them in the
	// same order every sweep instead of reshuffling an operator's log.
	sort.Strings(ambiguousKeys)
	for _, k := range ambiguousKeys {
		group := grouped[k]
		ips := make([]string, 0, len(group))
		addrs := make([]int, 0, len(group))
		for _, l := range group {
			ips = append(ips, l.IP)
			addrs = append(addrs, l.NetBoxIPID)
		}
		sort.Strings(ips)
		sort.Ints(addrs)
		slog.Warn("netbox mirror: two or more live leases claim one MAC on one network, so "+
			"neither NIC's NetBox address can be resolved; this pass assigns none of them, "+
			"detaches none of them and withholds its deletes — give each NIC a unique MAC "+
			"on this network, or release the lease that should not exist",
			"network", group[0].Network, "mac", group[0].MAC,
			"leased_ips", ips, "netbox_address_ids", addrs)
	}
	return out, dropped
}

// leaseKey keys a lease by (network, MAC) — not by (network, ip), which is the
// row's primary key.
//
// The NetBox address object is named by the NIC's IDENTITY,
// lv:<fingerprint>:<uuid>:<mac>, so the lookup that resolves it has to be keyed
// on an identity component. The recorded IP is not one: `vm_interfaces.ip` is
// an inventory field, and any disagreement between it and the IP the lease
// claimed — an operator edit, a scanner, a lease re-claimed at a new address —
// makes an IP-keyed lookup MISS. A miss reads as "this NIC holds no NetBox
// address", which routes a correct, live assignment into the clear branch and
// detaches it.
//
// The MAC is the same component the identity carries, so it cannot drift out
// from under the join the way the recorded IP can. It is NOT unique, though —
// nothing in litevirt enforces one MAC per network, and this key is therefore
// not a primary key masquerading under another name. indexLeases is what makes
// that safe: a key claimed twice resolves to nothing at all. Lower-cased at both
// ends because NetBox echoes MACs upper-cased and litevirt records them either
// way.
func leaseKey(network, mac string) string { return network + "\x00" + strings.ToLower(mac) }

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

// totalDiskMB sums a VM's disks in BYTES and converts once, at the NetBox
// boundary, into the unit `virtual_machine.disk` is counted in: decimal
// megabytes, rounded up.
//
// Deliberately NOT corrosion.DiskQuotaGiB. That helper rounds each disk up to
// whole gibibytes, which is right for quota admission — a project must never be
// under-charged for a partial GiB — and lossy for an inventory record: it
// reports a 64 MiB disk as 1 GiB before the megabyte conversion can see it.
// Quota and inventory answer different questions, and only quota's needs the
// rounding.
//
// The round trip is necessary but NOT sufficient here, and assuming otherwise
// is what let the gibibyte-into-a-megabyte-column bug survive: a value written
// in the wrong unit reads back in the wrong unit and compares equal to itself,
// so no amount of sweeping detects it. What pins the unit is an assertion on
// the number, in tests/fleet/netbox_mirror_test.go and
// internal/netbox/disk_megabytes_test.go.
func totalDiskMB(disks []corrosion.DiskRecord) int {
	var totalBytes int64
	for _, d := range disks {
		if d.SizeBytes > 0 {
			totalBytes += d.SizeBytes
		}
	}
	return netbox.DiskMBFromBytes(totalBytes)
}
