package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netboxsync"
)

// The NetBox inventory mirror's wiring.
//
// The reconciler itself lives in internal/netboxsync, which knows nothing about
// this package. What it cannot own is the LEADER LEASE: the mirror runs under
// the SAME `leader_election` key as the orphan sweeper (netBoxLeaseKey), and
// two keys would let the sweeper and the mirror each believe it leads the
// cluster — one reclaiming addresses while the other rewrote the inventory that
// names them. So the lease is threaded in as two function values here rather
// than reimplemented there, and there is exactly one copy of the SQL.

// netboxMirror builds the reconciler for this node.
//
// A fresh value per pass. The reconciler carries per-sweep state (the resolved
// NetBox cluster id), so a long-lived one shared between the ticker and a
// harness-driven pass would let one pass observe the other's half-resolved
// state.
func (s *Server) netboxMirror(interval time.Duration) *netboxsync.Reconciler {
	interval = effectiveNetBoxSweepInterval(interval)
	return netboxsync.New(netboxsync.Options{
		NetBox:   s.netbox,
		DB:       s.db,
		Metrics:  s.nbMetrics(),
		Interval: interval,
		// HALF an interval behind the maintenance loop. Both run on this same
		// cadence and serialise on this same node's nbPassMu, and the daemon
		// starts them microseconds apart — so without the skew the mirror's
		// sweep reaches the gate second every time and is declined for the life
		// of the process. That starves the whole mirror rather than one tick:
		// the sweep is the only caller that ACQUIRES the leader lease, and the
		// queue poll acts only on a lease already held. See Options.SweepPhase.
		SweepPhase:  interval / 2,
		ClusterName: s.netboxClusterName,
		// The TTL is sized from the cadence this node actually runs at, exactly
		// as the sweeper's is, so a cluster on a slower cadence does not hand
		// leadership away between its own passes.
		AcquireLease: func(ctx context.Context) bool { return s.acquireNetBoxLease(ctx, interval) },
		HoldsLease:   s.netboxMirrorHoldsLease,
		// A closure, so both latches AND the cluster-name pin are re-read on
		// EVERY pass. See netboxMirrorPassAuthorized.
		Latched: s.netboxMirrorPassAuthorized,
		// The cluster half of the mirror's removal-evidence policy. The mirror
		// cannot own it: the answer is a fan-out over the closed participant
		// universe, which lives here beside the prefix bind that already
		// requires the identical property. See corroborateMirrorInventory.
		//
		// A SAMPLER, not a predicate. The mirror takes this at the top of a pass
		// and asks the value it returns later, so the proof answers for the read
		// the pass was computed from rather than for whatever the tables hold by
		// the time some removal turns out to need it. See
		// netboxInventorySnapshot.
		InventorySnapshot: s.netboxInventorySnapshot,
		// The intra-node half of the exclusion the leader lease only covers
		// across nodes. See netboxExclusivePass.
		Exclusive: s.netboxExclusivePass,
	})
}

// netboxInventorySnapshot samples this node's inventory digests and returns the
// mirror's corroboration BOUND to that sample.
//
// The binding is the whole reason this is two steps. The mirror reads its
// desired state and its removal evidence, diffs against NetBox, and only then
// discovers that some removal rests on a mapping row alone; a predicate that
// sampled its own digests at that moment would certify a different read from the
// one the conclusion came out of. So the sample is taken here, before the pass
// reads anything, and travels with the pass — see netboxsync.InventoryProof and
// corroborateMirrorInventory, which requires the sample to still be this node's
// own read before it compares it with a peer's.
//
// A sampling failure returns a proof that answers NO with the reason, rather
// than a nil the caller has to remember to check: an unreadable digest is not a
// corroborated inventory.
func (s *Server) netboxInventorySnapshot(ctx context.Context) netboxsync.InventoryProof {
	bound, err := s.localTableDigests(ctx, adoptionInventoryTables())
	if err != nil {
		return unreadableInventory{err: err}
	}
	return boundInventory{s: s, bound: bound}
}

// boundInventory is one sampled inventory, and the corroboration of THAT
// inventory.
type boundInventory struct {
	s     *Server
	bound map[string]corrosion.TableDigest
}

// Corroborated answers for the bound sample. See corroborateMirrorInventory.
func (b boundInventory) Corroborated(ctx context.Context) (bool, string) {
	return b.s.corroborateMirrorInventory(ctx, b.bound)
}

// unreadableInventory is the sample that could not be taken. It answers no,
// always, and carries the read failure to the operator-facing line.
type unreadableInventory struct{ err error }

// Corroborated reports that nothing was sampled, so nothing can be corroborated.
func (u unreadableInventory) Corroborated(context.Context) (bool, string) {
	return false, fmt.Sprintf("this node's own inventory digests could not be sampled before "+
		"the pass read its state (%v), so no absence can be concluded from a mapping row alone",
		u.err)
}

// NetBoxInventorySnapshotOnce samples the mirror's inventory proof once, exactly
// as a pass does.
//
// It exists so a scenario can drive the PRODUCTION sampler and the PRODUCTION
// corroboration on a cluster whose nodes hold genuinely divergent databases —
// which is the state the whole policy turns on, and the one thing a
// single-package test cannot build: it needs two real daemons, two real local
// databases and the real peer fan-out. It hands back the bound proof rather than
// an answer, because the binding is the property under test: a scenario asks it
// AFTER doing whatever the pass would have done in between. The mirror's own
// passes call the wired sampler, not this.
func (s *Server) NetBoxInventorySnapshotOnce(ctx context.Context) netboxsync.InventoryProof {
	return s.netboxInventorySnapshot(ctx)
}

// effectiveNetBoxSweepInterval is the cadence a mirror built with this argument
// actually runs at.
//
// It exists so the normalisation has ONE home. `netbox.sweep_interval_sec`
// defaults to 0, and every consumer of that zero has to reach the same answer:
// the reconciler's cadence, the leader lease TTL sized from it, and the line
// StartNetBoxMirror logs. The log was the one that did not — it printed the raw
// argument, so an unset key read `sweep_interval=0s` while the mirror swept
// every 15 minutes, which is exactly the logged-vs-used divergence these lines
// exist to make findable.
func effectiveNetBoxSweepInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return defaultNetBoxSweepInterval
	}
	return interval
}

// netboxExclusivePass runs one NetBox pass under this node's single-pass gate,
// or declines it.
//
// DECLINES, rather than waits. A background pass has another tick a minute or
// fifteen away, and queueing them behind a re-key that runs for as long as
// NetBox takes would leave a pile of passes to run back to back the moment it
// finished — every one of them reading state the one before it had just
// rewritten.
//
// A declined pass returns nil and records nothing. It is not a failure: nothing
// was skipped that the next pass does not re-derive from scratch, and counting
// it as a failed sweep would raise the mirror's staleness signal every time an
// operator re-keyed.
func (s *Server) netboxExclusivePass(ctx context.Context, pass func(context.Context) error) error {
	if !s.nbPassMu.TryLock() {
		slog.Info("netbox mirror: another NetBox pass or a re-key is already running on this " +
			"node; skipping this tick")
		return nil
	}
	defer s.nbPassMu.Unlock()
	return pass(ctx)
}

// netboxMirrorAuthorized reports whether inventory mirroring is authorized on
// this node: the local opt-in AND both cluster-wide latches, DURABLY.
//
// THREE conditions, and each answers a different question.
//
// `netbox.mirror_inventory` (enfNetBoxMirror) is whether this installation wants
// the inventory half at all. NetBox is two integrations behind one config block
// — an address authority and an inventory mirror — and only the first is the
// default. With this off, NetBox holds `ip_address` objects carrying our
// identity and nothing else: no `virtual_machine`, no `vminterface`, no assign
// and no clear. That is coherent rather than degraded, because the identity is
// what makes an address ours, and the orphan sweeper's negative proof is a
// per-host fan-out that never asks what an address is assigned to.
//
// netbox_mirror_v1 is whether the CLUSTER wants it. The sweep runs on whichever
// node holds the `netbox` leader lease, so a flag set on some nodes only makes
// the inventory appear and disappear with leadership, and strands every object
// the mirroring node created under a successor that never reaps it. The token is
// advertised only while the flag is set, so its latch proves config uniformity
// and not merely a uniform build — enabling on one node changes nothing.
//
// netbox_ipam_v1 remains required, for the reason it always was. The mirror
// writes `netbox_objects` and `netbox_sync_queue`, and a build that predates
// them carries neither table in either of its ledgers — a statement the LWW
// apply path cannot place does not fail on that peer, it BACK-PRESSURES, which
// stalls the replication watermark for the whole stream rather than for those
// rows. netbox_mirror_v1 cannot stand in for it: a cluster can opt into
// mirroring mid-rolling-upgrade, when every node has the flag but not every node
// has the tables.
//
// Both latches in their DURABLE form, the same form a prefix binding requires. A
// latch held only in memory does not survive a restart, and the node that
// restarts mid-rolling-upgrade is the one still replicating with an old peer.
//
// The FLAG is checked here and not only at advertisement because a latch is
// monotone and durable: it can never be withdrawn, so a flag that stopped
// mattering once netbox_mirror_v1 formed would leave the mirror impossible to
// turn off. Checking it at the decision keeps it the reversible kill switch.
//
// It is a method rather than a captured bool so every pass asks again: a latch
// closes while the daemon runs, and nothing restarts the mirror when it does.
func (s *Server) netboxMirrorAuthorized() bool {
	if !s.enfNetBoxMirror || s.gate == nil {
		return false
	}
	return s.gate.DurablyLatched(capabilities.NetBoxMirrorV1) &&
		s.gate.DurablyLatched(capabilities.NetBoxIPAMV1)
}

// netboxMirrorHoldsLease is the lease READ — no write, no renewal — the mirror
// re-runs before each write batch, with the test seam folded in.
func (s *Server) netboxMirrorHoldsLease(ctx context.Context) bool {
	if s.nbLeaseProbe != nil {
		return s.nbLeaseProbe(ctx)
	}
	return s.holdsLeaderLease(ctx)
}

// StartNetBoxMirror starts the inventory mirror if — and only if — this node is
// configured for NetBox, and reports whether it did.
//
// The guard is the same one StartNetBoxMaintenance uses and for the same
// reason: a node with no NetBox client has nothing to mirror into, and the loop
// it would run could only ever be a goroutine taking no decisions. Every
// configured node runs it; the lease decides which one writes.
//
// The CAPABILITY latch is deliberately not checked here. It is checked once per
// pass instead (netboxMirrorAuthorized), because a latch forms while the daemon
// runs — it is the last act of a rolling upgrade — and a check made here would
// leave the mirror inert for the life of a process that started a moment too
// early, with nothing to say so.
//
// The LOCAL opt-in is different and IS checked here. `netbox.mirror_inventory`
// is read from a config file at startup and cannot change while the process
// runs, so a node that has not opted in will not opt in later — the goroutine it
// would start could only ever be a ticker taking no decisions, and answering
// false is what lets a caller (and a test) see that mirroring is off rather than
// infer it from an absence of writes. The per-pass gate still re-checks the
// flag, so nothing depends on this being the only place it is read.
func (s *Server) StartNetBoxMirror(ctx context.Context, interval time.Duration) bool {
	if s.netbox == nil || s.db == nil {
		return false
	}
	if !s.enfNetBoxMirror {
		return false
	}
	// Normalised BEFORE the log line below, not only inside netboxMirror: an
	// unset `netbox.sweep_interval_sec` arrives here as 0, and logging that
	// would report a cadence no mirror ever runs at.
	interval = effectiveNetBoxSweepInterval(interval)
	// The NetBox cluster this node would mirror into, named ONCE at startup.
	//
	// `netbox.cluster_name` has to be uniform cluster-wide and has no latch to
	// make it so: the sweep runs on whichever node holds the `netbox` lease, so
	// a value set on some nodes only duplicates the whole inventory into a
	// second `virtualization.cluster` at the first handover. A node cannot read
	// a peer's configured value, so this line is what makes a disagreement
	// findable — one comparison across the fleet's logs. Logged at start rather
	// than per sweep because it cannot change while the process runs, and a
	// per-sweep line would be noise on every node every interval.
	//
	// Best-effort: a name that cannot be resolved yet (the `cluster` row has not
	// healed) is not a reason to leave the mirror unstarted — the sweep resolves
	// it again, and fails there if it still cannot.
	if name, err := netboxsync.ClusterName(ctx, s.db, s.netboxClusterName); err == nil {
		slog.Info("netbox mirror: starting", "netbox_cluster", name,
			"from_config", s.netboxClusterName != "", "sweep_interval", interval)
	}
	go s.netboxMirror(interval).Run(ctx)
	return true
}

// RunNetBoxMirrorOnce runs exactly one leader-gated mirror pass. It exists so a
// test can drive a pass deterministically instead of waiting on a ticker,
// through the SAME gate the loop uses — a harness that reached past the gate
// could not tell a leader-gated mirror from an ungated one.
func (s *Server) RunNetBoxMirrorOnce(ctx context.Context) error {
	if s.netbox == nil || s.db == nil {
		return nil
	}
	return s.netboxMirror(defaultNetBoxSweepInterval).SyncOnce(ctx)
}

// The netbox_sync_queue ops the lifecycle paths record. The mirror resolves
// NOTHING from a queued item — the full sweep covers every object one could name
// — so these are for the operator reading the table, and for any future consumer
// that wants to act on one item without diffing the fleet.
const (
	mirrorOpUpsert = "upsert"
	mirrorOpDelete = "delete"
)

// enqueueMirrorSync names one VM for the inventory mirror's next pass.
//
// LATENCY ONLY. Every caller has already committed the operation locally, and
// the periodic full sweep converges the mirror whether or not anything was
// queued — which it has to, because a node that dies mid-operation never
// enqueues at all. So a failure here is logged and the operation continues:
// failing an operator's delete over a queue row would report a delete that
// genuinely happened as an error.
//
// Gated on a wired NetBox client. Without one nothing ever drains this queue,
// and every VM lifecycle operation on a cluster that does not use NetBox would
// leave a row behind forever.
//
// Gated on the capability latch as well, and for a different reason: the INSERT
// itself is a replicated statement against a table an older peer does not
// carry. The mirror loop's own gate cannot cover this one — it is a second
// producer, on the lifecycle paths, and a sweep that never runs still leaves
// these rows on the wire.
func (s *Server) enqueueMirrorSync(ctx context.Context, vmName, op string) {
	if s.netbox == nil || s.db == nil {
		return
	}
	if !s.netboxMirrorAuthorized() {
		return
	}
	if err := corrosion.EnqueueSync(ctx, s.db, netboxsync.QueueKind, vmName, op); err != nil {
		slog.Warn("netbox mirror: could not queue a VM for the mirror; the next full sweep covers it",
			"vm", vmName, "op", op, "error", err)
	}
}

// SetNetBoxLeaseProbe replaces the lease read the mirror re-validates before
// each write batch.
//
// Test-only seam, nil in production. It is the only way to model a leadership
// handover that lands MID-SWEEP, which is precisely what the per-batch
// re-validation exists for: a real lease can be stolen between passes, but not
// between two batches of one pass without racing the test.
//
// It deliberately does NOT replace the ACQUIRE. Folding it in there too would
// let the acquire's own read-back consume the seam's budget, and a scenario
// meaning "lose the lease after the first batch" would instead never start.
func (s *Server) SetNetBoxLeaseProbe(fn func(context.Context) bool) { s.nbLeaseProbe = fn }
