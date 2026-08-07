package health

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// VM runtime states reported by the runtime inventory — the single vocabulary the
// owner-assert reconciler interprets and the gRPC handler produces.
const (
	RuntimeAbsent         = "absent"
	RuntimeDefinedStopped = "defined_stopped"
	RuntimeRunning        = "running"
	RuntimeUnknown        = "unknown"
)

// peerRuntimeProbeTimeout bounds each peer runtime-inventory probe. PeerDial is lazy
// (it doesn't connect at construction), so an unreachable/segmented peer would
// otherwise hang on the reconciler's long-lived daemon context and wedge the
// whole tick (including normal reconcile + selfFence). A timed-out probe is
// treated as inconclusive (we just can't confirm absence). A var so tests can
// shrink it.
var peerRuntimeProbeTimeout = 3 * time.Second

// ownershipAssertDebounce is how long the "runs locally but the DB says another
// host" condition must persist before the reconciler reclaims ownership. The
// PRIMARY guards against racing a legitimate ownership move are the migration
// markers (state=migrating/pending) and the vm_lock lease; this debounce is a
// belt-and-suspenders for the brief window before such a marker lands. It must
// comfortably exceed that window without being so long that a genuine split is
// left unrepaired (the manual `lv doctor repair-owner` is always available for
// the urgent case).
const ownershipAssertDebounce = 2 * time.Minute

// workloadCapablePeers returns the hosts to corroborate runtime ownership
// against: every host that COULD be running the workload. We must include not
// just active hosts but draining/upgrading/offline ones too — a domain/container
// keeps running across a daemon re-exec (KillMode=process) and during a drain, so
// skipping them could miss a live copy and reclaim into a split-brain. We exclude
// only: self; witnesses (never host workloads, and may have no runtime → always
// "unknown", which would block every reclaim); and FENCED hosts (positively dead
// by fencing proof → their workloads are gone). An unreachable peer in any
// included state simply yields "inconclusive", which is safe.
func workloadCapablePeers(hosts []corrosion.HostRecord, self string) []string {
	var others []string
	for _, h := range hosts {
		if h.Name == self || h.IsWitness() || h.State == "fenced" {
			continue
		}
		others = append(others, h.Name)
	}
	return others
}

// localHostIsActiveWorker reports whether this host may perform a runtime
// ownership repair: it must be present, active, and a worker (never a witness).
func localHostIsActiveWorker(hosts []corrosion.HostRecord, self string) bool {
	for i := range hosts {
		if hosts[i].Name == self {
			return hosts[i].State == "active" && !hosts[i].IsWitness()
		}
	}
	return false
}

// SetPeerRuntimeChecker injects the peer runtime checker (answered from the
// peer's GetRuntimeInventory). Without it,
// runtime owner-assert is disabled (no peer corroboration possible).
func (r *Reconciler) SetPeerRuntimeChecker(fn func(ctx context.Context, host, name string) (string, error)) {
	r.checkPeerRuntime = fn
}

// SetOwnerAssertObserver registers a nil-safe observer of owner-assert outcomes.
func (r *Reconciler) SetOwnerAssertObserver(fn func(vm, result string)) { r.onOwnerAssert = fn }

func (r *Reconciler) observeOwnerAssert(vm, result string) {
	if r.onOwnerAssert != nil {
		r.onOwnerAssert(vm, result)
	}
}

// assertRuntimeOwnership reclaims ownership of VMs that run locally but whose DB
// row (the equal-timestamp LWW tie the resolver deliberately leaves unresolved
// for runtime repair) points at another host — but ONLY on positive,
// decision-complete proof that no other host also runs the VM.
//
// This is the automated, more-conservative sibling of the manual
// `lv doctor repair-owner`: it corroborates against EVERY workload-capable peer,
// not just the one the operator names, and stands down on any ambiguity. Only an
// active worker host (never a witness) runs this repair.
func (r *Reconciler) assertRuntimeOwnership(ctx context.Context) {
	if r.virt == nil || r.checkPeerRuntime == nil {
		return
	}
	localDomains, err := r.virt.ListDomains()
	if err != nil {
		slog.Error("owner-assert: list local domains", "error", err)
		return
	}
	hosts, err := corrosion.ListHosts(ctx, r.db)
	if err != nil {
		return
	}

	// Local host gate: only an ACTIVE WORKER may claim a workload. A witness votes
	// but never owns workloads (the witness invariant); a non-active local host
	// (draining/upgrading/fenced) must not be writing new ownership.
	if !localHostIsActiveWorker(hosts, r.hostName) {
		return
	}
	// Split-brain gate (Phase 1): once enforced cluster-wide, an owner-assert
	// reclaim (a runtime-ownership write) additionally requires local quorum —
	// an isolated minority worker must not re-key ownership. ExecutionGate-only:
	// this is a per-host reclaim, not a coordinator-forwarded action (no lease,
	// no proof). Fail-open until split_brain_gate_v1 is cluster-wide.
	if r.gate != nil && r.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
		if g := r.gate.ExecutionGate(ctx); !g.OK {
			slog.Info("owner-assert: execution gate refused reclaim (no quorum)", "reason", g.Reason)
			r.noteGateRefused(corrosion.ActionOwnerAssert, g.Reason)
			return
		}
	}
	others := workloadCapablePeers(hosts, r.hostName)

	seen := make(map[string]bool, len(localDomains))
	for _, domName := range localDomains {
		// Only a domain RUNNING locally is a candidate to claim — a stopped
		// leftover whose row moved elsewhere is selfFence's concern, not ours.
		state, serr := r.virt.DomainState(domName)
		if serr != nil || state != RuntimeRunning {
			continue
		}
		vm, gerr := corrosion.GetVM(ctx, r.db, domName)
		if gerr != nil || vm == nil {
			continue // external/manual domain — not cluster-managed
		}
		if vm.HostName == r.hostName {
			continue // already ours
		}
		// An ownership operation in flight → stand down (its marker/lease owns
		// the transition).
		if vm.State == "migrating" || vm.State == "pending" {
			continue
		}
		if r.activeVMLock(ctx, domName) {
			continue
		}

		seen[domName] = true
		// The condition must persist (debounce) before we act.
		if !r.ownershipDebounceElapsed(domName) {
			continue
		}
		r.tryAssertOwnership(ctx, domName, vm.HostName, others)
	}
	r.pruneOwnershipDebounce(seen)
}

// tryAssertOwnership runs the decision-complete corroboration: query every other
// workload-capable peer's local libvirt and act only on a unanimous result.
func (r *Reconciler) tryAssertOwnership(ctx context.Context, name, dbHost string, others []string) {
	anyRunning := false
	allAbsent := true
	for _, h := range others {
		// Bound each probe so an unreachable/segmented peer can't stall the tick.
		pctx, cancel := context.WithTimeout(ctx, peerRuntimeProbeTimeout)
		st, err := r.checkPeerRuntime(pctx, h, name)
		cancel()
		if err != nil {
			// Unreachable / segmented / timed-out / old build with no
			// the runtime probe → we cannot confirm absence, so we must not assert.
			allAbsent = false
			slog.Info("owner-assert: peer unreachable, deferring", "vm", name, "peer", h, "error", err)
			continue
		}
		switch st {
		case RuntimeAbsent:
			// good — this host does not have the VM
		case RuntimeRunning:
			anyRunning = true
			allAbsent = false
		default: // defined_stopped, unknown → ambiguous, blocks the assert
			allAbsent = false
		}
	}

	switch {
	case anyRunning:
		// TRUE SPLIT-BRAIN: the VM runs here AND on another host. A stable
		// host-order tiebreak is NOT proof for two live disk writers; destruction
		// requires positive fencing/quorum proof (the existing fencing path),
		// absent here. Alert and require manual intervention — never ping-pong.
		slog.Error("owner-assert: SPLIT-BRAIN — VM runs locally AND on another host; refusing to act, manual intervention required",
			"vm", name, "local_host", r.hostName, "db_host", dbHost)
		r.observeOwnerAssert(name, "split_brain")
	case !allAbsent:
		// A peer was unreachable / reported defined_stopped / unknown → not
		// decision-complete. Take no action; retry next cycle.
		slog.Info("owner-assert: inconclusive (a peer is unreachable or holds a stale definition); will retry",
			"vm", name, "db_host", dbHost)
		r.observeOwnerAssert(name, "inconclusive")
	default:
		// Decision-complete: every workload-capable peer answered ABSENT and the VM
		// runs here → reclaim ownership with a fresh timestamp (wins by ordinary
		// LWW everywhere). Non-destructive: a DB row write only.
		//
		// Phase 4: the re-key is an ownership transition — CAS on the epoch the
		// decision was made against and advance it. A lost CAS means the row moved
		// while probes ran; refuse and let the next assert pass re-decide.
		fresh, gerr := corrosion.GetVM(ctx, r.db, name)
		if gerr != nil || fresh == nil {
			slog.Warn("owner-assert: re-read before re-key failed", "vm", name, "error", gerr)
			r.observeOwnerAssert(name, "error")
			return
		}
		// EXACT-MARKER PROOF. The re-key supersedes fresh.OwnerEpoch, so this
		// host's own marker must say its runtime BELONGS to exactly that epoch:
		//
		//   - unreadable/corrupt evidence NEVER authorizes (garbage read as any
		//     epoch is how stale actions get authorized);
		//   - an UNEQUAL marker means this runtime is from another generation —
		//     older (superseded, must not resurrect) or newer (the DB row is the
		//     stale one and will catch up) — either way not ours to re-key;
		//   - a MISSING marker refuses once owner_epoch_v1 is enforced; before
		//     the latch, pre-epoch runtimes legitimately have none and the
		//     unanimous-absence rule above remains the (weaker) standard.
		markerEpoch, found, merr := ReadVMOwnerEpochMarker(r.dataDir, name)
		switch {
		case merr != nil:
			slog.Warn("owner-assert: refusing re-key — owner-epoch marker unreadable or corrupt",
				"vm", name, "error", merr)
			r.observeOwnerAssert(name, "marker_unreadable")
			return
		case found && markerEpoch != fresh.OwnerEpoch:
			slog.Warn("owner-assert: refusing re-key — marker epoch does not equal the DB epoch being superseded",
				"vm", name, "marker_epoch", markerEpoch, "db_epoch", fresh.OwnerEpoch)
			r.observeOwnerAssert(name, "marker_epoch_mismatch")
			return
		case !found && r.ownerEpochEnforced(ctx):
			slog.Warn("owner-assert: refusing re-key — owner-epoch marker missing under owner_epoch_v1",
				"vm", name)
			r.observeOwnerAssert(name, "marker_missing")
			return
		}
		// An ACTIVE ownership condition on this workload freezes automated
		// repair outright: the evaluator has standing evidence of a dispute,
		// and repairing under a dispute is how the dispute becomes damage.
		if disputed, code, cerr := corrosion.WorkloadHasActiveOwnershipCondition(ctx, r.db, "vm", name); cerr != nil {
			slog.Warn("owner-assert: cannot read health conditions; deferring", "vm", name, "error", cerr)
			r.observeOwnerAssert(name, "inconclusive")
			return
		} else if disputed {
			slog.Warn("owner-assert: refusing re-key — active ownership condition", "vm", name, "condition", code)
			r.observeOwnerAssert(name, "disputed")
			return
		}
		if err := corrosion.TransferVMOwner(ctx, r.db, name, r.hostName, RuntimeRunning, fresh.OwnerEpoch); err != nil {
			slog.Warn("owner-assert: epoch-guarded re-key refused or failed", "vm", name, "error", err)
			r.observeOwnerAssert(name, "error")
			return
		}
		slog.Warn("owner-assert: reclaimed VM ownership — runs locally and all workload-capable peers report absent",
			"vm", name, "from_host", dbHost, "to_host", r.hostName)
		r.auditOwnerAssert(ctx, name, dbHost)
		r.observeOwnerAssert(name, "asserted")
		r.clearOwnershipDebounce(name)
	}
}

// activeVMLock reports whether a non-expired vm_lock exists for vmName (any
// holder) — an ownership operation may be in flight, so stand down. Fails safe
// (treats a read error as "locked").
func (r *Reconciler) activeVMLock(ctx context.Context, vmName string) bool {
	now := r.now().UTC().Format(time.RFC3339)
	rows, err := r.db.Query(ctx,
		`SELECT 1 FROM vm_locks WHERE vm_name = ? AND expires_at > ?`, vmName, now)
	if err != nil {
		return true
	}
	return len(rows) > 0
}

// ownershipDebounceElapsed records first-observation and reports whether the
// condition has persisted at least ownershipAssertDebounce.
func (r *Reconciler) ownershipDebounceElapsed(vm string) bool {
	r.ownerMu.Lock()
	defer r.ownerMu.Unlock()
	if r.ownershipFirstSeen == nil {
		r.ownershipFirstSeen = make(map[string]time.Time)
	}
	first, ok := r.ownershipFirstSeen[vm]
	if !ok {
		r.ownershipFirstSeen[vm] = r.now()
		return false
	}
	return r.now().Sub(first) >= ownershipAssertDebounce
}

func (r *Reconciler) clearOwnershipDebounce(vm string) {
	r.ownerMu.Lock()
	delete(r.ownershipFirstSeen, vm)
	r.ownerMu.Unlock()
}

// pruneOwnershipDebounce drops entries for VMs that no longer meet the condition
// (converged, stopped, or moved) so the debounce timer restarts cleanly next time.
func (r *Reconciler) pruneOwnershipDebounce(stillCandidate map[string]bool) {
	r.ownerMu.Lock()
	for vm := range r.ownershipFirstSeen {
		if !stillCandidate[vm] {
			delete(r.ownershipFirstSeen, vm)
		}
	}
	r.ownerMu.Unlock()
}

func (r *Reconciler) auditOwnerAssert(ctx context.Context, name, fromHost string) {
	_ = corrosion.InsertAuditLog(ctx, r.db, corrosion.AuditRecord{
		ID:       ownerAssertID(),
		Username: "system",
		HostName: r.hostName,
		Action:   "vm.runtime-owner-assert",
		Target:   name,
		Detail:   "reclaimed from " + fromHost + " (runs locally; all workload-capable peers absent)",
		Result:   "ok",
	})
}

func ownerAssertID() string {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return hex.EncodeToString(b)
}
