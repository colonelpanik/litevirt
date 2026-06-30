package health

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// VM runtime states reported by CheckVMRuntime — the single vocabulary the
// owner-assert reconciler interprets and the gRPC handler produces.
const (
	RuntimeAbsent         = "absent"
	RuntimeDefinedStopped = "defined_stopped"
	RuntimeRunning        = "running"
	RuntimeUnknown        = "unknown"
)

// peerRuntimeProbeTimeout bounds each peer CheckVMRuntime probe. PeerDial is lazy
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

// SetPeerRuntimeChecker injects the peer CheckVMRuntime client. Without it,
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
	// (draining/upgrading/fenced) must not be writing new ownership. If our own
	// row is missing/witness/non-active, stand down entirely.
	var self *corrosion.HostRecord
	for i := range hosts {
		if hosts[i].Name == r.hostName {
			self = &hosts[i]
			break
		}
	}
	if self == nil || self.State != "active" || self.IsWitness() {
		return
	}

	// Corroborate against every peer that COULD be running the VM. We must include
	// not just active hosts but draining/upgrading/offline ones too — a domain
	// keeps running across a daemon re-exec (KillMode=process) and during a drain,
	// so skipping them could miss a live copy and assert into a split-brain. We
	// exclude only: self; witnesses (never host workloads, and may have no libvirt
	// → always "unknown", which would block every reclaim); and FENCED hosts
	// (positively dead by fencing proof → their domains are gone). An unreachable
	// peer in any included state simply yields "inconclusive", which is safe.
	var others []string
	for _, h := range hosts {
		if h.Name == r.hostName || h.IsWitness() || h.State == "fenced" {
			continue
		}
		others = append(others, h.Name)
	}

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
			// CheckVMRuntime → we cannot confirm absence, so we must not assert.
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
		if err := corrosion.UpdateVMHost(ctx, r.db, name, r.hostName, RuntimeRunning); err != nil {
			slog.Warn("owner-assert: UpdateVMHost failed", "vm", name, "error", err)
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
