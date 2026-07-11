package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
)

const reconcileInterval = 15 * time.Second

// Reconciler watches for VMs in "pending" state on the local host
// and starts them. It also detects split-brain conditions where a VM
// is running locally in libvirt but corrosion says it belongs to another host.
type Reconciler struct {
	hostName         string
	dataDir          string
	db               *corrosion.Client
	virt             LibvirtBackend
	onVMStarted      func(ctx context.Context, stackName string)       // optional: called after VM starts (LB refresh)
	autoPullImage    func(ctx context.Context, imageName string) error // optional: auto-pull image from peer
	backupInProgress func(vmName string) bool                          // optional: is a backup actively running locally?
	firmware         lv.FirmwarePaths                                  // resolved OVMF paths (G1); set via SetFirmwarePaths

	// Now is the reconciler's clock for vm_lock lease timestamps. Defaults to
	// time.Now; the fleet harness overrides it so lock-expiry scenarios advance
	// deterministically without sleeping.
	Now func() time.Time

	// checkPeerRuntime asks a peer for its LOCAL libvirt view of a VM
	// (absent/defined_stopped/running/unknown) — injected by the daemon (it wires
	// the gRPC CheckVMRuntime client). nil disables runtime owner-assert (e.g. in
	// tests that don't exercise it). See SetPeerRuntimeChecker.
	checkPeerRuntime func(ctx context.Context, host, name string) (string, error)
	// onOwnerAssert observes each owner-assert decision (result ∈ asserted /
	// split_brain / inconclusive / error) — nil-safe; tests assert on it and
	// Phase 5 can wire a metric. See SetOwnerAssertObserver.
	onOwnerAssert func(vm, result string)

	// ownerMu guards ownershipFirstSeen, the debounce map recording when each VM
	// was first observed running-locally-but-owned-elsewhere, so a transient
	// in-flight ownership move isn't reclaimed before its marker lands.
	ownerMu            sync.Mutex
	ownershipFirstSeen map[string]time.Time

	// gate is the split-brain safety gate (Phase 1). When a pending VM carries a
	// proof marker (vms.pending_action_id), the reconciler enforces ExecutionGate
	// and validates/claims the linked runtime_action_proofs row before starting.
	// nil disables gating (tests that don't exercise it). See SetGate.
	gate runtimeGate
	// onGateRefused observes each gate/proof refusal (action, reason from the
	// closed vocab) — nil-safe; the daemon wires it to the refusal metric.
	onGateRefused func(action, reason string)
	// onStateWriteFail observes an authoritative state write that failed (nil-safe);
	// the daemon wires it to the litevirt_state_write_failures_total counter.
	onStateWriteFail func(op, class string)

	// onbootMu guards onbootPending: onboot VMs whose boot-time autostart the
	// split-brain gate refused (warmup / transient quorum loss). reconcile() retries
	// them each tick (dropping any now running) so a latched gate can't PERMANENTLY
	// strand onboot autostart after a reboot — the refusal is a safe gap that closes
	// when quorum returns. Only VMs that are onboot AND not-running-at-boot ever
	// enter this set, so a deliberately-stopped VM is never autostarted by the retry.
	onbootMu      sync.Mutex
	onbootPending map[string]corrosion.VMRecord
}

// runtimeGate is the subset of *Checker the reconciler needs (injectable for tests).
type runtimeGate interface {
	ExecutionGate(ctx context.Context) GateResult
	CapabilityActive(ctx context.Context, token string) (bool, string)
	// Enforced is the LATCHED enforcement decision (partition → fail closed).
	Enforced(ctx context.Context, token string) bool
	// SelfFenced reports whether THIS node has self-fenced (tripped the watchdog).
	SelfFenced() bool
}

// selfFenceHardGate reports whether a self-fenced node must refuse a runtime-ownership
// action HERE — unconditionally, before any marker/enforcement branch. A self-fenced node
// (doomed, waiting for the watchdog to reboot it) takes NO decide/execute at all. This is
// checked separately from ExecutionGate because the health loops only consult ExecutionGate
// on the marker-or-enforced path, while `vip_demote_v1` (whose demote-failure path can
// self-fence when a verified watchdog is armed) latches INDEPENDENTLY of
// `split_brain_gate_v1` — so a node can self-fence while the Phase-1 gate is unenforced
// and would otherwise take the legacy (ungated) markerless path.
func selfFenceHardGate(g runtimeGate) bool { return g != nil && g.SelfFenced() }

// SetGate injects the split-brain safety gate (the health.Checker).
func (r *Reconciler) SetGate(g runtimeGate) { r.gate = g }

// SetGateRefusedObserver wires the refusal metric hook (nil-safe).
func (r *Reconciler) SetGateRefusedObserver(fn func(action, reason string)) { r.onGateRefused = fn }

// SetStateWriteFailObserver wires the state-write-failure metric hook (nil-safe).
func (r *Reconciler) SetStateWriteFailObserver(fn func(op, class string)) { r.onStateWriteFail = fn }

func (r *Reconciler) noteStateWriteFail(op string, err error) {
	if r.onStateWriteFail != nil {
		r.onStateWriteFail(op, corrosion.ClassifyWriteErr(err))
	}
}

func (r *Reconciler) noteGateRefused(action, reason string) {
	if r.onGateRefused != nil {
		r.onGateRefused(action, reason)
	}
}

// SetFirmwarePaths injects the host's resolved OVMF firmware paths (G1) so the
// reconciler renders the same firmware as CreateVM when it rebuilds a domain.
func (r *Reconciler) SetFirmwarePaths(fp lv.FirmwarePaths) { r.firmware = fp }

// NewReconciler creates a VM reconciler for the local host. virt is a
// LibvirtBackend — production passes the real *libvirt.Client; tests/the fleet
// harness pass a fake. A nil virt is tolerated (the reconcile loop guards every
// use), so existing call sites that pass nil keep working.
func NewReconciler(hostName, dataDir string, db *corrosion.Client, virt LibvirtBackend) *Reconciler {
	return &Reconciler{
		hostName: hostName,
		dataDir:  dataDir,
		db:       db,
		virt:     virt,
	}
}

// now returns the reconciler's clock (overridable via Now for tests).
func (r *Reconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// SetOnVMStarted registers a callback invoked after a pending VM is started.
// Used to trigger LB refresh after failover.
func (r *Reconciler) SetOnVMStarted(fn func(ctx context.Context, stackName string)) {
	r.onVMStarted = fn
}

// SetAutoPullImage registers a callback to pull images from peers when missing locally.
func (r *Reconciler) SetAutoPullImage(fn func(ctx context.Context, imageName string) error) {
	r.autoPullImage = fn
}

// SetBackupInProgress registers a predicate reporting whether a backup is
// actively running locally for a VM. The reconciler uses it to avoid clearing
// the "backing-up" state of a genuinely in-flight backup. When nil, the
// reconciler treats any "backing-up" row as stuck (no live backup tracked).
func (r *Reconciler) SetBackupInProgress(fn func(vmName string) bool) {
	r.backupInProgress = fn
}

// ReconcileOnce runs a single reconcile + self-fence pass — the body of the
// periodic loop, exported for the fleet harness (and one-shot ops) to drive a
// deterministic pass without waiting on the ticker.
func (r *Reconciler) ReconcileOnce(ctx context.Context) {
	r.reconcile(ctx)
	r.selfFence(ctx)
	r.assertRuntimeOwnership(ctx)
}

// Start begins the reconcile loop. Blocks until ctx is cancelled.
func (r *Reconciler) Start(ctx context.Context) {
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.reconcile(ctx)
			r.selfFence(ctx)
			r.assertRuntimeOwnership(ctx)
		}
	}
}

// StartOnbootVMs starts every local VM marked onboot that is NOT currently
// running in libvirt, in ascending startup_order, pausing start_delay_sec
// between each (#10). Run ONCE at daemon startup, not on the periodic tick.
//
// Keying on "not running in libvirt" distinguishes a host reboot from a plain
// daemon restart for free: KillMode=process keeps qemu alive across a daemon
// restart (domains still running → skipped), whereas a host reboot leaves the
// domains shut off (→ started here). So deliberately-stopped VMs are only
// (re)started when the host actually boots.
func (r *Reconciler) StartOnbootVMs(ctx context.Context) {
	// Defensive: this runs in a startup goroutine — a panic here must never take
	// the daemon down (which would strand the host).
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("onboot: recovered from panic", "panic", rec)
		}
	}()
	if r.virt == nil {
		return
	}
	vms, err := corrosion.ListVMs(ctx, r.db, "", r.hostName)
	if err != nil {
		slog.Error("onboot: list VMs", "error", err)
		return
	}
	type onbootVM struct {
		vm    corrosion.VMRecord
		order int
		delay int
	}
	var list []onbootVM
	for _, vm := range vms {
		if vm.Spec == "" {
			continue
		}
		spec := &pb.VMSpec{}
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil || !spec.Onboot {
			continue
		}
		// Already running (e.g. survived a daemon restart) → leave it.
		if r.virt.DomainExists(vm.Name) {
			if st, sErr := r.virt.DomainState(vm.Name); sErr == nil && st == "running" {
				continue
			}
		}
		list = append(list, onbootVM{vm: vm, order: int(spec.StartupOrder), delay: int(spec.StartDelaySec)})
	}
	if len(list) == 0 {
		return
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].order < list[j].order })
	slog.Info("onboot: starting VMs in order", "count", len(list))
	for i, e := range list {
		slog.Info("onboot: starting VM", "vm", e.vm.Name, "order", e.order)
		// Record the boot-time autostart decision BEFORE attempting: if the split-brain
		// gate refuses now (warmup / transient quorum loss), reconcile() retries from
		// this set until quorum returns, so onboot autostart isn't permanently stranded.
		r.rememberOnboot(e.vm)
		r.startPendingVM(ctx, e.vm)
		if e.delay > 0 && i < len(list)-1 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(e.delay) * time.Second):
			}
		}
	}
}

// rememberOnboot records a VM whose onboot autostart is owed, so reconcile() keeps
// retrying it through the gate until it runs (a gate refusal is a safe gap, not a
// permanent stop). Only ever called for onboot=true, not-running-at-boot VMs.
func (r *Reconciler) rememberOnboot(vm corrosion.VMRecord) {
	r.onbootMu.Lock()
	if r.onbootPending == nil {
		r.onbootPending = make(map[string]corrosion.VMRecord)
	}
	r.onbootPending[vm.Name] = vm
	r.onbootMu.Unlock()
}

func (r *Reconciler) clearOnbootPending(name string) {
	r.onbootMu.Lock()
	delete(r.onbootPending, name)
	r.onbootMu.Unlock()
}

// specOnboot reports whether a VM's stored spec still marks it onboot. An empty or
// unparseable spec → false (fail safe: never autostart a VM we can't confirm is
// onboot). Used by the retry path so a since-disabled onboot is not resurrected.
func specOnboot(specJSON string) bool {
	if specJSON == "" {
		return false
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(specJSON), spec); err != nil {
		return false
	}
	return spec.Onboot
}

// retryOnbootPending re-attempts onboot autostarts the gate previously refused.
// It re-reads the CURRENT row each time (the remembered snapshot is stale) and
// drops the retry — never autostarting — if the VM is already running, its row is
// gone or reassigned, the operator has since stopped it (operator-stop), or onboot
// was disabled. So a returning quorum can't resurrect a VM the operator stood down
// while it was absent. Idempotent: startPendingVM no-ops on an already-running domain.
func (r *Reconciler) retryOnbootPending(ctx context.Context) {
	r.onbootMu.Lock()
	names := make([]string, 0, len(r.onbootPending))
	for name := range r.onbootPending {
		names = append(names, name)
	}
	r.onbootMu.Unlock()
	for _, name := range names {
		if r.virt != nil && r.virt.DomainExists(name) {
			if st, err := r.virt.DomainState(name); err == nil && st == "running" {
				r.clearOnbootPending(name) // already up — duty discharged
				continue
			}
		}
		fresh, err := corrosion.GetVM(ctx, r.db, name)
		if err != nil || fresh == nil || fresh.HostName != r.hostName {
			r.clearOnbootPending(name) // gone / reassigned — no longer our onboot duty
			continue
		}
		// Operator intent may have changed while quorum was absent: honor it.
		if fresh.StateDetail == operatorStopDetail || !specOnboot(fresh.Spec) {
			slog.Info("reconciler: dropping onboot retry — operator intent changed",
				"vm", name, "state_detail", fresh.StateDetail, "onboot", specOnboot(fresh.Spec))
			r.clearOnbootPending(name)
			continue
		}
		r.startPendingVM(ctx, *fresh) // gated + current row; succeeds once quorum returns
	}
}

func (r *Reconciler) reconcile(ctx context.Context) {
	vms, err := corrosion.ListVMs(ctx, r.db, "", r.hostName)
	if err != nil {
		slog.Error("reconciler: list VMs", "error", err)
		return
	}

	for _, vm := range vms {
		switch vm.State {
		case "pending":
			r.startPendingVM(ctx, vm)

		case "starting":
			// "starting" is an INTERMEDIATE state written only by startPendingVM (just
			// before the libvirt define+start). A VM left here means a start didn't
			// finish its final state write — a daemon crash mid-start, or a failed
			// post-libvirt DB write (revert-to-pending / CompleteVMStartProof). Without
			// this path such a VM would strand (reconcile otherwise only retries
			// "pending"), and a proof-gated one would strand its proof in_progress too.
			// Re-drive startPendingVM: it is idempotent (an already-running domain
			// completes the proof + heals to running; a not-yet-running one re-attempts),
			// serialized by the per-VM vm_lock so an in-flight start isn't double-driven.
			r.startPendingVM(ctx, vm)

		case "running":
			if r.virt == nil {
				break
			}
			// After daemon restart or libvirt reconnect, verify VMs that
			// corrosion says are "running" are actually alive in libvirt (#43/#53).
			if !r.virt.DomainExists(vm.Name) {
				slog.Warn("reconciler: VM marked running but not in libvirt — attempting restart",
					"vm", vm.Name)
				r.startPendingVM(ctx, vm)
				break
			}
			// One-shot machine-type backfill: pin the concrete machine type for VMs created
			// before pinning existed. No-op once pinned (cheap stored-spec check).
			r.maybePinMachineType(ctx, vm)
			// The domain is defined but may have been stopped out-of-band (a
			// crash, an external `virsh destroy`, or a fence that powered it
			// off). Reconcile the cluster state to libvirt reality so it doesn't
			// linger as "running" everywhere (the list/host UI reads cluster
			// state, the detail view reads live state — they must not disagree),
			// AND record WHY in state_detail so the restart engine can later tell
			// a crash from a clean guest shutdown. Never reclassify an operator
			// stop. classifyStop decides whether the VM is genuinely down.
			st, err := r.virt.DomainStateReason(vm.Name)
			if err != nil || st.State == "running" {
				break
			}
			if vm.StateDetail == operatorStopDetail {
				break
			}
			newState, detail, sync := classifyStop(st.State, st.Reason)
			if !sync {
				break // paused / migrated / not genuinely down — leave alone
			}
			slog.Warn("reconciler: VM stopped out-of-band — syncing cluster state",
				"vm", vm.Name, "reason", st.Reason, "to", newState)
			if err := corrosion.UpdateVMState(ctx, r.db, vm.Name, newState, detail); err != nil {
				slog.Error("reconciler: out-of-band stop sync write failed", "vm", vm.Name, "error", err)
				r.noteStateWriteFail(corrosion.OpVMState, err)
			}

		case "stopped":
			// One-shot machine-type backfill for a STOPPED but still-defined VM (a legacy VM,
			// or one updated with --machine q35 while stopped): pin the concrete
			// machine type from its persistent domain. No-op once pinned, and a
			// no-op if the domain isn't defined (DumpXMLInactive errors → "").
			r.maybePinMachineType(ctx, vm)

		case "error":
			// Check if an errored VM is actually running in libvirt (e.g. after
			// daemon crash mid-operation). If so, update state to running.
			if r.virt != nil && r.virt.DomainExists(vm.Name) {
				if state, err := r.virt.DomainState(vm.Name); err == nil && state == "running" {
					slog.Info("reconciler: VM in error state but running in libvirt — updating state",
						"vm", vm.Name)
					if err := corrosion.UpdateVMState(ctx, r.db, vm.Name, "running", "reconciler: domain is alive"); err != nil {
						r.noteStateWriteFail(corrosion.OpVMState, err)
					}
				}
			}

		case "backing-up":
			// Self-heal a stuck "backing-up" flag. A crashed/restarted daemon or
			// an interrupted backup stream can strand a VM in "backing-up"
			// forever, which blocks console/VNC, delete, and drain even though
			// the VM is running fine. If no backup is actually running here,
			// reconcile the state from libvirt reality.
			if r.backupInProgress != nil && r.backupInProgress(vm.Name) {
				continue // genuine backup in flight — leave it alone
			}
			if r.virt == nil {
				continue
			}
			live := "stopped"
			if r.virt.DomainExists(vm.Name) {
				st, err := r.virt.DomainState(vm.Name)
				if err != nil {
					continue // can't determine — retry next tick
				}
				live = st
			}
			slog.Info("reconciler: clearing stuck backing-up state", "vm", vm.Name, "live", live)
			if err := corrosion.UpdateVMState(ctx, r.db, vm.Name, live, "reconciler: stale backing-up cleared"); err != nil {
				r.noteStateWriteFail(corrosion.OpVMState, err)
			}
		}
	}

	// Retry any onboot autostart the split-brain gate refused during warmup/quorum
	// loss, so a latched gate can't permanently strand it after a reboot.
	r.retryOnbootPending(ctx)
}

// selfFence detects split-brain: VMs running locally in libvirt that corrosion
// says belong to another host. This happens when a network partition heals and
// the VM was rescheduled during the partition (#5).
// maybePinMachineType is the one-shot machine-type backfill for VMs created before
// machine-type pinning. If the stored spec still carries an unversioned alias
// ("q35"/"pc"/"") but libvirt has the domain bound to a concrete versioned type
// (e.g. "pc-q35-9.0"), it rewrites spec.machine to that concrete value so a
// later failover/reschedule regenerates the domain XML with the same guest ABI
// instead of re-resolving the alias on the destination host's qemu version.
// Fires at most once per VM — the cheap stored-spec pre-check makes every
// subsequent tick a no-op — and preserves every other spec field via a raw edit.
func (r *Reconciler) maybePinMachineType(ctx context.Context, vm corrosion.VMRecord) {
	if r.virt == nil || vm.Spec == "" {
		return
	}
	var cur struct {
		Machine string `json:"machine"`
	}
	if err := json.Unmarshal([]byte(vm.Spec), &cur); err != nil {
		return
	}
	if lv.IsPinnedMachineType(cur.Machine) {
		return // already pinned — the steady-state case
	}
	xmlDesc, err := r.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return
	}
	resolved := lv.MachineTypeFromXML(xmlDesc)
	if !lv.IsPinnedMachineType(resolved) {
		return // libvirt gave no concrete type; leave the alias untouched
	}
	// Surgical edit: round-trip the raw object and replace only "machine" so no
	// other spec field is dropped or reordered.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(vm.Spec), &raw); err != nil {
		return
	}
	mj, err := json.Marshal(resolved)
	if err != nil {
		return
	}
	raw["machine"] = mj
	out, err := json.Marshal(raw)
	if err != nil {
		return
	}
	// Compare-and-swap on the spec column keyed by the exact spec we based the edit
	// on: if a concurrent user UpdateVM changed the spec since this reconcile pass
	// read it, the write no-ops (applied=false) rather than clobbering that edit
	// with our stale-plus-machine copy — the next tick re-reads and retries.
	applied, err := corrosion.UpdateVMSpecIfUnchanged(ctx, r.db, vm.Name, vm.Spec, string(out))
	if err != nil {
		slog.Warn("reconciler: pin machine type failed", "vm", vm.Name, "machine", resolved, "error", err)
		return
	}
	if !applied {
		return // spec changed underneath us; retry next tick off the fresh value
	}
	slog.Info("reconciler: pinned machine type (one-shot backfill)", "vm", vm.Name, "from", cur.Machine, "to", resolved)
}

func (r *Reconciler) selfFence(ctx context.Context) {
	if r.virt == nil {
		return
	}

	localDomains, err := r.virt.ListDomains()
	if err != nil {
		slog.Error("reconciler: list local domains", "error", err)
		return
	}

	for _, domName := range localDomains {
		vm, err := corrosion.GetVM(ctx, r.db, domName)
		if err != nil || vm == nil {
			// Domain exists locally but not in corrosion — might be external/manual.
			continue
		}

		// If the VM is mid-migration, a transient domain will appear on the
		// target host before corrosion is updated — don't destroy it.
		if vm.State == "migrating" {
			continue
		}

		// If corrosion says this VM belongs to a different host, we no longer own it.
		if vm.HostName != r.hostName {
			// Non-destruction guard (LWW-repair Phase 1): NEVER destroy a domain
			// that holds live or resumable state locally, whatever the DB host_name
			// says. A converged-wrong host_name — the equal-`updated_at` LWW tie this
			// repair targets — must not be able to drive selfFence into destroying a
			// live VM. Destroying is permitted ONLY on positive proof the domain is a
			// clearly-dead leftover (see cleanableDomainReason); everything else —
			// running, PAUSED, PM-SUSPENDED, SAVED (managed-save memory image),
			// shutting-down, crashed, migrated, from-snapshot, and any unknown or
			// unreadable state — is skipped and deferred to the Phase-3 runtime/
			// fencing ownership reconciliation. We use DomainStateReason, not the
			// coarse DomainState, because the latter collapses paused/pm-suspended/
			// saved/shutoff all into "stopped" and would destroy resumable workloads.
			st, serr := r.virt.DomainStateReason(domName)
			if serr != nil || !cleanableLeftover(st) {
				slog.Warn("reconciler: NOT destroying a local domain whose DB row points elsewhere — not a clearly-dead leftover; deferring to runtime ownership repair",
					"vm", domName, "local_host", r.hostName, "corrosion_host", vm.HostName, "state", st.State, "reason", st.Reason, "state_err", serr)
				continue
			}
			slog.Warn("reconciler: removing clearly-dead local leftover whose DB row moved to another host",
				"vm", domName, "local_host", r.hostName, "corrosion_host", vm.HostName, "reason", st.Reason)
			if err := r.virt.DestroyDomain(domName); err != nil {
				slog.Warn("reconciler: destroy stale domain failed", "vm", domName, "error", err)
			}
			// wipe by design: a stopped/defined leftover whose VM now lives on
			// another host (the authoritative firmware state travels with it).
			if err := r.virt.UndefineDomain(domName, false); err != nil {
				slog.Warn("reconciler: undefine stale domain failed", "vm", domName, "error", err)
			}
		}
	}
}

// cleanableLeftover reports whether a local domain is a CLEARLY-DEAD leftover —
// no live or resumable state — so it is safe to destroy+undefine when its DB row
// has moved to another host. Both conditions must hold (positive proof, fail
// closed):
//
//   - coarse State == "stopped" — defensive belt-and-suspenders. Today the
//     cleanable reasons below all originate from DomainShutoff (which coarse-maps
//     to "stopped"), so this is redundant against the current mapping; it guards
//     against a future reason/state decoupling silently re-admitting a non-stopped
//     (possibly live) domain to destruction.
//   - Reason in the allowlist below. An allowlist (default: do NOT clean) so any
//     state holding recoverable memory (paused, pmsuspended, saved), in transition
//     (shutting-down, migrated, from-snapshot), needing investigation (crashed), or
//     unknown/unreadable is skipped and deferred to Phase-3 runtime ownership repair.
func cleanableLeftover(st lv.DomainStatus) bool {
	if st.State != "stopped" {
		return false
	}
	switch st.Reason {
	case "guest-shutdown", // guest cleanly powered itself off
		"destroyed", // forcibly destroyed — no state retained
		"daemon",    // shut off by the daemon
		"failed":    // failed to start — never held live state
		return true
	default:
		return false
	}
}

func (r *Reconciler) startPendingVM(ctx context.Context, vm corrosion.VMRecord) {
	// Take a per-VM startup lease before doing anything destructive.
	// Without this, two reconcilers on different hosts that both briefly
	// see vm.HostName=self in CRDT-stale state would both call libvirt.Start
	// on the same VM UUID — the same physical disk gets two QEMU writers
	// → guaranteed corruption.
	if !r.acquireVMLock(ctx, vm.Name) {
		slog.Info("reconciler: VM lock held by another host, skipping",
			"vm", vm.Name)
		return
	}
	// Re-read the VM row after acquiring the lock — if CRDT replication
	// between the lock-acquire and now has reassigned the VM elsewhere,
	// abort so the legitimate host can pick it up.
	fresh, err := corrosion.GetVM(ctx, r.db, vm.Name)
	if err != nil || fresh == nil || fresh.HostName != vm.HostName {
		slog.Info("reconciler: VM no longer assigned to this host after lock, releasing",
			"vm", vm.Name)
		r.releaseVMLock(ctx, vm.Name)
		return
	}
	defer r.releaseVMLock(ctx, vm.Name)

	// A pending transition that carries a proof marker (pending_action_id) was minted
	// by a coordinator that held the lease + quorum, so we MUST validate + claim it
	// single-use — AND run the local ExecutionGate — regardless of local activation.
	proofID := fresh.PendingActionID

	// A proof MARKER present with NO gate wired fails CLOSED: we can't verify quorum,
	// and a marker implies enforcement was active when it was stamped. (Production
	// wires the gate before the reconcile loops; this is defense-in-depth.)
	if proofID != "" && r.gate == nil {
		slog.Warn("reconciler: pending proof marker present but no gate wired — refusing start (fail closed)", "vm", vm.Name)
		r.noteGateRefused(corrosion.ActionReschedule, ReasonNoQuorum)
		return
	}

	// Self-fence is an UNCONDITIONAL hard gate (independent of marker/enforcement): a
	// doomed node must not start ANY VM — pending transfer, onboot autostart, or local
	// domain-died recovery — during its fence-timeout window.
	if selfFenceHardGate(r.gate) {
		slog.Warn("reconciler: self-fenced — refusing VM start (no runtime action while doomed)", "vm", vm.Name)
		r.noteGateRefused(corrosion.ActionReschedule, ReasonSelfFenced)
		return
	}

	// Split-brain gate (Phase 1), EXECUTE side: run the local ExecutionGate when a
	// proof MARKER is present OR enforcement is latched. The marker forcing the gate
	// is the key case: in an asymmetric partition a target can receive a valid marker
	// while itself lacking quorum, and must NOT execute. Any automated start (pending
	// reschedule, onboot autostart, "DB running / libvirt missing" recovery) is thus
	// gated. Legacy (ungated) is allowed ONLY when there's no marker AND enforcement
	// never activated.
	if r.gate != nil && (proofID != "" || r.gate.Enforced(ctx, capabilities.SplitBrainGateV1)) {
		if g := r.gate.ExecutionGate(ctx); !g.OK {
			slog.Warn("reconciler: execution gate refused start (no quorum)", "vm", vm.Name, "reason", g.Reason)
			r.noteGateRefused(corrosion.ActionReschedule, g.Reason)
			return // lock released by defer; retry next tick if quorum returns
		}
	}

	// Post-activation, a coordinator OWNERSHIP TRANSFER writes state=pending AND a
	// proof marker (pending_action_id) atomically. A PENDING row with NO marker under
	// enforcement is therefore stale / pre-activation / hand-mutated — refuse it
	// (proof_missing) rather than complete an ownership transfer with no proof. This
	// enforces the "post-activation proof + pending_action_id mandatory" rule for the
	// transfer path even though the coordinator should never mint such a row.
	//
	// Scope is deliberately state=="pending" (the transfer signal the coordinator
	// writes): onboot autostart and domain-died recovery ENTER with state stopped/
	// running (not pending), so they stay legitimate markerless LOCAL starts gated by
	// the ExecutionGate above — no ownership transfer, no proof required. A markerless
	// "starting" row is likewise not a transfer: a transfer can only reach "starting"
	// via "pending", which is refused here first, so a markerless "starting" is a local
	// start (or a pre-flip transfer off an already-fenced source) — both safe under the
	// ExecutionGate — and refusing it would strand a crashed local start.
	if proofID == "" && fresh.State == "pending" &&
		r.gate != nil && r.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
		slog.Warn("reconciler: enforced pending start carries no proof marker — refusing (proof_missing): stale/pre-activation/hand-mutated pending row",
			"vm", vm.Name)
		r.noteGateRefused(corrosion.ActionReschedule, ReasonProofMissing)
		return
	}

	if proofID != "" {
		// The proof must actually authorize THIS start: a reschedule proof whose
		// target/dest is this VM on this host. A mismatched id (stale pointer,
		// collision) must never authorize a start.
		pr, ok, gerr := corrosion.GetActionProof(ctx, r.db, proofID)
		if gerr != nil || !ok {
			// Can't read/find the proof row → we can't verify it authorizes THIS start, and
			// ClaimActionProof matches only by id+status, so it would start the VM UNVALIDATED
			// (a fail-open double-run vector). Refuse (fail closed).
			slog.Warn("reconciler: pending proof unreadable/missing — refusing start (fail closed)",
				"vm", vm.Name, "proof", proofID, "found", ok, "error", gerr)
			r.noteGateRefused(corrosion.ActionReschedule, ReasonProofConflict)
			return
		}
		// Exact match required: a reschedule proof for THIS vm, destined for THIS host. An
		// empty/other dest is not accepted — a malformed/stale proof for the right VM must not
		// become usable on any host.
		if pr.Action != corrosion.ActionReschedule || pr.TargetKind != "vm" ||
			pr.TargetName != vm.Name || pr.DestHost != r.hostName {
			slog.Warn("reconciler: pending proof does not match this VM/host, refusing start",
				"vm", vm.Name, "proof", proofID, "proof_target", pr.TargetName, "proof_dest", pr.DestHost)
			r.noteGateRefused(corrosion.ActionReschedule, ReasonProofConflict)
			return
		}
		if err := corrosion.ClaimActionProof(ctx, r.db, proofID, r.hostName); err != nil {
			if errors.Is(err, corrosion.ErrProofSpent) {
				slog.Warn("reconciler: pending proof terminal/missing, refusing start",
					"vm", vm.Name, "proof", proofID)
				r.noteGateRefused(corrosion.ActionReschedule, ReasonProofTerminal)
				return
			}
			// Transient (proof row not yet visible / DB error): retry next tick.
			// The vm_lock is released by defer, so we don't tie it up while waiting.
			slog.Warn("reconciler: claim pending proof failed (transient), retrying",
				"vm", vm.Name, "proof", proofID, "error", err)
			return
		}
	}

	slog.Info("reconciler: starting pending VM", "vm", vm.Name)

	// Check if a domain already exists locally from a partial migration (#14).
	if r.virt != nil && r.virt.DomainExists(vm.Name) {
		state, err := r.virt.DomainState(vm.Name)
		if err == nil && state == "running" {
			slog.Warn("reconciler: domain already running locally, updating state", "vm", vm.Name)
			// Idempotent retry: the domain is already up. Complete the proof
			// (single-use) + clear pending_action_id in one guarded mutation. Do NOT
			// downgrade to a plain running update on guard failure — that would bypass
			// the pointer/status preconditions and could strand pending_action_id. If
			// completion doesn't apply (proof already terminal / VM re-pointed), leave
			// the row: the domain is running, so the state reconciler converges it.
			if proofID != "" {
				if cerr := corrosion.CompleteVMStartProof(ctx, r.db, proofID, vm.Name, r.hostName); cerr != nil {
					slog.Error("reconciler: complete start proof (already-running) did not apply — leaving state for reconcile",
						"vm", vm.Name, "proof", proofID, "error", cerr)
				}
			} else if err := corrosion.UpdateVMState(ctx, r.db, vm.Name, "running", "domain already present"); err != nil {
				slog.Error("reconciler: already-present running-state write failed", "vm", vm.Name, "error", err)
				r.noteStateWriteFail(corrosion.OpVMState, err)
			}
			r.clearOnbootPending(vm.Name) // onboot duty discharged
			return
		}
		// Domain exists but not running — destroy and redefine the SAME VM cleanly.
		// KEEP firmware state: the redefine below reuses the NVRAM/swtpm; wiping
		// here would break an SB/vTPM guest on the next start (G1).
		r.virt.DestroyDomain(vm.Name)
		r.virt.UndefineDomainPreservingState(vm.Name)
	}

	if err := corrosion.UpdateVMState(ctx, r.db, vm.Name, "starting", "reconciler"); err != nil {
		slog.Error("reconciler: failover start-marker write failed", "vm", vm.Name, "error", err)
		r.noteStateWriteFail(corrosion.OpVMState, err)
	}

	// Parse the stored spec to rebuild the domain XML.
	spec := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			slog.Error("reconciler: parse VM spec", "vm", vm.Name, "error", err)
			r.failPendingStart(ctx, vm.Name, proofID, false, "invalid spec JSON")
			return
		}
	}

	// Retrieve stored disk records to build disk config.
	diskRecords, err := corrosion.ListDisks(ctx, r.db, vm.Name)
	if err != nil {
		slog.Error("reconciler: list disks", "vm", vm.Name, "error", err)
		r.failPendingStart(ctx, vm.Name, proofID, true, fmt.Sprintf("list disks: %v", err)) // transient DB
		return
	}

	var diskConfigs []lv.DiskConfig
	for _, d := range diskRecords {
		// Verify disk file exists on this host.
		if _, err := os.Stat(d.Path); err != nil {
			// If disk has a backing image, try auto-pulling it and recreating the overlay.
			if d.BackingImage != "" && r.autoPullImage != nil {
				slog.Info("reconciler: disk missing, attempting auto-pull of backing image",
					"vm", vm.Name, "disk", d.DiskName, "image", d.BackingImage)
				if pullErr := r.autoPullImage(ctx, d.BackingImage); pullErr != nil {
					slog.Error("reconciler: auto-pull failed", "vm", vm.Name, "image", d.BackingImage, "error", pullErr)
					r.failPendingStart(ctx, vm.Name, proofID, true, // transient: a peer may return
						fmt.Sprintf("disk %s not found and image auto-pull failed: %v", d.DiskName, pullErr))
					return
				}
				// Recreate overlay disk from pulled image.
				imgStore := image.NewStore(r.dataDir)
				newPath, createErr := imgStore.CreateOverlayDisk(vm.Name, d.DiskName, d.BackingImage, "")
				if createErr != nil {
					slog.Error("reconciler: recreate overlay failed", "vm", vm.Name, "error", createErr)
					r.failPendingStart(ctx, vm.Name, proofID, true, // transient: retry the overlay build
						fmt.Sprintf("recreate disk %s: %v", d.DiskName, createErr))
					return
				}
				d.Path = newPath
				slog.Info("reconciler: recreated overlay disk", "vm", vm.Name, "disk", d.DiskName, "path", newPath)
			} else {
				slog.Error("reconciler: disk not found", "vm", vm.Name, "disk", d.DiskName, "path", d.Path)
				r.failPendingStart(ctx, vm.Name, proofID, false, // non-retryable: no source to rebuild from
					fmt.Sprintf("disk %s not found at %s (no backing image for auto-pull)", d.DiskName, d.Path))
				return
			}
		}
		bus := "virtio"
		if len(spec.Disks) > 0 {
			for _, sd := range spec.Disks {
				if sd.Name == d.DiskName && sd.Bus != "" {
					bus = sd.Bus
					break
				}
			}
		}
		diskConfigs = append(diskConfigs, lv.DiskConfig{
			Name: d.DiskName,
			Path: d.Path,
			Bus:  bus,
		})
	}

	// Check for cloud-init ISO. The reconciler acts on a stored (possibly
	// peer-replicated) row, so build the ISO path through the validated builder
	// — a malformed vm.Name must not escape the cloudinit dir.
	cloudInitISO := ""
	isoPath, isoErr := lv.SafeCloudInitISOPath(r.dataDir, vm.Name)
	if isoErr != nil {
		slog.Error("reconciler: invalid vm name for cloud-init path", "vm", vm.Name, "error", isoErr)
		r.failPendingStart(ctx, vm.Name, proofID, false, fmt.Sprintf("invalid name: %v", isoErr)) // non-retryable
		return
	}
	if _, err := os.Stat(isoPath); err == nil {
		cloudInitISO = isoPath
	} else if spec.CloudInit != nil {
		// Regenerate cloud-init ISO from spec.
		userData := spec.CloudInit.Userdata
		if userData == "" {
			userData = "#cloud-config\n{}\n"
		}
		if genErr := cloudinit.GenerateISO(cloudinit.Config{
			InstanceID:    vm.Name,
			LocalHostname: vm.Name,
			UserData:      userData,
			NetworkConfig: spec.CloudInit.Networkconfig,
		}, isoPath); genErr != nil {
			slog.Warn("reconciler: cloud-init ISO generation failed", "vm", vm.Name, "error", genErr)
		} else {
			cloudInitISO = isoPath
		}
	}

	// Provision networks and build network configs from stored interfaces.
	// A query failure must NOT be swallowed: starting the VM with zero NICs
	// brings it up headless (no network) after a failover. Fail it instead,
	// matching the ListDisks error handling above.
	ifaces, err := corrosion.GetVMInterfaces(ctx, r.db, vm.Name)
	if err != nil {
		slog.Error("reconciler: get VM interfaces", "vm", vm.Name, "error", err)
		r.failPendingStart(ctx, vm.Name, proofID, true, fmt.Sprintf("get interfaces: %v", err)) // transient DB
		return
	}
	var netConfigs []lv.NetworkConfig
	for _, iface := range ifaces {
		bridge := iface.NetworkName
		// Provision network infrastructure (VXLAN tunnels, DHCP, NAT, bridges).
		// This is critical after failover — the new host may not have the network set up.
		if provBridge, err := network.ProvisionForVM(ctx, r.db, iface.NetworkName, r.hostName); err != nil {
			slog.Warn("reconciler: network provision failed, using raw name",
				"vm", vm.Name, "network", iface.NetworkName, "error", err)
		} else if provBridge != "" {
			bridge = provBridge
		}
		if strings.HasPrefix(bridge, "direct:") {
			netConfigs = append(netConfigs, lv.NetworkConfig{
				Direct: strings.TrimPrefix(bridge, "direct:"),
				Model:  "virtio",
				MAC:    iface.MAC,
			})
		} else {
			netConfigs = append(netConfigs, lv.NetworkConfig{
				Bridge: bridge,
				MAC:    iface.MAC,
			})
		}
	}

	// Build libvirt domain config.
	vmCfg := lv.VMConfig{
		Name:         vm.Name,
		CPU:          vm.CPUActual,
		MemoryMiB:    vm.MemActual,
		Machine:      spec.Machine,
		Firmware:     spec.Firmware,
		GuestAgent:   spec.GuestAgent,
		Disks:        diskConfigs,
		Networks:     netConfigs,
		CloudInitISO: cloudInitISO,
		Boot:         spec.Boot,
	}
	if vmCfg.Machine == "" {
		vmCfg.Machine = "q35"
	}
	if vmCfg.Firmware == "" {
		vmCfg.Firmware = "uefi"
	}
	// Secure Boot + vTPM (G1): stable UUID makes the swtpm state path
	// (/var/lib/libvirt/swtpm/<uuid>/) deterministic; render the same firmware
	// CreateVM did. A vTPM VM whose state isn't present on this host can't be
	// rebuilt faithfully — fail clearly (state=error) rather than booting with a
	// fresh TPM and silently breaking BitLocker.
	vmCfg.UUID = spec.Uuid
	r.firmware.ApplyTo(&vmCfg, r.dataDir, vm.Name, spec.SecureBoot, spec.Tpm)
	if spec.Tpm && !lv.HasTPMState(spec.Uuid) {
		slog.Error("reconciler: vTPM VM has no local TPM state; refusing to start with a fresh TPM", "vm", vm.Name)
		r.failPendingStart(ctx, vm.Name, proofID, false, "vTPM state missing on this host (would break BitLocker)") // non-retryable
		return
	}
	// Same rule for NVRAM (Secure Boot keys / boot entries): a UEFI firmware VM
	// whose vars aren't present here can't be rebuilt faithfully — refuse rather
	// than redefine with fresh vars from the template (would lose enrolled keys).
	uefiFW := spec.Firmware == "uefi" || spec.Firmware == ""
	if (spec.SecureBoot || spec.Tpm) && uefiFW && !lv.HasNvram(r.dataDir, vm.Name) {
		slog.Error("reconciler: firmware VM has no local UEFI NVRAM; refusing to start with fresh vars", "vm", vm.Name)
		r.failPendingStart(ctx, vm.Name, proofID, false, "UEFI NVRAM missing on this host (would lose Secure Boot keys)") // non-retryable
		return
	}
	if r := spec.Resources; r != nil {
		vmCfg.HugePages = r.Hugepages
		vmCfg.IOThreads = int(r.IoThreads)
		for _, pin := range r.CpuPinning {
			vmCfg.CPUPinning = append(vmCfg.CPUPinning, int(pin))
		}
		if np := r.NumaPolicy; np != nil {
			vmCfg.NUMAPolicy = &lv.NUMAPolicy{
				PreferredNode: int(np.PreferredNode),
				Strict:        np.Strict,
			}
		}
	}

	domXML, err := lv.GenerateDomainXML(vmCfg)
	if err != nil {
		slog.Error("reconciler: generate domain XML", "vm", vm.Name, "error", err)
		r.failPendingStart(ctx, vm.Name, proofID, false, fmt.Sprintf("XML gen: %v", err)) // non-retryable (bad config)
		return
	}

	// Define and start the domain.
	if err := r.virt.DefineDomain(domXML); err != nil {
		slog.Error("reconciler: define domain", "vm", vm.Name, "error", err)
		r.failPendingStart(ctx, vm.Name, proofID, true, fmt.Sprintf("define: %v", err)) // transient libvirt
		return
	}

	if err := r.virt.StartDomain(vm.Name); err != nil {
		slog.Error("reconciler: start domain", "vm", vm.Name, "error", err)
		r.failPendingStart(ctx, vm.Name, proofID, true, fmt.Sprintf("start: %v", err)) // transient libvirt
		return
	}

	// Success. When a proof authorized this start, mark it completed AND move the
	// VM to running + clear pending_action_id in ONE guarded mutation (crash can't
	// desync state and pointer; the terminal proof makes a duplicate start a no-op).
	// Do NOT downgrade to a plain running update if the guard doesn't apply — that
	// would bypass the pointer/status preconditions. If CompleteVMStartProof fails
	// (DB error / guard didn't apply), the VM is left in "starting" with the proof
	// still in_progress — NOT stranded: the reconcile "starting" case re-drives
	// startPendingVM, whose already-running-domain branch retries CompleteVMStartProof
	// until it lands (the marker safely blocks any re-start meanwhile).
	if proofID != "" {
		if err := corrosion.CompleteVMStartProof(ctx, r.db, proofID, vm.Name, r.hostName); err != nil {
			slog.Error("reconciler: complete start proof did not apply after start — leaving 'starting' for the reconcile starting-case to retry",
				"vm", vm.Name, "proof", proofID, "error", err)
		}
	} else if err := corrosion.UpdateVMState(ctx, r.db, vm.Name, "running", "started by reconciler after failover"); err != nil {
		slog.Error("reconciler: post-failover running-state write failed", "vm", vm.Name, "error", err)
		r.noteStateWriteFail(corrosion.OpVMState, err)
	}
	r.clearOnbootPending(vm.Name) // onboot duty discharged
	slog.Info("reconciler: VM started successfully", "vm", vm.Name)

	// Notify LB to refresh backends now that this VM is running.
	if r.onVMStarted != nil && vm.StackName != "" {
		go r.onVMStarted(context.Background(), vm.StackName)
	}
}

// failPendingStart records a local start failure inside startPendingVM, honoring the
// proof lifecycle (plan: transient → retryable, only a KNOWN non-retryable point →
// terminal) so a proof-gated start is never stranded in_progress:
//   - no proof (legacy): set the VM to error (unchanged behavior).
//   - retryable (a transient libvirt / DB / image-pull hiccup): revert the VM to
//     pending and LEAVE the proof in_progress, so reconcile retries and the same
//     executor re-claims it — never stranding HA on a blip. (The pending_action_id
//     stays set, so the retry re-validates + re-claims the same proof.)
//   - non-retryable (bad spec/disk/firmware/XML — retrying HERE can't help): mark the
//     proof FAILED (terminal) which atomically sets the VM to error + clears the
//     pointer, so no in_progress proof dangles and no marker-less pending row is left.
func (r *Reconciler) failPendingStart(ctx context.Context, vmName, proofID string, retryable bool, detail string) {
	if proofID == "" {
		if err := corrosion.UpdateVMState(ctx, r.db, vmName, "error", detail); err != nil {
			r.noteStateWriteFail(corrosion.OpVMState, err)
		}
		return
	}
	if retryable {
		if err := corrosion.UpdateVMState(ctx, r.db, vmName, "pending", "retrying after transient start failure: "+detail); err != nil {
			slog.Error("reconciler: retry re-arm write failed", "vm", vmName, "error", err)
			r.noteStateWriteFail(corrosion.OpVMState, err)
		}
		return
	}
	if err := corrosion.FailActionProof(ctx, r.db, proofID, vmName, "start_failed", detail); err != nil {
		slog.Error("reconciler: terminalize failed-start proof did not apply — setting VM error",
			"vm", vmName, "proof", proofID, "error", err)
		if werr := corrosion.UpdateVMState(ctx, r.db, vmName, "error", detail); werr != nil {
			r.noteStateWriteFail(corrosion.OpVMState, werr)
		}
	}
}

// vmLockTTL is the lease duration for vm_locks entries. It must comfortably
// exceed the worst-case startPendingVM duration (image pull + disk recreate
// + libvirt start). Longer is safer; in pathological cases a stuck reconciler
// will hold the lock until expiry.
const vmLockTTL = 10 * time.Minute

// acquireVMLock takes the per-VM startup lease. Returns true if this host
// holds the lock. CRDT-tolerant via the same INSERT-OR-UPDATE-WHERE-expired
// pattern as failover leader election.
//
// NOT linearizable across partitions — but combined with the "re-read VM
// row after lock" check in startPendingVM, the failure mode is "we held a
// lock then discovered the VM moved, and we release without acting", not
// "two hosts both started the VM."
func (r *Reconciler) acquireVMLock(ctx context.Context, vmName string) bool {
	// Read the clock ONCE so `now` and `expires` derive from the same instant
	// (a per-call test clock could otherwise advance between two reads).
	base := r.now().UTC()
	now := base.Format(time.RFC3339)
	expires := base.Add(vmLockTTL).Format(time.RFC3339)
	// expired-check compares RFC3339-vs-RFC3339 (bound now), not datetime('now'):
	// expires_at is RFC3339, so a string compare to datetime('now')'s space text
	// breaks on a date match ('T' > ' ') and a same-day lock NEVER looks expired —
	// a crashed holder's vm_lock would then block another host from reconciling
	// that VM until the UTC date rolls.
	if err := r.db.Execute(ctx,
		`INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(vm_name) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at
		   WHERE vm_locks.expires_at < ?
		      OR vm_locks.holder = excluded.holder`,
		vmName, r.hostName, expires, now, now); err != nil {
		slog.Warn("reconciler: vm_lock write failed", "vm", vmName, "error", err)
		return false
	}
	rows, err := r.db.Query(ctx,
		`SELECT holder FROM vm_locks WHERE vm_name = ?`, vmName)
	if err != nil || len(rows) == 0 {
		return false
	}
	return rows[0].String("holder") == r.hostName
}

// releaseVMLock clears the per-VM lock. Best-effort; leaving a stale lock
// is recoverable (next acquire after vmLockTTL succeeds).
func (r *Reconciler) releaseVMLock(ctx context.Context, vmName string) {
	if err := r.db.Execute(ctx,
		`DELETE FROM vm_locks WHERE vm_name = ? AND holder = ?`,
		vmName, r.hostName); err != nil {
		slog.Debug("reconciler: vm_lock release failed", "vm", vmName, "error", err)
	}
}
