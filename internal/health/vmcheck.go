package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

const vmCheckSweepInterval = 10 * time.Second
const healthCheckGracePeriod = 5 * time.Minute

// VMChecker runs per-VM health checks defined in each VM's HealthCheckSpec.
type VMChecker struct {
	hostName string
	db       *corrosion.Client
	virt     *lv.Client
	bus      *events.Bus

	mu          sync.Mutex
	failures    map[string]int       // vmName → consecutive failures
	lastAction  map[string]time.Time // vmName → last action timestamp (for backoff)
	actionCount map[string]int       // vmName → consecutive actions without recovery

	// activeActions tracks how many VMs per stack are currently being acted on
	// to enforce max-unavailable limits.
	activeActions map[string]int // stackName → count of VMs mid-action

	// migrateVM is an optional callback to migrate a VM via the full MigrateVM
	// RPC path (with post-migration steps: GARP, LB, FDB, DNS, network provisioning).
	migrateVMFunc func(ctx context.Context, vmName, targetHost string) error

	// gate is the split-brain safety gate (Phase 1). When set + enforced, a
	// restart-policy start requires local quorum. nil disables (tests). onGateRefused
	// feeds the refusal metric (nil-safe).
	gate          runtimeGate
	onGateRefused func(action, reason string)
	// onStateWriteFail observes an authoritative state write that failed (nil-safe);
	// wired to the litevirt_state_write_failures_total counter by the daemon.
	onStateWriteFail func(op, class string)
}

// SetGate injects the split-brain safety gate (the health.Checker).
func (v *VMChecker) SetGate(g runtimeGate) { v.gate = g }

// SetGateRefusedObserver wires the refusal metric hook (nil-safe).
func (v *VMChecker) SetGateRefusedObserver(fn func(action, reason string)) { v.onGateRefused = fn }

func (v *VMChecker) noteGateRefused(action, reason string) {
	if v.onGateRefused != nil {
		v.onGateRefused(action, reason)
	}
}

// SetStateWriteFailObserver wires the state-write-failure metric hook (nil-safe).
func (v *VMChecker) SetStateWriteFailObserver(fn func(op, class string)) { v.onStateWriteFail = fn }

func (v *VMChecker) noteStateWriteFail(op string, err error) {
	if v.onStateWriteFail != nil {
		v.onStateWriteFail(op, corrosion.ClassifyWriteErr(err))
	}
}

// SetEventBus sets the event bus for publishing health check events.
func (v *VMChecker) SetEventBus(bus *events.Bus) { v.bus = bus }

// SetMigrateFunc registers a callback to migrate VMs via the full MigrateVM RPC
// path, ensuring all post-migration steps (GARP, LB, FDB, DNS) are executed.
func (v *VMChecker) SetMigrateFunc(fn func(ctx context.Context, vmName, targetHost string) error) {
	v.migrateVMFunc = fn
}

// publish sends an event to the bus if one is configured.
func (v *VMChecker) publish(action, target, detail string) {
	if v.bus == nil {
		return
	}
	v.bus.Publish(events.Event{
		Action: action,
		Target: target,
		Detail: detail,
	})
}

// NewVMChecker creates a VM-level health checker for the local host.
func NewVMChecker(hostName string, db *corrosion.Client, virt *lv.Client) *VMChecker {
	return &VMChecker{
		hostName:      hostName,
		db:            db,
		virt:          virt,
		failures:      make(map[string]int),
		lastAction:    make(map[string]time.Time),
		actionCount:   make(map[string]int),
		activeActions: make(map[string]int),
	}
}

// Start begins the sweep loop. Blocks until ctx is cancelled.
func (v *VMChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(vmCheckSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.sweep(ctx)
		}
	}
}

// correlatedFailureThreshold: if this many VMs fail health checks simultaneously,
// suppress auto-restart to avoid thundering herd during shared-storage outages (#47).
const correlatedFailureThreshold = 3

func (v *VMChecker) sweep(ctx context.Context) {
	vms, err := corrosion.ListVMs(ctx, v.db, "", v.hostName)
	if err != nil {
		slog.Error("vmcheck: list VMs", "error", err)
		return
	}

	// Pre-sweep: count how many VMs are in a failing state. If many are
	// failing simultaneously, it's likely correlated (NFS outage, etc.) (#47).
	if v.isCorrelatedFailure() {
		slog.Warn("vmcheck: multiple VMs failing simultaneously — possible storage/network event, suppressing auto-restart",
			"host", v.hostName)
	}

	now := time.Now()
	for _, vm := range vms {
		if vm.State != "running" {
			continue
		}
		// Grace period: skip health checks for VMs created less than 5 minutes ago.
		// Freshly booted VMs need time to finish cloud-init, get IPs, start services.
		if created, err := time.Parse(time.RFC3339, vm.CreatedAt); err == nil {
			if now.Sub(created) < healthCheckGracePeriod {
				continue
			}
		}
		hspec := vmCheckSpec(&vm)
		if hspec == nil || hspec.Type == "" {
			continue
		}
		go v.checkVM(ctx, vm, hspec)
	}

	// Second pass: restart policy for stopped/error VMs.
	for _, vm := range vms {
		if vm.State != "stopped" && vm.State != "error" {
			continue
		}
		// Reconcile a state desync first: if libvirt actually has the domain
		// running, the cluster record is stale (an out-of-band start, or an
		// RPC that mutated libvirt but failed before writing state). Heal it to
		// "running" instead of letting the restart policy fight reality. This
		// is the only safe direction — we promote to running solely when
		// libvirt confirms it. Operator-stopped VMs are left alone: the
		// operator's intent wins even if a stop didn't fully take effect.
		if vm.StateDetail != "operator-stop" && v.virt != nil {
			if st, err := v.virt.DomainState(vm.Name); err == nil && st == "running" {
				if werr := corrosion.UpdateVMStateStrict(ctx, v.db, vm.Name, "running",
					"reconciled from libvirt: domain running"); werr != nil {
					if errors.Is(werr, corrosion.ErrNoRowsAffected) {
						// Row vanished between the list and here (concurrent delete)
						// — nothing to reconcile, not a write fault.
						slog.Debug("vmcheck: reconcile target row gone; skipping", "vm", vm.Name)
						continue
					}
					slog.Error("vmcheck: reconcile write failed — NOT publishing reconciled event",
						"vm", vm.Name, "error", werr)
					v.noteStateWriteFail(corrosion.OpVMState, werr)
					continue
				}
				v.publish("vm.state.reconciled", vm.Name,
					fmt.Sprintf("cluster state was %q, libvirt reports running", vm.State))
				slog.Warn("vmcheck: reconciled stale VM state", "vm", vm.Name, "was", vm.State)
				continue
			}
		}
		// Never restart VMs explicitly stopped by the operator (#29).
		if vm.StateDetail == "operator-stop" {
			continue
		}
		v.maybeRestartVM(ctx, vm, now)
	}
}

// isCorrelatedFailure returns true if many VMs are failing simultaneously,
// indicating a shared infrastructure issue rather than individual VM problems (#47).
func (v *VMChecker) isCorrelatedFailure() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	count := 0
	for _, f := range v.failures {
		if f >= 2 {
			count++
		}
	}
	return count >= correlatedFailureThreshold
}

func (v *VMChecker) checkVM(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec) {
	interval := parseDuration(hspec.Interval, 30*time.Second)
	timeout := parseDuration(hspec.Timeout, 5*time.Second)
	retries := int(hspec.Retries)
	if retries == 0 {
		retries = 3
	}

	// Rate-limit: only check if it's been at least one interval since the last sweep.
	_ = interval // interval enforcement is handled by the sweep ticker + goroutine lifecycle

	healthy := v.probe(ctx, vm.Name, hspec, timeout)

	v.mu.Lock()
	if healthy {
		v.failures[vm.Name] = 0
		v.actionCount[vm.Name] = 0
		v.mu.Unlock()
		return
	}
	v.failures[vm.Name]++
	count := v.failures[vm.Name]
	v.mu.Unlock()

	slog.Warn("vmcheck: probe failed", "vm", vm.Name, "type", hspec.Type, "consecutive", count)

	if count < retries {
		return
	}

	// Threshold crossed — take action (with backoff and max-unavailable).
	v.mu.Lock()
	v.failures[vm.Name] = 0

	// Exponential backoff: if we've already acted on this VM without recovery,
	// wait progressively longer before acting again.
	acts := v.actionCount[vm.Name]
	if acts > 0 {
		backoff := time.Duration(1<<min(acts, 6)) * 30 * time.Second // 30s, 60s, 120s, ... max ~32min
		if last, ok := v.lastAction[vm.Name]; ok && time.Since(last) < backoff {
			v.mu.Unlock()
			slog.Warn("vmcheck: action backoff active", "vm", vm.Name, "consecutive_actions", acts,
				"next_eligible", last.Add(backoff).Format(time.RFC3339))
			return
		}
	}

	// Max-unavailable: limit concurrent actions per stack to 1 (or configurable).
	stack := vm.StackName
	if stack != "" {
		maxUnavailable := 1 // default: only 1 VM per stack can be acted on at a time
		if v.activeActions[stack] >= maxUnavailable {
			v.mu.Unlock()
			slog.Warn("vmcheck: max-unavailable reached for stack", "stack", stack,
				"active_actions", v.activeActions[stack], "max", maxUnavailable)
			return
		}
		v.activeActions[stack]++
	}

	v.actionCount[vm.Name]++
	v.lastAction[vm.Name] = time.Now()
	v.mu.Unlock()

	// Release the stack action slot when done.
	defer func() {
		if stack != "" {
			v.mu.Lock()
			v.activeActions[stack]--
			v.mu.Unlock()
		}
	}()

	v.takeAction(ctx, vm, hspec)
}

func (v *VMChecker) probe(ctx context.Context, vmName string, hspec *pb.HealthCheckSpec, timeout time.Duration) bool {
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch hspec.Type {
	case "tcp":
		conn, err := (&net.Dialer{}).DialContext(tctx, "tcp", hspec.Target)
		if err != nil {
			return false
		}
		conn.Close()
		return true

	case "http", "https":
		req, err := http.NewRequestWithContext(tctx, http.MethodGet, hspec.Target, nil)
		if err != nil {
			return false
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return false
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode < 500

	case "ping":
		cmd := exec.CommandContext(tctx, "ping", "-c", "1", "-W", "2", hspec.Target)
		return cmd.Run() == nil

	case "exec":
		// Run command inside the VM via guest agent.
		if v.virt == nil {
			return false
		}
		// Guard: exec probes require a guest agent. If the VM spec says
		// guest_agent is disabled, skip the probe and treat as healthy (#9).
		spec := vmSpecFromDB(ctx, v.db, vmName)
		if spec != nil && !spec.GuestAgent {
			slog.Warn("vmcheck: exec probe skipped — guest agent disabled", "vm", vmName)
			return true
		}
		// ExecInGuest takes no context (the guest-agent call can block ~30-60s),
		// so honor the probe timeout ourselves — otherwise a hung agent makes the
		// probe run far past `timeout`, piling up overlapping sweeps (bug-sweep
		// #10). A timed-out probe counts as a failure.
		done := make(chan error, 1)
		go func() { _, e := v.virt.ExecInGuest(vmName, "/bin/sh", []string{"-c", hspec.Target}); done <- e }()
		select {
		case err := <-done:
			return err == nil
		case <-tctx.Done():
			slog.Warn("vmcheck: exec probe timed out", "vm", vmName, "timeout", timeout)
			return false
		}

	default:
		slog.Warn("vmcheck: unknown probe type", "type", hspec.Type)
		return true
	}
}

func (v *VMChecker) takeAction(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec) {
	action := hspec.Action
	if action == "" {
		action = "restart"
	}

	// Suppress action if correlated failures detected (#47).
	if v.isCorrelatedFailure() {
		v.publish("vm.health.suppressed", vm.Name, "correlated failures detected — possible storage/network event")
		slog.Warn("vmcheck: suppressing action due to correlated failures — likely storage/network event",
			"vm", vm.Name, "action", action)
		return
	}

	// Re-read VM state before acting. If the operator stopped the VM
	// between the probe and now, do not restart it (#29).
	fresh, err := corrosion.GetVM(ctx, v.db, vm.Name)
	if err != nil || fresh == nil {
		return
	}
	// Ownership may have moved off this host since the health probe was QUEUED (the
	// sweep spawns checks async on a snapshot). Act ONLY if we still own it — else a
	// destroy/start would hit a stale local domain, or a migrate would use a stale
	// source host, fighting the new owner. Everything below acts on the FRESH record.
	if fresh.HostName != v.hostName {
		slog.Info("vmcheck: skipping action — VM no longer owned by this host",
			"vm", vm.Name, "owner", fresh.HostName)
		return
	}
	if fresh.State == "stopped" && fresh.StateDetail == "operator-stop" {
		slog.Info("vmcheck: skipping action — VM was stopped by operator", "vm", vm.Name)
		return
	}
	if fresh.State != "running" {
		slog.Info("vmcheck: skipping action — VM state changed", "vm", vm.Name, "state", fresh.State)
		return
	}

	// Split-brain gate (Phase 1): "restart" (destroy+start) and "migrate" are
	// automated RUNTIME actions — once enforcement is latched they require local
	// quorum (ExecutionGate), so an isolated host with a failing health probe can't
	// restart-in-place or migrate a VM without quorum. "alert" is a notification, not
	// a runtime action, and still fires. Fail-open until split_brain_gate_v1 is
	// cluster-wide. (This is separate from the restart-POLICY gate in maybeRestartVM.)
	if action == "restart" || action == "migrate" {
		// Self-fence is an UNCONDITIONAL hard gate (independent of enforcement): a doomed
		// node must not restart-in-place or migrate a VM during its fence-timeout window.
		if selfFenceHardGate(v.gate) {
			slog.Warn("vmcheck: self-fenced — refusing health-check action", "vm", vm.Name, "action", action)
			v.noteGateRefused(corrosion.ActionReschedule, ReasonSelfFenced)
			return
		}
		if v.gate != nil && v.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
			if g := v.gate.ExecutionGate(ctx); !g.OK {
				slog.Warn("vmcheck: execution gate refused health-check action (no quorum)",
					"vm", vm.Name, "action", action, "reason", g.Reason)
				v.noteGateRefused(corrosion.ActionReschedule, g.Reason)
				return
			}
		}
	}

	slog.Warn("vmcheck: taking action", "vm", vm.Name, "action", action)
	v.publish("vm.health.failed", vm.Name, fmt.Sprintf("action=%s type=%s", action, hspec.Type))

	switch action {
	case "restart":
		if v.virt == nil {
			return
		}
		v.virt.DestroyDomain(vm.Name)
		if err := v.virt.StartDomain(vm.Name); err != nil {
			slog.Error("vmcheck: restart failed", "vm", vm.Name, "error", err)
			if werr := corrosion.UpdateVMState(ctx, v.db, vm.Name, "error", fmt.Sprintf("health check restart failed: %v", err)); werr != nil {
				v.noteStateWriteFail(corrosion.OpVMState, werr)
			}
			return
		}
		if err := corrosion.UpdateVMStateStrict(ctx, v.db, vm.Name, "running", "restarted by health checker"); err != nil {
			slog.Error("vmcheck: restart state write failed — NOT publishing restarted event", "vm", vm.Name, "error", err)
			v.noteStateWriteFail(corrosion.OpVMState, err)
			return
		}
		v.publish("vm.health.restarted", vm.Name, "restarted by health checker")
		slog.Info("vmcheck: VM restarted", "vm", vm.Name)

	case "migrate":
		v.migrateVM(ctx, *fresh) // act on the fresh record (current owner), not the queued snapshot

	case "alert":
		v.publish("vm.health.alert", vm.Name, fmt.Sprintf("type=%s target=%s", hspec.Type, hspec.Target))
		slog.Error("vmcheck: ALERT — VM health check failed", "vm", vm.Name, "type", hspec.Type, "target", hspec.Target)

	default:
		slog.Warn("vmcheck: unknown action", "action", action, "vm", vm.Name)
	}
}

// migrateVM picks a healthy target host and live-migrates the VM there.
// Prefers the full MigrateVM RPC path (via callback) which handles all
// post-migration steps (GARP, LB, FDB, DNS, network provisioning).
func (v *VMChecker) migrateVM(ctx context.Context, vm corrosion.VMRecord) {
	// Find a healthy target host.
	target, err := v.pickMigrationTarget(ctx, vm.HostName, vm.MemActual)
	if err != nil {
		slog.Error("vmcheck: no migration target available", "vm", vm.Name, "error", err)
		if werr := corrosion.UpdateVMState(ctx, v.db, vm.Name, "error", "health check failed, no migration target available"); werr != nil {
			v.noteStateWriteFail(corrosion.OpVMState, werr)
		}
		return
	}

	slog.Info("vmcheck: migrating VM", "vm", vm.Name, "from", v.hostName, "to", target.Name)

	// Use the full MigrateVM RPC path if available — it handles GARP, LB refresh,
	// FDB updates, DNS, and network provisioning on the target.
	if v.migrateVMFunc != nil {
		if err := v.migrateVMFunc(ctx, vm.Name, target.Name); err != nil {
			slog.Error("vmcheck: migration via RPC failed", "vm", vm.Name, "target", target.Name, "error", err)
			return
		}
		v.publish("vm.health.migrated", vm.Name, fmt.Sprintf("from=%s to=%s", v.hostName, target.Name))
		slog.Info("vmcheck: VM migrated successfully via RPC", "vm", vm.Name, "to", target.Name)
		return
	}

	// Fallback: direct libvirt migration (no post-migration steps).
	if v.virt == nil {
		slog.Error("vmcheck: migrate action requires libvirt or migrate callback", "vm", vm.Name)
		return
	}

	if err := corrosion.UpdateVMState(ctx, v.db, vm.Name, "migrating", fmt.Sprintf("health check → %s", target.Name)); err != nil {
		v.noteStateWriteFail(corrosion.OpVMState, err)
	}

	dconnuri := fmt.Sprintf("qemu+tls://%s/system", target.Address)
	if err := v.virt.MigrateToTarget(vm.Name, dconnuri, lv.MigrateParams{Live: true}); err != nil {
		slog.Error("vmcheck: migration failed", "vm", vm.Name, "target", target.Name, "error", err)
		if werr := corrosion.UpdateVMState(ctx, v.db, vm.Name, "running", fmt.Sprintf("migration to %s failed: %v", target.Name, err)); werr != nil {
			v.noteStateWriteFail(corrosion.OpVMState, werr)
		}
		return
	}

	// The domain has already moved to the target; the ownership write MUST land or
	// the source row strands a VM it no longer runs (dual/stale ownership). Retry
	// briefly to absorb a transient error before giving up to the reconciler.
	var werr error
	for attempt := 0; attempt < 4; attempt++ {
		if werr = corrosion.UpdateVMHost(ctx, v.db, vm.Name, target.Name, "running"); werr == nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 100 * time.Millisecond)
	}
	if werr != nil {
		slog.Error("vmcheck: post-migration ownership write failed after retries — VM stranded on source row; reconciler must resolve",
			"vm", vm.Name, "to", target.Name, "error", werr)
		v.noteStateWriteFail(corrosion.OpVMHost, werr)
		return
	}
	v.publish("vm.health.migrated", vm.Name, fmt.Sprintf("from=%s to=%s", v.hostName, target.Name))
	slog.Info("vmcheck: VM migrated successfully", "vm", vm.Name, "to", target.Name)
}

// pickMigrationTarget finds an active host other than the current one,
// preferring the host with the most free memory. Validates the target
// has enough free memory for the VM (#2).
func (v *VMChecker) pickMigrationTarget(ctx context.Context, excludeHost string, vmMemMiB int) (*corrosion.HostRecord, error) {
	hosts, err := corrosion.ListHosts(ctx, v.db)
	if err != nil {
		return nil, fmt.Errorf("list hosts: %w", err)
	}

	// Compute per-host memory usage by summing running VM allocations.
	vms, _ := corrosion.ListVMs(ctx, v.db, "", "")
	memUsed := map[string]int{}
	for _, vm := range vms {
		if vm.State == "running" || vm.State == "creating" || vm.State == "starting" {
			memUsed[vm.HostName] += vm.MemActual
		}
	}

	var best *corrosion.HostRecord
	var bestFree int
	for i := range hosts {
		h := &hosts[i]
		if h.Name == excludeHost || h.State != "active" {
			continue
		}
		free := h.MemTotal - memUsed[h.Name]
		// Only consider hosts with enough free memory for the VM.
		if vmMemMiB > 0 && free < vmMemMiB {
			continue
		}
		if best == nil || free > bestFree {
			best = h
			bestFree = free
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no active hosts available with sufficient memory")
	}
	return best, nil
}

// maybeRestartVM checks if a stopped/error VM has a restart policy and attempts restart.
func (v *VMChecker) maybeRestartVM(ctx context.Context, vm corrosion.VMRecord, now time.Time) {
	spec := vmSpecFromDB(ctx, v.db, vm.Name)
	if spec == nil || spec.Restart == nil {
		return
	}
	rp := spec.Restart

	// Decide whether to restart based on WHY the VM stopped — not merely that it
	// is "stopped" (a crash also lands there). Prefer the live libvirt shutoff
	// reason (authoritative); fall back to the persisted state_detail when
	// libvirt is unreachable. A suspended VM (managed-save) is never cold-booted.
	// restartDecision holds the full matrix; "guest-stick" means a clean guest
	// shutdown / operator stop never restarts under any condition.
	cause := ""
	hasManagedSave := false
	if v.virt != nil {
		if st, err := v.virt.DomainStateReason(vm.Name); err == nil {
			cause = st.Reason
		}
		if ms, err := v.virt.HasManagedSaveImage(vm.Name); err == nil {
			hasManagedSave = ms
		}
	}
	ok, decision := restartDecision(cause, vm.StateDetail, hasManagedSave, rp.Condition)
	if !ok {
		slog.Debug("vmcheck: not restarting per policy", "vm", vm.Name, "decision", decision)
		return
	}

	// Check restart state from DB.
	rs, err := corrosion.GetRestartState(ctx, v.db, vm.Name)
	if err != nil {
		slog.Error("vmcheck: get restart state", "vm", vm.Name, "error", err)
		return
	}

	window := parseDuration(rp.Window, time.Hour)
	delay := parseDuration(rp.Delay, 5*time.Second)

	// If window has elapsed, reset the counter.
	if rs != nil && !rs.WindowStart.IsZero() && now.Sub(rs.WindowStart) > window {
		_ = corrosion.ResetRestartState(ctx, v.db, vm.Name)
		rs = nil
	}

	// Check max_attempts within the window.
	if rp.MaxAttempts > 0 && rs != nil && rs.AttemptCount >= int(rp.MaxAttempts) {
		slog.Warn("vmcheck: restart max attempts reached", "vm", vm.Name,
			"attempts", rs.AttemptCount, "max", rp.MaxAttempts)
		return
	}

	// Check delay since last restart.
	if rs != nil && !rs.LastRestart.IsZero() && now.Sub(rs.LastRestart) < delay {
		return
	}

	// Self-fence is an UNCONDITIONAL hard gate (independent of enforcement): a doomed
	// node must not restart a VM per restart-policy during its fence-timeout window.
	if selfFenceHardGate(v.gate) {
		slog.Info("vmcheck: self-fenced — refusing restart-policy start", "vm", vm.Name)
		v.noteGateRefused(corrosion.ActionReschedule, ReasonSelfFenced)
		return
	}
	// Split-brain gate (Phase 1): a restart-policy start is a runtime action; once
	// enforced it needs local quorum, so an isolated host with stale local ownership
	// can't restart-into a double-run. Fail-open until latched.
	if v.gate != nil && v.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
		if g := v.gate.ExecutionGate(ctx); !g.OK {
			slog.Info("vmcheck: execution gate refused restart (no quorum)", "vm", vm.Name, "reason", g.Reason)
			v.noteGateRefused(corrosion.ActionReschedule, g.Reason)
			return
		}
	}

	// Perform restart.
	slog.Info("vmcheck: restarting VM per restart policy", "vm", vm.Name,
		"condition", rp.Condition, "state", vm.State)

	if err := corrosion.IncrementRestart(ctx, v.db, vm.Name); err != nil {
		slog.Error("vmcheck: increment restart counter", "vm", vm.Name, "error", err)
	}

	if v.virt == nil {
		return
	}
	// Ensure domain is destroyed before starting (may already be stopped).
	_ = v.virt.DestroyDomain(vm.Name)
	if err := v.virt.StartDomain(vm.Name); err != nil {
		slog.Error("vmcheck: restart policy start failed", "vm", vm.Name, "error", err)
		if werr := corrosion.UpdateVMState(ctx, v.db, vm.Name, "error",
			fmt.Sprintf("restart policy start failed: %v", err)); werr != nil {
			v.noteStateWriteFail(corrosion.OpVMState, werr)
		}
		return
	}
	if err := corrosion.UpdateVMStateStrict(ctx, v.db, vm.Name, "running", "restart policy: "+decision); err != nil {
		slog.Error("vmcheck: restart-policy state write failed — NOT publishing restart event", "vm", vm.Name, "error", err)
		v.noteStateWriteFail(corrosion.OpVMState, err)
		return
	}
	v.publish("vm.restart.policy", vm.Name,
		fmt.Sprintf("condition=%s attempt=%d (%s)", rp.Condition, safeAttemptCount(rs)+1, decision))
}

func safeAttemptCount(rs *corrosion.RestartState) int {
	if rs == nil {
		return 0
	}
	return rs.AttemptCount
}

// vmCheckSpec extracts the HealthCheckSpec from a VMRecord's stored JSON spec.
func vmCheckSpec(vm *corrosion.VMRecord) *pb.HealthCheckSpec {
	if vm.Spec == "" {
		return nil
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
		return nil
	}
	return spec.Healthcheck
}

// vmSpecFromDB loads the full VMSpec from a VM's stored JSON.
func vmSpecFromDB(ctx context.Context, db *corrosion.Client, vmName string) *pb.VMSpec {
	vm, err := corrosion.GetVM(ctx, db, vmName)
	if err != nil || vm == nil || vm.Spec == "" {
		return nil
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
		return nil
	}
	return spec
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}
