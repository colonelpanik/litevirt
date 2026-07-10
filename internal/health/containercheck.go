package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/network"
)

const containerCheckInterval = 15 * time.Second

// ContainerChecker is the container analogue of the VM reconciler + restart
// engine: every cycle it reconciles the cluster row for each locally-owned
// container against the LXC runtime's reality, and auto-restarts a container
// that stopped UNEXPECTEDLY per its restart policy.
//
// Coarser than the VM path by necessity: lxc-info reports only
// RUNNING/STOPPED/FROZEN — there is no stop *reason*, so a container cannot
// distinguish a clean in-guest shutdown from a crash. We therefore treat any
// non-operator stop as unexpected (the documented limitation). Only an operator
// `lv ct stop` (which records state_detail='operator-stop') is guaranteed-stick.
// FROZEN maps to running upstream (lxc.parseLxcInfoState), so paused containers
// are never restarted. Like the VM reconciler, this acts ONLY on containers the
// local host owns — host-loss relocation is a follow-up.
type ContainerChecker struct {
	hostName string
	db       *corrosion.Client
	runtime  lxc.Runtime
	bus      *events.Bus

	// checkPeerRuntime asks a peer for its local LXC view of a container
	// (absent/defined_stopped/running/unknown) — injected by the daemon. nil
	// disables runtime re-key. See SetPeerContainerRuntimeChecker.
	checkPeerRuntime func(ctx context.Context, host, name string) (string, error)
	// onRekey observes each runtime re-key decision (result ∈ rekeyed /
	// split_brain / inconclusive / error) — nil-safe; tests assert on it.
	onRekey func(name, result string)

	// gate is the split-brain safety gate (Phase 1). When set + enforced, a
	// container re-key additionally requires local quorum (ExecutionGate). See
	// SetGate. onGateRefused feeds the refusal metric (nil-safe).
	gate          runtimeGate
	onGateRefused func(action, reason string)
	// onStateWriteFail observes an authoritative state write that failed (nil-safe);
	// wired to the litevirt_state_write_failures_total counter by the daemon.
	onStateWriteFail func(op, class string)

	// Now is the clock for the re-key debounce (defaults to time.Now); tests
	// override it to advance deterministically.
	Now func() time.Time

	// ownerMu guards ownershipFirstSeen, the debounce map recording when each
	// container was first seen running-locally-but-owned-elsewhere.
	ownerMu            sync.Mutex
	ownershipFirstSeen map[string]time.Time
}

// NewContainerChecker creates a container reconciler/restart engine for the
// local host, sharing the LXC runtime wired into the gRPC server.
func NewContainerChecker(hostName string, db *corrosion.Client, runtime lxc.Runtime) *ContainerChecker {
	return &ContainerChecker{hostName: hostName, db: db, runtime: runtime}
}

// SetEventBus sets the event bus for publishing container lifecycle events.
func (c *ContainerChecker) SetEventBus(bus *events.Bus) { c.bus = bus }

// SetGate injects the split-brain safety gate (the health.Checker).
func (c *ContainerChecker) SetGate(g runtimeGate) { c.gate = g }

// SetGateRefusedObserver wires the refusal metric hook (nil-safe).
func (c *ContainerChecker) SetGateRefusedObserver(fn func(action, reason string)) {
	c.onGateRefused = fn
}

func (c *ContainerChecker) noteGateRefused(action, reason string) {
	if c.onGateRefused != nil {
		c.onGateRefused(action, reason)
	}
}

// SetStateWriteFailObserver wires the state-write-failure metric hook (nil-safe).
func (c *ContainerChecker) SetStateWriteFailObserver(fn func(op, class string)) {
	c.onStateWriteFail = fn
}

func (c *ContainerChecker) noteStateWriteFail(op string, err error) {
	if c.onStateWriteFail != nil {
		c.onStateWriteFail(op, corrosion.ClassifyWriteErr(err))
	}
}

func (c *ContainerChecker) publish(action, target, detail string) {
	if c.bus == nil {
		return
	}
	c.bus.Publish(events.Event{Action: action, Target: target, Detail: detail})
}

// Start begins the sweep loop. Blocks until ctx is cancelled.
func (c *ContainerChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(containerCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.sweep(ctx)
		}
	}
}

// SweepOnce runs a single reconcile pass — the body of the periodic loop,
// exported (mirroring Reconciler.ReconcileOnce) so the fleet harness and one-shot
// ops can drive a deterministic pass without waiting on the 15s ticker.
func (c *ContainerChecker) SweepOnce(ctx context.Context) { c.sweep(ctx) }

func (c *ContainerChecker) sweep(ctx context.Context) {
	if c.runtime == nil {
		return
	}
	cts, err := corrosion.ListContainers(ctx, c.db, c.hostName)
	if err != nil {
		slog.Error("containercheck: list containers", "error", err)
		return
	}
	now := time.Now()
	live := make(map[string]bool, len(cts))
	for _, ct := range cts {
		live[ct.Name] = true
		c.checkContainer(ctx, ct, now)
	}

	// Runtime owner re-key (Phase 4): reclaim a container running locally whose
	// only live DB row points at another host. Runs BEFORE the orphan-lease GC so
	// a re-key (which transfers the container's leases to us) isn't racing a GC of
	// those same leases.
	c.assertContainerOwnership(ctx)

	// GC IPAM leases stranded by a crash between allocating a lease and persisting
	// the container row (an orphan lease — owner with no live container row). The
	// age guard keeps this from racing an in-flight create. The live set also
	// includes every container present in the LOCAL RUNTIME, not just those with a
	// local DB row: in the exact ownership-divergence case the runtime container
	// exists but its DB row points elsewhere, and its lease must NOT be reclaimed
	// out from under the pending re-key.
	if names, lerr := c.runtime.List(ctx); lerr == nil {
		for _, n := range names {
			live[n] = true
		}
	}
	if _, err := network.ReleaseOrphanContainerLeases(ctx, c.db, c.hostName, live, orphanLeaseMinAge); err != nil {
		slog.Warn("containercheck: orphan-lease GC failed", "error", err)
	}
}

// orphanLeaseMinAge is how long a CT IPAM lease with no live container row must
// persist before the sweep reclaims it — comfortably longer than any in-flight
// create (which holds the name lock and completes in seconds).
const orphanLeaseMinAge = 5 * time.Minute

// recreateRelocated rebuilds a container the failover coordinator re-homed here
// after a host loss (B5), from its re-pullable image. Best-effort tier-1: the
// recreated container is a fresh instance of the image (networks/advanced config
// from the original aren't preserved — the faithful path is restore-from-backup,
// a follow-up). On failure it leaves the row pending so the next sweep retries.
func (c *ContainerChecker) recreateRelocated(ctx context.Context, ct corrosion.ContainerRecord) {
	spec := corrosion.DecodeCreateSpec(ct.CreateSpec)

	// Already materialized by a prior tick (runtime container exists)? A prior tick
	// may have created the runtime but failed to write the interface rows — so
	// ENSURE the managed rows are present (and IPs re-reserved) BEFORE clearing the
	// relocate marker, otherwise clearing it would drop the rebuild forever.
	if live, err := c.runtime.State(ctx, ct.Name); err == nil &&
		(live == lxc.StateRunning || live == lxc.StateStopped) {
		ifs := corrosion.BuildContainerInterfacesFromSpec(c.hostName, ct.Name, spec)
		if !c.writeRelocatedNICs(ctx, ct.Name, ifs) {
			return // row write failed → keep the marker, retry next sweep
		}
		if _, err := network.ReserveContainerNICs(ctx, c.db, c.hostName, ct.Name, ifs); err != nil {
			slog.Warn("containercheck: relocate IP re-reservation incomplete", "container", ct.Name, "error", err)
		}
		state := "stopped"
		if live == lxc.StateRunning {
			state = "running"
		}
		if err := corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, state, ""); err != nil {
			slog.Warn("containercheck: relocate materialize state write failed", "container", ct.Name, "error", err)
			c.noteStateWriteFail(corrosion.OpContainerState, err)
		}
		return
	}

	slog.Info("containercheck: recreating relocated container from image",
		"container", ct.Name, "image", ct.Image)
	// Reconstruct litevirt-managed networking from the create spec, RESERVING each
	// managed IP up front so the on-disk config never names an address we don't own
	// (a NIC we can't claim is rendered without an IP → DHCP/re-discovery). Legacy
	// raw-bridge NICs pass through with no managed state.
	opts := lxc.CreateOpts{
		Name: ct.Name, Template: ct.Image,
		CPULimit: ct.CPULimit, MemoryMiB: ct.MemMiB, Labels: ct.Labels,
	}
	var ifs []corrosion.ContainerInterfaceRecord
	for i, n := range spec.Networks {
		if n.NetworkName == "" {
			opts.Network = append(opts.Network, lxc.NetworkAttach{Name: n.Name, Bridge: n.Bridge, IP: n.IP, MAC: n.MAC})
			continue
		}
		veth := corrosion.ContainerVethName(ct.Name, i)
		ip := n.IP
		if ip != "" {
			if ok, rerr := network.ReserveContainerIP(ctx, c.db, n.NetworkName, ip, n.MAC, c.hostName, ct.Name); rerr != nil || !ok {
				if rerr != nil {
					slog.Warn("containercheck: relocate IP reserve errored; using DHCP", "container", ct.Name, "ip", ip, "error", rerr)
				}
				ip = "" // couldn't claim → don't put it on-disk
			}
		}
		opts.Network = append(opts.Network, lxc.NetworkAttach{Name: n.Name, Bridge: n.Bridge, IP: ip, MAC: n.MAC, Veth: veth})
		ifs = append(ifs, corrosion.ContainerInterfaceRecord{
			HostName: c.hostName, CtName: ct.Name, NetworkName: n.NetworkName, Ordinal: i,
			MAC: n.MAC, IP: ip, VethDevice: veth, SecurityGroups: n.SecurityGroups,
		})
	}
	if _, err := c.runtime.Create(ctx, opts); err != nil {
		_ = network.ReleaseContainerLeases(ctx, c.db, c.hostName, ct.Name) // undo the reserved leases
		slog.Error("containercheck: relocate-recreate failed (will retry)",
			"container", ct.Name, "image", ct.Image, "error", err)
		c.publish("ct.relocate.failed", ct.Name, err.Error())
		return // leave pending → retried next sweep
	}
	// Fail closed: if the interface rows can't be written, leave the relocate marker
	// so the next sweep retries — never clear it with NIC state missing.
	if !c.writeRelocatedNICs(ctx, ct.Name, ifs) {
		return
	}
	if err := c.runtime.Start(ctx, ct.Name); err != nil {
		slog.Error("containercheck: relocate-recreate start failed", "container", ct.Name, "error", err)
		if werr := corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "stopped", ""); werr != nil {
			c.noteStateWriteFail(corrosion.OpContainerState, werr)
		}
		return
	}
	if err := corrosion.SetContainerStateDetailStrict(ctx, c.db, c.hostName, ct.Name, "running", ""); err != nil {
		slog.Error("containercheck: relocate-recreate state write failed — NOT publishing relocated event",
			"container", ct.Name, "error", err)
		c.noteStateWriteFail(corrosion.OpContainerState, err)
		return
	}
	c.publish("ct.relocated", ct.Name, "recreated from image after host loss")
	slog.Info("containercheck: relocated container recreated", "container", ct.Name)
}

// writeRelocatedNICs persists the relocated container's managed interface rows.
// Returns false (caller keeps the relocate marker for retry) if any write fails.
func (c *ContainerChecker) writeRelocatedNICs(ctx context.Context, ctName string, ifs []corrosion.ContainerInterfaceRecord) bool {
	for _, ifc := range ifs {
		if err := corrosion.UpsertContainerInterface(ctx, c.db, ifc); err != nil {
			slog.Error("containercheck: relocate interface-row write failed (will retry)",
				"container", ctName, "network", ifc.NetworkName, "error", err)
			return false
		}
	}
	return true
}

// claimRelocationProof validates + claims the token-bound relocation proof for a
// relocate-recreate container. Returns (id, true) to proceed — including the
// legacy (no-token) case where the row predates enforcement — or ("", false) to
// refuse/retry (missing/mismatched/terminal proof; already logged + metered).
func (c *ContainerChecker) claimRelocationProof(ctx context.Context, ct corrosion.ContainerRecord) (string, bool) {
	if ct.RelocateToken == "" {
		return "", true // legacy (pre-enforcement) relocate row → no proof to claim
	}
	pr, ok, err := corrosion.GetActionProofByToken(ctx, c.db, ct.RelocateToken)
	if err != nil || !ok {
		slog.Info("containercheck: relocation proof not yet visible, retrying", "container", ct.Name)
		return "", false // replication lag — retry next tick
	}
	if pr.Action != corrosion.ActionRelocate || pr.TargetKind != "container" ||
		pr.TargetName != ct.Name || pr.DestHost != c.hostName {
		slog.Warn("containercheck: relocation proof does not match this container/host, refusing",
			"container", ct.Name, "proof", pr.ID)
		c.noteGateRefused(corrosion.ActionRelocate, ReasonProofConflict)
		return "", false
	}
	if err := corrosion.ClaimActionProof(ctx, c.db, pr.ID, c.hostName); err != nil {
		reason := ReasonProofTerminal
		if !errors.Is(err, corrosion.ErrProofSpent) {
			reason = ReasonProofClaimError // transient DB error, not a spent proof
		}
		slog.Warn("containercheck: claim relocation proof failed, refusing", "container", ct.Name, "proof", pr.ID, "error", err)
		c.noteGateRefused(corrosion.ActionRelocate, reason)
		return "", false
	}
	return pr.ID, true
}

// checkContainer reconciles one container's cluster row to the runtime's reality
// and applies the restart policy when it stopped unexpectedly.
func (c *ContainerChecker) checkContainer(ctx context.Context, ct corrosion.ContainerRecord, now time.Time) {
	// B5 host-loss relocation: the failover coordinator re-homed this container
	// to us (state=pending, detail=relocate-recreate) after its host was fenced.
	// Its rootfs died with that host, so recreate it from its image here. This
	// runs before the normal state read because a not-yet-created container has
	// no LXC instance (lxc-info would error).
	if ct.State == "pending" && ct.StateDetail == corrosion.ContainerRelocateRecreateDetail {
		// Split-brain gate (Phase 1, execute site): materializing a relocated
		// container is a runtime-ownership action.
		//   - A non-empty relocate_token is the MARKER: it FORCES both the local
		//     ExecutionGate AND proof validation, regardless of local activation — a
		//     token is only ever minted alongside a proof, and in an asymmetric
		//     partition a target can receive a valid token while itself lacking quorum,
		//     so it must not execute without local quorum.
		//   - Enforcement latched (no token) also requires the ExecutionGate.
		// Fail-open only for a truly markerless (pre-enforcement) row. A relocate_token
		// (marker) present with NO gate wired fails CLOSED — we can't verify quorum or
		// validate the proof, and a token is only ever minted alongside one. (Production
		// wires the gate before the sweep; this is defense-in-depth.)
		proofID := ""
		if ct.RelocateToken != "" && c.gate == nil {
			slog.Warn("containercheck: relocate_token present but no gate wired — refusing relocate-recreate (fail closed)",
				"container", ct.Name)
			c.noteGateRefused(corrosion.ActionRelocate, ReasonNoQuorum)
			return
		}
		// Self-fence is an UNCONDITIONAL hard gate (independent of token/enforcement): a
		// doomed node must not materialize a relocated container during its fence window.
		if selfFenceHardGate(c.gate) {
			slog.Warn("containercheck: self-fenced — refusing relocate-recreate", "container", ct.Name)
			c.noteGateRefused(corrosion.ActionRelocate, ReasonSelfFenced)
			return
		}
		if c.gate != nil {
			if ct.RelocateToken != "" || c.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
				if g := c.gate.ExecutionGate(ctx); !g.OK {
					slog.Info("containercheck: execution gate refused relocate-recreate (no quorum)",
						"container", ct.Name, "reason", g.Reason)
					c.noteGateRefused(corrosion.ActionRelocate, g.Reason)
					return
				}
			}
			// Post-activation, a relocate-recreate row is a coordinator OWNERSHIP
			// TRANSFER that mints a relocation token + proof atomically. A token-less
			// one under enforcement is stale / pre-activation / hand-mutated — refuse
			// (proof_missing) rather than recreate an ownership transfer with no proof.
			// (Unlike a VM "starting", this state is EXCLUSIVELY a coordinator transfer
			// — there is no local-start analogue — so the refusal is unambiguous.)
			if ct.RelocateToken == "" && c.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
				slog.Warn("containercheck: enforced relocate-recreate carries no token — refusing (proof_missing): stale/pre-activation/hand-mutated row",
					"container", ct.Name)
				c.noteGateRefused(corrosion.ActionRelocate, ReasonProofMissing)
				return
			}
			if ct.RelocateToken != "" {
				id, ok := c.claimRelocationProof(ctx, ct)
				if !ok {
					return // proof missing/mismatched/terminal — refuse (already logged/metered)
				}
				proofID = id
			}
		}
		c.recreateRelocated(ctx, ct)
		// If materialized (marker cleared), mark the proof terminal (single-use).
		if proofID != "" {
			if fresh, _ := corrosion.GetContainer(ctx, c.db, c.hostName, ct.Name); fresh != nil &&
				fresh.StateDetail != corrosion.ContainerRelocateRecreateDetail {
				if err := corrosion.CompleteActionProof(ctx, c.db, proofID, c.hostName); err != nil {
					slog.Warn("containercheck: complete relocation proof", "container", ct.Name, "proof", proofID, "error", err)
				}
			}
		}
		return
	}

	live, err := c.runtime.State(ctx, ct.Name)
	if err != nil {
		// lxc-info failed (container being deleted, runtime hiccup) — can't
		// determine reality this tick; retry next sweep rather than guess.
		return
	}

	switch live {
	case lxc.StateRunning:
		// Reality: up (FROZEN maps to running). Heal cluster drift and clear any
		// stale stop cause so a later unexpected stop is judged fresh.
		if ct.State != "running" {
			if err := corrosion.SetContainerStateDetailStrict(ctx, c.db, c.hostName, ct.Name, "running", ""); err != nil {
				if errors.Is(err, corrosion.ErrNoRowsAffected) {
					// Row vanished between the sweep list and here (concurrent
					// delete) — nothing to reconcile, not a write fault.
					slog.Debug("containercheck: reconcile target row gone; skipping", "container", ct.Name)
					return
				}
				slog.Error("containercheck: reconcile write failed — NOT publishing reconciled event",
					"container", ct.Name, "error", err)
				c.noteStateWriteFail(corrosion.OpContainerState, err)
				return
			}
			c.publish("ct.state.reconciled", ct.Name,
				fmt.Sprintf("cluster state was %q, runtime reports running", ct.State))
			slog.Warn("containercheck: reconciled stale container state", "container", ct.Name, "was", ct.State)
		}
		return
	case lxc.StateStarting, lxc.StateStopping:
		return // transient — let it settle
	case lxc.StateStopped, lxc.StateError:
		// genuinely down — fall through to the restart decision
	default:
		// StateUnknown: container not present on this host / indeterminate.
		return
	}

	// Operator intent always wins (the container analogue of vms.state_detail).
	if ct.StateDetail == operatorStopDetail {
		if ct.State != "stopped" {
			if err := corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "stopped", operatorStopDetail); err != nil {
				slog.Warn("containercheck: operator-stop heal write failed", "container", ct.Name, "error", err)
				c.noteStateWriteFail(corrosion.OpContainerState, err)
			}
		}
		return
	}

	rp := containerRestartPolicy(ct.RestartPolicy)
	if rp == nil {
		// No policy: heal state drift only — don't fabricate a stop cause or act.
		if ct.State != "stopped" {
			if err := corrosion.SetContainerState(ctx, c.db, c.hostName, ct.Name, "stopped"); err != nil {
				slog.Warn("containercheck: no-policy state heal write failed", "container", ct.Name, "error", err)
				c.noteStateWriteFail(corrosion.OpContainerState, err)
			}
		}
		return
	}

	// Policy present and the stop wasn't operator-initiated: record it as an
	// out-of-band stop. This is both the UI write-back and the evidence
	// restartDecision reads (containers have no libvirt-style cause, so we pass
	// cause="" and let the detail drive the decision).
	if ct.State != "stopped" || ct.StateDetail != outOfBandDestroyDetail {
		if err := corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "stopped", outOfBandDestroyDetail); err != nil {
			slog.Warn("containercheck: out-of-band stop record write failed", "container", ct.Name, "error", err)
			c.noteStateWriteFail(corrosion.OpContainerState, err)
		}
	}

	ok, decision := restartDecision("", outOfBandDestroyDetail, false, rp.Condition)
	if !ok {
		slog.Debug("containercheck: not restarting per policy", "container", ct.Name, "decision", decision)
		return
	}

	// Window / max_attempts / delay machinery, mirroring maybeRestartVM.
	rs, err := corrosion.GetContainerRestartState(ctx, c.db, c.hostName, ct.Name)
	if err != nil {
		slog.Error("containercheck: get restart state", "container", ct.Name, "error", err)
		return
	}
	window := parseDuration(rp.Window, time.Hour)
	delay := parseDuration(rp.Delay, 5*time.Second)

	if rs != nil && !rs.WindowStart.IsZero() && now.Sub(rs.WindowStart) > window {
		_ = corrosion.ResetContainerRestartState(ctx, c.db, c.hostName, ct.Name)
		rs = nil
	}
	if rp.MaxAttempts > 0 && rs != nil && rs.AttemptCount >= int(rp.MaxAttempts) {
		slog.Warn("containercheck: restart max attempts reached", "container", ct.Name,
			"attempts", rs.AttemptCount, "max", rp.MaxAttempts)
		return
	}
	if rs != nil && !rs.LastRestart.IsZero() && now.Sub(rs.LastRestart) < delay {
		return
	}

	// Self-fence is an UNCONDITIONAL hard gate (independent of enforcement): a doomed
	// node must not restart a container per restart-policy during its fence window.
	if selfFenceHardGate(c.gate) {
		slog.Info("containercheck: self-fenced — refusing restart-policy start", "container", ct.Name)
		c.noteGateRefused(corrosion.ActionReschedule, ReasonSelfFenced)
		return
	}
	// Split-brain gate (Phase 1): a restart-policy start is a runtime action; once
	// enforced it needs local quorum, so an isolated host with stale local ownership
	// can't restart-into a double-run. Fail-open until latched.
	if c.gate != nil && c.gate.Enforced(ctx, capabilities.SplitBrainGateV1) {
		if g := c.gate.ExecutionGate(ctx); !g.OK {
			slog.Info("containercheck: execution gate refused restart (no quorum)", "container", ct.Name, "reason", g.Reason)
			c.noteGateRefused(corrosion.ActionReschedule, g.Reason)
			return
		}
	}
	slog.Info("containercheck: restarting container per restart policy", "container", ct.Name,
		"condition", rp.Condition)
	if err := corrosion.IncrementContainerRestart(ctx, c.db, c.hostName, ct.Name); err != nil {
		slog.Error("containercheck: increment restart counter", "container", ct.Name, "error", err)
	}
	if err := c.runtime.Start(ctx, ct.Name); err != nil {
		slog.Error("containercheck: restart policy start failed", "container", ct.Name, "error", err)
		if werr := corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "error",
			"restart policy start failed: "+err.Error()); werr != nil {
			c.noteStateWriteFail(corrosion.OpContainerState, werr)
		}
		return
	}
	if err := corrosion.SetContainerStateDetailStrict(ctx, c.db, c.hostName, ct.Name, "running", "restart policy: "+decision); err != nil {
		slog.Error("containercheck: restart-policy state write failed — NOT publishing restart event",
			"container", ct.Name, "error", err)
		c.noteStateWriteFail(corrosion.OpContainerState, err)
		return
	}
	c.publish("ct.restart.policy", ct.Name,
		fmt.Sprintf("condition=%s attempt=%d (%s)", rp.Condition, ctAttemptCount(rs)+1, decision))
}

// containerRestartPolicy decodes the stored restart_policy JSON; an empty string
// or garbage yields nil (treated as "none"). Mirrors grpcapi.decodeRestartPolicy
// without a cross-package dependency (health must not import grpcapi).
func containerRestartPolicy(s string) *pb.RestartPolicy {
	if s == "" {
		return nil
	}
	rp := &pb.RestartPolicy{}
	if err := json.Unmarshal([]byte(s), rp); err != nil {
		return nil
	}
	return rp
}

func ctAttemptCount(rs *corrosion.ContainerRestartState) int {
	if rs == nil {
		return 0
	}
	return rs.AttemptCount
}
