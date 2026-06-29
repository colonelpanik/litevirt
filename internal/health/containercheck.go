package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
}

// NewContainerChecker creates a container reconciler/restart engine for the
// local host, sharing the LXC runtime wired into the gRPC server.
func NewContainerChecker(hostName string, db *corrosion.Client, runtime lxc.Runtime) *ContainerChecker {
	return &ContainerChecker{hostName: hostName, db: db, runtime: runtime}
}

// SetEventBus sets the event bus for publishing container lifecycle events.
func (c *ContainerChecker) SetEventBus(bus *events.Bus) { c.bus = bus }

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
	// GC IPAM leases stranded by a crash between allocating a lease and persisting
	// the container row (an orphan lease — owner with no live container row). The
	// age guard keeps this from racing an in-flight create.
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
		_ = corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, state, "")
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
		_ = corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "stopped", "")
		return
	}
	_ = corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "running", "")
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

// checkContainer reconciles one container's cluster row to the runtime's reality
// and applies the restart policy when it stopped unexpectedly.
func (c *ContainerChecker) checkContainer(ctx context.Context, ct corrosion.ContainerRecord, now time.Time) {
	// B5 host-loss relocation: the failover coordinator re-homed this container
	// to us (state=pending, detail=relocate-recreate) after its host was fenced.
	// Its rootfs died with that host, so recreate it from its image here. This
	// runs before the normal state read because a not-yet-created container has
	// no LXC instance (lxc-info would error).
	if ct.State == "pending" && ct.StateDetail == corrosion.ContainerRelocateRecreateDetail {
		c.recreateRelocated(ctx, ct)
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
			_ = corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "running", "")
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
			_ = corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "stopped", operatorStopDetail)
		}
		return
	}

	rp := containerRestartPolicy(ct.RestartPolicy)
	if rp == nil {
		// No policy: heal state drift only — don't fabricate a stop cause or act.
		if ct.State != "stopped" {
			_ = corrosion.SetContainerState(ctx, c.db, c.hostName, ct.Name, "stopped")
		}
		return
	}

	// Policy present and the stop wasn't operator-initiated: record it as an
	// out-of-band stop. This is both the UI write-back and the evidence
	// restartDecision reads (containers have no libvirt-style cause, so we pass
	// cause="" and let the detail drive the decision).
	if ct.State != "stopped" || ct.StateDetail != outOfBandDestroyDetail {
		_ = corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "stopped", outOfBandDestroyDetail)
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

	slog.Info("containercheck: restarting container per restart policy", "container", ct.Name,
		"condition", rp.Condition)
	if err := corrosion.IncrementContainerRestart(ctx, c.db, c.hostName, ct.Name); err != nil {
		slog.Error("containercheck: increment restart counter", "container", ct.Name, "error", err)
	}
	if err := c.runtime.Start(ctx, ct.Name); err != nil {
		slog.Error("containercheck: restart policy start failed", "container", ct.Name, "error", err)
		_ = corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "error",
			"restart policy start failed: "+err.Error())
		return
	}
	_ = corrosion.SetContainerStateDetail(ctx, c.db, c.hostName, ct.Name, "running", "restart policy: "+decision)
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
