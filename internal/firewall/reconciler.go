package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// PlanLoader builds the desired Plan for *this host* from cluster
// state. The reconciler polls it; the daemon wires a real
// implementation that joins security_groups, sg_rules, vm_interfaces,
// and host config.
type PlanLoader func(ctx context.Context) (Plan, error)

// Reconciler periodically rebuilds the local firewall plan and applies
// it via the Applier. Pull-based polling beats push-via-event for
// firewall state because:
//   - Nftables is local; no network round trip is needed.
//   - A periodic re-apply self-heals out-of-band drift (e.g. a sysadmin
//     ran `nft flush` to debug).
//   - Cache short-circuit on the Applier means most ticks are free.
type Reconciler struct {
	loader   PlanLoader
	applier  *Applier
	interval time.Duration

	mu       sync.Mutex
	running  bool
	stopCh   chan struct{}
	doneCh   chan struct{}
	lastErr  error
	lastTick time.Time

	// legacyCleanup removes a bridge's pre-consolidation out-of-band rules (old
	// iptables masquerade + the separate `inet litevirt` iso/snat chains) once the
	// equivalent rules are live in litevirt-fw. Run per bridge exactly once
	// (tracked in cleaned) AFTER a successful apply, so there is never a window
	// without NAT/isolation during the upgrade migration. nil in tests.
	legacyCleanup func(bridge, masqueradeSubnet string) error
	cleaned       map[string]bool
}

// NewReconciler wires a loader to an applier. interval controls the
// poll cadence; the daemon defaults to 30s — fast enough that a rule
// add propagates quickly, cheap enough that idle clusters don't
// burn CPU.
func NewReconciler(loader PlanLoader, applier *Applier, interval time.Duration) *Reconciler {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Reconciler{loader: loader, applier: applier, interval: interval, cleaned: map[string]bool{}}
}

// SetLegacyCleanup registers the per-bridge migration hook that clears
// pre-consolidation NAT/isolation rules a prior binary left behind. The daemon
// wires network.RemoveLegacyBridgeFirewall; tests leave it unset.
func (r *Reconciler) SetLegacyCleanup(fn func(bridge, masqueradeSubnet string) error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.legacyCleanup = fn
}

// Start launches the reconciler in a goroutine. Calling Start while
// already running is a no-op (idempotent so daemon restart paths
// don't double-spawn).
func (r *Reconciler) Start(ctx context.Context) {
	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		return
	}
	r.running = true
	r.stopCh = make(chan struct{})
	r.doneCh = make(chan struct{})
	r.mu.Unlock()

	go r.loop(ctx)
}

// Stop signals the reconciler to exit and waits for the goroutine to
// finish. Safe to call multiple times.
func (r *Reconciler) Stop() {
	r.mu.Lock()
	if !r.running {
		r.mu.Unlock()
		return
	}
	close(r.stopCh)
	doneCh := r.doneCh
	r.running = false
	r.mu.Unlock()
	<-doneCh
}

// LastError returns the most recent reconcile error (or nil). Useful
// for `lv firewall status` — surfaces "Corrosion unreachable" without
// the operator needing to dig through logs.
func (r *Reconciler) LastError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// LastTick returns the time of the most recent successful (no-error)
// reconcile attempt.
func (r *Reconciler) LastTick() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastTick
}

// Reconcile runs one poll-load-apply cycle, exposed publicly so
// `lv firewall reload` can drive it on demand.
func (r *Reconciler) Reconcile(ctx context.Context) error {
	plan, err := r.loader(ctx)
	if err != nil {
		r.recordErr(fmt.Errorf("load plan: %w", err))
		return err
	}
	changed, err := r.applier.Apply(ctx, plan)
	if err != nil {
		r.recordErr(fmt.Errorf("apply plan: %w", err))
		return err
	}
	r.recordOK()
	if changed {
		slog.Info("firewall ruleset applied",
			"rules", countRules(plan), "nics", len(plan.NICs))
	}
	// New NAT/isolation rules are now live in litevirt-fw (this apply, or an earlier
	// one if unchanged) — safe to clear the old out-of-band rules for these bridges.
	r.migrateLegacy(plan)
	return nil
}

// migrateLegacy removes, once per bridge, the pre-consolidation rules a prior
// binary applied out-of-band. Keyed on bridges the just-applied plan now covers,
// so a bridge's old rules are only removed after its new rules exist.
func (r *Reconciler) migrateLegacy(p Plan) {
	r.mu.Lock()
	fn := r.legacyCleanup
	r.mu.Unlock()
	if fn == nil {
		return
	}
	// bridge → masquerade subnet ("" when the bridge is isolation/SNAT-only).
	masq := map[string]string{}
	bridges := map[string]bool{}
	for _, n := range p.NAT {
		if n.SNATTo == "" && n.Bridge != "" { // masquerade rule
			masq[n.Bridge] = n.Subnet
			bridges[n.Bridge] = true
		}
	}
	for _, iso := range p.HostIsolation {
		if iso.Bridge != "" {
			bridges[iso.Bridge] = true
		}
	}
	for b := range bridges {
		r.mu.Lock()
		done := r.cleaned[b]
		r.mu.Unlock()
		if done {
			continue
		}
		// Mark cleaned ONLY after the hook confirms the old rules are gone. A
		// transient nft/iptables failure must not permanently strand old
		// `inet litevirt` chains (which would lack the new LB exceptions) — leave
		// the bridge unmarked so the next tick retries.
		if err := fn(b, masq[b]); err != nil {
			slog.Warn("firewall: legacy rule cleanup failed; will retry next tick", "bridge", b, "error", err)
			continue
		}
		r.mu.Lock()
		r.cleaned[b] = true
		r.mu.Unlock()
	}
}

func (r *Reconciler) loop(ctx context.Context) {
	defer close(r.doneCh)
	tick := time.NewTicker(r.interval)
	defer tick.Stop()

	// Run once immediately so we don't wait for the first tick on
	// daemon startup.
	if err := r.Reconcile(ctx); err != nil {
		slog.Warn("firewall: initial reconcile failed", "error", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-tick.C:
			if err := r.Reconcile(ctx); err != nil {
				slog.Warn("firewall: reconcile failed", "error", err)
			}
		}
	}
}

func (r *Reconciler) recordErr(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastErr = err
}

func (r *Reconciler) recordOK() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastErr = nil
	r.lastTick = time.Now()
}

// CorrosionPlanLoader builds a Plan from the cluster's
// security_groups + sg_rules + vm_interfaces tables, scoped to the
// current host.
//
// closes the loop: per-NIC bindings come from the
// vm_interfaces.security_groups column. Each VM interface owned by
// `hostName` produces a NICBinding referencing the SG names stored on
// that row. NICs without a tap_device (not yet provisioned) are
// skipped so we don't emit chains for non-existent interfaces.
func CorrosionPlanLoader(db *corrosion.Client, hostName string, defaults Plan) PlanLoader {
	return func(ctx context.Context) (Plan, error) {
		plan := defaults

		// Non-NIC tiers + named address lists + default policy. These were
		// dead in production before v21 (the loader only filled SecurityGroups
		// + NICs); now they come from the cluster_firewall_rules /
		// host_firewall_rules / ip_sets / firewall_defaults tables.
		clusterRules, err := corrosion.ListClusterFirewallRules(ctx, db)
		if err != nil {
			return plan, err
		}
		plan.ClusterRules = toFWRules(clusterRules)

		hostRules, err := corrosion.ListHostFirewallRules(ctx, db, hostName)
		if err != nil {
			return plan, err
		}
		plan.HostRules = toFWRules(hostRules)

		deny, err := corrosion.ResolveDefaultDeny(ctx, db, hostName)
		if err != nil {
			return plan, err
		}
		plan.DefaultDeny = deny

		ipsets, err := corrosion.ListIPSets(ctx, db)
		if err != nil {
			return plan, err
		}
		plan.IPSets = plan.IPSets[:0:0]
		for _, s := range ipsets {
			plan.IPSets = append(plan.IPSets, IPSet{Name: s.Name, CIDRs: s.CIDRs})
		}

		sgs, err := corrosion.ListSecurityGroups(ctx, db, "")
		if err != nil {
			return plan, err
		}
		plan.SecurityGroups = plan.SecurityGroups[:0:0]
		for _, sg := range sgs {
			rules, err := corrosion.ListSGRules(ctx, db, sg.ID)
			if err != nil {
				return plan, err
			}
			out := SecurityGroup{Name: sg.Name}
			for _, r := range rules {
				out.Rules = append(out.Rules, FromCorrosionRule(
					r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action,
				))
			}
			plan.SecurityGroups = append(plan.SecurityGroups, out)
		}

		// Resolve per-NIC SG bindings. Unknown SG names are dropped
		// silently — the renderer would refuse to compile otherwise,
		// taking down the whole firewall on a single typo. Operators
		// see the missing rules but the rest stays applied.
		valid := make(map[string]bool, len(plan.SecurityGroups))
		for _, sg := range plan.SecurityGroups {
			valid[sg.Name] = true
		}
		ifaces, err := corrosion.ListVMInterfacesByHost(ctx, db, hostName)
		if err != nil {
			return plan, err
		}
		plan.NICs = plan.NICs[:0:0]
		for _, ifc := range ifaces {
			if ifc.TapDevice == "" {
				continue
			}
			bound := make([]string, 0, len(ifc.SecurityGroups))
			for _, name := range ifc.SecurityGroups {
				if valid[name] {
					bound = append(bound, name)
				}
			}
			plan.NICs = append(plan.NICs, NICBinding{
				NICDev:         ifc.TapDevice,
				VMName:         ifc.VMName,
				SecurityGroups: bound,
			})
		}

		// Container NICs: identical per-NIC SG enforcement on the veth. The loader
		// is host-scoped and ListContainerInterfacesByHost joins the live container
		// row, so only this host's MANAGED, live CT NICs appear; skip a NIC with no
		// veth yet (not provisioned), mirroring the tap_device skip above.
		ctIfaces, err := corrosion.ListContainerInterfacesByHost(ctx, db, hostName)
		if err != nil {
			return plan, err
		}
		for _, ifc := range ctIfaces {
			if ifc.VethDevice == "" {
				continue
			}
			bound := make([]string, 0, len(ifc.SecurityGroups))
			for _, name := range ifc.SecurityGroups {
				if valid[name] {
					bound = append(bound, name)
				}
			}
			plan.NICs = append(plan.NICs, NICBinding{
				NICDev:         ifc.VethDevice,
				VMName:         ifc.CtName,
				SecurityGroups: bound,
			})
		}

		// NAT / SNAT / host-isolation infra: read this host's resolved intent
		// (written by network provisioning + LB apply) and fold it into the same
		// atomic ruleset. Empty → no nat/input chains, identical to before v40.
		intents, err := corrosion.ListHostFWIntent(ctx, db, hostName)
		if err != nil {
			return plan, err
		}
		plan.NAT, plan.HostIsolation = intentToNATIsolation(intents)
		return plan, nil
	}
}

// intentToNATIsolation aggregates per-host firewall intent rows into the
// renderer's NAT + isolation inputs.
//
// Isolation is OWNED by network intent (scope "net:<name>"): only a net row can
// mark a bridge isolated. An LB row (scope "lb:<name>") contributes VIP:port
// exceptions and SNAT but never isolation authority — so a stale LB row can't keep
// a bridge dropped after the network's isolation is removed. SNAT likewise renders
// only while the bridge still has a base isolated-network intent.
func intentToNATIsolation(intents []corrosion.HostFWIntent) ([]NATRule, []IsolationChain) {
	isolated := map[string]bool{}
	for _, in := range intents {
		if in.Bridge != "" && in.Isolate && strings.HasPrefix(in.ScopeKey, "net:") {
			isolated[in.Bridge] = true
		}
	}

	var nat []NATRule
	exc := map[string][]IsolationException{}
	for _, in := range intents {
		if in.MasqueradeSubnet != "" {
			nat = append(nat, NATRule{Subnet: in.MasqueradeSubnet, Bridge: in.Bridge})
		}
		if in.SNATVIP != "" && isolated[in.Bridge] {
			nat = append(nat, NATRule{OutIface: in.SNATOutIface, Subnet: in.SNATSubnet, SNATTo: in.SNATVIP})
		}
		for _, e := range in.Exceptions {
			exc[in.Bridge] = append(exc[in.Bridge], IsolationException{VIP: e.VIP, Ports: e.Ports})
		}
	}

	// One isolation chain per isolated bridge, merging exceptions from every row
	// (the net base + any LB holes) for it. Sorted for determinism (renderer re-sorts).
	bridges := make([]string, 0, len(isolated))
	for b := range isolated {
		bridges = append(bridges, b)
	}
	sort.Strings(bridges)
	var iso []IsolationChain
	for _, b := range bridges {
		iso = append(iso, IsolationChain{Bridge: b, Exceptions: exc[b]})
	}
	return nat, iso
}

// toFWRules converts the on-disk cluster/host-tier rows into renderer Rules,
// preserving the operator-supplied comment.
func toFWRules(in []corrosion.FirewallRule) []Rule {
	out := make([]Rule, 0, len(in))
	for _, r := range in {
		rule := FromCorrosionRule(r.Direction, r.Proto, r.PortRange, r.CIDR, r.Action)
		rule.Comment = r.Comment
		out = append(out, rule)
	}
	return out
}

func countRules(p Plan) int {
	n := len(p.ClusterRules) + len(p.HostRules)
	for _, sg := range p.SecurityGroups {
		n += len(sg.Rules)
	}
	for _, nic := range p.NICs {
		n += len(nic.ExtraRules)
	}
	return n
}
