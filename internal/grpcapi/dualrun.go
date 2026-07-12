package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/notify"
)

// Dual-run detector notification Kinds (stable — notification routes subscribe to these;
// see docs/notifications.md). Keep these strings stable across releases.
const (
	kindDualRunVM       = "ha.dualrun.vm"       // a VM is an active disk-holder on >1 host
	kindDualRunCT       = "ha.dualrun.ct"       // a container is running on >1 host
	kindDualRunVIP      = "ha.dualrun.vip"      // a VIP is kernel-assigned on >1 host
	kindOwnerMismatch   = "ha.owner.mismatch"   // the DB owner is not the sole runtime holder
	kindLWWUnresolved   = "ha.lww.unresolved"   // a node is tracking unresolved LWW ties
	kindDualRunCoverage = "ha.dualrun.coverage" // a workload-capable host could not be probed
)

// dualRunLeaseKey elects the single node that runs the detector, so a fleet-wide
// split-brain pages once (from the leader), not once per node.
const dualRunLeaseKey = "dual_run_detector"

// dualRunDebounce is the number of consecutive passes a finding must persist before it
// pages: a real dual-run holds for >=1 interval; a migration/cutover clears within one.
const dualRunDebounce = 2

// dualRunPeerTimeout bounds each peer ReportRuntime call so one hung/segmented peer can't
// stall a whole pass (which, if it exceeded the lease TTL, would let a second node also
// take leadership). Mirrors the 5s bound other periodic peer probes use.
const dualRunPeerTimeout = 5 * time.Second

// migrationStates are DB workload states in which a second runtime holder is LEGITIMATE
// (an incoming migration/relocation target, or a create still landing) — never a
// dual-run. A live-migration target is PAUSED until cutover so it already reads as a
// non-disk-holder; this set covers the DB-state axis (source still "running", target
// row "migrating") and the owner-mismatch cutover-lag window.
var migrationStates = map[string]bool{
	"migrating":  true,
	"relocating": true,
	"pending":    true,
	"starting":   true,
}

// runtimeSnapshot is one host's local ground-truth runtime view: which VMs are active
// disk-holders, which containers are running, which VIPs are assigned on its kernel, and
// how many unresolved LWW ties it is tracking. Built locally for self, or fetched from a
// peer via ReportRuntime.
type runtimeSnapshot struct {
	diskHolderVMs  []string
	runningCTs     []string
	kernelVIPs     []string // bare IPs (prefix stripped) so cross-host grouping is consistent
	unresolvedTies int
}

// ReportRuntime returns THIS host's local runtime ground truth for the leader-gated
// dual-run detector. Peer-only (host-cert mTLS); never consults the cluster DB — the
// leader cross-references the DB itself.
func (s *Server) ReportRuntime(ctx context.Context, _ *pb.ReportRuntimeRequest) (*pb.ReportRuntimeResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	snap := s.localRuntimeSnapshot(ctx)
	return &pb.ReportRuntimeResponse{
		DiskHolderVms:      snap.diskHolderVMs,
		RunningContainers:  snap.runningCTs,
		KernelAssignedVips: snap.kernelVIPs,
		UnresolvedTieCount: int32(snap.unresolvedTies),
	}, nil
}

// localRuntimeSnapshot builds this host's runtime snapshot from libvirt + LXC + the
// kernel VIP state. It never consults the DB except to enumerate the CONFIGURED LBs
// whose VIPs to kernel-check.
func (s *Server) localRuntimeSnapshot(ctx context.Context) runtimeSnapshot {
	var snap runtimeSnapshot

	// VMs that are ACTIVE DISK-HOLDERS. DomainState=="running" is precisely RUNNING|BLOCKED
	// (coarseDomainState collapses both to "running"); a PAUSED incoming-migration target
	// reads as not-running and is correctly excluded — two hosts must never both be
	// writing the same disk.
	if s.virt != nil {
		if names, err := s.virt.ListDomains(); err == nil {
			for _, n := range names {
				if st, err := s.virt.DomainState(n); err == nil && st == "running" {
					snap.diskHolderVMs = append(snap.diskHolderVMs, n)
				}
			}
		}
	}

	// Running containers.
	if s.containerRuntime != nil {
		if names, err := s.containerRuntime.ListContainers(ctx); err == nil {
			for _, n := range names {
				if st, err := s.containerRuntime.StateContainer(ctx, n); err == nil && st == "running" {
					snap.runningCTs = append(snap.runningCTs, n)
				}
			}
		}
	}

	// VIP addresses assigned on THIS host's KERNEL. The kernel check is authoritative — a
	// VRRP backup renders the config but holds no address, so a participant-claims signal
	// would falsely count it. Collect every enabled LB's VIP and check them against a
	// SINGLE `ip addr` dump; a config-less orphan keepalived on a deleted LB's VIP is out
	// of scope here (the Phase-2 orphan sweep covers that).
	if cfgs, err := corrosion.ListLBConfigs(ctx, s.db); err == nil {
		var vips []string
		for _, cfg := range cfgs {
			if cfg.Enabled && cfg.VIP != "" {
				vips = append(vips, cfg.VIP)
			}
		}
		// Alert-only: on an `ip` error skip the VIPs — a missed alert is safer than a
		// false one, and there is no per-VIP "unknown" to report.
		if assigned, err := lb.NewManager().AssignedVIPs(vips); err == nil {
			for v := range assigned {
				snap.kernelVIPs = append(snap.kernelVIPs, v)
			}
		}
	}

	if s.db != nil {
		snap.unresolvedTies = s.db.UnresolvedTieCount()
	}
	return snap
}

// reportPeerRuntime dials a peer for its local runtime snapshot.
func (s *Server) reportPeerRuntime(ctx context.Context, host string) (runtimeSnapshot, error) {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return runtimeSnapshot{}, err
	}
	defer conn.Close()
	resp, err := client.ReportRuntime(ctx, &pb.ReportRuntimeRequest{})
	if err != nil {
		return runtimeSnapshot{}, err
	}
	return runtimeSnapshot{
		diskHolderVMs:  resp.GetDiskHolderVms(),
		runningCTs:     resp.GetRunningContainers(),
		kernelVIPs:     resp.GetKernelAssignedVips(),
		unresolvedTies: int(resp.GetUnresolvedTieCount()),
	}, nil
}

// gatherRuntime collects a runtime snapshot from every host in the probe set: self is
// built locally, peers are probed via ReportRuntime IN PARALLEL, each under a bounded
// timeout so one hung/segmented peer can't stall the pass. It returns the snapshot per
// successfully-gathered host, the hosts that could not be REACHED (a coverage gap — a
// probe_failed gauge + a debounced coverage page), and the hosts on an OLDER binary that
// does not implement ReportRuntime (surfaced in the gauge but NOT paged as a coverage gap
// — that is expected version skew during a rolling upgrade, not a segmentation).
func (s *Server) gatherRuntime(ctx context.Context, hosts []string) (snaps map[string]runtimeSnapshot, unreachable, unsupported []string) {
	if s.gatherRuntimeOverride != nil {
		return s.gatherRuntimeOverride(ctx, hosts)
	}
	type result struct {
		host        string
		snap        runtimeSnapshot
		err         error
		unsupported bool
	}
	results := make([]result, len(hosts))
	var wg sync.WaitGroup
	for i, h := range hosts {
		if h == s.hostName {
			results[i] = result{host: h, snap: s.localRuntimeSnapshot(ctx)}
			continue
		}
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, dualRunPeerTimeout)
			defer cancel()
			snap, err := s.reportPeerRuntime(pctx, h)
			results[i] = result{host: h, snap: snap, err: err, unsupported: status.Code(err) == codes.Unimplemented}
		}(i, h)
	}
	wg.Wait()

	snaps = make(map[string]runtimeSnapshot, len(hosts))
	for _, r := range results {
		switch {
		case r.err == nil:
			snaps[r.host] = r.snap
		case r.unsupported:
			// An older peer without the ReportRuntime handler — expected mid-upgrade.
			unsupported = append(unsupported, r.host)
		default:
			// docker->kvm gRPC is permanently segmented on some clusters, so whenever the
			// lease sits on the far side of that boundary a host is unreachable — surface
			// it rather than treat "unseen" as "no dual-run".
			slog.Debug("dual-run detector: peer probe failed", "host", r.host, "error", r.err)
			unreachable = append(unreachable, r.host)
		}
	}
	return snaps, unreachable, unsupported
}

// finding is one detector finding: a stable (kind, target) pair used as the debounce key.
type finding struct {
	kind   string
	target string
}

// dualRunState is the detector's per-leader debounce state, held across passes.
type dualRunState struct {
	seen      map[finding]int  // consecutive passes each current finding has been present
	confirmed map[finding]bool // findings currently past the debounce threshold (paged)
}

func newDualRunState() *dualRunState {
	return &dualRunState{seen: map[finding]int{}, confirmed: map[finding]bool{}}
}

// RunDualRunDetector runs the leader-gated dual-run detector on a fixed interval. Only
// the node holding the dual_run_detector lease does work; the rest hold no state and
// keep their local gauges clear, so the fleet pages once (from the leader).
//
// Debounce state is per-leader and in-memory (not replicated), so a leadership handover
// re-arms the debounce on the new leader: a still-active finding is re-paged once after
// the new leader's own two-pass debounce, and the old leader emits no `.cleared` for it
// (emitting a clear would falsely imply the condition resolved). This is an accepted
// trade for an alert-only detector — the alternative (replicated debounce state) is not
// worth the complexity. The per-peer timeout keeps a pass well under the lease TTL, so
// leadership only moves on a genuine failover, not on a slow pass.
func (s *Server) RunDualRunDetector(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	st := newDualRunState()
	eval := func() {
		if !s.acquireDualRunLease(ctx, interval) {
			// Not (or no longer) the leader: drop debounce state so a fresh leader starts
			// clean, and clear our own process gauges so a former leader leaves no stale 1.
			if len(st.seen) > 0 || len(st.confirmed) > 0 {
				st = newDualRunState()
				s.dualRunMetrics.SetDetected(nil)
				s.dualRunMetrics.SetProbeFailed(nil)
			}
			return
		}
		s.detectDualRunPass(ctx, st)
	}
	eval()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			eval()
		}
	}
}

// acquireDualRunLease takes/renews the dual_run_detector leader lease (mirrors the
// rebalancer's lease: RFC3339 expiry compared bound-now-vs-stored so a dead leader's
// lease looks expired without waiting for datetime('now')). TTL = 2x interval.
func (s *Server) acquireDualRunLease(ctx context.Context, interval time.Duration) bool {
	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().Add(2 * interval).UTC().Format(time.RFC3339)
	if err := s.db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at
		   WHERE leader_election.expires_at < ?
		      OR leader_election.holder = excluded.holder`,
		dualRunLeaseKey, s.hostName, expires, now, now); err != nil {
		slog.Warn("dual-run detector: lease write", "error", err)
		return false
	}
	rows, err := s.db.Query(ctx, `SELECT holder FROM leader_election WHERE key = ?`, dualRunLeaseKey)
	if err != nil || len(rows) == 0 {
		return false
	}
	return rows[0].String("holder") == s.hostName
}

// detectDualRunPass runs one detector pass: gather runtime across workload-capable hosts,
// cross-reference against the DB, debounce, and emit metrics + set-transition
// notifications. It NEVER destroys or reconciles anything — alert-only.
func (s *Server) detectDualRunPass(ctx context.Context, st *dualRunState) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		slog.Warn("dual-run detector: list hosts", "error", err)
		return
	}
	targets := dualRunProbeTargets(hosts)
	snaps, unreachable, unsupported := s.gatherRuntime(ctx, targets)

	// Invert the per-host snapshots into workload -> holders, in a deterministic host
	// order (targets order) so detail messages are stable.
	vmHolders := map[string][]string{}
	ctHolders := map[string][]string{}
	vipHolders := map[string][]string{}
	tieHosts := map[string]int{}
	for _, h := range targets {
		snap, ok := snaps[h]
		if !ok {
			continue
		}
		for _, vm := range snap.diskHolderVMs {
			vmHolders[vm] = append(vmHolders[vm], h)
		}
		for _, ct := range snap.runningCTs {
			ctHolders[ct] = append(ctHolders[ct], h)
		}
		for _, vip := range snap.kernelVIPs {
			vipHolders[vip] = append(vipHolders[vip], h)
		}
		if snap.unresolvedTies > 0 {
			tieHosts[h] = snap.unresolvedTies
		}
	}

	// DB view for the migration exclusion + owner mismatch.
	vmState, vmOwner := s.dbVMIndex(ctx)
	ctState := s.dbContainerStates(ctx)

	current := map[finding]bool{}
	details := map[finding]string{}
	add := func(kind, target, detail string) {
		f := finding{kind: kind, target: target}
		current[f] = true
		details[f] = detail
	}

	// 1. Same VM an active disk-holder on >1 host (excluding a legitimately-migrating VM).
	for vm, hs := range vmHolders {
		if len(hs) > 1 && !migrationStates[vmState[vm]] {
			add(kindDualRunVM, vm, fmt.Sprintf(
				"VM %q is an active disk-holder on %d hosts (%s) — possible split-brain; the disk can corrupt if both write.",
				vm, len(hs), strings.Join(hs, ", ")))
		}
	}
	// 2. Same container running on >1 host (excluding a legitimately-migrating container).
	for ct, hs := range ctHolders {
		if len(hs) > 1 && !migrationStates[ctState[ct]] {
			add(kindDualRunCT, ct, fmt.Sprintf(
				"container %q is running on %d hosts (%s) — possible split-brain.",
				ct, len(hs), strings.Join(hs, ", ")))
		}
	}
	// 3. Same VIP kernel-assigned on >1 host.
	for vip, hs := range vipHolders {
		if len(hs) > 1 {
			add(kindDualRunVIP, vip, fmt.Sprintf(
				"VIP %s is kernel-assigned on %d hosts (%s) — dual VIP holder; traffic will split.",
				vip, len(hs), strings.Join(hs, ", ")))
		}
	}
	// 4. DB owner != the sole runtime holder (VM-only), COVERAGE-GATED: flag ONLY when the
	//    DB owner was POSITIVELY probed and reported the VM absent. If the owner was not
	//    probed at all — unreachable, or structurally outside the probe set (a witness, or
	//    a stale row pointing at a removed host) — a sole holder elsewhere could just mean
	//    the owner is running it too but we couldn't see it, so we defer to the coverage
	//    signal rather than false-page.
	for vm, owner := range vmOwner {
		if migrationStates[vmState[vm]] {
			continue // cutover lag is legitimate
		}
		hs := vmHolders[vm]
		if len(hs) != 1 || hs[0] == owner {
			continue // 0 holders = stopped/unprobed; >1 = the dual-run VM case; match = fine
		}
		if _, ownerProbed := snaps[owner]; !ownerProbed {
			continue // owner not positively probed → defer to the coverage signal
		}
		add(kindOwnerMismatch, vm, fmt.Sprintf(
			"VM %q DB owner is %q but the sole runtime holder is %q — ownership drift; the DB and runtime disagree.",
			vm, owner, hs[0]))
	}
	// 5. Any host tracking unresolved LWW ties.
	for h, n := range tieHosts {
		add(kindLWWUnresolved, h, fmt.Sprintf(
			"host %q reports %d unresolved LWW tie(s) — an equal-timestamp merge conflict was not resolved.", h, n))
	}
	// 6. Coverage: a host that could not be REACHED this pass (an older binary without the
	//    ReportRuntime handler is NOT a coverage page — that is expected version skew during
	//    a rolling upgrade; it still shows in the probe_failed gauge below).
	for _, h := range unreachable {
		add(kindDualRunCoverage, h, fmt.Sprintf(
			"host %q could not be probed this pass — dual-run coverage gap; a segmented or down host cannot be checked for split-brain.", h))
	}

	// The probe_failed gauge shows every host we could not gather from (unreachable OR on
	// an older binary), so the gap is visible immediately even though only unreachable
	// hosts page.
	probeFailed := append(append([]string(nil), unreachable...), unsupported...)
	s.applyDualRunDebounce(ctx, st, current, details, probeFailed)
}

// applyDualRunDebounce advances the debounce counters, emits set-transition
// notifications + events for findings crossing (or leaving) the confirmed threshold, and
// rebuilds both gauges. The probe-failed gauge reflects the CURRENT pass immediately (a
// coverage gap must be visible at once); the detected gauge reflects only DEBOUNCED
// findings (a real dual-run persists).
func (s *Server) applyDualRunDebounce(ctx context.Context, st *dualRunState, current map[finding]bool, details map[finding]string, probeFailed []string) {
	// Advance counters: present this pass -> prevCount+1; absent -> dropped (resets to 0).
	seen := make(map[finding]int, len(current))
	for f := range current {
		seen[f] = st.seen[f] + 1
	}
	st.seen = seen

	confirmedNow := map[finding]bool{}
	for f, n := range seen {
		if n >= dualRunDebounce {
			confirmedNow[f] = true
		}
	}
	// Set transitions (newly confirmed) — page + event.
	for f := range confirmedNow {
		if !st.confirmed[f] {
			s.publish("ha.dualrun", f.kind+":"+f.target, details[f])
			s.notify(ctx, notify.Notification{
				Kind:     f.kind,
				Severity: dualRunSeverity(f.kind),
				Subject:  f.target,
				Detail:   details[f],
			})
			slog.Warn("dual-run detector: finding confirmed", "kind", f.kind, "target", f.target, "detail", details[f])
		}
	}
	// Clear transitions (was confirmed, no longer) — recovery event.
	for f := range st.confirmed {
		if !confirmedNow[f] {
			s.publish("ha.dualrun.cleared", f.kind+":"+f.target, "")
		}
	}
	st.confirmed = confirmedNow

	// Rebuild gauges. detected = confirmed dual-run conditions (coverage has its own gauge).
	// probe_failed = the current unprobed set (immediate, not debounced).
	s.dualRunMetrics.SetDetected(detectedLabels(confirmedNow))
	sort.Strings(probeFailed)
	s.dualRunMetrics.SetProbeFailed(probeFailed)
}

// detectedLabels maps the confirmed findings to the litevirt_dual_run_detected gauge
// labels, EXCLUDING coverage findings (those have their own probe_failed gauge).
func detectedLabels(confirmed map[finding]bool) []metrics.DualRunLabel {
	var labels []metrics.DualRunLabel
	for f := range confirmed {
		if f.kind == kindDualRunCoverage {
			continue
		}
		labels = append(labels, metrics.DualRunLabel{Kind: dualRunKindLabel(f.kind), Target: f.target})
	}
	return labels
}

// dbVMIndex returns per-VM DB state and owner (host_name) maps for all non-deleted VMs.
func (s *Server) dbVMIndex(ctx context.Context) (state map[string]string, owner map[string]string) {
	state, owner = map[string]string{}, map[string]string{}
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		slog.Warn("dual-run detector: list VMs", "error", err)
		return
	}
	for _, vm := range vms {
		state[vm.Name] = vm.State
		owner[vm.Name] = vm.HostName
	}
	return
}

// dbContainerStates returns per-container DB state for all containers.
func (s *Server) dbContainerStates(ctx context.Context) map[string]string {
	out := map[string]string{}
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		slog.Warn("dual-run detector: list containers", "error", err)
		return out
	}
	for _, ct := range cts {
		out[ct.Name] = ct.State
	}
	return out
}

// dualRunProbeTargets returns the hosts the detector must probe for a hidden runtime copy
// (INCLUDING self). It excludes ONLY witnesses (which never host workloads). Every other
// state — draining, upgrading, offline, and crucially FENCED — is INCLUDED: KillMode=process
// keeps QEMU running while a daemon is down, and without a real STONITH/watchdog a "fenced"
// host is a DB state whose disk may still be live, so a fenced host that failover has
// already restarted elsewhere is the canonical dual-run this detector exists to catch.
// (This deliberately differs from health.workloadCapablePeers, which excludes fenced for
// OWNERSHIP eligibility — a fenced host is not eligible to own a workload, but it is exactly
// where an illegitimate second copy hides.) An unreachable fenced host degrades to a
// coverage finding, which is the correct fail-safe.
func dualRunProbeTargets(hosts []corrosion.HostRecord) []string {
	var out []string
	for _, h := range hosts {
		if h.IsWitness() {
			continue
		}
		out = append(out, h.Name)
	}
	sort.Strings(out)
	return out
}

// dualRunSeverity maps a finding kind to a notification severity. The corruption-class
// conditions page as errors; coverage gaps and unresolved ties are advisory warnings.
func dualRunSeverity(kind string) notify.Severity {
	switch kind {
	case kindDualRunVM, kindDualRunCT, kindDualRunVIP, kindOwnerMismatch:
		return notify.SevError
	default:
		return notify.SevWarn
	}
}

// dualRunKindLabel maps a notification Kind to the short gauge label.
func dualRunKindLabel(kind string) string {
	switch kind {
	case kindDualRunVM:
		return "vm"
	case kindDualRunCT:
		return "ct"
	case kindDualRunVIP:
		return "vip"
	case kindOwnerMismatch:
		return "owner_mismatch"
	case kindLWWUnresolved:
		return "lww_unresolved"
	default:
		return kind
	}
}
