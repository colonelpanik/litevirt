package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
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
	kindEpochMismatch   = "ha.owner.epoch_mismatch" // the owner's runtime marker disagrees with its DB epoch
)

// dualRunLeaseKey elects the single node that runs the detector, so a fleet-wide
// split-brain pages once (from the leader), not once per node.
const dualRunLeaseKey = "dual_run_detector"

// dualRunDebounce is the number of consecutive passes a finding must persist before it
// pages: a real dual-run holds for >=1 interval; a migration/cutover clears within one.
const dualRunDebounce = 2

// dualRunPeerTimeout bounds each peer GetRuntimeInventory call so one hung/segmented peer can't
// stall a whole pass (which, if it exceeded the lease TTL, would let a second node also
// take leadership). Mirrors the 5s bound other periodic peer probes use.
const dualRunPeerTimeout = 5 * time.Second

// lxcCapable reports whether this host has the lxc-* tooling (lxc-create) needed to run
// containers — the SAME probe the daemon uses to set the LXC-capable host label. The
// container runtime is wired even where the tooling is absent, so on a VM-only host a
// container list would fail "lxc-ls: executable not found"; that is NOT a coverage blind
// spot (containers can't run here), so the detector skips the CT probe entirely rather
// than marking the snapshot partial. It's a var so tests can stub it.
var lxcCapable = func() bool {
	_, err := exec.LookPath("lxc-create")
	return err == nil
}

// migrationStates are DB workload states in which the DB owner legitimately differs from
// the sole runtime holder — the OWNER-MISMATCH cutover-lag window (the DB row is mid-move
// while the runtime has already landed elsewhere). It is used ONLY to suppress
// owner-mismatch, NOT the multi-holder dual-run findings: a genuine second ACTIVE
// disk-holder is a dual-run regardless of the DB state (see conditions 1 & 2).
var migrationStates = map[string]bool{
	"migrating":  true,
	"relocating": true,
	"pending":    true,
	"starting":   true,
}

// runtimeSnapshot is one host's local ground-truth runtime view: which VMs are active
// disk-holders, which containers are running, which VIPs are assigned on its kernel, and
// how many unresolved LWW ties it is tracking. Derived from the unified runtime
// inventory (see runtime_inventory.go) — locally for self, via GetRuntimeInventory
// for a peer.
type runtimeSnapshot struct {
	diskHolderVMs  []string
	runningCTs     []string
	kernelVIPs     []string // bare IPs (prefix stripped) so cross-host grouping is consistent
	unresolvedTies int
	// Owner-epoch markers for RUNNING workloads (nil in fixtures that predate
	// them — the epoch check simply cannot evaluate those hosts).
	vmMarkers map[string]markerInfo
	ctMarkers map[string]markerInfo
	// partial is true when ANY local probe errored (libvirt list/state, container
	// list/state, LB-config read, or the `ip` dump). Positive holders are still real, but
	// ABSENCE is unreliable: the leader must not treat a partial snapshot as absence proof
	// (owner-mismatch), and raises a coverage gap for the host instead.
	partial bool
}

// reportPeerRuntime fetches a peer's full runtime inventory and derives the
// detector's grouping snapshot from it.
func (s *Server) reportPeerRuntime(ctx context.Context, host string) (runtimeSnapshot, error) {
	inv, err := s.getPeerRuntimeInventory(ctx, host, "", "")
	if err != nil {
		return runtimeSnapshot{}, err
	}
	return snapshotFromInventory(inv), nil
}

// gatherRuntime collects a runtime snapshot from every host in the probe set: self is
// built locally, peers are probed via GetRuntimeInventory IN PARALLEL, each under a bounded
// timeout so one hung/segmented peer can't stall the pass. It returns the snapshot per
// successfully-gathered host, the hosts that could not be REACHED (a coverage gap — a
// probe_failed gauge + a debounced coverage page), and the hosts on an OLDER binary that
// does not implement GetRuntimeInventory (surfaced in the gauge but NOT paged as a coverage gap
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
			results[i] = result{host: h, snap: snapshotFromInventory(s.collectRuntimeInventory(ctx))}
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
			// An older peer without the GetRuntimeInventory handler — expected mid-upgrade.
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

// stepDownDualRun is called when this node is NOT the dual-run leader: it clears this
// node's process gauges so a former leader leaves no stale series. The condition
// LIFECYCLE needs nothing here — it lives in health_conditions rows, so the new
// leader's first pass continues the counts exactly where this one left them.
func (s *Server) stepDownDualRun() {
	s.dualRunMetrics.SetDetected(nil)
	s.dualRunMetrics.SetProbeFailed(nil)
}

// RunDualRunDetector runs the leader-gated dual-run detector on a fixed interval. Only
// the node holding the dual_run_detector lease does work; the rest hold no state and
// keep their local gauges clear, so the fleet pages once (from the leader).
//
// Lifecycle state is DURABLE (health_conditions rows), so a leadership handover
// preserves observation counts and confirmed state: the new leader's first pass picks
// up exactly where the old one stopped — no re-arm, no false `.cleared`, no re-page.
// The per-peer timeout keeps a pass well under the lease TTL, so leadership only moves
// on a genuine failover, not on a slow pass.
func (s *Server) RunDualRunDetector(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	eval := func() {
		if !s.acquireDualRunLease(ctx, interval) {
			s.stepDownDualRun()
			return
		}
		s.detectDualRunPass(ctx)
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
func (s *Server) detectDualRunPass(ctx context.Context) {
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		slog.Warn("dual-run detector: list hosts", "error", err)
		return
	}
	targets := dualRunProbeTargets(hosts)
	snaps, unreachable, unsupported := s.gatherRuntime(ctx, targets)

	// Invert the per-host snapshots into workload -> holders, in a deterministic host
	// order (targets order) so detail messages are stable. A PARTIAL snapshot's positive
	// holders are still valid (a reported-running workload is real), so they are counted;
	// the host is separately recorded as a coverage gap because its ABSENCE is unreliable.
	vmHolders := map[string][]string{}
	ctHolders := map[string][]string{}
	vipHolders := map[string][]string{}
	tieHosts := map[string]int{}
	var partialHosts []string
	for _, h := range targets {
		snap, ok := snaps[h]
		if !ok {
			continue
		}
		if snap.partial {
			partialHosts = append(partialHosts, h)
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

	// DB view for the owner-mismatch cutover-lag exclusion.
	vmState, vmOwner, vmEpoch, dbIndexOK := s.dbVMIndex(ctx)

	current := map[finding]bool{}
	details := map[finding]string{}
	evidenceHosts := map[finding][]string{}
	add := func(kind, target, detail string, hosts ...string) {
		f := finding{kind: kind, target: target}
		current[f] = true
		details[f] = detail
		evidenceHosts[f] = hosts
	}

	// 1. Same VM an ACTIVE DISK-HOLDER on >1 host. This does NOT exempt DB "migrating"
	//    states: a healthy live migration keeps the incoming target PAUSED (a non-disk-holder)
	//    until cutover, so a legitimate migration shows only ONE disk-holder and the brief
	//    cutover overlap is filtered by the debounce. Exempting the DB state instead would
	//    hide the case this check exists for — a failed/stuck failover left "pending"/"migrating"
	//    while BOTH the old and new hosts actively run (and write) the VM.
	for vm, hs := range vmHolders {
		if len(hs) > 1 {
			add(kindDualRunVM, vm, fmt.Sprintf(
				"VM %q is an active disk-holder on %d hosts (%s) — possible split-brain; the disk can corrupt if both write.",
				vm, len(hs), strings.Join(hs, ", ")), hs...)
		}
	}
	// 2. Same container running on >1 host. Same reasoning as VMs: a cold CT migration
	//    stops the source before starting the target (never two running at once beyond a
	//    debounce window), so a sustained two-holder state is a real dual-run, not a migration.
	for ct, hs := range ctHolders {
		if len(hs) > 1 {
			add(kindDualRunCT, ct, fmt.Sprintf(
				"container %q is running on %d hosts (%s) — possible split-brain.",
				ct, len(hs), strings.Join(hs, ", ")), hs...)
		}
	}
	// 3. Same VIP kernel-assigned on >1 host.
	for vip, hs := range vipHolders {
		if len(hs) > 1 {
			add(kindDualRunVIP, vip, fmt.Sprintf(
				"VIP %s is kernel-assigned on %d hosts (%s) — dual VIP holder; traffic will split.",
				vip, len(hs), strings.Join(hs, ", ")), hs...)
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
		if snap, ownerProbed := snaps[owner]; !ownerProbed || snap.partial {
			continue // owner not COMPLETELY probed → its absence is unreliable; defer to coverage
		}
		add(kindOwnerMismatch, vm, fmt.Sprintf(
			"VM %q DB owner is %q but the sole runtime holder is %q — ownership drift; the DB and runtime disagree.",
			vm, owner, hs[0]), owner, hs[0])
	}
	// 5. Any host tracking unresolved LWW ties.
	for h, n := range tieHosts {
		add(kindLWWUnresolved, h, fmt.Sprintf(
			"host %q reports %d unresolved LWW tie(s) — an equal-timestamp merge conflict was not resolved.", h, n), h)
	}
	// 6. Coverage: a host whose runtime the leader could not fully establish this pass —
	//    either UNREACHABLE (no data) or PARTIAL (a local probe errored, so its absence is
	//    unreliable). Both are real coverage gaps and page (debounced). An older binary
	//    without the GetRuntimeInventory handler is NOT paged — that is expected version skew
	//    during a rolling upgrade; it still shows in the probe_failed gauge below.
	for _, h := range unreachable {
		add(kindDualRunCoverage, h, fmt.Sprintf(
			"host %q could not be probed this pass — dual-run coverage gap; a segmented or down host cannot be checked for split-brain.", h), h)
	}
	for _, h := range partialHosts {
		add(kindDualRunCoverage, h, fmt.Sprintf(
			"host %q returned a PARTIAL runtime (a local libvirt/container/ip probe errored) — its workload absence is unreliable, so split-brain cannot be ruled out there.", h), h)
	}

	// 7. OWNER-EPOCH MISMATCH, active only once owner_epoch_v1 is latched (before
	//    that, markers legitimately do not exist). Judged on the DB OWNER's runtime
	//    only — a non-owner running the workload is already conditions 1/2/4. A
	//    marker that is missing, corrupt, unreadable, or unequal to the DB epoch is
	//    a violation of the regime: this host's runtime cannot prove it belongs to
	//    the generation the cluster believes is running there.
	if s.gate != nil && s.gate.Enforced(ctx, capabilities.OwnerEpochV1) {
		for vm, owner := range vmOwner {
			if migrationStates[vmState[vm]] {
				continue
			}
			snap, probed := snaps[owner]
			if !probed || snap.vmMarkers == nil {
				continue // owner unprobed (coverage covers it) or a fixture without markers
			}
			mi, running := snap.vmMarkers[vm]
			if !running {
				continue // not running on its owner — conditions 1/4 territory
			}
			if mi.status == MarkerValid && mi.epoch == vmEpoch[vm] {
				continue
			}
			add(kindEpochMismatch, vm, fmt.Sprintf(
				"VM %q on its DB owner %q carries an owner-epoch marker that is %s (marker %d, DB epoch %d) — "+
					"the runtime cannot prove it belongs to the current ownership generation.",
				vm, owner, mi.status, mi.epoch, vmEpoch[vm]), owner)
		}
	}

	// The probe_failed gauge shows every host we could not fully gather from — unreachable,
	// partial, OR on an older binary — so the gap is visible immediately even though only
	// unreachable/partial hosts page.
	probeFailed := append(append(append([]string(nil), unreachable...), unsupported...), partialHosts...)

	// Coverage this pass: COMPLETE only when every probe target answered fully
	// AND the DB index was readable. Unsupported (older-binary) peers block
	// resolution too — a peer that cannot report its runtime cannot prove a
	// workload is absent from it. And a failed DB read blinds the owner- and
	// epoch-mismatch checks entirely (they iterate the index), so it must gate
	// resolution exactly like an unreachable host: the pass proved nothing.
	coverageComplete := len(unreachable) == 0 && len(partialHosts) == 0 && len(unsupported) == 0 && dbIndexOK
	coverageDetail := ""
	if !coverageComplete {
		coverageDetail = fmt.Sprintf("unreachable=%v partial=%v unsupported=%v db_index_ok=%v",
			unreachable, partialHosts, unsupported, dbIndexOK)
	}
	s.applyConditionLifecycle(ctx, current, details, evidenceHosts, coverageComplete, coverageDetail, probeFailed)
}

// dbVMIndex returns per-VM DB state and owner (host_name) maps for all non-deleted VMs.
//
// ok=false means the read FAILED: the maps are then empty because nothing could
// be read, not because no VMs exist, and the caller must treat this pass's
// coverage as PARTIAL. The owner-mismatch and epoch-mismatch checks iterate
// these maps, so an unreadable index silently detects nothing — and two such
// passes counted as "clean" would auto-resolve a confirmed ownership condition
// the detector simply could not see.
func (s *Server) dbVMIndex(ctx context.Context) (state, owner map[string]string, epoch map[string]int64, ok bool) {
	state, owner, epoch = map[string]string{}, map[string]string{}, map[string]int64{}
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		slog.Warn("dual-run detector: list VMs", "error", err)
		return state, owner, epoch, false
	}
	for _, vm := range vms {
		state[vm.Name] = vm.State
		owner[vm.Name] = vm.HostName
		epoch[vm.Name] = vm.OwnerEpoch
	}
	return state, owner, epoch, true
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
	case kindDualRunVM, kindDualRunCT, kindDualRunVIP, kindOwnerMismatch, kindEpochMismatch:
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
	case kindEpochMismatch:
		return "epoch_mismatch"
	default:
		return kind
	}
}
