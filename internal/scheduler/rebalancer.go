// Package scheduler implements litevirt's day-2 control loops:
//
//   - Rebalancer (this file): periodically scores cluster imbalance under each
//     workload's resolved policy and proposes (or applies) live-migrations to
//     flatten the cost gradient.
//
// The rebalancer is leader-only via the leader_election lease to
// avoid duplicate work across coordinators. It is policy-aware on a per-VM
// basis: a single cluster can mix bin-pack batch jobs with
// spread-strict prod VMs without one's policy influencing the other.
package scheduler

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// Default tunables. Operators may override via cluster config.
const (
	defaultPollInterval  = 60 * time.Second
	defaultProposalTTL   = 30 * time.Minute
	defaultThresholdPct  = 15.0 // % score-gain required before a move is proposed
	defaultPerVMCooldown = 5 * time.Minute
	defaultMaxConcurrent = 2
	defaultMaxPerHour    = 10
	defaultLeaseKey      = "rebalancer"
)

// Mode mirrors compose's RebalanceDef.Mode.
type Mode string

const (
	ModeOff      Mode = "off"
	ModeDryRun   Mode = "dry-run"
	ModeOnDemand Mode = "on-demand"
	ModeAuto     Mode = "auto"
)

// vmPolicy is the rebalancer's view of one VM's resolved placement+rebalance.
// We extract this once per cycle (parsing JSON from vms.spec) and use it for
// both candidate scoring and budget gating.
type vmPolicy struct {
	Policy        placement.Policy
	Mode          Mode
	ThresholdPct  float64
	Cooldown      time.Duration
	NoMigrate     bool
	MaxConcurrent int
	MaxPerHour    int
}

// parseSpec unmarshals vms.spec (encoding/json-serialized pb.VMSpec) into a
// VMSpec. Returns nil on empty/invalid spec. Uses encoding/json — NOT protojson
// — to match how the spec is written (internal/grpcapi/vm.go) and read
// (internal/health/reconciler.go), so enum fields decode from their numeric
// form.
func parseSpec(vm corrosion.VMRecord) *pb.VMSpec {
	if vm.Spec == "" {
		return nil
	}
	spec := &pb.VMSpec{}
	if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
		return nil
	}
	return spec
}

// Rebalancer is the engine. One per cluster, leader-gated.
type Rebalancer struct {
	hostName string
	db       *corrosion.Client

	// Tunables — overridable per cluster.
	PollInterval time.Duration
	ProposalTTL  time.Duration

	// Lease handle: rebalancer must hold this lease to act.
	LeaseKey string

	// Now is the time source for lease TTL + proposal-expiry +
	// audit-row timestamps. Defaults to time.Now; fleet scenarios
	// override it with a virtual clock so multi-cycle behaviour can
	// be observed without sleeping.
	Now func() time.Time
}

// NewRebalancer constructs a Rebalancer with default tunables.
func NewRebalancer(hostName string, db *corrosion.Client) *Rebalancer {
	return &Rebalancer{
		hostName:     hostName,
		db:           db,
		PollInterval: defaultPollInterval,
		ProposalTTL:  defaultProposalTTL,
		LeaseKey:     defaultLeaseKey,
		Now:          func() time.Time { return time.Now() },
	}
}

// now is the rebalancer's clock.
func (r *Rebalancer) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

// Start runs the rebalancer loop until ctx is cancelled.
func (r *Rebalancer) Start(ctx context.Context) {
	t := time.NewTicker(r.PollInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.RunOnce(ctx); err != nil {
				slog.Warn("rebalancer: cycle failed", "error", err)
			}
		}
	}
}

// RunOnce performs a single rebalance evaluation. Idempotent and safe to
// call from tests.
func (r *Rebalancer) RunOnce(ctx context.Context) error {
	if !r.acquireLease(ctx) {
		return nil
	}
	if err := r.expireOldProposals(ctx); err != nil {
		slog.Warn("rebalancer: expiring proposals", "error", err)
	}
	snap, err := placement.BuildSnapshot(ctx, r.db)
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	proposals, err := r.evaluateAll(ctx, snap)
	if err != nil {
		return err
	}
	if len(proposals) == 0 {
		return nil
	}
	for _, p := range proposals {
		if err := r.recordProposal(ctx, p); err != nil {
			slog.Warn("rebalancer: record proposal", "vm", p.VMName, "error", err)
			continue
		}
		if p.Mode == ModeAuto {
			// Auto-mode is a placeholder for the actual migration trigger.
			// We mark the row "approved" so the migration controller picks
			// it up; budget gating inside that controller does the real work.
			if err := r.markApproved(ctx, p.ID); err != nil {
				slog.Warn("rebalancer: auto-approve", "id", p.ID, "error", err)
			}
		}
	}
	return nil
}

// Proposal is one suggested live-migration produced by RunOnce.
type Proposal struct {
	ID           string
	VMName       string
	Src          string
	Dst          string
	Policy       placement.Policy
	Mode         Mode
	ExpectedGain float64
	Detail       string
}

// evaluateAll scans every running VM and emits proposals per the policy
// matrix. We greedily commit each chosen move into a working copy of the
// snapshot so subsequent decisions in this cycle see the new placement.
//
// Budget enforcement: a per-cycle counter caps proposals at MaxConcurrent.
// Per-hour caps are enforced lazily — if too many proposals were applied
// in the past hour, the cycle exits early.
func (r *Rebalancer) evaluateAll(ctx context.Context, snap *placement.ClusterSnapshot) ([]Proposal, error) {
	// Resolve the cluster rebalance budget from the VMs' own policies rather
	// than the package-constant defaults (which ignored every VM's configured
	// budget). The executor enforces the same budget on in-flight + hourly
	// migrations; here it caps proposal *generation* per cycle.
	clusterMaxConcurrent, clusterMaxPerHour := resolveClusterBudget(snap)
	if applied, err := r.appliedInLastHour(ctx); err == nil && applied >= clusterMaxPerHour {
		slog.Info("rebalancer: hourly budget reached; skipping cycle",
			"applied_last_hour", applied, "limit", clusterMaxPerHour)
		return nil, nil
	}

	// Build a working snapshot we can mutate as we commit moves.
	working := cloneSnapshot(snap)

	var out []Proposal
	for _, vm := range snap.VMs {
		if vm.State != "running" {
			continue
		}
		spec := parseSpec(vm)
		pol := resolveVMPolicyFromSpec(spec)
		if pol.Mode == ModeOff {
			continue
		}
		if pol.NoMigrate {
			continue
		}
		// Per-VM cooldown.
		if recent, err := r.recentProposalForVM(ctx, vm.Name, pol.Cooldown); err == nil && recent {
			continue
		}

		// Budget cap on proposals generated per cycle (resolved budget).
		if len(out) >= clusterMaxConcurrent {
			break
		}

		best := r.bestMove(working, vm, spec, pol)
		if best == nil {
			continue
		}

		out = append(out, *best)

		// Commit the move into the working snapshot so the *next* VM's
		// scoring sees the updated occupancy. This prevents cycles where
		// every VM "wants" the same destination and we propose them all there.
		working.CPUUsed[best.Src] -= vm.CPUActual
		working.MemUsed[best.Src] -= vm.MemActual
		working.VMCount[best.Src]--
		working.CPUUsed[best.Dst] += vm.CPUActual
		working.MemUsed[best.Dst] += vm.MemActual
		working.VMCount[best.Dst]++
		working.VMHost[vm.Name] = best.Dst
	}
	return out, nil
}

// bestMove evaluates `vm`'s candidate destinations under its own policy using
// the SAME hard-filter + scoring pipeline as initial placement (anti-affinity,
// required labels, max-per-node, devices, witness exclusion, spread-strict
// pressure cap), so a proposed move can never violate a constraint that
// admission would have rejected. Returns nil if no move improves the score by
// at least the threshold, or if the VM is pinned / unmovable.
func (r *Rebalancer) bestMove(snap *placement.ClusterSnapshot, vm corrosion.VMRecord, spec *pb.VMSpec, pol vmPolicy) *Proposal {
	src := vm.HostName
	if src == "" {
		return nil
	}
	srcHost, ok := snap.Hosts[src]
	if !ok || srcHost.IsWitness() {
		return nil
	}

	// Build the FULL placement request from the VM's stored spec — not just
	// CPU/Mem — so destination eligibility honors every hard constraint.
	req := buildPlacementRequest(vm, spec, pol)

	// A pinned VM can only ever live on its pinned host → never propose a move.
	if req.PinHost != "" {
		return nil
	}

	// Score against a snapshot with THIS VM removed from its source: the source
	// is then scored as "VM placed here as a newcomer" on identical footing with
	// every destination, and the VM never blocks itself on resources, replica
	// counts, or its own anti-affinity anchor.
	work := snapshotWithoutVM(snap, vm)

	cands, err := placement.RankFromSnapshot(work, &req)
	if err != nil || len(cands) == 0 {
		// No host (incl. the source) is eligible for this VM right now — don't
		// churn; the executor would fail re-validation anyway.
		return nil
	}

	// Source score (as newcomer) from the same ranking.
	srcScore, srcEligible := 0.0, false
	for _, c := range cands {
		if c.Host == src {
			srcScore, srcEligible = c.Score, true
			break
		}
	}

	// Best eligible destination — cands is sorted best-first, so the first
	// non-source candidate is the best move target.
	bestDst, bestScore := "", 0.0
	for _, c := range cands {
		if c.Host == src {
			continue
		}
		bestDst, bestScore = c.Host, c.Score
		break
	}
	if bestDst == "" {
		return nil // the source is the only eligible host
	}

	// Convert gain into a percentage so the threshold is unit-agnostic.
	gain := bestScore - srcScore
	gainPct := 0.0
	switch {
	case !srcEligible:
		// The source no longer admits this VM (e.g. it now exceeds the
		// spread-strict pressure cap): moving to any eligible host is warranted.
		gainPct = 100
	case srcScore > 0:
		gainPct = (gain / srcScore) * 100
	case bestScore > 0:
		gainPct = 100
	}
	if srcEligible && gain <= 0 {
		return nil // no improvement over staying put
	}
	if gainPct < pol.ThresholdPct {
		return nil
	}

	return &Proposal{
		ID:           newID(),
		VMName:       vm.Name,
		Src:          src,
		Dst:          bestDst,
		Policy:       pol.Policy,
		Mode:         pol.Mode,
		ExpectedGain: gainPct,
		Detail: fmt.Sprintf("policy=%s gain=%.1f%% src_score=%.2f dst_score=%.2f",
			pol.Policy, gainPct, srcScore, bestScore),
	}
}

// buildPlacementRequest constructs a placement.Request from a VM's stored spec
// so candidate scoring honors every hard constraint the VM was admitted under.
// A nil spec yields a CPU/Mem-only request (best effort for legacy rows).
func buildPlacementRequest(vm corrosion.VMRecord, spec *pb.VMSpec, pol vmPolicy) placement.Request {
	req := placement.Request{
		VMName:       vm.Name,
		CPUNeeded:    vm.CPUActual,
		MemMiBNeeded: vm.MemActual,
		Policy:       pol.Policy,
		VMBaseName:   vmBaseName(vm.Name),
	}
	if spec == nil {
		return req
	}
	if p := spec.Placement; p != nil {
		req.PinHost = p.Host
		req.AntiAffinity = p.AntiAffinity
		req.Affinity = p.Affinity
		req.RequireLabels = p.Require
		req.PreferLabels = p.Prefer
		req.Spread = p.Spread
		req.MaxPerNode = int(p.MaxPerNode)
	}
	for _, d := range spec.Devices {
		count := int(d.Count)
		if count <= 0 {
			count = 1
		}
		req.Devices = append(req.Devices, placement.DeviceRequest{
			Type:   d.Type,
			Count:  count,
			Vendor: d.Vendor,
		})
	}
	// Networks are intentionally omitted: the only network effect on scoring is
	// a host-independent SR-IOV soft penalty, which is constant across all
	// candidates and therefore cancels out of the src-vs-dst gain.
	return req
}

// snapshotWithoutVM returns a mutation-safe copy of snap with `vm` removed from
// its current host — resources freed, counts decremented, VMHost/replica index
// cleared — so the VM is scored as a newcomer and never blocks itself.
func snapshotWithoutVM(snap *placement.ClusterSnapshot, vm corrosion.VMRecord) *placement.ClusterSnapshot {
	out := cloneSnapshot(snap) // deep-copies CPUUsed/MemUsed/VMCount/VMHost
	src := vm.HostName
	if vm.State == "running" || vm.State == "creating" || vm.State == "starting" {
		out.CPUUsed[src] -= vm.CPUActual
		out.MemUsed[src] -= vm.MemActual
		out.VMCount[src]--
	}
	delete(out.VMHost, vm.Name)

	// When this VM participates in a replica group (MaxPerNode), the replica
	// index must exclude it. cloneSnapshot shares ReplicasByBase by pointer and
	// SeedReplicasForBase reads VMs, so give `out` a private VMs map without the
	// VM and a fresh replica index for RankFromSnapshot to seed.
	out.ReplicasByBase = make(map[string]map[string]int)
	out.VMs = make(map[string]corrosion.VMRecord, len(snap.VMs))
	for k, v := range snap.VMs {
		if k == vm.Name {
			continue
		}
		out.VMs[k] = v
	}
	return out
}

// resolveVMPolicy parses vms.spec and returns the rebalancer's view.
func resolveVMPolicy(vm corrosion.VMRecord) vmPolicy {
	return resolveVMPolicyFromSpec(parseSpec(vm))
}

// resolveVMPolicyFromSpec derives the rebalancer's view from an already-parsed
// spec (nil-safe). Defaults: balance + dry-run + 15% threshold + 5m cooldown +
// default budget.
func resolveVMPolicyFromSpec(spec *pb.VMSpec) vmPolicy {
	pol := vmPolicy{
		Policy:        placement.PolicyBalance,
		Mode:          ModeDryRun,
		ThresholdPct:  defaultThresholdPct,
		Cooldown:      defaultPerVMCooldown,
		MaxConcurrent: defaultMaxConcurrent,
		MaxPerHour:    defaultMaxPerHour,
	}
	if spec == nil {
		return pol
	}
	if p := spec.Placement; p != nil {
		if pp := placement.Policy(p.Policy); pp.Valid() {
			pol.Policy = pp
		}
		pol.NoMigrate = p.NoMigrate
		if rb := p.Rebalance; rb != nil {
			if m := Mode(rb.Mode); m != "" {
				pol.Mode = m
			}
			if rb.Threshold > 0 {
				pol.ThresholdPct = float64(rb.Threshold)
			}
			if d, err := time.ParseDuration(rb.Cooldown); err == nil && d > 0 {
				pol.Cooldown = d
			}
			if b := rb.Budget; b != nil {
				if b.MaxConcurrent > 0 {
					pol.MaxConcurrent = int(b.MaxConcurrent)
				}
				if b.MaxPerHour > 0 {
					pol.MaxPerHour = int(b.MaxPerHour)
				}
			}
		}
	}
	// A VM that opts out of all migration (migrate.strategy=none) is unmovable.
	if spec.Migrate != nil && spec.Migrate.Strategy == pb.MigrateStrategy_MIGRATE_NONE {
		pol.NoMigrate = true
	}
	// Sanitize: a known-bad combo (bin-pack + auto) downgrades to dry-run
	// at evaluation time (admission emits a warning but lets it through).
	if pol.Policy == placement.PolicyBinPack && pol.Mode == ModeAuto {
		pol.Mode = ModeDryRun
	}
	return pol
}

// resolveClusterBudget derives the cluster-wide rebalance budget (max
// concurrent in-flight migrations, max applied per hour) from the live VM
// policies. It takes the element-wise MAXIMUM over migratable VMs — the most
// permissive declared budget wins cluster-wide — falling back to the package
// defaults when no VM is migratable. Per-VM budget granularity is intentionally
// not modeled (it would need a per-group ledger / schema change); a single
// cluster throttle matches how migrations actually contend for network/IO.
func resolveClusterBudget(snap *placement.ClusterSnapshot) (maxConcurrent, maxPerHour int) {
	maxConcurrent, maxPerHour = defaultMaxConcurrent, defaultMaxPerHour
	found := false
	for _, vm := range snap.VMs {
		if vm.State != "running" {
			continue
		}
		pol := resolveVMPolicy(vm)
		if pol.Mode == ModeOff || pol.NoMigrate {
			continue
		}
		if !found {
			maxConcurrent, maxPerHour = pol.MaxConcurrent, pol.MaxPerHour
			found = true
			continue
		}
		if pol.MaxConcurrent > maxConcurrent {
			maxConcurrent = pol.MaxConcurrent
		}
		if pol.MaxPerHour > maxPerHour {
			maxPerHour = pol.MaxPerHour
		}
	}
	return maxConcurrent, maxPerHour
}

// ClusterRebalanceBudget resolves the cluster-wide rebalance budget from live
// VM policies. Exported for the rebalance executor (a separate loop in
// internal/grpcapi) so proposal generation and execution share one budget.
func ClusterRebalanceBudget(ctx context.Context, db *corrosion.Client) (maxConcurrent, maxPerHour int, err error) {
	snap, err := placement.BuildSnapshot(ctx, db)
	if err != nil {
		return defaultMaxConcurrent, defaultMaxPerHour, err
	}
	mc, mph := resolveClusterBudget(snap)
	return mc, mph, nil
}

// vmBaseName mirrors planner.vmBaseName — strips a trailing "-N" replica suffix.
func vmBaseName(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '-' {
			allDigits := true
			for j := i + 1; j < len(name); j++ {
				if name[j] < '0' || name[j] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits && i+1 < len(name) {
				return name[:i]
			}
			break
		}
	}
	return name
}

// recordProposal writes a pending proposal to the rebalance_proposals table.
func (r *Rebalancer) recordProposal(ctx context.Context, p Proposal) error {
	rNow := r.now()
	now := rNow.UTC().Format(time.RFC3339)
	expires := rNow.Add(r.ProposalTTL).UTC().Format(time.RFC3339)
	return r.db.Execute(ctx,
		`INSERT INTO rebalance_proposals
			(id, vm_name, src_host, dst_host, policy, expected_gain, status,
			 proposed_at, expires_at, detail, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)`,
		p.ID, p.VMName, p.Src, p.Dst, string(p.Policy), p.ExpectedGain,
		now, expires, p.Detail, now,
	)
}

// markApproved transitions a proposal to "approved" so the migration
// controller (out-of-scope for v1) can pick it up.
func (r *Rebalancer) markApproved(ctx context.Context, id string) error {
	now := r.now().UTC().Format(time.RFC3339)
	return r.db.Execute(ctx,
		`UPDATE rebalance_proposals SET status='approved', updated_at=? WHERE id=? AND status='pending'`,
		now, id,
	)
}

// recentProposalForVM returns true if a proposal for vm exists within
// the cooldown window.
func (r *Rebalancer) recentProposalForVM(ctx context.Context, vm string, cooldown time.Duration) (bool, error) {
	// Compare RFC3339-vs-RFC3339 (bound cutoff), NOT against datetime('now'):
	// proposed_at is stored RFC3339 ("…T…Z"); a string compare to datetime('now')'s
	// space text breaks once the date matches ('T' > ' '), so a same-day proposal
	// always looks "recent" → the cooldown never lapses and re-proposals stop.
	rows, err := r.db.Query(ctx,
		`SELECT 1 FROM rebalance_proposals
		 WHERE vm_name = ? AND proposed_at > ? LIMIT 1`,
		vm, r.now().Add(-cooldown).UTC().Format(time.RFC3339),
	)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// appliedInLastHour counts proposals applied in the last 60 minutes.
func (r *Rebalancer) appliedInLastHour(ctx context.Context) (int, error) {
	rows, err := r.db.Query(ctx,
		`SELECT COUNT(*) AS cnt FROM rebalance_proposals
		 WHERE status = 'applied' AND applied_at > ?`,
		r.now().Add(-time.Hour).UTC().Format(time.RFC3339),
	)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, nil
	}
	return rows[0].Int("cnt"), nil
}

// expireOldProposals transitions stale pending rows to expired.
func (r *Rebalancer) expireOldProposals(ctx context.Context) error {
	now := r.now().UTC().Format(time.RFC3339)
	return r.db.Execute(ctx,
		`UPDATE rebalance_proposals
		 SET status = 'expired', updated_at = ?
		 WHERE status = 'pending' AND expires_at < ?`,
		now, now,
	)
}

// HoldsLease acquires/renews the shared rebalancer leader lease and reports
// whether this node holds it. Exported so the rebalance executor (a separate
// loop) can gate on the SAME lease as the proposing loop — a single leader does
// both proposing and executing. Renewal by the same holder is idempotent, so
// two loops on the leader renewing concurrently is safe.
func (r *Rebalancer) HoldsLease(ctx context.Context) bool {
	return r.acquireLease(ctx)
}

// acquireLease returns true if this rebalancer holds the leader lease.
// Reuses the same leader_election table as the failover coordinator (Phase
// -1) but with a distinct key so the two coordinators run independently.
func (r *Rebalancer) acquireLease(ctx context.Context) bool {
	now := r.now().UTC().Format(time.RFC3339)
	expires := r.now().Add(2 * r.PollInterval).UTC().Format(time.RFC3339)
	// expired-check compares RFC3339-vs-RFC3339 (bound now), not datetime('now'):
	// otherwise a dead rebalancer-leader's same-day lease never looks expired and
	// no peer can take over until the UTC date rolls.
	if err := r.db.Execute(ctx,
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(key) DO UPDATE
		   SET holder = excluded.holder,
		       expires_at = excluded.expires_at,
		       updated_at = excluded.updated_at
		   WHERE leader_election.expires_at < ?
		      OR leader_election.holder = excluded.holder`,
		r.LeaseKey, r.hostName, expires, now, now); err != nil {
		slog.Warn("rebalancer: lease write", "error", err)
		return false
	}
	rows, err := r.db.Query(ctx,
		`SELECT holder FROM leader_election WHERE key = ?`, r.LeaseKey)
	if err != nil || len(rows) == 0 {
		return false
	}
	return rows[0].String("holder") == r.hostName
}

// cloneSnapshot makes a shallow-but-mutation-safe copy of the maps the
// rebalancer manipulates (CPUUsed, MemUsed, VMCount, VMHost).
func cloneSnapshot(s *placement.ClusterSnapshot) *placement.ClusterSnapshot {
	out := *s
	out.CPUUsed = copyIntMap(s.CPUUsed)
	out.MemUsed = copyIntMap(s.MemUsed)
	out.VMCount = copyIntMap(s.VMCount)
	out.VMHost = make(map[string]string, len(s.VMHost))
	for k, v := range s.VMHost {
		out.VMHost[k] = v
	}
	return &out
}

func copyIntMap(m map[string]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// newID generates a short random hex ID for proposals.
func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
