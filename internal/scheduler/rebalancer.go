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
	"strings"
	"time"

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

// vmSpecJSON is the shape we expect inside vms.spec; only fields we care
// about. Forward-compatible: extra JSON fields are ignored.
type vmSpecJSON struct {
	Placement *struct {
		Host      string `json:"host"`
		Policy    string `json:"policy"`
		NoMigrate bool   `json:"no_migrate"`
		Rebalance *struct {
			Mode      string `json:"mode"`
			Threshold int    `json:"threshold"`
			Cooldown  string `json:"cooldown"`
			Budget    *struct {
				MaxConcurrent int    `json:"max_concurrent"`
				MaxPerHour    int    `json:"max_per_hour"`
				Window        string `json:"window"`
			} `json:"budget"`
		} `json:"rebalance"`
	} `json:"placement"`
	Migrate *struct {
		Strategy string `json:"strategy"`
	} `json:"migrate"`
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
	clusterMaxPerHour := defaultMaxPerHour
	clusterMaxConcurrent := defaultMaxConcurrent
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
		pol := resolveVMPolicy(vm)
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

		best := r.bestMove(working, vm, pol)
		if best == nil {
			continue
		}

		// Budget cap on concurrent proposals per cycle.
		if len(out) >= clusterMaxConcurrent {
			break
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

// bestMove evaluates `vm`'s candidate destinations under its own policy.
// Returns nil if no move improves the score by at least the threshold.
func (r *Rebalancer) bestMove(snap *placement.ClusterSnapshot, vm corrosion.VMRecord, pol vmPolicy) *Proposal {
	src := vm.HostName
	if src == "" {
		return nil
	}
	srcHost, ok := snap.Hosts[src]
	if !ok || srcHost.IsWitness() {
		return nil
	}

	// Build a placement.Request representing this VM as if newly admitted.
	req := placement.Request{
		VMName:       vm.Name,
		CPUNeeded:    vm.CPUActual,
		MemMiBNeeded: vm.MemActual,
		Policy:       pol.Policy,
		VMBaseName:   vmBaseName(vm.Name),
	}

	// Score the source host (with the VM's own resources removed; the
	// snapshot already reflects the fact that the VM IS there).
	srcScore := scoreHostFor(snap, src, &req)
	bestDst := ""
	bestGain := 0.0
	bestScore := 0.0

	for _, h := range snap.HostsBy {
		if h.Name == src || h.State != "active" || h.IsWitness() {
			continue
		}
		// Skip if dst can't fit the VM.
		if h.CPUTotal-snap.CPUUsed[h.Name] < vm.CPUActual {
			continue
		}
		if h.MemTotal-snap.MemUsed[h.Name] < vm.MemActual {
			continue
		}
		// Pretend-place the VM on h; rescore against this hypothetical state.
		dstScore := scoreHostForMove(snap, src, h.Name, &req)
		gain := dstScore - srcScore
		if gain > bestGain {
			bestGain = gain
			bestDst = h.Name
			bestScore = dstScore
		}
	}

	// Convert gain into percentage of score so the threshold is unit-agnostic.
	gainPct := 0.0
	if srcScore > 0 {
		gainPct = (bestGain / srcScore) * 100
	} else if bestScore > 0 {
		gainPct = 100
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

// scoreHostFor scores `host` for `req` against the snapshot — the VM's
// resources are NOT counted as used (so we can compute "score if VM were
// placed here as a newcomer"). For the source-host case, the VM is
// notionally not on the source for the purpose of this score either; the
// caller must use scoreHostForMove for the destination side, or call this
// after stripping the VM from the source maps.
func scoreHostFor(snap *placement.ClusterSnapshot, host string, req *placement.Request) float64 {
	// Use placement's scoreCandidates for one host? It's not exported.
	// We replicate the dimension loop here for clarity.
	policy := req.Policy
	if !policy.Valid() {
		policy = placement.PolicyBalance
	}
	weights := req.Weights
	if weights == nil {
		w := placement.DefaultWeights()
		weights = &w
	}
	dims := placement.AllDimensions(*weights)
	var s float64
	for _, d := range dims {
		s += scoreDimContribution(d, snap, host, req, policy)
	}
	return s
}

// scoreHostForMove computes the destination's score if `req` were placed
// there, removing it from the source first.
func scoreHostForMove(snap *placement.ClusterSnapshot, src, dst string, req *placement.Request) float64 {
	// Make a tiny working copy by adjusting the few maps we read.
	cpuUsedSrc := snap.CPUUsed[src]
	memUsedSrc := snap.MemUsed[src]
	snap.CPUUsed[src] -= req.CPUNeeded
	snap.MemUsed[src] -= req.MemMiBNeeded
	defer func() {
		snap.CPUUsed[src] = cpuUsedSrc
		snap.MemUsed[src] = memUsedSrc
	}()
	return scoreHostFor(snap, dst, req)
}

// scoreDimContribution mirrors placement.scoreDimension. Duplicated here
// because that helper is unexported. If we expose it later, this collapses.
func scoreDimContribution(d placement.Dimension, snap *placement.ClusterSnapshot, host string, req *placement.Request, policy placement.Policy) float64 {
	w := d.Weight()
	if w <= 0 {
		return 0
	}
	cap := d.Capacity(snap, host)
	if cap <= 0 {
		return 0
	}
	used := d.Used(snap, host)
	demand := d.Demand(req)
	p := (used + demand) / cap
	switch policy {
	case placement.PolicyBinPack:
		if p > 1.0 {
			p = 1.0
		}
		return w * p
	default:
		head := 1.0 - p
		if head < 0 {
			head = 0
		}
		return w * head
	}
}

// resolveVMPolicy parses vms.spec JSON and returns the rebalancer's view.
// Defaults: balance + dry-run + 15% threshold + 5m cooldown.
func resolveVMPolicy(vm corrosion.VMRecord) vmPolicy {
	pol := vmPolicy{
		Policy:        placement.PolicyBalance,
		Mode:          ModeDryRun,
		ThresholdPct:  defaultThresholdPct,
		Cooldown:      defaultPerVMCooldown,
		MaxConcurrent: defaultMaxConcurrent,
		MaxPerHour:    defaultMaxPerHour,
	}
	if vm.Spec == "" {
		return pol
	}
	var s vmSpecJSON
	if err := json.Unmarshal([]byte(vm.Spec), &s); err != nil {
		return pol
	}
	if s.Placement != nil {
		if p := placement.Policy(s.Placement.Policy); p.Valid() {
			pol.Policy = p
		}
		pol.NoMigrate = s.Placement.NoMigrate
		if s.Placement.Rebalance != nil {
			rb := s.Placement.Rebalance
			if m := Mode(rb.Mode); m != "" {
				pol.Mode = m
			}
			if rb.Threshold > 0 {
				pol.ThresholdPct = float64(rb.Threshold)
			}
			if d, err := time.ParseDuration(rb.Cooldown); err == nil && d > 0 {
				pol.Cooldown = d
			}
			if rb.Budget != nil {
				if rb.Budget.MaxConcurrent > 0 {
					pol.MaxConcurrent = rb.Budget.MaxConcurrent
				}
				if rb.Budget.MaxPerHour > 0 {
					pol.MaxPerHour = rb.Budget.MaxPerHour
				}
			}
		}
	}
	if s.Migrate != nil && s.Migrate.Strategy == "none" {
		pol.NoMigrate = true
	}
	// Sanitize: a known-bad combo (bin-pack + auto) downgrades to dry-run
	// at evaluation time (admission emits a warning but lets it through).
	if pol.Policy == placement.PolicyBinPack && pol.Mode == ModeAuto {
		pol.Mode = ModeDryRun
	}
	return pol
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

// hasPrefix is a tiny helper to keep imports terse.
var _ = strings.HasPrefix
