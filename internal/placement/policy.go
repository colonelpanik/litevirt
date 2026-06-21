package placement

// Policy selects the scoring strategy used by the placement engine.
//
// The two-axis design:
//
//   - Placement policy (this enum) decides initial host selection.
//   - Rebalancer mode (separate; internal/scheduler) decides whether the
//     day-2 loop reacts to ongoing imbalance.
//
// They compose freely: bin-pack + rebalancer-off is "consolidate and forget";
// balance + rebalancer-dry-run is the recommended cluster default.
type Policy string

const (
	// PolicyBalance spreads load across hosts using a weighted-sum scorer
	// over multiple resource dimensions. The default for new clusters.
	//
	// score(h) = Σ wᵢ · max(0, 1 − pressureᵢ(h))
	//
	// Pressure curves are concave so balance arises naturally without an
	// explicit "spread" rule.
	PolicyBalance Policy = "balance"

	// PolicyBinPack inverts the balance score: hosts with higher pressure
	// score higher. The cluster fills hosts before spreading. Useful only
	// when the goal is to free hosts for maintenance/scale-down. Pre-rewrite
	// engine had this as the accidental default; we now require explicit
	// opt-in.
	PolicyBinPack Policy = "bin-pack"

	// PolicySpreadStrict hard-caps per-host pressure at 50 % on any single
	// dimension. Hosts above the cap are excluded entirely (not just
	// down-scored). Used for HA-critical workloads that must not co-locate.
	PolicySpreadStrict Policy = "spread-strict"

	// PolicyCostAware multiplies the balance score by host `$/h` cost
	// (read from a `cost.hourly` host label, default 1.0). Cheap hosts
	// chosen first; balanced within a cost tier.
	PolicyCostAware Policy = "cost-aware"
)

// Valid returns true if p is a recognized policy. Empty/unknown policies
// fall back to PolicyBalance — see ResolvePolicy.
func (p Policy) Valid() bool {
	switch p {
	case PolicyBalance, PolicyBinPack, PolicySpreadStrict, PolicyCostAware:
		return true
	}
	return false
}

// ResolvePolicy returns p if valid, otherwise PolicyBalance. Use this on
// every Request entering the engine so a typo in compose doesn't silently
// fall back to surprising behavior.
func ResolvePolicy(p Policy) Policy {
	if p.Valid() {
		return p
	}
	return PolicyBalance
}

// Dimension is one factor that contributes to a host's placement score.
//
// Each dimension expresses three things about a (host, request) pair:
//
//   - Used: how much of the resource is already consumed on the host
//     (e.g. CPU cores allocated, RAM in MiB, disk IOPS in current use).
//   - Capacity: the host's total quota for this resource.
//   - Demand: how much the candidate request would consume.
//
// pressure = (Used + Demand) / Capacity, clamped to [0, ∞).
//
// Dimensions whose capacity is 0 (unknown / not measured / N/A on a host)
// produce zero contribution rather than divide-by-zero. This lets a cluster
// run with partial telemetry — e.g. before iperf3 measurements seed the
// network-bandwidth dimension, that dimension is silently weight-zero.
type Dimension interface {
	// Name is the dimension's identifier, used in metrics labels (e.g. "cpu").
	Name() string
	// Weight controls relative importance in the weighted sum. 0 disables it.
	Weight() float64
	// Used returns the host's current usage of this resource.
	Used(snapshot *ClusterSnapshot, host string) float64
	// Capacity returns the host's total quota for this resource. 0 = unknown,
	// in which case the dimension contributes nothing.
	Capacity(snapshot *ClusterSnapshot, host string) float64
	// Demand returns how much of this resource the request would consume.
	Demand(req *Request) float64
}

// Pressure returns post-placement pressure (in [0, +∞)) for one dimension.
// Pressure < 1 means the host has headroom; ≥ 1 means it would be over-
// committed. Capacity == 0 returns 0 (dimension N/A on this host).
func Pressure(d Dimension, snap *ClusterSnapshot, host string, req *Request) float64 {
	cap := d.Capacity(snap, host)
	if cap <= 0 {
		return 0
	}
	used := d.Used(snap, host)
	demand := d.Demand(req)
	return (used + demand) / cap
}

// scoreDimension computes one dimension's contribution to the host score.
// Sign convention depends on policy:
//
//   - balance / spread-strict: prefer LOW pressure → contribution = w · (1 − p).
//   - bin-pack: prefer HIGH pressure → contribution = w · p.
//   - cost-aware: same as balance, but the final score is multiplied by
//     1 / cost_label after summation.
//
// We clamp `1 − p` at 0 so over-committed hosts contribute zero rather
// than a negative drag (the over-commit is already a hard reject upstream).
func scoreDimension(d Dimension, snap *ClusterSnapshot, host string, req *Request, policy Policy) float64 {
	w := d.Weight()
	if w <= 0 {
		return 0
	}
	p := Pressure(d, snap, host, req)
	switch policy {
	case PolicyBinPack:
		// Cap at 1.0 so we don't reward over-commit (an over-committed host
		// is rejected by the hard-resource check before we get here).
		if p > 1.0 {
			p = 1.0
		}
		return w * p
	default: // balance | spread-strict | cost-aware
		head := 1.0 - p
		if head < 0 {
			head = 0
		}
		return w * head
	}
}
