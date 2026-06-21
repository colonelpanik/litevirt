package placement

import (
	"context"
	"fmt"
	"math"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// equalCapHosts returns N hosts, all with identical CPU/RAM. Used to
// exercise the bias of a policy without resource asymmetry skewing things.
func equalCapHosts(n, cpu, memMiB int) []corrosion.HostRecord {
	hosts := make([]corrosion.HostRecord, n)
	for i := range hosts {
		hosts[i] = corrosion.HostRecord{
			Name:     fmt.Sprintf("h%d", i),
			Address:  fmt.Sprintf("10.0.0.%d", 10+i),
			State:    "active",
			CPUTotal: cpu,
			MemTotal: memMiB,
		}
	}
	return hosts
}

// hostUtilizationVariance returns variance of CPU-utilization across hosts
// after a batch is placed. Used as the spread metric in tests.
func hostUtilizationVariance(snap *ClusterSnapshot) float64 {
	if len(snap.HostsBy) == 0 {
		return 0
	}
	var (
		n   = float64(len(snap.HostsBy))
		sum float64
	)
	utils := make([]float64, 0, len(snap.HostsBy))
	for _, h := range snap.HostsBy {
		if h.IsWitness() || h.State != "active" {
			continue
		}
		var u float64
		if h.CPUTotal > 0 {
			u = float64(snap.CPUUsed[h.Name]) / float64(h.CPUTotal)
		}
		utils = append(utils, u)
		sum += u
	}
	mean := sum / n
	var ssd float64
	for _, u := range utils {
		ssd += (u - mean) * (u - mean)
	}
	return ssd / n
}

// runBatchAndSnapshot places `requests` on `hosts` and returns the post-
// placement snapshot reflecting the chosen layout.
func runBatchAndSnapshot(t *testing.T, hosts []corrosion.HostRecord, requests []Request) *ClusterSnapshot {
	t.Helper()
	results, err := SelectBatch(hosts, nil, nil, requests)
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	// Build a fake VM list from results so the snapshot reflects placement.
	var vms []corrosion.VMRecord
	for _, req := range requests {
		r, ok := results[req.VMName]
		if !ok {
			t.Fatalf("missing result for %s", req.VMName)
		}
		vms = append(vms, corrosion.VMRecord{
			Name:      req.VMName,
			HostName:  r.Host,
			State:     "running",
			CPUActual: req.CPUNeeded,
			MemActual: req.MemMiBNeeded,
		})
	}
	return BuildSnapshotFrom(hosts, vms)
}

// TestPolicy_BalanceSpreadsAcrossHosts verifies the new default makes
// 100 VMs of mixed sizes land with low CPU-utilization variance across 8 hosts.
// Pre-rewrite: bin-pack default gave ~0.4 variance (one host filled, others empty).
// Post-rewrite: balance gives < 0.05 variance.
func TestPolicy_BalanceSpreadsAcrossHosts(t *testing.T) {
	hosts := equalCapHosts(8, 64, 256*1024)
	requests := make([]Request, 100)
	for i := range requests {
		requests[i] = Request{
			VMName:       fmt.Sprintf("vm-%03d", i),
			CPUNeeded:    1 + (i % 4),      // 1..4 vCPU
			MemMiBNeeded: 1024 * (1 + i%4), // 1..4 GiB
			Policy:       PolicyBalance,
		}
	}
	snap := runBatchAndSnapshot(t, hosts, requests)
	v := hostUtilizationVariance(snap)
	if v > 0.01 {
		t.Errorf("balance variance = %.4f, want < 0.01 (hosts: %v)", v, hostUsageSummary(snap))
	}
	// Sanity: every host should have at least one VM.
	for _, h := range snap.HostsBy {
		if snap.VMCount[h.Name] == 0 {
			t.Errorf("balance left host %q empty; should spread", h.Name)
		}
	}
}

// TestPolicy_BinPackConcentrates verifies the bin-pack policy still works:
// 100 small VMs across 8 large hosts should fill the lowest-name host first.
func TestPolicy_BinPackConcentrates(t *testing.T) {
	hosts := equalCapHosts(8, 64, 256*1024)
	requests := make([]Request, 16) // 16 × 4 cores = exactly one host's CPU
	for i := range requests {
		requests[i] = Request{
			VMName:       fmt.Sprintf("vm-%03d", i),
			CPUNeeded:    4,
			MemMiBNeeded: 4096,
			Policy:       PolicyBinPack,
		}
	}
	snap := runBatchAndSnapshot(t, hosts, requests)

	// Expect strong concentration on a single host.
	maxOnOne := 0
	for _, h := range snap.HostsBy {
		if c := snap.VMCount[h.Name]; c > maxOnOne {
			maxOnOne = c
		}
	}
	if maxOnOne < 16 {
		t.Errorf("bin-pack: max VMs on a single host = %d, want 16 (hosts: %v)", maxOnOne, hostUsageSummary(snap))
	}
}

// TestPolicy_SpreadStrictRefusesAbovePressureCap verifies that spread-strict
// rejects hosts above the 50% pressure cap on any wired dimension.
func TestPolicy_SpreadStrictRefusesAbovePressureCap(t *testing.T) {
	// Single host: 4 cores. First request (3 cores) → 75% post-placement
	// pressure, exceeds 0.5 cap; should fail.
	hosts := equalCapHosts(1, 4, 16*1024)
	_, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "big", CPUNeeded: 3, MemMiBNeeded: 1024, Policy: PolicySpreadStrict},
	})
	if err == nil {
		t.Fatal("spread-strict: expected rejection when post-placement pressure > 0.5")
	}

	// Same host: 1-core request → 25% post-placement pressure; allowed.
	hosts = equalCapHosts(1, 4, 16*1024)
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "small", CPUNeeded: 1, MemMiBNeeded: 1024, Policy: PolicySpreadStrict},
	})
	if err != nil {
		t.Fatalf("spread-strict accepted at-cap placement: %v", err)
	}
	if results["small"].Host == "" {
		t.Fatal("spread-strict: at-cap placement returned no host")
	}
}

// TestPolicy_MixedBatchPerVMPolicy is the headline test from:
// a single batch can mix bin-pack and balance VMs, and the engine must
// honor each request's own policy.
func TestPolicy_MixedBatchPerVMPolicy(t *testing.T) {
	hosts := equalCapHosts(4, 32, 128*1024)

	// First, two large bin-pack VMs (should land on the same host).
	// Then, two balance VMs (should spread).
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "batch-1", CPUNeeded: 8, MemMiBNeeded: 16 * 1024, Policy: PolicyBinPack},
		{VMName: "batch-2", CPUNeeded: 8, MemMiBNeeded: 16 * 1024, Policy: PolicyBinPack},
		{VMName: "prod-1", CPUNeeded: 4, MemMiBNeeded: 8 * 1024, Policy: PolicyBalance},
		{VMName: "prod-2", CPUNeeded: 4, MemMiBNeeded: 8 * 1024, Policy: PolicyBalance},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["batch-1"].Host != results["batch-2"].Host {
		t.Errorf("mixed batch: bin-pack VMs landed on %s and %s — should match",
			results["batch-1"].Host, results["batch-2"].Host)
	}
	if results["prod-1"].Host == results["prod-2"].Host {
		t.Errorf("mixed batch: balance VMs both landed on %s — should spread",
			results["prod-1"].Host)
	}
}

// TestPolicy_BalanceRespectsMaxPerNode asserts that anti-affinity-like
// constraints continue to be enforced regardless of policy.
func TestPolicy_BalanceRespectsMaxPerNode(t *testing.T) {
	hosts := equalCapHosts(3, 16, 64*1024)
	var requests []Request
	for i := 0; i < 4; i++ {
		requests = append(requests, Request{
			VMName:       fmt.Sprintf("web-%d", i),
			CPUNeeded:    1,
			MemMiBNeeded: 512,
			Policy:       PolicyBalance,
			VMBaseName:   "web",
			MaxPerNode:   1,
		})
	}
	// 4 VMs, max 1 per node, only 3 nodes → last must fail.
	_, err := SelectBatch(hosts, nil, nil, requests)
	if err == nil {
		t.Fatal("expected MaxPerNode rejection at 4th VM")
	}
}

// TestPolicy_CostAwarePreferCheapHosts verifies cost-aware respects the
// `cost.hourly` host label.
func TestPolicy_CostAwarePreferCheapHosts(t *testing.T) {
	hosts := []corrosion.HostRecord{
		{Name: "cheap", Address: "10.0.0.1", State: "active",
			CPUTotal: 16, MemTotal: 64 * 1024,
			Labels: map[string]string{"cost.hourly": "0.10"}},
		{Name: "expensive", Address: "10.0.0.2", State: "active",
			CPUTotal: 16, MemTotal: 64 * 1024,
			Labels: map[string]string{"cost.hourly": "1.00"}},
	}
	// First placement on equal-headroom hosts: cost-aware should pick cheap.
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", CPUNeeded: 1, MemMiBNeeded: 1024, Policy: PolicyCostAware},
	})
	if err != nil {
		t.Fatalf("cost-aware: %v", err)
	}
	if results["vm1"].Host != "cheap" {
		t.Errorf("cost-aware: chose %q, want cheap", results["vm1"].Host)
	}
}

// TestPolicy_DefaultIsBalance verifies an unset Policy resolves to balance.
func TestPolicy_DefaultIsBalance(t *testing.T) {
	r := Request{}
	if got := r.effectivePolicy(); got != PolicyBalance {
		t.Errorf("effectivePolicy() = %q, want balance", got)
	}
	r.Spread = true
	if got := r.effectivePolicy(); got != PolicySpreadStrict {
		t.Errorf("effectivePolicy(Spread=true) = %q, want spread-strict", got)
	}
}

// TestSelect_NoEligibleHostsErrorIncludesPolicyHint verifies the error
// message is informative when spread-strict refuses every host.
func TestSelect_SpreadStrictNoEligibleErrorMessage(t *testing.T) {
	hosts := equalCapHosts(1, 4, 4*1024)
	// Pre-fill the host above 50% pressure with a fake VM.
	vms := []corrosion.VMRecord{
		{Name: "incumbent", HostName: "h0", State: "running", CPUActual: 3, MemActual: 1024},
	}
	db := mustTestDB(t)
	for _, h := range hosts {
		_ = corrosion.InsertHost(context.Background(), db, h)
	}
	for _, v := range vms {
		_ = corrosion.InsertVM(context.Background(), db, v, nil, nil)
	}
	_, err := Select(context.Background(), db, Request{
		VMName: "newcomer", CPUNeeded: 1, MemMiBNeeded: 512, Policy: PolicySpreadStrict,
	})
	if err == nil {
		t.Fatal("expected error from spread-strict over-pressure")
	}
}

// hostUsageSummary returns a short string for failure-message formatting.
func hostUsageSummary(snap *ClusterSnapshot) string {
	out := ""
	for _, h := range snap.HostsBy {
		used := snap.CPUUsed[h.Name]
		total := h.CPUTotal
		if total == 0 {
			continue
		}
		pct := math.Round(float64(used)*1000/float64(total)) / 10
		out += fmt.Sprintf(" %s=%d/%d(%.1f%%)", h.Name, used, total, pct)
	}
	return out
}

// mustTestDB is a small helper used by Select-based tests.
func mustTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}
