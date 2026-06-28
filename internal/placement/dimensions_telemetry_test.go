package placement

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestScoreDimension_ZeroCapacitySkipped is the skew regression: a dimension with
// no capacity (telemetry unwired / no label) must contribute 0, NOT full weight.
// RED before the scoreDimension fix (balance mapped pressure 0 → head 1.0 → w).
func TestScoreDimension_ZeroCapacitySkipped(t *testing.T) {
	snap := BuildSnapshotFrom([]corrosion.HostRecord{
		{Name: "h", State: "active", CPUTotal: 8, MemTotal: 8192},
	}, nil)
	// diskIOPSDim with no placement.iops_capacity label → Capacity 0.
	for _, p := range []Policy{PolicyBalance, PolicyCostAware, PolicyBinPack} {
		if got := scoreDimension(diskIOPSDim{w: 15}, snap, "h", &Request{}, p); got != 0 {
			t.Errorf("policy %v: zero-capacity dim contributed %v, want 0", p, got)
		}
	}
}

// TestDiskNetDims_LabelCapacityAndUsage: with a capacity label + sampled usage,
// a busy host scores below an idle one (real signal), and a host without the
// label is unaffected (capacity 0 → skipped).
func TestDiskNetDims_LabelCapacityAndUsage(t *testing.T) {
	labels := map[string]string{"placement.iops_capacity": "1000", "placement.netbw_mbps": "1000"}
	hosts := []corrosion.HostRecord{
		{Name: "busy", State: "active", CPUTotal: 8, MemTotal: 8192, Labels: labels},
		{Name: "idle", State: "active", CPUTotal: 8, MemTotal: 8192, Labels: labels},
		{Name: "labeled_nosample", State: "active", CPUTotal: 8, MemTotal: 8192, Labels: labels},
		{Name: "nolabel", State: "active", CPUTotal: 8, MemTotal: 8192},
	}
	usage := map[string]corrosion.HostRuntimeUsage{
		"busy":    {DiskIOPS: 800, NetMbps: 800}, // sampled, loaded
		"idle":    {DiskIOPS: 0, NetMbps: 0},     // sampled, a REAL zero → still active
		"nolabel": {DiskIOPS: 50, NetMbps: 50},   // sampled but no capacity label
		// labeled_nosample: labeled but NO usage row → must SKIP (no sample).
	}
	snap := BuildSnapshotFromUsage(hosts, nil, usage)

	for _, d := range []Dimension{diskIOPSDim{w: 15}, netBWDim{w: 10}} {
		busy := scoreDimension(d, snap, "busy", &Request{}, PolicyBalance)
		idle := scoreDimension(d, snap, "idle", &Request{}, PolicyBalance)
		if !(idle > busy) {
			t.Errorf("%s: idle (%v) should score above the busy host (%v)", d.Name(), idle, busy)
		}
		// A labeled host with NO usage sample must skip (not be credited full
		// headroom from a missing Used) — the finding-1 regression.
		if got := scoreDimension(d, snap, "labeled_nosample", &Request{}, PolicyBalance); got != 0 {
			t.Errorf("%s: labeled-but-unsampled host should contribute 0, got %v", d.Name(), got)
		}
		// No capacity label → skipped regardless of sample.
		if got := scoreDimension(d, snap, "nolabel", &Request{}, PolicyBalance); got != 0 {
			t.Errorf("%s: host without a capacity label should contribute 0, got %v", d.Name(), got)
		}
	}
}

// TestBuildSnapshot_IgnoresUsageForUnknownHost: a host_runtime_usage row for a
// host absent from the snapshot (e.g. a removed host) must not affect placement.
func TestBuildSnapshot_IgnoresUsageForUnknownHost(t *testing.T) {
	hosts := []corrosion.HostRecord{{Name: "h1", State: "active", CPUTotal: 8, MemTotal: 8192}}
	usage := map[string]corrosion.HostRuntimeUsage{
		"removed-host": {DiskIOPS: 999, NetMbps: 999},
		"h1":           {DiskIOPS: 100, NetMbps: 100},
	}
	snap := BuildSnapshotFromUsage(hosts, nil, usage)
	if _, ok := snap.DiskIOPSUsed["removed-host"]; ok {
		t.Error("usage for a host not in the snapshot was loaded")
	}
	if snap.DiskIOPSUsed["h1"] != 100 {
		t.Errorf("h1 DiskIOPSUsed = %d, want 100", snap.DiskIOPSUsed["h1"])
	}
}
