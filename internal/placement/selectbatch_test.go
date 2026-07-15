package placement

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func makeHosts(names ...string) []corrosion.HostRecord {
	hosts := make([]corrosion.HostRecord, len(names))
	for i, n := range names {
		hosts[i] = corrosion.HostRecord{
			Name:     n,
			Address:  "10.0.0." + string(rune('1'+i)),
			State:    "active",
			CPUTotal: 32,
			MemTotal: 65536,
		}
	}
	return hosts
}

func makeHostsWithResources(specs []struct {
	name string
	cpu  int
	mem  int
}) []corrosion.HostRecord {
	hosts := make([]corrosion.HostRecord, len(specs))
	for i, s := range specs {
		hosts[i] = corrosion.HostRecord{
			Name:     s.name,
			Address:  "10.0.0." + string(rune('1'+i)),
			State:    "active",
			CPUTotal: s.cpu,
			MemTotal: s.mem,
		}
	}
	return hosts
}

func makeVM(name, host string, cpu, mem int, state string) corrosion.VMRecord {
	return corrosion.VMRecord{
		Name:      name,
		HostName:  host,
		CPUActual: cpu,
		MemActual: mem,
		State:     state,
	}
}

// ── SelectBatch: basic placement ────────────────────────────────────────────

func TestSelectBatch_SingleVM(t *testing.T) {
	hosts := makeHosts("node1")
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", CPUNeeded: 2, MemMiBNeeded: 1024},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if r, ok := results["vm1"]; !ok {
		t.Fatal("vm1 not in results")
	} else if r.Host != "node1" {
		t.Errorf("vm1 host = %q, want node1", r.Host)
	}
}

func TestSelectBatch_MultipleVMs_BinPacking(t *testing.T) {
	// With Policy=PolicyBinPack, two consecutive placements should land on
	// the same host (the first vm raises that host's pressure, and bin-pack
	// scoring prefers higher pressure).
	hosts := makeHosts("node1", "node2")
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", CPUNeeded: 2, MemMiBNeeded: 1024, Policy: PolicyBinPack},
		{VMName: "vm2", CPUNeeded: 2, MemMiBNeeded: 1024, Policy: PolicyBinPack},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host != results["vm2"].Host {
		t.Errorf("bin-pack policy: vm1=%s, vm2=%s — expected same host",
			results["vm1"].Host, results["vm2"].Host)
	}
}

func TestSelectBatch_MultipleVMs_BalanceDefault(t *testing.T) {
	// With the new balance default (no Policy specified), two consecutive
	// placements on equally-sized hosts should split across them.
	hosts := makeHosts("node1", "node2")
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", CPUNeeded: 2, MemMiBNeeded: 1024},
		{VMName: "vm2", CPUNeeded: 2, MemMiBNeeded: 1024},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host == results["vm2"].Host {
		t.Errorf("balance default: vm1=%s, vm2=%s — expected different hosts (spread by default)",
			results["vm1"].Host, results["vm2"].Host)
	}
}

func TestSelectBatch_ResourceTracking(t *testing.T) {
	// Two hosts with limited CPU. Place enough VMs to exhaust host1,
	// forcing overflow to host2.
	hosts := makeHostsWithResources([]struct {
		name string
		cpu  int
		mem  int
	}{
		{"node1", 4, 65536},
		{"node2", 4, 65536},
	})

	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", CPUNeeded: 3},
		{VMName: "vm2", CPUNeeded: 3}, // node1 only has 1 CPU left, must go to node2
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host == results["vm2"].Host {
		t.Errorf("both VMs on %s — expected overflow to second host", results["vm1"].Host)
	}
}

func TestSelectBatch_NoEligibleHost(t *testing.T) {
	hosts := makeHostsWithResources([]struct {
		name string
		cpu  int
		mem  int
	}{
		{"small", 2, 4096},
	})
	_, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", CPUNeeded: 8},
	})
	if err == nil {
		t.Fatal("expected error for insufficient resources")
	}
}

func TestSelectBatch_InactiveHostSkipped(t *testing.T) {
	hosts := []corrosion.HostRecord{
		{Name: "offline", State: "offline", CPUTotal: 64, MemTotal: 131072},
		{Name: "active", State: "active", CPUTotal: 8, MemTotal: 16384},
	}
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", CPUNeeded: 2},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host != "active" {
		t.Errorf("expected active host, got %s", results["vm1"].Host)
	}
}

// ── SelectBatch: pinned host ────────────────────────────────────────────────

func TestSelectBatch_PinnedHost(t *testing.T) {
	hosts := makeHosts("node1", "node2")
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", PinHost: "node2"},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host != "node2" {
		t.Errorf("pinned: got %s, want node2", results["vm1"].Host)
	}
}

func TestSelectBatch_PinnedHost_NotFound(t *testing.T) {
	hosts := makeHosts("node1")
	_, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", PinHost: "missing"},
	})
	if err == nil {
		t.Fatal("expected error for missing pinned host")
	}
}

func TestSelectBatch_PinnedHost_Inactive(t *testing.T) {
	hosts := []corrosion.HostRecord{
		{Name: "drain", State: "draining", CPUTotal: 32, MemTotal: 65536},
	}
	_, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", PinHost: "drain"},
	})
	if err == nil {
		t.Fatal("expected error for inactive pinned host")
	}
}

// ── SelectBatch: anti-affinity ──────────────────────────────────────────────

func TestSelectBatch_AntiAffinity_ExistingVMs(t *testing.T) {
	hosts := makeHosts("node1", "node2")
	existingVMs := []corrosion.VMRecord{
		makeVM("web-1", "node1", 2, 1024, "running"),
	}
	results, err := SelectBatch(hosts, existingVMs, nil, []Request{
		{VMName: "web-2", CPUNeeded: 2, AntiAffinity: []string{"web-1"}},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["web-2"].Host != "node2" {
		t.Errorf("anti-affinity: got %s, want node2", results["web-2"].Host)
	}
}

func TestSelectBatch_AntiAffinity_BatchAware(t *testing.T) {
	// Two VMs with mutual anti-affinity placed in the same batch.
	// The second VM should see the first VM's placement.
	hosts := makeHosts("node1", "node2")
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "web-1", CPUNeeded: 2},
		{VMName: "web-2", CPUNeeded: 2, AntiAffinity: []string{"web-1"}},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["web-1"].Host == results["web-2"].Host {
		t.Errorf("anti-affinity violated: both on %s", results["web-1"].Host)
	}
}

func TestSelectBatch_AntiAffinity_Impossible(t *testing.T) {
	// Only one host, anti-affinity against existing VM on that host.
	hosts := makeHosts("node1")
	existingVMs := []corrosion.VMRecord{
		makeVM("web-1", "node1", 2, 1024, "running"),
	}
	_, err := SelectBatch(hosts, existingVMs, nil, []Request{
		{VMName: "web-2", AntiAffinity: []string{"web-1"}},
	})
	if err == nil {
		t.Fatal("expected error when anti-affinity is impossible")
	}
}

// ── SelectBatch: MaxPerNode ─────────────────────────────────────────────────

func TestSelectBatch_MaxPerNode(t *testing.T) {
	hosts := makeHosts("node1", "node2")
	existingVMs := []corrosion.VMRecord{
		makeVM("web-1", "node1", 1, 512, "running"),
	}
	results, err := SelectBatch(hosts, existingVMs, nil, []Request{
		{VMName: "web-2", MaxPerNode: 1, VMBaseName: "web"},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	// node1 already has web-1, so web-2 should go to node2.
	if results["web-2"].Host != "node2" {
		t.Errorf("max-per-node: got %s, want node2", results["web-2"].Host)
	}
}

func TestSelectBatch_MaxPerNode_BatchAware(t *testing.T) {
	// Place 3 replicas across 2 hosts with max-per-node=2.
	hosts := makeHosts("node1", "node2")
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "web-1", MaxPerNode: 2, VMBaseName: "web"},
		{VMName: "web-2", MaxPerNode: 2, VMBaseName: "web"},
		{VMName: "web-3", MaxPerNode: 2, VMBaseName: "web"},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}

	perHost := map[string]int{}
	for _, r := range results {
		perHost[r.Host]++
	}
	for host, count := range perHost {
		if count > 2 {
			t.Errorf("%s has %d replicas, max-per-node=2", host, count)
		}
	}
}

// ── SelectBatch: spread ─────────────────────────────────────────────────────

func TestSelectBatch_Spread(t *testing.T) {
	hosts := makeHosts("node1", "node2", "node3")
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", Spread: true},
		{VMName: "vm2", Spread: true},
		{VMName: "vm3", Spread: true},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}

	// With spread, each VM should go to a different host.
	used := map[string]bool{}
	for _, r := range results {
		if used[r.Host] {
			t.Errorf("spread violated: host %s used more than once", r.Host)
		}
		used[r.Host] = true
	}
}

// ── SelectBatch: affinity ───────────────────────────────────────────────────

func TestSelectBatch_Affinity(t *testing.T) {
	hosts := makeHosts("node1", "node2")
	existingVMs := []corrosion.VMRecord{
		makeVM("db-1", "node2", 4, 8192, "running"),
	}
	results, err := SelectBatch(hosts, existingVMs, nil, []Request{
		{VMName: "app-1", Affinity: []string{"db-1"}},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["app-1"].Host != "node2" {
		t.Errorf("affinity: got %s, want node2", results["app-1"].Host)
	}
}

// ── SelectBatch: required labels ────────────────────────────────────────────

func TestSelectBatch_RequireLabels(t *testing.T) {
	hosts := []corrosion.HostRecord{
		{Name: "node1", State: "active", CPUTotal: 32, MemTotal: 65536, Labels: map[string]string{"zone": "us-east"}},
		{Name: "node2", State: "active", CPUTotal: 32, MemTotal: 65536, Labels: map[string]string{"zone": "eu-west"}},
	}
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", RequireLabels: map[string]string{"zone": "eu-west"}},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host != "node2" {
		t.Errorf("labels: got %s, want node2", results["vm1"].Host)
	}
}

func TestSelectBatch_RequireLabels_NoneMatch(t *testing.T) {
	hosts := makeHosts("node1")
	_, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", RequireLabels: map[string]string{"gpu": "true"}},
	})
	if err == nil {
		t.Fatal("expected error when no host matches labels")
	}
}

// ── SelectBatch: prefer labels ──────────────────────────────────────────────

func TestSelectBatch_PreferLabels(t *testing.T) {
	hosts := []corrosion.HostRecord{
		{Name: "node1", State: "active", CPUTotal: 32, MemTotal: 65536, Labels: map[string]string{}},
		{Name: "node2", State: "active", CPUTotal: 32, MemTotal: 65536, Labels: map[string]string{"tier": "high"}},
	}
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", PreferLabels: map[string]string{"tier": "high"}},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host != "node2" {
		t.Errorf("prefer labels: got %s, want node2", results["vm1"].Host)
	}
}

// ── SelectBatch: network penalty ────────────────────────────────────────────

func TestSelectBatch_SRIOVNetworkPenalty(t *testing.T) {
	// SR-IOV network without device requirements gets a score penalty.
	// The test verifies that the penalty doesn't cause a crash and placement still works.
	hosts := makeHosts("node1")
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", Networks: []NetworkReq{{Name: "sriov-net", Type: "sriov"}}},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host != "node1" {
		t.Errorf("got %s, want node1", results["vm1"].Host)
	}
}

// ── SelectBatch: existing VM state filtering ────────────────────────────────

func TestSelectBatch_IgnoresStoppedVMs(t *testing.T) {
	// Stopped VMs should not count toward resource usage.
	hosts := makeHostsWithResources([]struct {
		name string
		cpu  int
		mem  int
	}{
		{"node1", 4, 8192},
	})
	existingVMs := []corrosion.VMRecord{
		makeVM("old-vm", "node1", 4, 8192, "stopped"), // stopped — should be ignored
	}
	results, err := SelectBatch(hosts, existingVMs, nil, []Request{
		{VMName: "vm1", CPUNeeded: 4, MemMiBNeeded: 8192},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host != "node1" {
		t.Errorf("stopped VM counted as used resources")
	}
}

// ── SelectBatch: tie-breaking ───────────────────────────────────────────────

func TestSelectBatch_TieBreak_ByVMCount_ThenName(t *testing.T) {
	hosts := makeHosts("node-b", "node-a")
	// Equal score, equal VM count → alphabetical name wins.
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", Spread: true},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host != "node-a" {
		t.Errorf("tie-break: got %s, want node-a (alphabetical)", results["vm1"].Host)
	}
}

// ── assignDevices ───────────────────────────────────────────────────────────

func TestAssignDevices_NoRequests(t *testing.T) {
	pool := map[string][]corrosion.PCIDeviceRecord{}
	result := assignDevices(pool, "node1", nil)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestAssignDevices_SingleGPU(t *testing.T) {
	pool := map[string][]corrosion.PCIDeviceRecord{
		"node1": {
			{Address: "0000:03:00.0", Type: "gpu", VMName: "", VendorName: "NVIDIA", DeviceName: "A100"},
			{Address: "0000:04:00.0", Type: "gpu", VMName: "", VendorName: "NVIDIA", DeviceName: "A100"},
		},
	}
	result := assignDevices(pool, "node1", []DeviceRequest{
		{Type: "gpu", Count: 1},
	})
	if len(result) != 1 {
		t.Fatalf("expected 1 device, got %d", len(result))
	}
	if result[0].Type != "gpu" {
		t.Errorf("type = %q, want gpu", result[0].Type)
	}

	// Verify device was marked as reserved in pool.
	reserved := 0
	for _, d := range pool["node1"] {
		if d.VMName == "reserved" {
			reserved++
		}
	}
	if reserved != 1 {
		t.Errorf("expected 1 reserved device, got %d", reserved)
	}
}

func TestAssignDevices_MultipleGPUs(t *testing.T) {
	pool := map[string][]corrosion.PCIDeviceRecord{
		"node1": {
			{Address: "0000:03:00.0", Type: "gpu", VMName: "", VendorName: "NVIDIA", DeviceName: "A100", NUMANode: 0},
			{Address: "0000:04:00.0", Type: "gpu", VMName: "", VendorName: "NVIDIA", DeviceName: "A100", NUMANode: 0},
			{Address: "0000:05:00.0", Type: "gpu", VMName: "", VendorName: "NVIDIA", DeviceName: "A100", NUMANode: 1},
		},
	}
	result := assignDevices(pool, "node1", []DeviceRequest{
		{Type: "gpu", Count: 2},
	})
	if len(result) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(result))
	}
}

func TestAssignDevices_VendorFilter(t *testing.T) {
	pool := map[string][]corrosion.PCIDeviceRecord{
		"node1": {
			{Address: "0000:03:00.0", Type: "gpu", VMName: "", VendorID: "10de", VendorName: "NVIDIA"},
			{Address: "0000:04:00.0", Type: "gpu", VMName: "", VendorID: "1002", VendorName: "AMD"},
		},
	}
	result := assignDevices(pool, "node1", []DeviceRequest{
		{Type: "gpu", Count: 1, Vendor: "AMD"},
	})
	if len(result) != 1 {
		t.Fatalf("expected 1 device, got %d", len(result))
	}
	if result[0].Vendor != "AMD" {
		t.Errorf("vendor = %q, want AMD", result[0].Vendor)
	}
}

func TestAssignDevices_AlreadyReserved(t *testing.T) {
	pool := map[string][]corrosion.PCIDeviceRecord{
		"node1": {
			{Address: "0000:03:00.0", Type: "gpu", VMName: "other-vm"}, // already taken
			{Address: "0000:04:00.0", Type: "gpu", VMName: ""},         // available
		},
	}
	result := assignDevices(pool, "node1", []DeviceRequest{
		{Type: "gpu", Count: 1},
	})
	if len(result) != 1 {
		t.Fatalf("expected 1 device, got %d", len(result))
	}
	if result[0].Address != "0000:04:00.0" {
		t.Errorf("expected available device, got %s", result[0].Address)
	}
}

func TestAssignDevices_CountDefaultsToOne(t *testing.T) {
	pool := map[string][]corrosion.PCIDeviceRecord{
		"node1": {
			{Address: "0000:03:00.0", Type: "nvme", VMName: ""},
		},
	}
	result := assignDevices(pool, "node1", []DeviceRequest{
		{Type: "nvme", Count: 0}, // should default to 1
	})
	if len(result) != 1 {
		t.Fatalf("expected 1 device (count defaults to 1), got %d", len(result))
	}
}

func TestAssignDevices_EmptyPool(t *testing.T) {
	pool := map[string][]corrosion.PCIDeviceRecord{}
	result := assignDevices(pool, "node1", []DeviceRequest{
		{Type: "gpu", Count: 1},
	})
	// No devices available — should return empty (fallback path).
	if len(result) != 0 {
		t.Errorf("expected 0 devices from empty pool, got %d", len(result))
	}
}

// ── SelectBatch: device integration ─────────────────────────────────────────

func TestSelectBatch_WithDevices(t *testing.T) {
	hosts := makeHosts("node1", "node2")
	devices := map[string][]corrosion.PCIDeviceRecord{
		"node1": {},
		"node2": {
			{Address: "0000:03:00.0", Type: "gpu", VMName: "", VendorName: "NVIDIA"},
		},
	}
	results, err := SelectBatch(hosts, nil, devices, []Request{
		{VMName: "vm1", Devices: []DeviceRequest{{Type: "gpu", Count: 1}}},
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host != "node2" {
		t.Errorf("expected node2 (has GPU), got %s", results["vm1"].Host)
	}
	if len(results["vm1"].Devices) != 1 {
		t.Errorf("expected 1 assigned device, got %d", len(results["vm1"].Devices))
	}
}

func TestSelectBatch_DevicePoolDepleted(t *testing.T) {
	// Two VMs each need a GPU, but node1 only has one.
	hosts := makeHosts("node1")
	devices := map[string][]corrosion.PCIDeviceRecord{
		"node1": {
			{Address: "0000:03:00.0", Type: "gpu", VMName: ""},
		},
	}
	_, err := SelectBatch(hosts, nil, devices, []Request{
		{VMName: "vm1", Devices: []DeviceRequest{{Type: "gpu", Count: 1}}},
		{VMName: "vm2", Devices: []DeviceRequest{{Type: "gpu", Count: 1}}},
	})
	if err == nil {
		t.Fatal("expected error when GPU pool depleted")
	}
}

// ── SelectBatch: large batch ────────────────────────────────────────────────

func TestSelectBatch_LargeBatch_Spread(t *testing.T) {
	hosts := makeHosts("node1", "node2", "node3", "node4")
	reqs := make([]Request, 12)
	for i := range reqs {
		reqs[i] = Request{VMName: "vm-" + string(rune('a'+i)), Spread: true}
	}
	results, err := SelectBatch(hosts, nil, nil, reqs)
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}

	perHost := map[string]int{}
	for _, r := range results {
		perHost[r.Host]++
	}
	// With 12 VMs across 4 hosts and spread, each host should get 3.
	for host, count := range perHost {
		if count != 3 {
			t.Errorf("%s has %d VMs, want 3 with spread", host, count)
		}
	}
}

func TestSelectBatch_MemoryTracking(t *testing.T) {
	hosts := makeHostsWithResources([]struct {
		name string
		cpu  int
		mem  int
	}{
		{"node1", 32, 4096},
		{"node2", 32, 4096},
	})
	results, err := SelectBatch(hosts, nil, nil, []Request{
		{VMName: "vm1", MemMiBNeeded: 3000},
		{VMName: "vm2", MemMiBNeeded: 3000}, // node1 only has ~1096 left
	})
	if err != nil {
		t.Fatalf("SelectBatch: %v", err)
	}
	if results["vm1"].Host == results["vm2"].Host {
		t.Errorf("memory overflow: both on %s (only 4096 MiB each)", results["vm1"].Host)
	}
}

// TestAssignDevices_SRIOV_NoPin: an SR-IOV request is resolved on-demand by the
// owner's allocator, so placement neither pins a VF address nor consumes a device.
func TestAssignDevices_SRIOV_NoPin(t *testing.T) {
	pool := map[string][]corrosion.PCIDeviceRecord{
		"node1": {
			{Address: "0000:41:00.0", Type: "network", VMName: "", SRIOVCapable: true, SRIOVVFsTotal: 7},
		},
	}
	result := assignDevices(pool, "node1", []DeviceRequest{
		{Type: "network", Count: 1, Sriov: true, Parent: "0000:41:00.0"},
	})
	if len(result) != 0 {
		t.Fatalf("SR-IOV request must not pin a device, got %v", result)
	}
	for _, d := range pool["node1"] {
		if d.VMName == "reserved" {
			t.Error("SR-IOV request must not consume/reserve a device from the pool")
		}
	}
}

// TestScoreHostDevices_SRIOV: a host with an SR-IOV-capable PF is eligible even with
// zero existing VFs (VFs are created on-demand); a host without one is not.
func TestScoreHostDevices_SRIOV(t *testing.T) {
	pfHost := []corrosion.PCIDeviceRecord{
		{Address: "0000:41:00.0", Type: "network", SRIOVCapable: true, SRIOVVFsTotal: 7, SRIOVVFsFree: 0},
	}
	if ok, _ := scoreHostDevices(pfHost, []DeviceRequest{{Type: "network", Sriov: true}}); !ok {
		t.Error("an SR-IOV-capable PF with 0 current VFs must still be eligible (created on-demand)")
	}
	// Parent-specified match.
	if ok, _ := scoreHostDevices(pfHost, []DeviceRequest{{Type: "network", Sriov: true, Parent: "0000:41:00.0"}}); !ok {
		t.Error("matching parent PF must be eligible")
	}
	if ok, _ := scoreHostDevices(pfHost, []DeviceRequest{{Type: "network", Sriov: true, Parent: "0000:99:00.0"}}); ok {
		t.Error("non-matching parent must NOT be eligible")
	}
	// No SR-IOV-capable device of the type → not eligible.
	plain := []corrosion.PCIDeviceRecord{{Address: "0000:03:00.0", Type: "gpu", SRIOVCapable: false}}
	if ok, _ := scoreHostDevices(plain, []DeviceRequest{{Type: "network", Sriov: true}}); ok {
		t.Error("host without an SR-IOV-capable network PF must not be eligible")
	}
}
