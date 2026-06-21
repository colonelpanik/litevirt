package placement

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func makeGPU(addr, root, bridge, clique string, numa int) corrosion.PCIDeviceRecord {
	return corrosion.PCIDeviceRecord{
		Address:      addr,
		Type:         "gpu",
		VendorID:     "10de",
		NUMANode:     numa,
		PCIeRootPort: root,
		PCIeBridge:   bridge,
		LinkClique:   clique,
	}
}

func TestTopologyScore_SingleDevice(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
	}
	req := DeviceRequest{Type: "gpu", Count: 1}
	score, selected := TopologyScore(devices, req)
	if len(selected) != 1 {
		t.Fatalf("expected 1 selected, got %d", len(selected))
	}
	if score != 0 {
		t.Errorf("single device should have no pair bonus, got %d", score)
	}
}

func TestTopologyScore_PrefersNVLinkClique(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		// Two GPUs in clique-a (NVLink connected)
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		makeGPU("0000:42:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		// Two GPUs in clique-b on different NUMA node
		makeGPU("0000:81:00.0", "0000:00:02.0", "0000:02:00.0", "clique-b", 1),
		makeGPU("0000:82:00.0", "0000:00:02.0", "0000:02:00.0", "clique-b", 1),
	}

	req := DeviceRequest{Type: "gpu", Count: 2}
	score, selected := TopologyScore(devices, req)
	if len(selected) != 2 {
		t.Fatalf("expected 2 selected, got %d", len(selected))
	}
	// Should pick a clique pair with bonus = 1 pair * 40 = 40
	if score != 40 {
		t.Errorf("expected NVLink clique bonus of 40, got %d", score)
	}
	// Both should be from the same clique.
	if selected[0] != "0000:41:00.0" || selected[1] != "0000:42:00.0" {
		t.Errorf("expected clique-a devices, got %v", selected)
	}
}

func TestTopologyScore_FallsToBridge(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		// Two GPUs on same bridge but no clique
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "", 0),
		makeGPU("0000:41:00.1", "0000:00:01.0", "0000:01:00.0", "", 0),
		// One GPU on different bridge
		makeGPU("0000:81:00.0", "0000:00:02.0", "0000:02:00.0", "", 1),
	}

	req := DeviceRequest{Type: "gpu", Count: 2}
	score, selected := TopologyScore(devices, req)
	if len(selected) != 2 {
		t.Fatalf("expected 2 selected, got %d", len(selected))
	}
	// Bridge bonus = 1 pair * 25 = 25
	if score != 25 {
		t.Errorf("expected bridge bonus of 25, got %d", score)
	}
}

func TestTopologyScore_FallsToRoot(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		// Two GPUs on same root but different bridges
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "", 0),
		makeGPU("0000:42:00.0", "0000:00:01.0", "0000:02:00.0", "", 0),
	}

	req := DeviceRequest{Type: "gpu", Count: 2}
	score, _ := TopologyScore(devices, req)
	// Root bonus = 1 pair * 15 = 15
	if score != 15 {
		t.Errorf("expected root bonus of 15, got %d", score)
	}
}

func TestTopologyScore_FallsToNUMA(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		// Two GPUs on same NUMA but different root ports
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "", 0),
		makeGPU("0000:81:00.0", "0000:00:03.0", "0000:03:00.0", "", 0),
	}

	req := DeviceRequest{Type: "gpu", Count: 2}
	score, _ := TopologyScore(devices, req)
	// NUMA bonus = 1 pair * 8 = 8
	if score != 8 {
		t.Errorf("expected NUMA bonus of 8, got %d", score)
	}
}

func TestTopologyScore_CrossNUMA_NoBonus(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "", 0),
		makeGPU("0000:81:00.0", "0000:00:02.0", "0000:02:00.0", "", 1),
	}

	req := DeviceRequest{Type: "gpu", Count: 2}
	score, selected := TopologyScore(devices, req)
	if len(selected) != 2 {
		t.Fatalf("expected 2 selected, got %d", len(selected))
	}
	if score != 0 {
		t.Errorf("expected no bonus for cross-NUMA, got %d", score)
	}
}

func TestTopologyScore_SameNUMA_Enforced(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "", 0),
		makeGPU("0000:81:00.0", "0000:00:02.0", "0000:02:00.0", "", 1),
	}

	req := DeviceRequest{Type: "gpu", Count: 2, SameNUMA: true}
	_, selected := TopologyScore(devices, req)
	if selected != nil {
		t.Error("SameNUMA=true should fail when no single NUMA node has enough devices")
	}
}

func TestTopologyScore_CliqueHint(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		makeGPU("0000:42:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		makeGPU("0000:81:00.0", "0000:00:02.0", "0000:02:00.0", "clique-b", 1),
		makeGPU("0000:82:00.0", "0000:00:02.0", "0000:02:00.0", "clique-b", 1),
	}

	req := DeviceRequest{Type: "gpu", Count: 2, Clique: "clique-b"}
	score, selected := TopologyScore(devices, req)
	if len(selected) != 2 {
		t.Fatalf("expected 2 selected, got %d", len(selected))
	}
	if selected[0] != "0000:81:00.0" || selected[1] != "0000:82:00.0" {
		t.Errorf("expected clique-b devices, got %v", selected)
	}
	if score != 40 {
		t.Errorf("expected NVLink bonus 40, got %d", score)
	}
}

func TestTopologyScore_VendorFilter(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		{Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", PCIeBridge: "0000:01:00.0"},
		{Address: "0000:42:00.0", Type: "gpu", VendorID: "1002", PCIeBridge: "0000:01:00.0"},
	}

	req := DeviceRequest{Type: "gpu", Count: 1, Vendor: "1002"}
	_, selected := TopologyScore(devices, req)
	if len(selected) != 1 || selected[0] != "0000:42:00.0" {
		t.Errorf("expected AMD GPU, got %v", selected)
	}
}

func TestTopologyScore_InsufficientDevices(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "", 0),
	}

	req := DeviceRequest{Type: "gpu", Count: 4}
	_, selected := TopologyScore(devices, req)
	if selected != nil {
		t.Error("should return nil when insufficient devices")
	}
}

func TestTopologyScore_FourGPUs_NVLink(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		makeGPU("0000:42:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		makeGPU("0000:43:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		makeGPU("0000:44:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		// Other GPUs not in clique
		makeGPU("0000:81:00.0", "0000:00:02.0", "0000:02:00.0", "", 1),
		makeGPU("0000:82:00.0", "0000:00:02.0", "0000:02:00.0", "", 1),
	}

	req := DeviceRequest{Type: "gpu", Count: 4}
	score, selected := TopologyScore(devices, req)
	if len(selected) != 4 {
		t.Fatalf("expected 4 selected, got %d", len(selected))
	}
	// 4 GPUs → 6 pairs → 6 * 40 = 240
	if score != 240 {
		t.Errorf("expected NVLink bonus of 240, got %d", score)
	}
}

func TestScoreHostDevices(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		makeGPU("0000:42:00.0", "0000:00:01.0", "0000:01:00.0", "clique-a", 0),
		{Address: "0000:03:00.0", Type: "network", VendorID: "15b3", PCIeRootPort: "0000:00:03.0"},
	}

	reqs := []DeviceRequest{
		{Type: "gpu", Count: 2},
		{Type: "network", Count: 1},
	}

	ok, bonus := scoreHostDevices(devices, reqs)
	if !ok {
		t.Fatal("expected host to satisfy device requirements")
	}
	if bonus < 40 { // at least NVLink bonus for the 2 GPUs
		t.Errorf("expected bonus >= 40, got %d", bonus)
	}
}

func TestScoreHostDevices_Insufficient(t *testing.T) {
	devices := []corrosion.PCIDeviceRecord{
		makeGPU("0000:41:00.0", "0000:00:01.0", "0000:01:00.0", "", 0),
	}

	reqs := []DeviceRequest{
		{Type: "gpu", Count: 4},
	}

	ok, _ := scoreHostDevices(devices, reqs)
	if ok {
		t.Error("should fail when insufficient devices")
	}
}
