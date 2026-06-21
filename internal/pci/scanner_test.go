package pci

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassifyDevice_GPU(t *testing.T) {
	tmp := t.TempDir()
	// PCI class 0x030000 = Display controller (VGA)
	os.WriteFile(filepath.Join(tmp, "class"), []byte("0x030000\n"), 0644)

	got := classifyDevice(tmp, "10de")
	if got != "gpu" {
		t.Errorf("classifyDevice(0x030000) = %q, want gpu", got)
	}
}

func TestClassifyDevice_Network(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "class"), []byte("0x020000\n"), 0644)

	got := classifyDevice(tmp, "8086")
	if got != "network" {
		t.Errorf("classifyDevice(0x020000) = %q, want network", got)
	}
}

func TestClassifyDevice_NVMe(t *testing.T) {
	tmp := t.TempDir()
	// Class 0x010802 = Mass storage / NVM Express
	os.WriteFile(filepath.Join(tmp, "class"), []byte("0x010802\n"), 0644)

	got := classifyDevice(tmp, "144d")
	if got != "nvme" {
		t.Errorf("classifyDevice(0x010802) = %q, want nvme", got)
	}
}

func TestClassifyDevice_MassStorage_NonNVMe(t *testing.T) {
	tmp := t.TempDir()
	// Class 0x010100 = IDE controller
	os.WriteFile(filepath.Join(tmp, "class"), []byte("0x010100\n"), 0644)

	got := classifyDevice(tmp, "8086")
	if got != "other" {
		t.Errorf("classifyDevice(0x010100) = %q, want other", got)
	}
}

func TestClassifyDevice_InfiniBand(t *testing.T) {
	tmp := t.TempDir()
	// Class 0x0C0600 = Serial bus / InfiniBand
	os.WriteFile(filepath.Join(tmp, "class"), []byte("0x0c0600\n"), 0644)

	got := classifyDevice(tmp, "15b3")
	if got != "infiniband" {
		t.Errorf("classifyDevice(0x0c0600) = %q, want infiniband", got)
	}
}

func TestClassifyDevice_SerialBus_NonIB(t *testing.T) {
	tmp := t.TempDir()
	// Class 0x0C0300 = Serial bus / USB
	os.WriteFile(filepath.Join(tmp, "class"), []byte("0x0c0300\n"), 0644)

	got := classifyDevice(tmp, "8086")
	if got != "other" {
		t.Errorf("classifyDevice(0x0c0300) = %q, want other", got)
	}
}

func TestClassifyDevice_NoClassFile(t *testing.T) {
	tmp := t.TempDir()
	got := classifyDevice(tmp, "10de")
	if got != "other" {
		t.Errorf("classifyDevice(no class file) = %q, want other", got)
	}
}

func TestClassifyDevice_InvalidClassHex(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "class"), []byte("notahex\n"), 0644)

	got := classifyDevice(tmp, "10de")
	if got != "other" {
		t.Errorf("classifyDevice(invalid hex) = %q, want other", got)
	}
}

func TestFilterInteresting(t *testing.T) {
	devices := []Device{
		{Address: "0000:00:00.0", Type: "other"},
		{Address: "0000:01:00.0", Type: "gpu"},
		{Address: "0000:02:00.0", Type: "network"},
		{Address: "0000:03:00.0", Type: "other"},
		{Address: "0000:04:00.0", Type: "nvme"},
		{Address: "0000:05:00.0", Type: "infiniband"},
	}

	filtered := FilterInteresting(devices)
	if len(filtered) != 4 {
		t.Fatalf("FilterInteresting: got %d devices, want 4", len(filtered))
	}

	types := map[string]bool{}
	for _, d := range filtered {
		types[d.Type] = true
	}
	for _, want := range []string{"gpu", "network", "nvme", "infiniband"} {
		if !types[want] {
			t.Errorf("FilterInteresting missing type %q", want)
		}
	}
}

func TestFilterInteresting_AllOther(t *testing.T) {
	devices := []Device{
		{Address: "0000:00:00.0", Type: "other"},
		{Address: "0000:00:01.0", Type: "other"},
	}
	filtered := FilterInteresting(devices)
	if len(filtered) != 0 {
		t.Errorf("FilterInteresting(all other) = %d, want 0", len(filtered))
	}
}

func TestFilterInteresting_Empty(t *testing.T) {
	filtered := FilterInteresting(nil)
	if len(filtered) != 0 {
		t.Errorf("FilterInteresting(nil) = %d, want 0", len(filtered))
	}
}

func TestIOMMUGroupMembers_NegativeGroup(t *testing.T) {
	addrs, err := IOMMUGroupMembers(-1)
	if err != nil {
		t.Fatalf("IOMMUGroupMembers(-1): unexpected error: %v", err)
	}
	if addrs != nil {
		t.Errorf("IOMMUGroupMembers(-1) = %v, want nil", addrs)
	}
}

func TestReadSysTrimmed(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "vendor")
	os.WriteFile(path, []byte("0x10de\n"), 0644)

	got := readSysTrimmed(path)
	// readSysTrimmed strips both whitespace and "0x" prefix
	if got != "10de" {
		t.Errorf("readSysTrimmed = %q, want 10de", got)
	}
}

func TestReadSysTrimmed_Missing(t *testing.T) {
	got := readSysTrimmed("/nonexistent/file")
	if got != "" {
		t.Errorf("readSysTrimmed(missing) = %q, want empty", got)
	}
}

func TestReadSysInt(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "numa_node")
	os.WriteFile(path, []byte("2\n"), 0644)

	got := readSysInt(path)
	if got != 2 {
		t.Errorf("readSysInt = %d, want 2", got)
	}
}

func TestReadSysInt_Invalid(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "bad")
	os.WriteFile(path, []byte("notanumber\n"), 0644)

	got := readSysInt(path)
	if got != 0 {
		t.Errorf("readSysInt(invalid) = %d, want 0", got)
	}
}

func TestReadDriverName_NoDriver(t *testing.T) {
	tmp := t.TempDir()
	got := readDriverName(tmp)
	if got != "" {
		t.Errorf("readDriverName(no symlink) = %q, want empty", got)
	}
}

func TestReadDriverName_WithDriver(t *testing.T) {
	tmp := t.TempDir()
	// Create a fake driver symlink
	driverTarget := filepath.Join(tmp, "drivers", "nvidia")
	os.MkdirAll(driverTarget, 0755)
	os.Symlink(driverTarget, filepath.Join(tmp, "driver"))

	got := readDriverName(tmp)
	if got != "nvidia" {
		t.Errorf("readDriverName = %q, want nvidia", got)
	}
}

func TestReadIOMMUGroup_NoGroup(t *testing.T) {
	tmp := t.TempDir()
	got := readIOMMUGroup(tmp)
	if got != -1 {
		t.Errorf("readIOMMUGroup(no symlink) = %d, want -1", got)
	}
}

func TestReadIOMMUGroup_WithGroup(t *testing.T) {
	tmp := t.TempDir()
	// Create a fake iommu_group symlink
	groupDir := filepath.Join(tmp, "iommu_groups", "42")
	os.MkdirAll(groupDir, 0755)
	os.Symlink(groupDir, filepath.Join(tmp, "iommu_group"))

	got := readIOMMUGroup(tmp)
	if got != 42 {
		t.Errorf("readIOMMUGroup = %d, want 42", got)
	}
}
