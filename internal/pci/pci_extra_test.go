package pci

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScan_FakeSysfs(t *testing.T) {
	tmp := t.TempDir()
	origSysDevices := sysDevices
	sysDevices = tmp
	defer func() { sysDevices = origSysDevices }()

	// Create a fake GPU device.
	gpuDir := filepath.Join(tmp, "0000:41:00.0")
	os.MkdirAll(gpuDir, 0755)
	os.WriteFile(filepath.Join(gpuDir, "vendor"), []byte("0x10de\n"), 0644)
	os.WriteFile(filepath.Join(gpuDir, "device"), []byte("0x2236\n"), 0644)
	os.WriteFile(filepath.Join(gpuDir, "class"), []byte("0x030000\n"), 0644)
	os.WriteFile(filepath.Join(gpuDir, "numa_node"), []byte("0\n"), 0644)

	// Create a fake network device.
	nicDir := filepath.Join(tmp, "0000:03:00.0")
	os.MkdirAll(nicDir, 0755)
	os.WriteFile(filepath.Join(nicDir, "vendor"), []byte("0x8086\n"), 0644)
	os.WriteFile(filepath.Join(nicDir, "device"), []byte("0x1533\n"), 0644)
	os.WriteFile(filepath.Join(nicDir, "class"), []byte("0x020000\n"), 0644)
	os.WriteFile(filepath.Join(nicDir, "numa_node"), []byte("0\n"), 0644)

	devices, err := Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}

	typeMap := map[string]string{}
	for _, d := range devices {
		typeMap[d.Address] = d.Type
	}
	if typeMap["0000:41:00.0"] != "gpu" {
		t.Errorf("expected gpu, got %q", typeMap["0000:41:00.0"])
	}
	if typeMap["0000:03:00.0"] != "network" {
		t.Errorf("expected network, got %q", typeMap["0000:03:00.0"])
	}
}

func TestScan_EmptySysfs(t *testing.T) {
	tmp := t.TempDir()
	origSysDevices := sysDevices
	sysDevices = tmp
	defer func() { sysDevices = origSysDevices }()

	devices, err := Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(devices) != 0 {
		t.Errorf("expected 0 devices, got %d", len(devices))
	}
}

func TestScan_NonexistentPath(t *testing.T) {
	origSysDevices := sysDevices
	sysDevices = "/nonexistent/path"
	defer func() { sysDevices = origSysDevices }()

	_, err := Scan()
	if err == nil {
		t.Error("expected error for nonexistent sysfs path")
	}
}

func TestScanDevice_FakeSysfs(t *testing.T) {
	tmp := t.TempDir()
	origSysDevices := sysDevices
	sysDevices = tmp
	defer func() { sysDevices = origSysDevices }()

	devDir := filepath.Join(tmp, "0000:05:00.0")
	os.MkdirAll(devDir, 0755)
	os.WriteFile(filepath.Join(devDir, "vendor"), []byte("0x144d\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "device"), []byte("0xa808\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "class"), []byte("0x010802\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "numa_node"), []byte("1\n"), 0644)

	d, err := ScanDevice("0000:05:00.0")
	if err != nil {
		t.Fatalf("ScanDevice: %v", err)
	}
	if d.Address != "0000:05:00.0" {
		t.Errorf("address = %q", d.Address)
	}
	if d.VendorID != "144d" {
		t.Errorf("VendorID = %q, want 144d", d.VendorID)
	}
	if d.Type != "nvme" {
		t.Errorf("Type = %q, want nvme", d.Type)
	}
	if d.NUMANode != 1 {
		t.Errorf("NUMANode = %d, want 1", d.NUMANode)
	}
}

func TestScanDevice_WithSRIOV(t *testing.T) {
	tmp := t.TempDir()
	origSysDevices := sysDevices
	sysDevices = tmp
	defer func() { sysDevices = origSysDevices }()

	devDir := filepath.Join(tmp, "0000:06:00.0")
	os.MkdirAll(devDir, 0755)
	os.WriteFile(filepath.Join(devDir, "vendor"), []byte("0x8086\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "device"), []byte("0x1533\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "class"), []byte("0x020000\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "numa_node"), []byte("0\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "sriov_totalvfs"), []byte("64\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "sriov_numvfs"), []byte("8\n"), 0644)

	d, err := ScanDevice("0000:06:00.0")
	if err != nil {
		t.Fatalf("ScanDevice: %v", err)
	}
	if !d.SRIOVCapable {
		t.Error("expected SRIOVCapable=true")
	}
	if d.SRIOVVFsTotal != 64 {
		t.Errorf("SRIOVVFsTotal = %d, want 64", d.SRIOVVFsTotal)
	}
	if d.SRIOVVFsFree != 56 {
		t.Errorf("SRIOVVFsFree = %d, want 56 (64-8)", d.SRIOVVFsFree)
	}
}

func TestListVFs(t *testing.T) {
	tmp := t.TempDir()
	origSysDevices := sysDevices
	sysDevices = tmp
	defer func() { sysDevices = origSysDevices }()

	pfDir := filepath.Join(tmp, "0000:07:00.0")
	os.MkdirAll(pfDir, 0755)

	// Create virtfn symlinks.
	os.MkdirAll(filepath.Join(pfDir, "vf_targets", "0000:07:00.1"), 0755)
	os.Symlink("../vf_targets/0000:07:00.1", filepath.Join(pfDir, "virtfn0"))
	os.MkdirAll(filepath.Join(pfDir, "vf_targets", "0000:07:00.2"), 0755)
	os.Symlink("../vf_targets/0000:07:00.2", filepath.Join(pfDir, "virtfn1"))

	addrs, err := ListVFs("0000:07:00.0")
	if err != nil {
		t.Fatalf("ListVFs: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 VFs, got %d", len(addrs))
	}
}

func TestListVFs_NoPF(t *testing.T) {
	tmp := t.TempDir()
	origSysDevices := sysDevices
	sysDevices = tmp
	defer func() { sysDevices = origSysDevices }()

	// PF doesn't exist.
	addrs, err := ListVFs("0000:ff:00.0")
	if err != nil {
		t.Fatalf("ListVFs: %v", err)
	}
	if addrs != nil {
		t.Errorf("expected nil, got %v", addrs)
	}
}

func TestCreateVFs_NotSRIOV(t *testing.T) {
	tmp := t.TempDir()
	origSysDevices := sysDevices
	sysDevices = tmp
	defer func() { sysDevices = origSysDevices }()

	// Device without sriov_totalvfs.
	devDir := filepath.Join(tmp, "0000:08:00.0")
	os.MkdirAll(devDir, 0755)

	_, err := CreateVFs("0000:08:00.0", 4)
	if err == nil {
		t.Error("expected error for non-SRIOV device")
	}
}

func TestCreateVFs_ExceedsMax(t *testing.T) {
	tmp := t.TempDir()
	origSysDevices := sysDevices
	sysDevices = tmp
	defer func() { sysDevices = origSysDevices }()

	devDir := filepath.Join(tmp, "0000:09:00.0")
	os.MkdirAll(devDir, 0755)
	os.WriteFile(filepath.Join(devDir, "sriov_totalvfs"), []byte("8\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "sriov_numvfs"), []byte("6\n"), 0644)

	_, err := CreateVFs("0000:09:00.0", 4) // 6 + 4 = 10 > 8
	if err == nil {
		t.Error("expected error when exceeding max VFs")
	}
}

func TestIsHexDigit(t *testing.T) {
	for _, c := range "0123456789abcdefABCDEF" {
		if !isHexDigit(byte(c)) {
			t.Errorf("isHexDigit(%c) = false, want true", c)
		}
	}
	for _, c := range "ghijGHIJ!@#_" {
		if isHexDigit(byte(c)) {
			t.Errorf("isHexDigit(%c) = true, want false", c)
		}
	}
}

func TestReadVendorName_WithLabel(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "label"), []byte("NVIDIA GeForce RTX 4090\n"), 0644)

	got := readVendorName(tmp, "10de")
	if got != "NVIDIA GeForce RTX 4090" {
		t.Errorf("readVendorName = %q, want NVIDIA GeForce RTX 4090", got)
	}
}

func TestReadVendorName_NoLabel(t *testing.T) {
	tmp := t.TempDir()
	got := readVendorName(tmp, "10de")
	if got != "10de" {
		t.Errorf("readVendorName = %q, want 10de (fallback)", got)
	}
}

func TestReadDeviceName(t *testing.T) {
	tmp := t.TempDir()
	got := readDeviceName(tmp, "2236")
	if got != "2236" {
		t.Errorf("readDeviceName = %q, want 2236", got)
	}
}

func TestParseCreatedGIID(t *testing.T) {
	tests := []struct {
		output string
		want   int
	}{
		{"Successfully created GPU instance ID  1 on GPU  0 using profile MIG 1g.5gb (ID  9)\n", 1},
		{"Successfully created GPU instance ID  7 on GPU  0 using profile MIG 3g.20gb (ID  5)\n", 7},
		{"No GPU instance ID found in output\n", -1},
		{"", -1},
	}
	for _, tt := range tests {
		got := parseCreatedGIID(tt.output)
		if got != tt.want {
			t.Errorf("parseCreatedGIID(%q) = %d, want %d", tt.output, got, tt.want)
		}
	}
}

func TestReadNVMeSize(t *testing.T) {
	tmp := t.TempDir()

	os.WriteFile(filepath.Join(tmp, "size"), []byte("2048\n"), 0644)
	got := readNVMeSize(tmp)
	if got != 2048*512 {
		t.Errorf("readNVMeSize = %d, want %d", got, 2048*512)
	}
}

func TestReadNVMeSize_Missing(t *testing.T) {
	tmp := t.TempDir()
	got := readNVMeSize(tmp)
	if got != 0 {
		t.Errorf("readNVMeSize(missing) = %d, want 0", got)
	}
}

func TestReadNVMeSize_Invalid(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "size"), []byte("not-a-number\n"), 0644)
	got := readNVMeSize(tmp)
	if got != 0 {
		t.Errorf("readNVMeSize(invalid) = %d, want 0", got)
	}
}

func TestReadNVMeState(t *testing.T) {
	tmp := t.TempDir()
	os.WriteFile(filepath.Join(tmp, "state"), []byte("dead\n"), 0644)
	got := readNVMeState(tmp)
	if got != "dead" {
		t.Errorf("readNVMeState = %q, want dead", got)
	}
}

func TestReadNVMeState_Missing(t *testing.T) {
	tmp := t.TempDir()
	got := readNVMeState(tmp)
	if got != "unknown" {
		t.Errorf("readNVMeState(missing) = %q, want unknown", got)
	}
}

func TestScanNVMeNamespaces_NonexistentPath(t *testing.T) {
	old := nvmeClassPath
	nvmeClassPath = "/nonexistent/path"
	defer func() { nvmeClassPath = old }()

	namespaces, err := ScanNVMeNamespaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if namespaces != nil {
		t.Errorf("expected nil, got %v", namespaces)
	}
}

func TestNvmeControllerPCIAddress_NoSymlink(t *testing.T) {
	tmp := t.TempDir()
	old := nvmeClassPath
	nvmeClassPath = tmp
	defer func() { nvmeClassPath = old }()

	ctrlDir := filepath.Join(tmp, "nvme0")
	os.MkdirAll(ctrlDir, 0755)

	got := nvmeControllerPCIAddress("nvme0")
	if got != "" {
		t.Errorf("expected empty for no device symlink, got %q", got)
	}
}

func TestNvmeControllerPCIAddress_WithSymlink(t *testing.T) {
	tmp := t.TempDir()
	old := nvmeClassPath
	nvmeClassPath = tmp
	defer func() { nvmeClassPath = old }()

	ctrlDir := filepath.Join(tmp, "nvme0")
	os.MkdirAll(ctrlDir, 0755)

	// Create target that looks like a PCI device.
	pciDevice := filepath.Join(tmp, "pci-devices", "0000:03:00.0")
	os.MkdirAll(pciDevice, 0755)
	os.Symlink(pciDevice, filepath.Join(ctrlDir, "device"))

	got := nvmeControllerPCIAddress("nvme0")
	if got != "0000:03:00.0" {
		t.Errorf("expected 0000:03:00.0, got %q", got)
	}
}

func TestScan_WithSRIOV(t *testing.T) {
	tmp := t.TempDir()
	origSysDevices := sysDevices
	sysDevices = tmp
	defer func() { sysDevices = origSysDevices }()

	devDir := filepath.Join(tmp, "0000:10:00.0")
	os.MkdirAll(devDir, 0755)
	os.WriteFile(filepath.Join(devDir, "vendor"), []byte("0x8086\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "device"), []byte("0x1533\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "class"), []byte("0x020000\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "numa_node"), []byte("0\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "sriov_totalvfs"), []byte("32\n"), 0644)
	os.WriteFile(filepath.Join(devDir, "sriov_numvfs"), []byte("10\n"), 0644)

	devices, err := Scan()
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	d := devices[0]
	if !d.SRIOVCapable {
		t.Error("expected SRIOVCapable=true")
	}
	if d.SRIOVVFsTotal != 32 {
		t.Errorf("SRIOVVFsTotal = %d", d.SRIOVVFsTotal)
	}
	if d.SRIOVVFsFree != 22 {
		t.Errorf("SRIOVVFsFree = %d, want 22", d.SRIOVVFsFree)
	}
}
