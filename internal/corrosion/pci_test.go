package corrosion

import (
	"context"
	"testing"
)

func TestUpsertAndListPCIDevices(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	dev := PCIDeviceRecord{
		HostName:      "node1",
		Address:       "0000:41:00.0",
		VendorID:      "10de",
		DeviceID:      "2236",
		VendorName:    "NVIDIA",
		DeviceName:    "A10",
		Type:          "gpu",
		IOMMUGroup:    42,
		SRIOVCapable:  false,
		SRIOVVFsTotal: 0,
		SRIOVVFsFree:  0,
		Driver:        "nvidia",
		NUMANode:      0,
	}

	if err := UpsertPCIDevice(ctx, c, dev); err != nil {
		t.Fatalf("UpsertPCIDevice: %v", err)
	}

	devices, err := ListPCIDevices(ctx, c, "node1", "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}

	got := devices[0]
	if got.HostName != "node1" {
		t.Errorf("HostName = %q, want node1", got.HostName)
	}
	if got.Address != "0000:41:00.0" {
		t.Errorf("Address = %q", got.Address)
	}
	if got.VendorID != "10de" {
		t.Errorf("VendorID = %q", got.VendorID)
	}
	if got.Type != "gpu" {
		t.Errorf("Type = %q, want gpu", got.Type)
	}
	if got.IOMMUGroup != 42 {
		t.Errorf("IOMMUGroup = %d, want 42", got.IOMMUGroup)
	}
	if got.Driver != "nvidia" {
		t.Errorf("Driver = %q, want nvidia", got.Driver)
	}
}

func TestListPCIDevices_TypeFilter(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:42:00.0", Type: "network", VendorID: "8086", DeviceID: "1521"})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:43:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2237"})

	gpus, err := ListPCIDevices(ctx, c, "node1", "gpu")
	if err != nil {
		t.Fatalf("ListPCIDevices(gpu): %v", err)
	}
	if len(gpus) != 2 {
		t.Errorf("expected 2 GPUs, got %d", len(gpus))
	}

	nics, err := ListPCIDevices(ctx, c, "node1", "network")
	if err != nil {
		t.Fatalf("ListPCIDevices(network): %v", err)
	}
	if len(nics) != 1 {
		t.Errorf("expected 1 NIC, got %d", len(nics))
	}
}

func TestListPCIDevices_DifferentHosts(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node2", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"})

	devs, _ := ListPCIDevices(ctx, c, "node1", "")
	if len(devs) != 1 {
		t.Errorf("node1: expected 1 device, got %d", len(devs))
	}
	devs, _ = ListPCIDevices(ctx, c, "node2", "")
	if len(devs) != 1 {
		t.Errorf("node2: expected 1 device, got %d", len(devs))
	}
}

func TestAssignPCIDevice(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"})

	if err := AssignPCIDevice(ctx, c, "node1", "0000:41:00.0", "my-vm"); err != nil {
		t.Fatalf("AssignPCIDevice: %v", err)
	}

	devices, _ := ListPCIDevices(ctx, c, "node1", "")
	if len(devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devices))
	}
	if devices[0].VMName != "my-vm" {
		t.Errorf("VMName = %q, want my-vm", devices[0].VMName)
	}
}

func TestReleasePCIDevicesByVM(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:42:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2237"})

	AssignPCIDevice(ctx, c, "node1", "0000:41:00.0", "vm1")
	AssignPCIDevice(ctx, c, "node1", "0000:42:00.0", "vm1")

	if err := ReleasePCIDevicesByVM(ctx, c, "vm1"); err != nil {
		t.Fatalf("ReleasePCIDevicesByVM: %v", err)
	}

	devices, _ := ListPCIDevices(ctx, c, "node1", "")
	for _, d := range devices {
		if d.VMName != "" {
			t.Errorf("device %s still assigned to %q after release", d.Address, d.VMName)
		}
	}
}

func TestSoftDeletePCIDevice(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"})

	if err := SoftDeletePCIDevice(ctx, c, "node1", "0000:41:00.0"); err != nil {
		t.Fatalf("SoftDeletePCIDevice: %v", err)
	}

	// ListPCIDevices should exclude soft-deleted devices
	devices, _ := ListPCIDevices(ctx, c, "node1", "")
	if len(devices) != 0 {
		t.Errorf("expected 0 devices after soft delete, got %d", len(devices))
	}
}

func TestGetAvailableDevicesByType(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:42:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2237"})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:43:00.0", Type: "network", VendorID: "8086", DeviceID: "1521"})

	// Assign one GPU
	AssignPCIDevice(ctx, c, "node1", "0000:41:00.0", "vm1")

	available, err := GetAvailableDevicesByType(ctx, c, "node1", "gpu")
	if err != nil {
		t.Fatalf("GetAvailableDevicesByType: %v", err)
	}
	if len(available) != 1 {
		t.Fatalf("expected 1 available GPU, got %d", len(available))
	}
	if available[0].Address != "0000:42:00.0" {
		t.Errorf("expected unassigned GPU 0000:42:00.0, got %s", available[0].Address)
	}
}

func TestGetAvailableDevicesByType_ExcludesDeleted(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"})
	SoftDeletePCIDevice(ctx, c, "node1", "0000:41:00.0")

	available, _ := GetAvailableDevicesByType(ctx, c, "node1", "gpu")
	if len(available) != 0 {
		t.Errorf("expected 0 available after soft delete, got %d", len(available))
	}
}

func TestGetDevicesByIOMMUGroup(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", IOMMUGroup: 42, VendorID: "10de", DeviceID: "2236"})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.1", Type: "gpu", IOMMUGroup: 42, VendorID: "10de", DeviceID: "2236"})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:42:00.0", Type: "network", IOMMUGroup: 43, VendorID: "8086", DeviceID: "1521"})

	group, err := GetDevicesByIOMMUGroup(ctx, c, "node1", 42)
	if err != nil {
		t.Fatalf("GetDevicesByIOMMUGroup: %v", err)
	}
	if len(group) != 2 {
		t.Fatalf("expected 2 devices in IOMMU group 42, got %d", len(group))
	}
}

func TestUpsertPCIDevice_Update(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Insert device with nvidia driver
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236", Driver: "nvidia"})

	// Upsert again with vfio-pci driver
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236", Driver: "vfio-pci"})

	devices, _ := ListPCIDevices(ctx, c, "node1", "")
	if len(devices) != 1 {
		t.Fatalf("expected 1 device after upsert, got %d", len(devices))
	}
	if devices[0].Driver != "vfio-pci" {
		t.Errorf("Driver = %q, want vfio-pci", devices[0].Driver)
	}
}

func TestReleasePCIDevice(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{HostName: "node1", Address: "0000:42:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2237"})

	AssignPCIDevice(ctx, c, "node1", "0000:41:00.0", "vm1")
	AssignPCIDevice(ctx, c, "node1", "0000:42:00.0", "vm1")

	// Release only one device (owner-scoped).
	if err := ReleasePCIDevice(ctx, c, "node1", "0000:41:00.0", "vm1"); err != nil {
		t.Fatalf("ReleasePCIDevice: %v", err)
	}

	devices, _ := ListPCIDevices(ctx, c, "node1", "")
	released := 0
	assigned := 0
	for _, d := range devices {
		if d.VMName == "" {
			released++
		} else {
			assigned++
		}
	}
	if released != 1 || assigned != 1 {
		t.Errorf("expected 1 released + 1 assigned, got %d released + %d assigned", released, assigned)
	}
}

func TestGetAvailableDevicesWithTopology(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	UpsertPCIDevice(ctx, c, PCIDeviceRecord{
		HostName: "node1", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceID: "2236", PCIeRootPort: "rp0", PCIeBridge: "br0",
	})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{
		HostName: "node1", Address: "0000:42:00.0", Type: "gpu",
		VendorID: "10de", DeviceID: "2237", PCIeRootPort: "rp1", PCIeBridge: "br1",
	})
	UpsertPCIDevice(ctx, c, PCIDeviceRecord{
		HostName: "node1", Address: "0000:43:00.0", Type: "network",
		VendorID: "8086", DeviceID: "1521", PCIeRootPort: "rp2",
	})

	// Assign one GPU
	AssignPCIDevice(ctx, c, "node1", "0000:41:00.0", "vm1")

	// All types
	all, err := GetAvailableDevicesWithTopology(ctx, c, "node1", "")
	if err != nil {
		t.Fatalf("GetAvailableDevicesWithTopology: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected 2 available devices, got %d", len(all))
	}

	// Only GPUs
	gpus, err := GetAvailableDevicesWithTopology(ctx, c, "node1", "gpu")
	if err != nil {
		t.Fatalf("GetAvailableDevicesWithTopology(gpu): %v", err)
	}
	if len(gpus) != 1 {
		t.Errorf("expected 1 available GPU, got %d", len(gpus))
	}
}

func TestScanPCIDevice(t *testing.T) {
	r := Row{
		Columns: []string{"host_name", "address", "vendor_id", "device_id", "vendor_name",
			"device_name", "type", "iommu_group", "sriov_capable", "sriov_vfs_total",
			"sriov_vfs_free", "driver", "vm_name", "numa_node"},
		Values: []interface{}{"node1", "0000:41:00.0", "10de", "2236", "NVIDIA",
			"A10", "gpu", float64(42), float64(1), float64(16),
			float64(8), "nvidia", "my-vm", float64(0)},
	}

	d := scanPCIDevice(r)
	if d.HostName != "node1" {
		t.Errorf("HostName = %q", d.HostName)
	}
	if d.Address != "0000:41:00.0" {
		t.Errorf("Address = %q", d.Address)
	}
	if d.Type != "gpu" {
		t.Errorf("Type = %q", d.Type)
	}
	if d.IOMMUGroup != 42 {
		t.Errorf("IOMMUGroup = %d", d.IOMMUGroup)
	}
	if !d.SRIOVCapable {
		t.Error("SRIOVCapable should be true")
	}
	if d.SRIOVVFsTotal != 16 {
		t.Errorf("SRIOVVFsTotal = %d", d.SRIOVVFsTotal)
	}
	if d.VMName != "my-vm" {
		t.Errorf("VMName = %q", d.VMName)
	}
}
