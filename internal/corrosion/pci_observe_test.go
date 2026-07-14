package corrosion

import (
	"context"
	"testing"
)

func pciVMName(t *testing.T, c *Client, host, addr string) string {
	t.Helper()
	devs, err := ListPCIDevices(context.Background(), c, host, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	for _, d := range devs {
		if d.Address == addr {
			return d.VMName
		}
	}
	return "<absent>"
}

// TestObservePCIDevice_PreservesOwnership reproduces the ownership-erasure bug:
// a rescan (which carries no vm_name) must NOT clear an assigned device's owner.
// It also confirms hardware facts still update.
func TestObservePCIDevice_PreservesOwnership(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	dev := PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236", Driver: "nvidia"}
	if err := ObservePCIDevice(ctx, c, dev); err != nil {
		t.Fatalf("observe (first scan): %v", err)
	}
	if err := AssignPCIDevice(ctx, c, "node1", "0000:41:00.0", "vm1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	// A later rescan re-observes the device with NO vm_name and a driver change
	// (nvidia → vfio-pci, the usual passthrough bind).
	dev.Driver = "vfio-pci"
	if err := ObservePCIDevice(ctx, c, dev); err != nil {
		t.Fatalf("observe (rescan): %v", err)
	}
	if got := pciVMName(t, c, "node1", "0000:41:00.0"); got != "vm1" {
		t.Fatalf("rescan erased ownership: vm_name=%q, want vm1", got)
	}
	devs, _ := ListPCIDevices(ctx, c, "node1", "")
	if len(devs) != 1 || devs[0].Driver != "vfio-pci" {
		t.Fatalf("rescan should update hardware facts (driver=vfio-pci), got %+v", devs)
	}
}

// TestObservePCIDevice_RevivesTombstonePreservingOwner: a device that vanished
// (soft-deleted) and reappears is revived by observation WITHOUT changing its
// ownership.
func TestObservePCIDevice_RevivesTombstonePreservingOwner(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	dev := PCIDeviceRecord{HostName: "node1", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", DeviceID: "2236"}
	if err := ObservePCIDevice(ctx, c, dev); err != nil {
		t.Fatalf("observe: %v", err)
	}
	if err := AssignPCIDevice(ctx, c, "node1", "0000:41:00.0", "vm1"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	if err := SoftDeletePCIDevice(ctx, c, "node1", "0000:41:00.0"); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	// Device reappears on a later scan.
	if err := ObservePCIDevice(ctx, c, dev); err != nil {
		t.Fatalf("re-observe: %v", err)
	}
	if got := pciVMName(t, c, "node1", "0000:41:00.0"); got != "vm1" {
		t.Fatalf("revived device lost its owner: vm_name=%q, want vm1", got)
	}
}
