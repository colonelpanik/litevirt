package placement

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func insertDevice(t *testing.T, c *corrosion.Client, d corrosion.PCIDeviceRecord) {
	t.Helper()
	if err := corrosion.UpsertPCIDevice(context.Background(), c, d); err != nil {
		t.Fatalf("UpsertPCIDevice %s: %v", d.Address, err)
	}
}

func TestSelect_DeviceRequirement_Satisfied(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "gpu-node", Address: "10.0.0.1", State: "active", CPUTotal: 32, MemTotal: 65536,
	})
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "gpu-node", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceID: "2236",
	})

	host, err := Select(context.Background(), db, Request{
		VMName: "vm1",
		Devices: []DeviceRequest{
			{Type: "gpu", Count: 1},
		},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "gpu-node" {
		t.Errorf("got %q, want gpu-node", host)
	}
}

func TestSelect_DeviceRequirement_NotSatisfied(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "no-gpu", Address: "10.0.0.1", State: "active", CPUTotal: 32, MemTotal: 65536,
	})
	// No devices inserted

	_, err := Select(context.Background(), db, Request{
		VMName: "vm1",
		Devices: []DeviceRequest{
			{Type: "gpu", Count: 1},
		},
	})
	if err == nil {
		t.Fatal("expected error when no GPU available")
	}
}

func TestSelect_DeviceRequirement_InsufficientCount(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active", CPUTotal: 32, MemTotal: 65536,
	})
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node1", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceID: "2236",
	})

	// Need 2 GPUs but only 1 available
	_, err := Select(context.Background(), db, Request{
		VMName: "vm1",
		Devices: []DeviceRequest{
			{Type: "gpu", Count: 2},
		},
	})
	if err == nil {
		t.Fatal("expected error when insufficient GPUs")
	}
}

func TestSelect_DeviceRequirement_VendorFilter(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active", CPUTotal: 32, MemTotal: 65536,
	})
	insertHost(t, db, corrosion.HostRecord{
		Name: "node2", Address: "10.0.0.2", State: "active", CPUTotal: 32, MemTotal: 65536,
	})

	// node1 has AMD GPU
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node1", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "1002", DeviceID: "7340",
	})
	// node2 has NVIDIA GPU
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node2", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceID: "2236",
	})

	host, err := Select(context.Background(), db, Request{
		VMName: "vm1",
		Devices: []DeviceRequest{
			{Type: "gpu", Count: 1, Vendor: "10de"},
		},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "node2" {
		t.Errorf("got %q, want node2 (NVIDIA host)", host)
	}
}

func TestSelect_DeviceRequirement_SkipsAssigned(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active", CPUTotal: 32, MemTotal: 65536,
	})
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node1", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceID: "2236",
	})
	// Assign the GPU to another VM
	corrosion.AssignPCIDevice(context.Background(), db, "node1", "0000:41:00.0", "existing-vm")

	_, err := Select(context.Background(), db, Request{
		VMName: "vm1",
		Devices: []DeviceRequest{
			{Type: "gpu", Count: 1},
		},
	})
	if err == nil {
		t.Fatal("expected error when GPU already assigned")
	}
}

func TestSelect_PinnedHostRejectsUnavailableDevice(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active",
		CPUTotal: 32, MemTotal: 65536,
	})

	_, err := Select(context.Background(), db, Request{
		VMName:  "vm1",
		PinHost: "node1",
		Devices: []DeviceRequest{{Type: "gpu", Count: 1}},
	})
	if err == nil {
		t.Fatal("pinned host bypassed unavailable-device hard constraint")
	}
}

func TestSelect_DeviceWithOtherConstraints(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active", CPUTotal: 4, MemTotal: 8192,
	})
	insertHost(t, db, corrosion.HostRecord{
		Name: "node2", Address: "10.0.0.2", State: "active", CPUTotal: 32, MemTotal: 65536,
	})

	// Both nodes have GPUs but node1 has insufficient CPU
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node1", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceID: "2236",
	})
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node2", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceID: "2236",
	})

	host, err := Select(context.Background(), db, Request{
		VMName:       "vm1",
		CPUNeeded:    8,
		MemMiBNeeded: 16384,
		Devices: []DeviceRequest{
			{Type: "gpu", Count: 1},
		},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "node2" {
		t.Errorf("got %q, want node2 (only host with enough CPU)", host)
	}
}

func TestSelect_MultipleDeviceTypes(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active", CPUTotal: 32, MemTotal: 65536,
	})

	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node1", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceID: "2236",
	})
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node1", Address: "0000:42:00.0", Type: "nvme",
		VendorID: "144d", DeviceID: "a808",
	})

	host, err := Select(context.Background(), db, Request{
		VMName: "vm1",
		Devices: []DeviceRequest{
			{Type: "gpu", Count: 1},
			{Type: "nvme", Count: 1},
		},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "node1" {
		t.Errorf("got %q, want node1", host)
	}
}

func TestSelect_MappingOnlyEligibleOnMappedHost(t *testing.T) {
	db := testDB(t)
	for _, host := range []string{"mapped", "unmapped"} {
		insertHost(t, db, corrosion.HostRecord{
			Name: host, Address: "10.0.0.1", State: "active",
			CPUTotal: 32, MemTotal: 65536,
		})
		insertDevice(t, db, corrosion.PCIDeviceRecord{
			HostName: host, Address: "0000:41:00.0", Type: "gpu",
			VendorID: "10de", DeviceName: "A100", IOMMUGroup: -1,
		})
	}
	if err := corrosion.CreateResourceMapping(context.Background(), db, "accelerator", "test"); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(context.Background(), db, "accelerator", "mapped", "0000:41:00.0", "10de", "A100"); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}

	host, err := Select(context.Background(), db, Request{
		VMName:  "vm1",
		Devices: []DeviceRequest{{Mapping: "accelerator"}},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "mapped" {
		t.Fatalf("host = %q, want mapped", host)
	}
}

func TestSelect_TypeSelectorRejectsWrongModel(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active",
		CPUTotal: 32, MemTotal: 65536,
	})
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node1", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceName: "A100", IOMMUGroup: -1,
	})

	_, err := Select(context.Background(), db, Request{
		VMName:  "vm1",
		Devices: []DeviceRequest{{Type: "gpu", Model: "H100"}},
	})
	if err == nil {
		t.Fatal("wrong-model device satisfied placement")
	}
}

func TestSelect_ExactAddressRejectsAssignedIOMMUSibling(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active",
		CPUTotal: 32, MemTotal: 65536,
	})
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node1", Address: "0000:41:00.0", Type: "gpu",
		IOMMUGroup: 9,
	})
	insertDevice(t, db, corrosion.PCIDeviceRecord{
		HostName: "node1", Address: "0000:41:00.1", Type: "network",
		IOMMUGroup: 9, VMName: "other-vm",
	})

	_, err := Select(context.Background(), db, Request{
		VMName:  "vm1",
		Devices: []DeviceRequest{{Address: "0000:41:00.0"}},
	})
	if err == nil {
		t.Fatal("exact address with an assigned IOMMU sibling satisfied placement")
	}
}

func TestValidatePinned_BackendFailureIsInfrastructureError(t *testing.T) {
	db := testDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	err := ValidatePinned(context.Background(), db, Request{VMName: "vm1"}, "node1")
	if err == nil {
		t.Fatal("expected backend failure")
	}
	if !IsInfrastructureError(err) {
		t.Fatalf("error = %T %v, want infrastructure error", err, err)
	}
}
