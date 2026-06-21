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
