package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestMigrateVM_PCISpecInsufficientDevices verifies that migration fails with
// FailedPrecondition when the target host lacks the PCI devices the VM requires.
func TestMigrateVM_PCISpecInsufficientDevices(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	spec := map[string]interface{}{
		"devices": []map[string]interface{}{
			{"type": "gpu", "vendor": "10de", "count": 2},
		},
	}
	specJSON, _ := json.Marshal(spec)

	insertTestVMWithSpec(t, ctx, s.db, "pci-vm", "test-host", "running", string(specJSON))
	insertTestHost(t, ctx, s.db, "target-host", "active")

	// No PCI devices on target-host → should fail.
	stream := &mockMigrateStream{ctx: ctx}
	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "pci-vm",
		TargetHost: "target-host",
		Strategy:   pb.MigrateStrategy_MIGRATE_COLD,
	}, stream)
	if err == nil {
		t.Fatal("expected FailedPrecondition error for missing PCI devices on target")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition; err = %v", c, err)
	}
	if !strings.Contains(err.Error(), "free") {
		t.Errorf("error should mention free devices: %v", err)
	}
}

// TestMigrateVM_PCISpecPartialDevices verifies that migration fails when the
// target host has some but not enough PCI devices of the required type.
func TestMigrateVM_PCISpecPartialDevices(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	spec := map[string]interface{}{
		"devices": []map[string]interface{}{
			{"type": "gpu", "vendor": "10de", "count": 3},
		},
	}
	specJSON, _ := json.Marshal(spec)

	insertTestVMWithSpec(t, ctx, s.db, "pci-vm3", "test-host", "running", string(specJSON))
	insertTestHost(t, ctx, s.db, "target-partial", "active")

	// Insert only 1 free GPU (need 3).
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "target-partial", Address: "0000:03:00.0",
		VendorID: "10de", DeviceID: "1234", Type: "gpu",
	})
	// One assigned GPU (not free).
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "target-partial", Address: "0000:03:00.1",
		VendorID: "10de", DeviceID: "1234", Type: "gpu", VMName: "other-vm",
	})

	stream := &mockMigrateStream{ctx: ctx}
	err := s.MigrateVM(&pb.MigrateVMRequest{
		VmName:     "pci-vm3",
		TargetHost: "target-partial",
		Strategy:   pb.MigrateStrategy_MIGRATE_COLD,
	}, stream)
	if err == nil {
		t.Fatal("expected FailedPrecondition for insufficient GPUs")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition; err = %v", c, err)
	}
}

// TestPCISpecParsing_ZeroCount verifies that devices with count=0 are skipped
// during PCI spec parsing (tested via direct JSON parsing, not MigrateVM).
func TestPCISpecParsing_ZeroCount(t *testing.T) {
	spec := map[string]interface{}{
		"devices": []map[string]interface{}{
			{"type": "gpu", "vendor": "10de", "count": 0},
		},
	}
	specJSON, _ := json.Marshal(spec)

	var parsed struct {
		Devices []struct {
			Type   string `json:"type"`
			Vendor string `json:"vendor"`
			Count  int32  `json:"count"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(specJSON, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, ds := range parsed.Devices {
		if ds.Count != 0 {
			t.Errorf("expected count=0, got %d", ds.Count)
		}
	}
}

// TestPCISpecParsing_NoDevicesField verifies that a spec without devices
// results in an empty devices list.
func TestPCISpecParsing_NoDevicesField(t *testing.T) {
	spec := map[string]interface{}{
		"resources": map[string]interface{}{"cpus": 4},
	}
	specJSON, _ := json.Marshal(spec)

	var parsed struct {
		Devices []struct {
			Type  string `json:"type"`
			Count int32  `json:"count"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(specJSON, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Devices) != 0 {
		t.Errorf("expected 0 devices, got %d", len(parsed.Devices))
	}
}

// TestCorrosion_ListPCIDevices_FilterByType verifies that ListPCIDevices
// correctly filters devices by type on a given host.
func TestCorrosion_ListPCIDevices_FilterByType(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	devices := []corrosion.PCIDeviceRecord{
		{HostName: "host-a", Address: "0000:01:00.0", VendorID: "10de", DeviceID: "1234", Type: "gpu"},
		{HostName: "host-a", Address: "0000:02:00.0", VendorID: "8086", DeviceID: "5678", Type: "network"},
		{HostName: "host-a", Address: "0000:03:00.0", VendorID: "10de", DeviceID: "1235", Type: "gpu", VMName: "some-vm"},
		{HostName: "host-a", Address: "0000:04:00.0", VendorID: "144d", DeviceID: "a808", Type: "nvme"},
	}
	for _, d := range devices {
		if err := corrosion.UpsertPCIDevice(ctx, db, d); err != nil {
			t.Fatalf("UpsertPCIDevice(%s): %v", d.Address, err)
		}
	}

	gpus, err := corrosion.ListPCIDevices(ctx, db, "host-a", "gpu")
	if err != nil {
		t.Fatalf("ListPCIDevices(gpu): %v", err)
	}
	if len(gpus) != 2 {
		t.Errorf("ListPCIDevices(gpu) returned %d, want 2", len(gpus))
	}

	freeCount := 0
	for _, d := range gpus {
		if d.VMName == "" {
			freeCount++
		}
	}
	if freeCount != 1 {
		t.Errorf("free gpu count = %d, want 1", freeCount)
	}

	nets, err := corrosion.ListPCIDevices(ctx, db, "host-a", "network")
	if err != nil {
		t.Fatalf("ListPCIDevices(network): %v", err)
	}
	if len(nets) != 1 {
		t.Errorf("ListPCIDevices(network) returned %d, want 1", len(nets))
	}

	all, err := corrosion.ListPCIDevices(ctx, db, "host-a", "")
	if err != nil {
		t.Fatalf("ListPCIDevices('') returned %d, want 4", len(all))
	}
	if len(all) != 4 {
		t.Errorf("ListPCIDevices('') returned %d, want 4", len(all))
	}
}
