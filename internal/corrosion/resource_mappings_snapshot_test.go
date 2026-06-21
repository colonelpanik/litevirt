package corrosion

import (
	"context"
	"testing"
)

func TestSnapshotRecord_MemoryRoundTrip(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := InsertSnapshot(ctx, c, SnapshotRecord{
		VMName: "web", HostName: "h1", Name: "snap1", State: "ok",
		SizeBytes: 1234, Type: "memory", VMStatePath: "/var/lib/litevirt/vmstate/web-snap1.save", VMStateBytes: 4096,
	}); err != nil {
		t.Fatalf("InsertSnapshot: %v", err)
	}
	// A disk-only snapshot defaults type to "disk".
	if err := InsertSnapshot(ctx, c, SnapshotRecord{
		VMName: "web", HostName: "h1", Name: "snap2", State: "ok", SizeBytes: 10,
	}); err != nil {
		t.Fatalf("InsertSnapshot disk: %v", err)
	}

	got, err := GetSnapshot(ctx, c, "web", "snap1")
	if err != nil || got == nil {
		t.Fatalf("GetSnapshot: %v (nil=%v)", err, got == nil)
	}
	if got.Type != "memory" || got.VMStateBytes != 4096 || got.VMStatePath == "" {
		t.Errorf("memory snapshot round-trip wrong: %+v", got)
	}

	d, err := GetSnapshot(ctx, c, "web", "snap2")
	if err != nil || d == nil {
		t.Fatalf("GetSnapshot disk: %v", err)
	}
	if d.Type != "disk" {
		t.Errorf("disk snapshot type = %q, want disk", d.Type)
	}

	all, err := ListSnapshots(ctx, c, "web")
	if err != nil || len(all) != 2 {
		t.Fatalf("ListSnapshots: %v len=%d", err, len(all))
	}
}

func TestResourceMappings_CRUD(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := CreateResourceMapping(ctx, c, "gpu-a100", "NVIDIA A100 pool"); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := AddMappingDevice(ctx, c, "gpu-a100", "host1", "0000:41:00.0", "10de", "A100"); err != nil {
		t.Fatalf("AddMappingDevice host1: %v", err)
	}
	if err := AddMappingDevice(ctx, c, "gpu-a100", "host2", "0000:81:00.0", "10de", "A100"); err != nil {
		t.Fatalf("AddMappingDevice host2: %v", err)
	}

	// Resolve per host.
	addr, err := ResolveMappingAddress(ctx, c, "gpu-a100", "host2")
	if err != nil || addr != "0000:81:00.0" {
		t.Fatalf("ResolveMappingAddress host2 = %q (%v)", addr, err)
	}
	if addr, _ := ResolveMappingAddress(ctx, c, "gpu-a100", "host-absent"); addr != "" {
		t.Errorf("ResolveMappingAddress on a host with no device should be empty, got %q", addr)
	}

	// Hosts eligible for placement.
	hosts, err := HostsForMapping(ctx, c, "gpu-a100")
	if err != nil || len(hosts) != 2 {
		t.Fatalf("HostsForMapping = %v (%v)", hosts, err)
	}

	// List groups by name, carries description + devices.
	all, err := ListResourceMappings(ctx, c)
	if err != nil || len(all) != 1 {
		t.Fatalf("ListResourceMappings len=%d (%v)", len(all), err)
	}
	if all[0].Description != "NVIDIA A100 pool" || len(all[0].Devices) != 2 {
		t.Errorf("mapping wrong: %+v", all[0])
	}

	// Remove one device, then delete the whole mapping.
	if err := RemoveMappingDevice(ctx, c, "gpu-a100", "host1", "0000:41:00.0"); err != nil {
		t.Fatalf("RemoveMappingDevice: %v", err)
	}
	if hosts, _ := HostsForMapping(ctx, c, "gpu-a100"); len(hosts) != 1 {
		t.Errorf("after remove, expected 1 host, got %v", hosts)
	}
	if err := DeleteResourceMapping(ctx, c, "gpu-a100"); err != nil {
		t.Fatalf("DeleteResourceMapping: %v", err)
	}
	if all, _ := ListResourceMappings(ctx, c); len(all) != 0 {
		t.Errorf("after delete, expected 0 mappings, got %d", len(all))
	}
}
