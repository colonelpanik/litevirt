package corrosion

import (
	"context"
	"testing"
)

func TestDumpState_Empty(t *testing.T) {
	c := testClient(t)

	data := c.dumpState()
	// Empty DB should still produce a valid (possibly small) gzipped payload
	// since no tables have data, the payload should contain an empty tables list
	if len(data) == 0 {
		t.Error("dumpState should return non-nil gzipped data even for empty DB")
	}
}

func TestDumpAndMergeState(t *testing.T) {
	// Create source client with data
	src := testClient(t)
	ctx := context.Background()

	// Insert some data into the source
	InsertHost(ctx, src, HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "abc",
	})
	InsertImage(ctx, src, ImageRecord{
		Name: "ubuntu", Format: "qcow2", SizeBytes: 1000,
	})
	InsertVM(ctx, src, VMRecord{
		Name: "vm1", HostName: "node1", Spec: "{}", State: "running",
	}, nil, nil)

	// Dump the source state
	data := src.dumpState()
	if len(data) == 0 {
		t.Fatal("dumpState returned empty data")
	}

	// Create a destination client and merge
	dst := testClient(t)

	dst.MergeStateBytesLWW(data)

	// Verify data was merged
	host, err := GetHost(ctx, dst, "node1")
	if err != nil {
		t.Fatalf("GetHost after merge: %v", err)
	}
	if host == nil {
		t.Fatal("host should exist after merge")
	}
	if host.Address != "10.0.0.1" {
		t.Errorf("host address = %q, want 10.0.0.1", host.Address)
	}

	img, err := GetImage(ctx, dst, "ubuntu")
	if err != nil {
		t.Fatalf("GetImage after merge: %v", err)
	}
	if img == nil {
		t.Fatal("image should exist after merge")
	}
	if img.Format != "qcow2" {
		t.Errorf("image format = %q, want qcow2", img.Format)
	}

	vm, err := GetVM(ctx, dst, "vm1")
	if err != nil {
		t.Fatalf("GetVM after merge: %v", err)
	}
	if vm == nil {
		t.Fatal("VM should exist after merge")
	}
	if vm.State != "running" {
		t.Errorf("VM state = %q, want running", vm.State)
	}
}

func TestMergeState_EmptyPayload(t *testing.T) {
	c := testClient(t)

	// Should not panic with empty buffer
	c.MergeStateBytesLWW(nil)
	c.MergeStateBytesLWW([]byte{})
}

func TestDumpState_WithMultipleTables(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Populate multiple tables
	InsertHost(ctx, c, HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "a",
	})
	InsertHost(ctx, c, HostRecord{
		Name: "node2", Address: "10.0.0.2", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "b",
	})
	InsertImage(ctx, c, ImageRecord{Name: "img1", Format: "qcow2"})
	InsertVM(ctx, c, VMRecord{
		Name: "vm1", HostName: "node1", Spec: "{}", State: "running",
	}, []InterfaceRecord{
		{VMName: "vm1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:cc"},
	}, []DiskRecord{
		{VMName: "vm1", DiskName: "root", HostName: "node1", Path: "/disks/vm1-root.qcow2",
			SizeBytes: 10737418240, StorageType: "local"},
	})
	InsertAuditLog(ctx, c, AuditRecord{
		ID: "a1", Username: "admin", Action: "create_vm", Target: "vm1", Result: "success",
	})

	data := c.dumpState()
	if len(data) == 0 {
		t.Fatal("dumpState returned empty data")
	}

	// Merge into a new client and verify all data is present
	dst := testClient(t)
	dst.MergeStateBytesLWW(data)

	hosts, _ := ListHosts(ctx, dst)
	if len(hosts) != 2 {
		t.Errorf("expected 2 hosts after merge, got %d", len(hosts))
	}

	images, _ := ListImages(ctx, dst)
	if len(images) != 1 {
		t.Errorf("expected 1 image after merge, got %d", len(images))
	}

	vms, _ := ListVMs(ctx, dst, "", "")
	if len(vms) != 1 {
		t.Errorf("expected 1 VM after merge, got %d", len(vms))
	}

	ifaces, _ := GetVMInterfaces(ctx, dst, "vm1")
	if len(ifaces) != 1 {
		t.Errorf("expected 1 interface after merge, got %d", len(ifaces))
	}

	disks, _ := GetVMDisks(ctx, dst, "vm1")
	if len(disks) != 1 {
		t.Errorf("expected 1 disk after merge, got %d", len(disks))
	}
}

func TestMergeState_InvalidGzip(t *testing.T) {
	c := testClient(t)

	// Should not panic with invalid gzip data
	c.MergeStateBytesLWW([]byte("not gzipped data"))
}

func TestDumpState_RoundTrip(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertHost(ctx, c, HostRecord{
		Name: "h1", Address: "10.0.0.1", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "x",
	})

	// Dump, then merge back into the same client (idempotent)
	data := c.dumpState()
	c.MergeStateBytesLWW(data)

	hosts, _ := ListHosts(ctx, c)
	if len(hosts) != 1 {
		t.Errorf("expected 1 host after round-trip, got %d", len(hosts))
	}
}
