package corrosion

import (
	"context"
	"strings"
	"testing"
)

func TestInsertAndGetVM(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	vm := VMRecord{
		Name:      "test-vm",
		StackName: "mystack",
		HostName:  "host1",
		Spec:      `{"image":"ubuntu"}`,
		State:     "running",
		CPUActual: 2,
		MemActual: 1024,
	}
	if err := InsertVM(ctx, c, vm, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	got, err := GetVM(ctx, c, "test-vm")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got == nil {
		t.Fatal("GetVM returned nil")
	}
	if got.Name != "test-vm" || got.StackName != "mystack" || got.CPUActual != 2 {
		t.Errorf("unexpected VM: %+v", got)
	}
}

func TestInsertVM_WithInterfaces(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	vm := VMRecord{Name: "vm-net", HostName: "h1", Spec: "{}", State: "running"}
	ifaces := []InterfaceRecord{
		{VMName: "vm-net", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:cc"},
		{VMName: "vm-net", NetworkName: "mgmt", Ordinal: 1, MAC: "52:54:00:aa:bb:dd"},
	}
	if err := InsertVM(ctx, c, vm, ifaces, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	got, err := GetVMInterfaces(ctx, c, "vm-net")
	if err != nil {
		t.Fatalf("GetVMInterfaces: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(got))
	}
	if got[0].NetworkName != "default" || got[1].NetworkName != "mgmt" {
		t.Errorf("unexpected interface order: %+v", got)
	}
}

func TestInsertVM_WithDisks(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	vm := VMRecord{Name: "vm-disk", HostName: "h1", Spec: "{}", State: "creating"}
	disks := []DiskRecord{
		{VMName: "vm-disk", DiskName: "root", HostName: "h1", Path: "/var/lib/litevirt/disks/vm-disk-root.qcow2", SizeBytes: 21474836480},
	}
	if err := InsertVM(ctx, c, vm, nil, disks); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	got, err := GetVMDisks(ctx, c, "vm-disk")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(got) != 1 || got[0].DiskName != "root" || got[0].SizeBytes != 21474836480 {
		t.Errorf("unexpected disks: %+v", got)
	}
}

func TestListVMs_Filter(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	for _, rec := range []VMRecord{
		{Name: "s1-web", StackName: "stack1", HostName: "h1", Spec: "{}", State: "running"},
		{Name: "s1-db", StackName: "stack1", HostName: "h2", Spec: "{}", State: "running"},
		{Name: "s2-api", StackName: "stack2", HostName: "h1", Spec: "{}", State: "stopped"},
	} {
		if err := InsertVM(ctx, c, rec, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
	}

	// Filter by stack
	vms, err := ListVMs(ctx, c, "stack1", "")
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(vms) != 2 {
		t.Errorf("expected 2 VMs in stack1, got %d", len(vms))
	}

	// Filter by host
	vms, err = ListVMs(ctx, c, "", "h1")
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(vms) != 2 {
		t.Errorf("expected 2 VMs on h1, got %d", len(vms))
	}
}

func TestUpdateVMState(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	vm := VMRecord{Name: "stateful", HostName: "h1", Spec: "{}", State: "creating"}
	if err := InsertVM(ctx, c, vm, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := UpdateVMState(ctx, c, "stateful", "running", ""); err != nil {
		t.Fatalf("UpdateVMState: %v", err)
	}

	got, _ := GetVM(ctx, c, "stateful")
	if got.State != "running" {
		t.Errorf("expected state running, got %s", got.State)
	}
}

func TestUpdateVMHost_VMs(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	vm := VMRecord{Name: "migratable", HostName: "h1", Spec: "{}", State: "running"}
	if err := InsertVM(ctx, c, vm, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := UpdateVMHost(ctx, c, "migratable", "h2", "running"); err != nil {
		t.Fatalf("UpdateVMHost: %v", err)
	}

	got, _ := GetVM(ctx, c, "migratable")
	if got.HostName != "h2" {
		t.Errorf("expected host h2, got %s", got.HostName)
	}
}

func TestDeleteVM(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	vm := VMRecord{Name: "deletable", HostName: "h1", Spec: "{}", State: "stopped"}
	if err := InsertVM(ctx, c, vm, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := DeleteVM(ctx, c, "deletable"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	got, _ := GetVM(ctx, c, "deletable")
	if got != nil {
		t.Error("expected nil after delete, got record")
	}
}

func TestRenameVM(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	vm := VMRecord{Name: "old-name", HostName: "h1", Spec: `{"cpu":2}`, State: "running"}
	ifaces := []InterfaceRecord{
		{VMName: "old-name", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:cc"},
	}
	disks := []DiskRecord{
		{VMName: "old-name", DiskName: "root", HostName: "h1", Path: "/disks/root.qcow2", SizeBytes: 10737418240, StorageType: "local"},
	}
	if err := InsertVM(ctx, c, vm, ifaces, disks); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := RenameVM(ctx, c, "old-name", "new-name"); err != nil {
		t.Fatalf("RenameVM: %v", err)
	}

	// Old name should not exist
	old, _ := GetVM(ctx, c, "old-name")
	if old != nil {
		t.Error("old name should not exist after rename")
	}

	// New name should exist
	got, err := GetVM(ctx, c, "new-name")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got == nil {
		t.Fatal("GetVM(new-name) returned nil")
	}
	// RenameVM now propagates the new name into the stored spec JSON (so later
	// XML/firmware-path derivation targets the right VM); cpu is preserved.
	if !strings.Contains(got.Spec, `"name":"new-name"`) || !strings.Contains(got.Spec, `"cpu":2`) {
		t.Errorf("Spec = %q after rename, want it to carry name=new-name + cpu=2", got.Spec)
	}

	// Interfaces should be renamed
	gotIfaces, _ := GetVMInterfaces(ctx, c, "new-name")
	if len(gotIfaces) != 1 {
		t.Fatalf("expected 1 interface after rename, got %d", len(gotIfaces))
	}
	if gotIfaces[0].VMName != "new-name" {
		t.Errorf("interface VMName = %q, want new-name", gotIfaces[0].VMName)
	}

	// Disks should be renamed
	gotDisks, _ := GetVMDisks(ctx, c, "new-name")
	if len(gotDisks) != 1 {
		t.Fatalf("expected 1 disk after rename, got %d", len(gotDisks))
	}
	if gotDisks[0].VMName != "new-name" {
		t.Errorf("disk VMName = %q, want new-name", gotDisks[0].VMName)
	}
}

func TestInsertDisk(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Create a VM first
	InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", Spec: "{}", State: "running"}, nil, nil)

	d := DiskRecord{
		VMName:        "vm1",
		DiskName:      "data",
		HostName:      "h1",
		Path:          "/disks/vm1-data.qcow2",
		SizeBytes:     53687091200,
		BackingImage:  "",
		StorageType:   "local",
		StorageVolume: "",
		TargetDev:     "vdb",
	}
	if err := InsertDisk(ctx, c, d); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	disks, err := GetVMDisks(ctx, c, "vm1")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 1 {
		t.Fatalf("expected 1 disk, got %d", len(disks))
	}
	if disks[0].DiskName != "data" {
		t.Errorf("DiskName = %q, want data", disks[0].DiskName)
	}
	if disks[0].TargetDev != "vdb" {
		t.Errorf("TargetDev = %q, want vdb", disks[0].TargetDev)
	}
	if disks[0].SizeBytes != 53687091200 {
		t.Errorf("SizeBytes = %d, want 53687091200", disks[0].SizeBytes)
	}
}

func TestSoftDeleteDisk(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", Spec: "{}", State: "running"}, nil, nil)
	InsertDisk(ctx, c, DiskRecord{VMName: "vm1", DiskName: "data1", HostName: "h1", Path: "/disks/d1.qcow2", StorageType: "local", TargetDev: "vdb"})
	InsertDisk(ctx, c, DiskRecord{VMName: "vm1", DiskName: "data2", HostName: "h1", Path: "/disks/d2.qcow2", StorageType: "local", TargetDev: "vdc"})

	if err := SoftDeleteDisk(ctx, c, "vm1", "data1"); err != nil {
		t.Fatalf("SoftDeleteDisk: %v", err)
	}

	disks, _ := GetVMDisks(ctx, c, "vm1")
	if len(disks) != 1 {
		t.Fatalf("expected 1 disk after soft delete, got %d", len(disks))
	}
	if disks[0].DiskName != "data2" {
		t.Errorf("remaining disk = %q, want data2", disks[0].DiskName)
	}
}

func TestListDisks(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", Spec: "{}", State: "running"}, nil, nil)
	InsertDisk(ctx, c, DiskRecord{VMName: "vm1", DiskName: "root", HostName: "h1", Path: "/disks/root.qcow2", StorageType: "local"})
	InsertDisk(ctx, c, DiskRecord{VMName: "vm1", DiskName: "data", HostName: "h1", Path: "/disks/data.qcow2", StorageType: "local"})

	disks, err := ListDisks(ctx, c, "vm1")
	if err != nil {
		t.Fatalf("ListDisks: %v", err)
	}
	if len(disks) != 2 {
		t.Errorf("expected 2 disks, got %d", len(disks))
	}
}

func TestInsertInterface(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", Spec: "{}", State: "running"}, nil, nil)

	iface := InterfaceRecord{
		VMName:      "vm1",
		NetworkName: "mgmt",
		Ordinal:     1,
		MAC:         "52:54:00:11:22:33",
		IP:          "10.0.1.5",
		TapDevice:   "tap-vm1-1",
	}
	if err := InsertInterface(ctx, c, iface); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}

	ifaces, err := GetVMInterfaces(ctx, c, "vm1")
	if err != nil {
		t.Fatalf("GetVMInterfaces: %v", err)
	}
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface, got %d", len(ifaces))
	}
	if ifaces[0].NetworkName != "mgmt" {
		t.Errorf("NetworkName = %q, want mgmt", ifaces[0].NetworkName)
	}
	if ifaces[0].MAC != "52:54:00:11:22:33" {
		t.Errorf("MAC = %q", ifaces[0].MAC)
	}
	if ifaces[0].IP != "10.0.1.5" {
		t.Errorf("IP = %q, want 10.0.1.5", ifaces[0].IP)
	}
	if ifaces[0].TapDevice != "tap-vm1-1" {
		t.Errorf("TapDevice = %q, want tap-vm1-1", ifaces[0].TapDevice)
	}
}

func TestSoftDeleteInterfaceByMAC(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "h1", Spec: "{}", State: "running"}, nil, nil)
	InsertInterface(ctx, c, InterfaceRecord{VMName: "vm1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:cc"})
	InsertInterface(ctx, c, InterfaceRecord{VMName: "vm1", NetworkName: "mgmt", Ordinal: 1, MAC: "52:54:00:dd:ee:ff"})

	if err := SoftDeleteInterfaceByMAC(ctx, c, "vm1", "52:54:00:aa:bb:cc"); err != nil {
		t.Fatalf("SoftDeleteInterfaceByMAC: %v", err)
	}

	ifaces, _ := GetVMInterfaces(ctx, c, "vm1")
	if len(ifaces) != 1 {
		t.Fatalf("expected 1 interface after soft delete, got %d", len(ifaces))
	}
	if ifaces[0].MAC != "52:54:00:dd:ee:ff" {
		t.Errorf("remaining interface MAC = %q, want 52:54:00:dd:ee:ff", ifaces[0].MAC)
	}
}

func TestGetVMInterfaces_Empty(t *testing.T) {
	c := testClient(t)

	ifaces, err := GetVMInterfaces(context.Background(), c, "nonexistent")
	if err != nil {
		t.Fatalf("GetVMInterfaces: %v", err)
	}
	if len(ifaces) != 0 {
		t.Errorf("expected 0 interfaces, got %d", len(ifaces))
	}
}

func TestGetVMDisks_Empty(t *testing.T) {
	c := testClient(t)

	disks, err := GetVMDisks(context.Background(), c, "nonexistent")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 0 {
		t.Errorf("expected 0 disks, got %d", len(disks))
	}
}

func TestUpdateDiskHostAndPath(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	vm := VMRecord{Name: "vm-migrate", HostName: "host-a", Spec: "{}", State: "running"}
	disks := []DiskRecord{
		{VMName: "vm-migrate", DiskName: "root", HostName: "host-a", Path: "/old/root.qcow2", SizeBytes: 10737418240, StorageType: "local"},
		{VMName: "vm-migrate", DiskName: "data", HostName: "host-a", Path: "/old/data.qcow2", SizeBytes: 53687091200, StorageType: "local"},
	}
	if err := InsertVM(ctx, c, vm, nil, disks); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Update only the root disk to a new host and path
	if err := UpdateDiskHostAndPath(ctx, c, "vm-migrate", "root", "host-b", "/new/root.qcow2"); err != nil {
		t.Fatalf("UpdateDiskHostAndPath: %v", err)
	}

	got, err := GetVMDisks(ctx, c, "vm-migrate")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 disks, got %d", len(got))
	}

	// Build a map for easy lookup
	byName := make(map[string]DiskRecord, len(got))
	for _, d := range got {
		byName[d.DiskName] = d
	}

	// Root disk should be updated
	root := byName["root"]
	if root.HostName != "host-b" {
		t.Errorf("root HostName = %q, want host-b", root.HostName)
	}
	if root.Path != "/new/root.qcow2" {
		t.Errorf("root Path = %q, want /new/root.qcow2", root.Path)
	}

	// Data disk should be unchanged
	data := byName["data"]
	if data.HostName != "host-a" {
		t.Errorf("data HostName = %q, want host-a", data.HostName)
	}
	if data.Path != "/old/data.qcow2" {
		t.Errorf("data Path = %q, want /old/data.qcow2", data.Path)
	}
}

func TestUpdateDiskHostAndPath_SoftDeleted(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	vm := VMRecord{Name: "vm-del-disk", HostName: "host-a", Spec: "{}", State: "running"}
	disks := []DiskRecord{
		{VMName: "vm-del-disk", DiskName: "root", HostName: "host-a", Path: "/old/root.qcow2", SizeBytes: 10737418240, StorageType: "local"},
	}
	if err := InsertVM(ctx, c, vm, nil, disks); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Soft-delete the disk
	if err := SoftDeleteDisk(ctx, c, "vm-del-disk", "root"); err != nil {
		t.Fatalf("SoftDeleteDisk: %v", err)
	}

	// Attempt to update the soft-deleted disk
	if err := UpdateDiskHostAndPath(ctx, c, "vm-del-disk", "root", "host-b", "/new/root.qcow2"); err != nil {
		t.Fatalf("UpdateDiskHostAndPath: %v", err)
	}

	// GetVMDisks filters out deleted disks, so should return 0
	got, err := GetVMDisks(ctx, c, "vm-del-disk")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 disks (soft-deleted), got %d", len(got))
	}

	// Verify the disk was NOT updated by querying directly (including deleted records)
	rows, err := c.Query(ctx,
		`SELECT host_name, path FROM vm_disks WHERE vm_name = ? AND disk_name = ?`,
		"vm-del-disk", "root")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 raw row, got %d", len(rows))
	}
	if rows[0].String("host_name") != "host-a" {
		t.Errorf("soft-deleted disk host_name = %q, want host-a (should not have been updated)", rows[0].String("host_name"))
	}
	if rows[0].String("path") != "/old/root.qcow2" {
		t.Errorf("soft-deleted disk path = %q, want /old/root.qcow2 (should not have been updated)", rows[0].String("path"))
	}
}

func TestUpdateDiskHostAndPath_NonexistentDisk(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	vm := VMRecord{Name: "vm-nodisk", HostName: "host-a", Spec: "{}", State: "running"}
	if err := InsertVM(ctx, c, vm, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Update a disk that doesn't exist — should not error
	if err := UpdateDiskHostAndPath(ctx, c, "vm-nodisk", "nonexistent", "host-b", "/new/path.qcow2"); err != nil {
		t.Fatalf("UpdateDiskHostAndPath: %v", err)
	}

	// Verify no disks were created or affected
	got, err := GetVMDisks(ctx, c, "vm-nodisk")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected 0 disks, got %d", len(got))
	}
}

func TestDeleteVM_WithInterfacesAndDisks(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	vm := VMRecord{Name: "vm-full", HostName: "h1", Spec: "{}", State: "running"}
	ifaces := []InterfaceRecord{
		{VMName: "vm-full", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:01:02:03"},
	}
	disks := []DiskRecord{
		{VMName: "vm-full", DiskName: "root", HostName: "h1", Path: "/disks/root.qcow2", StorageType: "local"},
	}
	InsertVM(ctx, c, vm, ifaces, disks)

	if err := DeleteVM(ctx, c, "vm-full"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	// VM should be gone
	got, _ := GetVM(ctx, c, "vm-full")
	if got != nil {
		t.Error("VM should be nil after delete")
	}

	// Interfaces should be tombstoned
	gotIfaces, _ := GetVMInterfaces(ctx, c, "vm-full")
	if len(gotIfaces) != 0 {
		t.Errorf("expected 0 interfaces after delete, got %d", len(gotIfaces))
	}

	// Disks should be tombstoned
	gotDisks, _ := GetVMDisks(ctx, c, "vm-full")
	if len(gotDisks) != 0 {
		t.Errorf("expected 0 disks after delete, got %d", len(gotDisks))
	}
}

func TestUpdateVMInterfaceIP(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	vm := VMRecord{Name: "vm-ip", HostName: "h1", Spec: "{}", State: "running"}
	ifaces := []InterfaceRecord{
		{VMName: "vm-ip", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:01:02:03"},
	}
	if err := InsertVM(ctx, c, vm, ifaces, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := UpdateVMInterfaceIP(ctx, c, "vm-ip", "default", "10.0.0.5"); err != nil {
		t.Fatalf("UpdateVMInterfaceIP: %v", err)
	}

	got, _ := GetVMInterfaces(ctx, c, "vm-ip")
	if len(got) != 1 || got[0].IP != "10.0.0.5" {
		t.Errorf("unexpected IP: %+v", got)
	}
}
