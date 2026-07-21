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

// TestInsertVMWithHardware_WritesNICsAndPCIIntents covers task 7.1: the extended
// writer must land vm_nics + vm_pci_intent rows in the SAME atomic batch as the
// vms/vm_interfaces row, and — when the caller passes adopt=true (the CreateVM
// path, which has just recorded this VM's complete hardware) — stamp
// hardware_adoption_state = "adopted" so a freshly created VM never needs the
// Phase-6 backfill to run for it.
func TestInsertVMWithHardware_WritesNICsAndPCIIntents(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	vm := VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "running"}
	nics := []NICRecord{
		{VMName: "vm1", ID: DeterministicNICID("vm1", "52:54:00:aa:bb:cc"), NetworkName: "lan0",
			Model: "virtio", MAC: "52:54:00:aa:bb:cc", Ordinal: 0, IP: "10.0.0.5"},
	}
	excl := "0000:41:00.0"
	intents := []PCIIntentRecord{
		{VMName: "vm1", DeviceID: DeterministicPCIIntentID("gpu", 0), HostName: "node-a",
			SelectorKind: "address", SelectorPayload: `{"address":"0000:41:00.0"}`, ExclusiveKey: &excl},
	}

	if err := InsertVMWithHardware(ctx, c, vm, nil, nil, nics, intents, true); err != nil {
		t.Fatalf("InsertVMWithHardware: %v", err)
	}

	gotNICs, err := GetVMNICsRaw(ctx, c, "vm_nics", "vm1")
	if err != nil {
		t.Fatalf("GetVMNICsRaw: %v", err)
	}
	if len(gotNICs) != 1 || gotNICs[0].MAC != "52:54:00:aa:bb:cc" || gotNICs[0].NetworkName != "lan0" {
		t.Fatalf("unexpected vm_nics rows: %+v", gotNICs)
	}

	gotIntents, err := ListVMPCIIntents(ctx, c, "vm1")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(gotIntents) != 1 || gotIntents[0].SelectorKind != "address" || gotIntents[0].ExclusiveKey == nil || *gotIntents[0].ExclusiveKey != excl {
		t.Fatalf("unexpected vm_pci_intent rows: %+v", gotIntents)
	}

	state, errReason, err := GetHardwareAdoptionState(ctx, c, "vm1")
	if err != nil {
		t.Fatalf("GetHardwareAdoptionState: %v", err)
	}
	if state != "adopted" {
		t.Errorf("adoption state = %q, want adopted", state)
	}
	if errReason != "" {
		t.Errorf("adoption error = %q, want empty", errReason)
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

// TestRenameVM_CarriesHardwareTables covers the v42 tables RenameVM must also
// carry: vm_nics (id RE-DERIVES under the new name — DeterministicNICID takes
// vmName), vm_pci_intent and vm_pci_realizations (device_id is name-independent
// and must be PRESERVED, only vm_name rekeyed). Nothing must remain live under
// the old name.
func TestRenameVM_CarriesHardwareTables(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	oldName, newName := "old-name", "new-name"
	mac := "52:54:00:aa:bb:cc"
	addr := "0000:41:00.0"
	exclusiveKey := addr
	deviceID := DeterministicPCIIntentID("address|"+addr, 0)

	vm := VMRecord{Name: oldName, HostName: "h1", Spec: "{}", State: "running"}
	nics := []NICRecord{{VMName: oldName, ID: DeterministicNICID(oldName, mac), NetworkName: "default", MAC: mac, Ordinal: 0}}
	pciIntents := []PCIIntentRecord{{
		VMName: oldName, DeviceID: deviceID, HostName: "h1",
		SelectorKind: "address", SelectorPayload: "{}", ExclusiveKey: &exclusiveKey,
	}}
	if err := InsertVMWithHardware(ctx, c, vm, nil, nil, nics, pciIntents, true); err != nil {
		t.Fatalf("InsertVMWithHardware: %v", err)
	}
	realization := PCIRealizationRecord{
		VMName: oldName, DeviceID: deviceID, MemberID: "m0",
		HostName: "h1", ResolvedAddress: addr, XMLAlias: "hostdev0", Ordinal: 0,
	}
	if err := UpsertPCIRealization(ctx, c, realization); err != nil {
		t.Fatalf("UpsertPCIRealization: %v", err)
	}

	if err := RenameVM(ctx, c, oldName, newName); err != nil {
		t.Fatalf("RenameVM: %v", err)
	}

	// vm_nics: id RE-DERIVES under the new name; nothing live under old.
	newNICs, err := GetVMNICsRaw(ctx, c, "vm_nics", newName)
	if err != nil {
		t.Fatalf("GetVMNICsRaw(new): %v", err)
	}
	var liveNew []NICRecord
	for _, n := range newNICs {
		if n.DeletedAt == "" {
			liveNew = append(liveNew, n)
		}
	}
	if len(liveNew) != 1 {
		t.Fatalf("got %d live vm_nics rows under new name, want 1: %+v", len(liveNew), liveNew)
	}
	if wantID := DeterministicNICID(newName, mac); liveNew[0].ID != wantID {
		t.Errorf("nic id = %q, want re-derived %q", liveNew[0].ID, wantID)
	}
	oldNICs, _ := GetVMNICsRaw(ctx, c, "vm_nics", oldName)
	for _, n := range oldNICs {
		if n.DeletedAt == "" {
			t.Errorf("live vm_nics row still under old name: %+v", n)
		}
	}

	// vm_pci_intent: device_id PRESERVED (name-independent); nothing under old.
	newIntents, err := ListVMPCIIntents(ctx, c, newName)
	if err != nil {
		t.Fatalf("ListVMPCIIntents(new): %v", err)
	}
	if len(newIntents) != 1 {
		t.Fatalf("got %d vm_pci_intent rows under new name, want 1: %+v", len(newIntents), newIntents)
	}
	if newIntents[0].DeviceID != deviceID {
		t.Errorf("device_id = %q, want preserved %q", newIntents[0].DeviceID, deviceID)
	}
	oldIntents, _ := ListVMPCIIntents(ctx, c, oldName)
	if len(oldIntents) != 0 {
		t.Errorf("vm_pci_intent rows still live under old name: %+v", oldIntents)
	}

	// vm_pci_realizations: device_id/member_id/xml_alias/resolved_address/ordinal preserved.
	newRealizations, err := ListVMPCIRealizations(ctx, c, newName)
	if err != nil {
		t.Fatalf("ListVMPCIRealizations(new): %v", err)
	}
	if len(newRealizations) != 1 {
		t.Fatalf("got %d vm_pci_realizations rows under new name, want 1: %+v", len(newRealizations), newRealizations)
	}
	if gotR := newRealizations[0]; gotR.DeviceID != realization.DeviceID || gotR.MemberID != realization.MemberID ||
		gotR.XMLAlias != realization.XMLAlias || gotR.ResolvedAddress != realization.ResolvedAddress ||
		gotR.Ordinal != realization.Ordinal {
		t.Errorf("realization = %+v, want fields preserved from %+v", gotR, realization)
	}
	oldRealizations, _ := ListVMPCIRealizations(ctx, c, oldName)
	if len(oldRealizations) != 0 {
		t.Errorf("vm_pci_realizations rows still live under old name: %+v", oldRealizations)
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

// TestDeleteVM_TombstonesHardwareTables covers the v42 tables DeleteVM must
// also tombstone: vm_nics, vm_pci_intent, vm_pci_realizations. It also proves
// the concrete-address exclusive reservation is FREED once the intent is
// tombstoned (PCIIntentExclusiveOwner filters deleted_at IS NULL), so another
// VM could subsequently intend the same host BDF.
func TestDeleteVM_TombstonesHardwareTables(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	name := "vm-hw"
	mac := "52:54:00:aa:bb:dd"
	addr := "0000:51:00.0"
	exclusiveKey := addr
	deviceID := DeterministicPCIIntentID("address|"+addr, 0)

	vm := VMRecord{Name: name, HostName: "h1", Spec: "{}", State: "running"}
	nics := []NICRecord{{VMName: name, ID: DeterministicNICID(name, mac), NetworkName: "default", MAC: mac, Ordinal: 0}}
	pciIntents := []PCIIntentRecord{{
		VMName: name, DeviceID: deviceID, HostName: "h1",
		SelectorKind: "address", SelectorPayload: "{}", ExclusiveKey: &exclusiveKey,
	}}
	if err := InsertVMWithHardware(ctx, c, vm, nil, nil, nics, pciIntents, true); err != nil {
		t.Fatalf("InsertVMWithHardware: %v", err)
	}
	realization := PCIRealizationRecord{
		VMName: name, DeviceID: deviceID, MemberID: "m0",
		HostName: "h1", ResolvedAddress: addr, XMLAlias: "hostdev0", Ordinal: 0,
	}
	if err := UpsertPCIRealization(ctx, c, realization); err != nil {
		t.Fatalf("UpsertPCIRealization: %v", err)
	}

	// Reservation held before delete.
	owner, err := PCIIntentExclusiveOwner(ctx, c, "h1", addr)
	if err != nil {
		t.Fatalf("PCIIntentExclusiveOwner (pre): %v", err)
	}
	if owner != name {
		t.Fatalf("PCIIntentExclusiveOwner (pre) = %q, want %q", owner, name)
	}

	if err := DeleteVM(ctx, c, name); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	nicsRows, err := GetVMNICsRaw(ctx, c, "vm_nics", name)
	if err != nil {
		t.Fatalf("GetVMNICsRaw: %v", err)
	}
	if len(nicsRows) != 1 || nicsRows[0].DeletedAt == "" {
		t.Fatalf("vm_nics row not tombstoned: %+v", nicsRows)
	}

	intentRows, err := c.Query(ctx, `SELECT device_id, deleted_at FROM vm_pci_intent WHERE vm_name = ?`, name)
	if err != nil {
		t.Fatalf("query vm_pci_intent: %v", err)
	}
	if len(intentRows) != 1 || intentRows[0].String("deleted_at") == "" {
		t.Fatalf("vm_pci_intent row not tombstoned: %+v", intentRows)
	}

	realizationRows, err := c.Query(ctx, `SELECT device_id, member_id, deleted_at FROM vm_pci_realizations WHERE vm_name = ?`, name)
	if err != nil {
		t.Fatalf("query vm_pci_realizations: %v", err)
	}
	if len(realizationRows) != 1 || realizationRows[0].String("deleted_at") == "" {
		t.Fatalf("vm_pci_realizations row not tombstoned: %+v", realizationRows)
	}

	// Reservation freed: another VM could now intend the same host BDF.
	owner, err = PCIIntentExclusiveOwner(ctx, c, "h1", addr)
	if err != nil {
		t.Fatalf("PCIIntentExclusiveOwner (post): %v", err)
	}
	if owner != "" {
		t.Errorf("PCIIntentExclusiveOwner (post) = %q, want \"\" (reservation freed)", owner)
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

// TestInsertDisk_HardwareColumns covers the v42 hardware-foundation columns
// (bus, device_kind, delete_with_vm, controller_model) round-tripping through
// InsertDisk/GetVMDisks.
func TestInsertDisk_HardwareColumns(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertVM(ctx, c, VMRecord{Name: "vm-hw", HostName: "h1", Spec: "{}", State: "running"}, nil, nil)

	d := DiskRecord{
		VMName:          "vm-hw",
		DiskName:        "data",
		HostName:        "h1",
		Path:            "/disks/vm-hw-data.qcow2",
		SizeBytes:       10737418240,
		StorageType:     "local",
		TargetDev:       "sda",
		Bus:             "scsi",
		DeviceKind:      "disk",
		DeleteWithVM:    true,
		ControllerModel: "virtio-scsi",
	}
	if err := InsertDisk(ctx, c, d); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	disks, err := GetVMDisks(ctx, c, "vm-hw")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 1 {
		t.Fatalf("expected 1 disk, got %d", len(disks))
	}
	got := disks[0]
	if got.Bus != "scsi" {
		t.Errorf("Bus = %q, want scsi", got.Bus)
	}
	if got.DeviceKind != "disk" {
		t.Errorf("DeviceKind = %q, want disk", got.DeviceKind)
	}
	if !got.DeleteWithVM {
		t.Errorf("DeleteWithVM = false, want true")
	}
	if got.ControllerModel != "virtio-scsi" {
		t.Errorf("ControllerModel = %q, want virtio-scsi", got.ControllerModel)
	}
}

// TestInsertDisk_HardwareColumnDefaults covers a caller that doesn't set the
// new fields: DeviceKind must still land as 'disk' (the column default),
// matching existing create-time callers until Phase 7 updates them.
func TestInsertDisk_HardwareColumnDefaults(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertVM(ctx, c, VMRecord{Name: "vm-hw-default", HostName: "h1", Spec: "{}", State: "running"}, nil, nil)

	if err := InsertDisk(ctx, c, DiskRecord{
		VMName:      "vm-hw-default",
		DiskName:    "root",
		HostName:    "h1",
		Path:        "/disks/vm-hw-default-root.qcow2",
		StorageType: "local",
		TargetDev:   "vda",
	}); err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	disks, err := GetVMDisks(ctx, c, "vm-hw-default")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 1 {
		t.Fatalf("expected 1 disk, got %d", len(disks))
	}
	if disks[0].DeviceKind != "disk" {
		t.Errorf("DeviceKind = %q, want disk (default)", disks[0].DeviceKind)
	}
}

// TestHardwareAdoptionState covers the vms.hardware_adoption_state/
// hardware_adoption_error accessors added for the hardware-foundation work.
func TestHardwareAdoptionState(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertVM(ctx, c, VMRecord{Name: "vm-adopt", HostName: "h1", Spec: "{}", State: "running"}, nil, nil)

	// The bare InsertVM wrapper calls InsertVMWithHardware with adopt=false: it
	// carries no hardware (nil NICs/PCI intents), and its producer-path callers
	// (Clone/import/promote/live-restore) may have written REAL vm_interfaces
	// rows outside this call, so it must NOT claim 'adopted' — the column stays
	// at its schema default 'pending' for the Phase-6 backfill audit to
	// reconcile.
	state, errReason, err := GetHardwareAdoptionState(ctx, c, "vm-adopt")
	if err != nil {
		t.Fatalf("GetHardwareAdoptionState: %v", err)
	}
	if state != "pending" {
		t.Errorf("initial state = %q, want pending", state)
	}
	if errReason != "" {
		t.Errorf("initial errReason = %q, want empty", errReason)
	}

	if err := SetHardwareAdoptionState(ctx, c, "vm-adopt", "blocked", "reason"); err != nil {
		t.Fatalf("SetHardwareAdoptionState: %v", err)
	}

	state, errReason, err = GetHardwareAdoptionState(ctx, c, "vm-adopt")
	if err != nil {
		t.Fatalf("GetHardwareAdoptionState: %v", err)
	}
	if state != "blocked" {
		t.Errorf("state = %q, want blocked", state)
	}
	if errReason != "reason" {
		t.Errorf("errReason = %q, want reason", errReason)
	}
}

// TestInsertVMWithHardware_AdoptFalseLeavesPending is the Fix 1 regression: a
// caller that passes adopt=false must NOT get the 'adopted' stamp even when it
// also supplies hardware rows — only the primary create path (adopt=true) may
// claim adoption. This guards against a future edit accidentally gating on
// "hardware present" instead of the explicit adopt flag.
func TestInsertVMWithHardware_AdoptFalseLeavesPending(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	vm := VMRecord{Name: "vm-noadopt", HostName: "node-a", Spec: "{}", State: "running"}
	nics := []NICRecord{
		{VMName: "vm-noadopt", ID: DeterministicNICID("vm-noadopt", "52:54:00:aa:bb:dd"), NetworkName: "lan0",
			Model: "virtio", MAC: "52:54:00:aa:bb:dd", Ordinal: 0, IP: "10.0.0.6"},
	}

	if err := InsertVMWithHardware(ctx, c, vm, nil, nil, nics, nil, false); err != nil {
		t.Fatalf("InsertVMWithHardware: %v", err)
	}

	state, errReason, err := GetHardwareAdoptionState(ctx, c, "vm-noadopt")
	if err != nil {
		t.Fatalf("GetHardwareAdoptionState: %v", err)
	}
	if state != "pending" {
		t.Errorf("state = %q, want pending (adopt=false must not stamp adopted)", state)
	}
	if errReason != "" {
		t.Errorf("errReason = %q, want empty", errReason)
	}
}
