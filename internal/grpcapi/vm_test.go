package grpcapi

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// testServerWithLocks returns a Server that has vmLocks and a dataDir, needed
// for operations that call lockVM (StopVM, DeleteVM, etc.).
func testServerWithLocks(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{
		hostName: "test-host",
		dataDir:  t.TempDir(),
		db:       db,
		events:   events.NewBus(),
		vmLocks:  make(map[string]*sync.Mutex),
	}
}

func insertTestVM(t *testing.T, ctx context.Context, db *corrosion.Client, name, host, state string) {
	t.Helper()
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      name,
		HostName:  host,
		State:     state,
		CPUActual: 2,
		MemActual: 4096,
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

func TestCreateVM_NilSpec(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{})
	if err == nil {
		t.Fatal("expected error for nil spec")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestCreateVM_EmptyName(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{}})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

// TestCreateVM_HooksRequireAdmin is the F3 regression: an operator (the floor
// for ordinary VM creation) may NOT define a lifecycle hook, since hooks run as
// root on the target host. An admin may.
func TestCreateVM_HooksRequireAdmin(t *testing.T) {
	s := testServer(t)
	opCtx := context.WithValue(context.Background(), ctxKeyUsername, "op")
	opCtx = context.WithValue(opCtx, ctxKeyRole, "operator")

	specWithHook := &pb.VMSpec{
		Name: "hooked-vm", Cpu: 1, MemoryMib: 512,
		Hooks: &pb.HooksSpec{PreStart: "/bin/touch /tmp/pwned"},
	}
	_, err := s.CreateVM(opCtx, &pb.CreateVMRequest{Spec: specWithHook})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator defining a hook: expected PermissionDenied, got %v", err)
	}

	// An operator WITHOUT hooks gets past the hook gate (fails later for other
	// reasons in this minimal harness, but NOT with PermissionDenied).
	_, err = s.CreateVM(opCtx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "plain-vm", Cpu: 1, MemoryMib: 512}})
	if status.Code(err) == codes.PermissionDenied {
		t.Fatalf("operator creating a hookless VM should not be permission-denied, got %v", err)
	}
}

func TestHooksDefined(t *testing.T) {
	if hooksDefined(nil) {
		t.Error("nil HooksSpec should be undefined")
	}
	if hooksDefined(&pb.HooksSpec{}) {
		t.Error("empty HooksSpec should be undefined")
	}
	if !hooksDefined(&pb.HooksSpec{PostMigrate: "x"}) {
		t.Error("a set hook should be defined")
	}
}

func TestCreateVM_AlreadyExists(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "dup-vm", "test-host", "running")

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{Name: "dup-vm", Cpu: 1, MemoryMib: 512},
	})
	if err == nil {
		t.Fatal("expected error for duplicate VM")
	}
	if c := status.Code(err); c != codes.AlreadyExists {
		t.Errorf("code = %v, want AlreadyExists", c)
	}
}

func TestCreateVM_QuotaThenPlacementLabelsAndAntiAffinity(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()

	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "/acme", Display: "Acme"}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, s.db, corrosion.ProjectQuotaRecord{
		ProjectName: "/acme", VCPULimit: 4, MemMiBLimit: 4096,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	for _, h := range []corrosion.HostRecord{
		{Name: "test-host", Address: "10.0.0.1", State: "active", CPUTotal: 8, MemTotal: 16384},
		{Name: "anti-host", Address: "10.0.0.2", State: "active", CPUTotal: 8, MemTotal: 16384},
		{Name: "wrong-label", Address: "10.0.0.3", State: "active", CPUTotal: 8, MemTotal: 16384},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	for host, tier := range map[string]string{"test-host": "gold", "anti-host": "gold", "wrong-label": "silver"} {
		if err := corrosion.SetHostLabel(ctx, s.db, host, "tier", tier); err != nil {
			t.Fatalf("SetHostLabel %s: %v", host, err)
		}
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "db", HostName: "anti-host", State: "running", CPUActual: 1, MemActual: 1024,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM db: %v", err)
	}

	resp, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name:      "api",
		Project:   "/acme",
		Cpu:       2,
		MemoryMib: 1024,
		Placement: &pb.PlacementSpec{
			Require:      map[string]string{"tier": "gold"},
			AntiAffinity: []string{"db"},
		},
	}})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if resp.HostName != "test-host" {
		t.Errorf("CreateVM host = %q, want test-host", resp.HostName)
	}
	rec, err := corrosion.GetVM(ctx, s.db, "api")
	if err != nil || rec == nil {
		t.Fatalf("GetVM api: %v %v", err, rec)
	}
	if rec.Project != "/acme" || rec.HostName != "test-host" {
		t.Errorf("persisted api = %+v, want project /acme on test-host", rec)
	}

	_, err = s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name:      "api-over-quota",
		Project:   "/acme",
		Cpu:       3,
		MemoryMib: 1024,
		Placement: &pb.PlacementSpec{
			Require:      map[string]string{"tier": "gold"},
			AntiAffinity: []string{"db"},
		},
	}})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over-quota CreateVM: got %v, want ResourceExhausted", err)
	}
	if rec, _ := corrosion.GetVM(ctx, s.db, "api-over-quota"); rec != nil {
		t.Errorf("over-quota VM should not be persisted: %+v", rec)
	}
}

// TestCreateVM_PopulatesHardwareTables is task 7.1's create-path case: a CreateVM
// with one NIC and one PCI device must land vm_nics + vm_pci_intent rows — dual-
// written alongside the legacy vm_interfaces row, not instead of it — and mark the
// VM's hardware-adoption state "adopted", all from the SAME call that creates it
// (no Phase-6 backfill needed for a VM created this way).
func TestCreateVM_PopulatesHardwareTables(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()

	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.1", State: "active", CPUTotal: 8, MemTotal: 16384,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	resp, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name:      "vm1",
		Cpu:       1,
		MemoryMib: 512,
		Placement: &pb.PlacementSpec{Host: "test-host"},
		Network:   []*pb.NetworkAttachment{{Name: "lo", Model: "virtio"}},
		Devices:   []*pb.DeviceSpec{{Address: "0000:41:00.0"}},
	}})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if resp.Name != "vm1" {
		t.Fatalf("CreateVM resp.Name = %q, want vm1", resp.Name)
	}

	// Dual-write: the legacy vm_interfaces row is still there.
	ifaces, err := corrosion.GetVMInterfaces(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("GetVMInterfaces: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].NetworkName != "lo" {
		t.Fatalf("vm_interfaces (dual-write) = %+v, want 1 row on lo", ifaces)
	}

	nics, err := corrosion.GetVMNICsRaw(ctx, s.db, "vm_nics", "vm1")
	if err != nil {
		t.Fatalf("GetVMNICsRaw: %v", err)
	}
	if len(nics) != 1 || nics[0].NetworkName != "lo" || nics[0].MAC != ifaces[0].MAC {
		t.Fatalf("vm_nics = %+v, want 1 row on lo matching the vm_interfaces MAC %q", nics, ifaces[0].MAC)
	}
	if nics[0].TapDevice != "" {
		t.Errorf("vm_nics[0].TapDevice = %q, want empty at create (assigned at start, not create)", nics[0].TapDevice)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 1 || intents[0].SelectorKind != "address" {
		t.Fatalf("vm_pci_intent = %+v, want 1 address-kind row", intents)
	}
	if intents[0].ExclusiveKey == nil || *intents[0].ExclusiveKey != "0000:41:00.0" {
		t.Errorf("vm_pci_intent[0].ExclusiveKey = %v, want 0000:41:00.0", intents[0].ExclusiveKey)
	}

	state, reason, err := corrosion.GetHardwareAdoptionState(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("GetHardwareAdoptionState: %v", err)
	}
	if state != "adopted" {
		t.Errorf("adoption state = %q, want adopted", state)
	}
	if reason != "" {
		t.Errorf("adoption error = %q, want empty", reason)
	}
}

// TestCreateVM_PCIIntentCanonicalizesAddress is a convergence-gap regression: a
// device spec carrying a non-canonical concrete BDF (short-form bus, e.g.
// "41:00.0") must still hash its vm_pci_intent.device_id off the CANONICAL BDF
// ("0000:41:00.0") — matching what the Phase-6 backfill derives from libvirt's
// canonicalized XML address (makeAddressedIntent). Without canonicalizing at
// create time, CreateVM and a later backfill pass would derive two different
// device_ids for the same physical device and fork into a divergent duplicate
// vm_pci_intent row.
func TestCreateVM_PCIIntentCanonicalizesAddress(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	ctx := adminCtx()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()

	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "test-host", Address: "10.0.0.1", State: "active", CPUTotal: 8, MemTotal: 16384,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	spec := &pb.VMSpec{
		Name:      "vm1",
		Cpu:       1,
		MemoryMib: 512,
		Placement: &pb.PlacementSpec{Host: "test-host"},
		Devices:   []*pb.DeviceSpec{{Address: "41:00.0"}},
	}
	resp, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: spec})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if resp.Name != "vm1" {
		t.Fatalf("CreateVM resp.Name = %q, want vm1", resp.Name)
	}

	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, "vm1")
	if err != nil {
		t.Fatalf("ListVMPCIIntents: %v", err)
	}
	if len(intents) != 1 {
		t.Fatalf("vm_pci_intent = %+v, want 1 row", intents)
	}

	wantID := corrosion.DeterministicPCIIntentID(
		corrosion.CanonicalPCISelector(&pb.DeviceSpec{Address: "0000:41:00.0"}), 0)
	if intents[0].DeviceID != wantID {
		t.Errorf("vm_pci_intent[0].DeviceID = %q, want %q (id derived from the canonical BDF)",
			intents[0].DeviceID, wantID)
	}

	// The input spec passed to CreateVM must not be mutated by the
	// canonicalization — only a clone used for the intent should change.
	if spec.Devices[0].Address != "41:00.0" {
		t.Errorf("input spec.Devices[0].Address = %q, want unchanged 41:00.0", spec.Devices[0].Address)
	}
}

func TestListVMs_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(resp.Vms) != 0 {
		t.Errorf("expected 0 VMs, got %d", len(resp.Vms))
	}
}

func TestListVMs_FilterByHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "vm-a", "host-1", "running")
	insertTestVM(t, ctx, s.db, "vm-b", "host-2", "stopped")

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{HostName: "host-1"})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(resp.Vms) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(resp.Vms))
	}
	if resp.Vms[0].Name != "vm-a" {
		t.Errorf("Name = %q, want vm-a", resp.Vms[0].Name)
	}
}

func TestListVMs_FilterByStack(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "stack-vm",
		StackName: "mystack",
		HostName:  "h1",
		State:     "running",
	}, nil, nil)
	insertTestVM(t, ctx, s.db, "other-vm", "h1", "running")

	resp, err := s.ListVMs(ctx, &pb.ListVMsRequest{StackName: "mystack"})
	if err != nil {
		t.Fatalf("ListVMs: %v", err)
	}
	if len(resp.Vms) != 1 {
		t.Fatalf("expected 1 VM, got %d", len(resp.Vms))
	}
	if resp.Vms[0].Name != "stack-vm" {
		t.Errorf("Name = %q, want stack-vm", resp.Vms[0].Name)
	}
}

func TestInspectVM_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestInspectVM_Found(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "inspect-me", "other-host", "running")

	vm, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "inspect-me"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if vm.Name != "inspect-me" {
		t.Errorf("Name = %q, want inspect-me", vm.Name)
	}
	if vm.State != pb.VMState_VM_RUNNING {
		t.Errorf("State = %v, want RUNNING", vm.State)
	}
}

// TestInspectVM_ProjectsDisksAndStorageVolume covers Task 4.1's two disk-side
// requirements: pbVM.Disks[i].StorageVolume must come through (previously
// dropped), and pbVM.Spec.Disks must be rebuilt from the authoritative
// vm_disks rows rather than the stale spec blob — including the bus
// resolution fallback chain (vm_disks.Bus -> blob bus by name -> target-dev
// heuristic) since vm_disks.bus is not yet persisted by every writer.
func TestInspectVM_ProjectsDisksAndStorageVolume(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	blob, err := json.Marshal(&pb.VMSpec{
		Disks: []*pb.DiskSpec{
			{Name: "root", Size: "10G", Bus: "scsi"}, // stale: DB below says 20G, no bus yet
		},
	})
	if err != nil {
		t.Fatalf("json.Marshal(spec): %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "disk-proj", HostName: "other-host", State: "running", Spec: string(blob),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// "root": vm_disks.bus is empty (not yet persisted) -> must fall back to
	// the blob's bus for this disk name ("scsi"), not go empty.
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "disk-proj", DiskName: "root", HostName: "other-host",
		Path: "/var/lib/litevirt/disk-proj/root.qcow2", SizeBytes: 20 * 1024 * 1024 * 1024,
		StorageType: "dir", StorageVolume: "pool0/vol1", TargetDev: "vda",
	}); err != nil {
		t.Fatalf("InsertDisk(root): %v", err)
	}
	// "data": vm_disks.bus is empty AND this disk name isn't in the blob at
	// all -> must fall back to the target-dev heuristic (sd* -> scsi).
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "disk-proj", DiskName: "data", HostName: "other-host",
		Path: "/var/lib/litevirt/disk-proj/data.qcow2", SizeBytes: 5 * 1024 * 1024 * 1024,
		StorageType: "dir", StorageVolume: "pool1/vol2", TargetDev: "sdb",
	}); err != nil {
		t.Fatalf("InsertDisk(data): %v", err)
	}

	resp, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "disk-proj"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}

	if len(resp.Disks) != 2 {
		t.Fatalf("Disks = %d, want 2", len(resp.Disks))
	}
	byName := map[string]*pb.VMDisk{}
	for _, d := range resp.Disks {
		byName[d.Name] = d
	}
	if got := byName["root"].StorageVolume; got != "pool0/vol1" {
		t.Errorf("root StorageVolume = %q, want pool0/vol1", got)
	}
	if got := byName["data"].StorageVolume; got != "pool1/vol2" {
		t.Errorf("data StorageVolume = %q, want pool1/vol2", got)
	}

	if resp.Spec == nil {
		t.Fatal("Spec is nil")
	}
	specByName := map[string]*pb.DiskSpec{}
	for _, ds := range resp.Spec.Disks {
		specByName[ds.Name] = ds
	}
	if len(specByName) != 2 {
		t.Fatalf("Spec.Disks = %d, want 2", len(specByName))
	}
	if got := specByName["root"].Size; got != "20G" {
		t.Errorf("root Spec.Disks size = %q, want 20G (vm_disks authoritative, blob's 10G is stale)", got)
	}
	if got := specByName["root"].Bus; got != "scsi" {
		t.Errorf("root Spec.Disks bus = %q, want scsi (fallback to blob bus; vm_disks.bus not persisted)", got)
	}
	if got := specByName["data"].Bus; got != "scsi" {
		t.Errorf("data Spec.Disks bus = %q, want scsi (target-dev heuristic for sdb; not in blob)", got)
	}
}

// TestInspectVM_PreservesSpecDisksOnDiskReadError is the fail-soft
// counterpart to TestInspectVM_ProjectsDisksAndStorageVolume: when the
// vm_disks read itself errors — simulated here by dropping the table via
// the same forced-error idiom used elsewhere in this package (e.g.
// container_failclosed_test.go's `DROP TABLE containers`) — the projection
// must NOT overwrite Spec.Disks with an empty slice. The blob's Disks must
// pass through untouched instead of being blanked by a transient read
// failure.
func TestInspectVM_PreservesSpecDisksOnDiskReadError(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	blob, err := json.Marshal(&pb.VMSpec{
		Disks: []*pb.DiskSpec{{Name: "root", Size: "10G", Bus: "virtio"}},
	})
	if err != nil {
		t.Fatalf("json.Marshal(spec): %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "disk-read-err", HostName: "other-host", State: "running", Spec: string(blob),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Force GetVMDisks to fail: drop the table it queries, AFTER InsertVM
	// (which itself touches vm_disks). The vms table (used by GetVM) is
	// untouched, so InspectVM still finds the VM and reaches the projection.
	if err := s.db.Execute(ctx, `DROP TABLE vm_disks`); err != nil {
		t.Fatalf("DROP TABLE vm_disks: %v", err)
	}

	resp, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "disk-read-err"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if resp.Spec == nil {
		t.Fatal("Spec is nil")
	}
	if len(resp.Spec.Disks) != 1 {
		t.Fatalf("Spec.Disks = %d, want 1 (blob untouched on read error, not blanked)", len(resp.Spec.Disks))
	}
	if got := resp.Spec.Disks[0]; got.Name != "root" || got.Size != "10G" || got.Bus != "virtio" {
		t.Errorf("Spec.Disks[0] = %+v, want blob's root/10G/virtio", got)
	}
}

// TestInspectVM_ProjectsNetworkFromLegacyOverlay covers Task 4.1's network
// requirement in its Phase-4 dormancy state: vm_nics is empty fleet-wide, so
// MergedVMNICs surfaces the legacy vm_interfaces row via its overlay, and
// that overlay result — not the stale spec blob — must be what
// resp.Spec.Network reflects.
func TestInspectVM_ProjectsNetworkFromLegacyOverlay(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	blob, err := json.Marshal(&pb.VMSpec{
		Network: []*pb.NetworkAttachment{{Name: "stale-net", Model: "e1000", Mac: "00:00:00:00:00:00"}},
	})
	if err != nil {
		t.Fatalf("json.Marshal(spec): %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "net-proj", HostName: "other-host", State: "running", Spec: string(blob),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Legacy vm_interfaces row -- vm_nics is empty in this phase (backfill,
	// Task 6.3, hasn't run yet); MergedVMNICs must still surface it.
	if err := corrosion.InsertInterface(ctx, s.db, corrosion.InterfaceRecord{
		VMName: "net-proj", NetworkName: "lan0", Ordinal: 0,
		MAC: "52:54:00:aa:bb:cc", IP: "10.0.0.5",
	}); err != nil {
		t.Fatalf("InsertInterface: %v", err)
	}

	resp, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "net-proj"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if resp.Spec == nil {
		t.Fatal("Spec is nil")
	}
	if len(resp.Spec.Network) != 1 {
		t.Fatalf("Spec.Network = %d, want 1 (overlay result, not the blob)", len(resp.Spec.Network))
	}
	nic := resp.Spec.Network[0]
	if nic.Name != "lan0" || nic.Mac != "52:54:00:aa:bb:cc" {
		t.Errorf("Spec.Network[0] = %+v, want lan0/52:54:00:aa:bb:cc", nic)
	}
	if nic.Model != "virtio" {
		t.Errorf("Spec.Network[0].Model = %q, want virtio (legacy vm_interfaces synthesized default)", nic.Model)
	}
	for _, n := range resp.Spec.Network {
		if n.Name == "stale-net" {
			t.Errorf("stale blob network %q leaked into projected Spec.Network", n.Name)
		}
	}
}

// TestInspectVM_PreservesSpecNetworkOnNICReadError is the fail-soft
// counterpart to TestInspectVM_ProjectsNetworkFromLegacyOverlay: when
// MergedVMNICs itself errors — simulated by dropping vm_nics, which
// GetVMNICsRaw queries before vm_interfaces so the error surfaces without
// needing to also touch the legacy table — the projection must NOT
// overwrite Spec.Network with an empty slice. The blob's Network must pass
// through untouched instead of being blanked by a transient read failure.
func TestInspectVM_PreservesSpecNetworkOnNICReadError(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	blob, err := json.Marshal(&pb.VMSpec{
		Network: []*pb.NetworkAttachment{{Name: "lan0", Model: "e1000", Mac: "52:54:00:aa:bb:cc"}},
	})
	if err != nil {
		t.Fatalf("json.Marshal(spec): %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "net-read-err", HostName: "other-host", State: "running", Spec: string(blob),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Force MergedVMNICs to fail: drop vm_nics. InsertVM doesn't touch
	// vm_nics (only vm_disks/vm_interfaces/vms), so this is safe to do after
	// the insert above; the vms table (used by GetVM) is untouched, so
	// InspectVM still finds the VM and reaches the projection.
	if err := s.db.Execute(ctx, `DROP TABLE vm_nics`); err != nil {
		t.Fatalf("DROP TABLE vm_nics: %v", err)
	}

	resp, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "net-read-err"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if resp.Spec == nil {
		t.Fatal("Spec is nil")
	}
	if len(resp.Spec.Network) != 1 {
		t.Fatalf("Spec.Network = %d, want 1 (blob untouched on read error, not blanked)", len(resp.Spec.Network))
	}
	if got := resp.Spec.Network[0]; got.Name != "lan0" || got.Model != "e1000" || got.Mac != "52:54:00:aa:bb:cc" {
		t.Errorf("Spec.Network[0] = %+v, want blob's lan0/e1000/52:54:00:aa:bb:cc", got)
	}
}

// TestInspectVM_DevicesDormantWithoutPCIIntents is the dormancy guard: Task
// 4.1 runs before Phase 6 populates vm_pci_intent, so the table is empty for
// every VM today. Projecting spec.Devices unconditionally would blank it for
// every VM and break the migration host-compatibility check at
// internal/ui/handle_vms.go (vm.GetSpec().GetDevices()). With zero intent
// rows, the blob's Devices must pass through untouched.
func TestInspectVM_DevicesDormantWithoutPCIIntents(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	blob, err := json.Marshal(&pb.VMSpec{
		Devices: []*pb.DeviceSpec{{Type: "gpu", Vendor: "10de", Count: 1}},
	})
	if err != nil {
		t.Fatalf("json.Marshal(spec): %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "dev-dormant", HostName: "other-host", State: "running", Spec: string(blob),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Deliberately NO vm_pci_intent rows inserted.

	resp, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "dev-dormant"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if resp.Spec == nil {
		t.Fatal("Spec is nil")
	}
	if len(resp.Spec.Devices) != 1 {
		t.Fatalf("Spec.Devices = %d, want 1 (blob untouched; no PCI intents yet)", len(resp.Spec.Devices))
	}
	if got := resp.Spec.Devices[0]; got.Type != "gpu" || got.Vendor != "10de" || got.Count != 1 {
		t.Errorf("Spec.Devices[0] = %+v, want blob's gpu/10de/1", got)
	}
}

// TestInspectVM_ProjectsDevicesFromPCIIntents is the positive counterpart to
// the dormancy guard above: once vm_pci_intent rows exist for a VM (Phase 6+),
// spec.Devices must be rebuilt from them (protojson-decoded selector_payload,
// matching resolveDeviceIntents' decode contract) instead of the stale blob.
func TestInspectVM_ProjectsDevicesFromPCIIntents(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	blob, err := json.Marshal(&pb.VMSpec{
		Devices: []*pb.DeviceSpec{{Type: "stale", Vendor: "0000", Count: 9}},
	})
	if err != nil {
		t.Fatalf("json.Marshal(spec): %v", err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "dev-proj", HostName: "other-host", State: "running", Spec: string(blob),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	payload, err := protojson.Marshal(&pb.DeviceSpec{Type: "gpu", Vendor: "10de", Count: 2})
	if err != nil {
		t.Fatalf("protojson.Marshal: %v", err)
	}
	if err := corrosion.UpsertPCIIntent(ctx, s.db, corrosion.PCIIntentRecord{
		VMName: "dev-proj", DeviceID: "dev0", HostName: "other-host",
		SelectorKind: "type", SelectorPayload: string(payload),
	}); err != nil {
		t.Fatalf("UpsertPCIIntent: %v", err)
	}

	resp, err := s.InspectVM(ctx, &pb.InspectVMRequest{Name: "dev-proj"})
	if err != nil {
		t.Fatalf("InspectVM: %v", err)
	}
	if resp.Spec == nil {
		t.Fatal("Spec is nil")
	}
	if len(resp.Spec.Devices) != 1 {
		t.Fatalf("Spec.Devices = %d, want 1 (projected from vm_pci_intent, blob replaced)", len(resp.Spec.Devices))
	}
	got := resp.Spec.Devices[0]
	if got.Type != "gpu" || got.Vendor != "10de" || got.Count != 2 {
		t.Errorf("Spec.Devices[0] = %+v, want gpu/10de/2 (from intent, not stale blob)", got)
	}
}

func TestStartVM_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestStartVM_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "stopped")

	_, err := s.StartVM(ctx, &pb.StartVMRequest{Name: "remote-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestStopVM_NotFound(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestStopVM_WrongHost(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "remote-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestDeleteVM_NotFound(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestDeleteVM_WrongHost(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "stopped")

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "remote-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestDeleteVM_BackingUp(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "busy-vm", "test-host", "backing-up")

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "busy-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestRestartVM_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.RestartVM(ctx, &pb.RestartVMRequest{Name: "nope"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestRestartVM_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.RestartVM(ctx, &pb.RestartVMRequest{Name: "remote-vm"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestExecVM_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "nope", Command: []string{"ls"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestExecVM_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "remote-vm", Command: []string{"ls"}})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestExecVM_NotRunning(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "stopped-vm", "test-host", "stopped")

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "stopped-vm", Command: []string{"ls"}})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestExecVM_NoCommand(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "exec-vm", "test-host", "running")

	_, err := s.ExecVM(ctx, &pb.ExecVMRequest{Name: "exec-vm", Command: nil})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestSetVMIP_Validation(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Empty name.
	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty name: code = %v, want InvalidArgument", c)
	}

	// Empty IP.
	_, err = s.SetVMIP(ctx, &pb.SetVMIPRequest{Name: "vm1"})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty ip: code = %v, want InvalidArgument", c)
	}

	// VM not found.
	_, err = s.SetVMIP(ctx, &pb.SetVMIPRequest{Name: "nope", Ip: "10.0.0.1"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("not found: code = %v, want NotFound", c)
	}
}

func TestSetBootOrder_Validation(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.SetBootOrder(ctx, &pb.SetBootOrderRequest{})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty name: code = %v, want InvalidArgument", c)
	}

	_, err = s.SetBootOrder(ctx, &pb.SetBootOrderRequest{Name: "vm1"})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty boot_order: code = %v, want InvalidArgument", c)
	}

	_, err = s.SetBootOrder(ctx, &pb.SetBootOrderRequest{Name: "nope", BootOrder: "disk"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("not found: code = %v, want NotFound", c)
	}
}

func TestRebuildVM_Validation(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty name: code = %v, want InvalidArgument", c)
	}

	_, err = s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "nope"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("not found: code = %v, want NotFound", c)
	}
}

func TestCutoverVM_Validation(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("empty name: code = %v, want InvalidArgument", c)
	}

	_, err = s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "vm1"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("not found -next: code = %v, want NotFound", c)
	}
}

func TestVmHooks_EmptySpec(t *testing.T) {
	vm := &corrosion.VMRecord{Name: "test-vm", Spec: ""}
	if hooks := vmHooks(vm); hooks != nil {
		t.Errorf("expected nil hooks for empty spec, got %v", hooks)
	}
}

func TestVmHooks_InvalidJSON(t *testing.T) {
	vm := &corrosion.VMRecord{Name: "test-vm", Spec: "not json"}
	if hooks := vmHooks(vm); hooks != nil {
		t.Errorf("expected nil hooks for invalid JSON, got %v", hooks)
	}
}

func TestReplaceDomainName(t *testing.T) {
	xml := `<domain><name>old-vm</name><uuid>123</uuid></domain>`
	got := replaceDomainName(xml, "old-vm", "new-vm")
	want := `<domain><name>new-vm</name><uuid>123</uuid></domain>`
	if got != want {
		t.Errorf("replaceDomainName:\n  got  %s\n  want %s", got, want)
	}
}

func TestReplaceDomainName_NotFound(t *testing.T) {
	xml := `<domain><name>different</name></domain>`
	got := replaceDomainName(xml, "old-vm", "new-vm")
	if got != xml {
		t.Errorf("expected unchanged XML when name not found, got %s", got)
	}
}

func TestReplaceFirst(t *testing.T) {
	tests := []struct {
		s, old, new, want string
	}{
		{"hello world hello", "hello", "hi", "hi world hello"},
		{"no match here", "xyz", "abc", "no match here"},
		{"", "a", "b", ""},
	}
	for _, tt := range tests {
		got := replaceFirst(tt.s, tt.old, tt.new)
		if got != tt.want {
			t.Errorf("replaceFirst(%q, %q, %q) = %q, want %q", tt.s, tt.old, tt.new, got, tt.want)
		}
	}
}

func TestParseDiskSizeBytes(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"20G", 20 * 1024 * 1024 * 1024},
		{"20g", 20 * 1024 * 1024 * 1024},
		{"512M", 512 * 1024 * 1024},
		{"1T", 1024 * 1024 * 1024 * 1024},
		{"", 0},
		{"100", 100},
	}
	for _, tt := range tests {
		got := parseDiskSizeBytes(tt.input)
		if got != tt.want {
			t.Errorf("parseDiskSizeBytes(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestVmBaseName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"web-3", "web"},
		{"web-10", "web"},
		{"db", "db"},
		{"worker-1", "worker"},
		{"my-service-2", "my-service"},
		// No trailing digits → name unchanged.
		{"web-", "web-"},
		// All digits → name unchanged (no dash prefix).
		{"123", "123"},
	}
	for _, tt := range tests {
		got := vmBaseName(tt.input)
		if got != tt.want {
			t.Errorf("vmBaseName(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestResolveStopTimeout_ReqTimeout(t *testing.T) {
	// Request timeout takes highest priority.
	got := resolveStopTimeout(60, `{"stop_timeout_sec":10}`)
	if got != 60 {
		t.Errorf("got %d, want 60 (req timeout wins)", got)
	}
}

func TestResolveStopTimeout_SpecTimeout(t *testing.T) {
	// No request timeout → fall back to spec JSON field.
	got := resolveStopTimeout(0, `{"stop_timeout_sec":90}`)
	if got != 90 {
		t.Errorf("got %d, want 90 (spec timeout)", got)
	}
}

func TestResolveStopTimeout_Default(t *testing.T) {
	// Neither request nor spec → default 30s.
	got := resolveStopTimeout(0, "")
	if got != 30 {
		t.Errorf("got %d, want 30 (default)", got)
	}
}

func TestResolveStopTimeout_Default_EmptySpec(t *testing.T) {
	// Spec JSON present but stop_timeout_sec is 0 → still use default.
	got := resolveStopTimeout(0, `{"stop_timeout_sec":0}`)
	if got != 30 {
		t.Errorf("got %d, want 30 (default when spec value is 0)", got)
	}
}

func TestResolveStopTimeout_Default_InvalidJSON(t *testing.T) {
	// Unparseable spec JSON → fall back to default.
	got := resolveStopTimeout(0, "not json")
	if got != 30 {
		t.Errorf("got %d, want 30 (default on invalid JSON)", got)
	}
}

func TestResolveStopTimeout_ReqOverridesSpec(t *testing.T) {
	// Explicit request timeout beats a spec value.
	got := resolveStopTimeout(15, `{"stop_timeout_sec":120}`)
	if got != 15 {
		t.Errorf("got %d, want 15 (req timeout beats spec)", got)
	}
}

func TestLockVM_Concurrent(t *testing.T) {
	s := testServerWithLocks(t)

	// Verify lockVM returns a working unlock function.
	unlock := s.lockVM("test-vm")
	unlock()

	// Verify the same VM can be locked again after unlock.
	unlock2 := s.lockVM("test-vm")
	unlock2()
}
