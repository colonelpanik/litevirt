package grpcapi

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// pciBindFakeFS is an in-memory vfio.SysFS for grpcapi PCI tests. It makes
// vfio.Bind succeed for any device (reporting a fabricated vendor/device and
// flipping the driver symlink to vfio-pci on the bind write) and counts how many
// vfio-pci bind operations occurred, so a test can assert that a PURE resolve
// performed zero binds.
type pciBindFakeFS struct {
	mu    sync.Mutex
	bound map[string]bool // address -> currently bound to vfio-pci
	binds int             // count of vfio-pci bind writes
}

func newPCIBindFakeFS() *pciBindFakeFS { return &pciBindFakeFS{bound: map[string]bool{}} }

func (f *pciBindFakeFS) addrFromDriverPath(path string) string {
	const pfx = "/sys/bus/pci/devices/"
	if !strings.HasPrefix(path, pfx) {
		return ""
	}
	return strings.TrimSuffix(strings.TrimPrefix(path, pfx), "/driver")
}

func (f *pciBindFakeFS) ReadFile(path string) ([]byte, error) {
	if strings.HasSuffix(path, "/vendor") {
		return []byte("0x8086\n"), nil
	}
	if strings.HasSuffix(path, "/device") {
		return []byte("0x1572\n"), nil
	}
	return nil, fmt.Errorf("pciBindFakeFS: no file %s", path)
}

func (f *pciBindFakeFS) WriteFile(path string, data []byte, _ os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Contains(path, "vfio-pci/bind") || strings.Contains(path, "drivers_probe") {
		f.bound[strings.TrimSpace(string(data))] = true
		f.binds++
	}
	return nil
}

func (f *pciBindFakeFS) Readlink(path string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasSuffix(path, "/driver") {
		if f.bound[f.addrFromDriverPath(path)] {
			return "/sys/bus/pci/drivers/vfio-pci", nil
		}
		// No driver bound → model real sysfs (ENOENT), which IsBoundToVFIO reads as
		// "not bound" (false, nil) rather than an unexpected FS error.
		return "", os.ErrNotExist
	}
	return "", fmt.Errorf("pciBindFakeFS: no link %s", path)
}

func (f *pciBindFakeFS) ReadDir(path string) ([]os.DirEntry, error) {
	return nil, fmt.Errorf("pciBindFakeFS: no dir %s", path)
}

// TestAllocateDevices_AddressSpec_ResolvesBDFAndSiblings is a characterization
// test pinning the current allocateDevices behavior for an exact-address spec: it
// resolves to the requested BDF FOLLOWED BY its IOMMU-group siblings (in address
// order), records ownership on every one, and returns them in that order. This is
// the invariant the resolve/acquire refactor must preserve.
func TestAllocateDevices_AddressSpec_ResolvesBDFAndSiblings(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()

	// Two devices in the same IOMMU group.
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: 20,
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.1", Type: "gpu", VendorID: "10de", IOMMUGroup: 20,
	})

	addrs, finish, err := s.allocateDevices(ctx, "vm-gpu", []*pb.DeviceSpec{{Address: "0000:41:00.0"}}, deviceLeaseStageBound)
	if err != nil {
		t.Fatalf("allocateDevices: %v", err)
	}
	defer finish()

	want := []string{"0000:41:00.0", "0000:41:00.1"}
	if !reflect.DeepEqual(addrs, want) {
		t.Fatalf("addresses = %v, want %v (BDF then IOMMU sibling)", addrs, want)
	}

	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	if len(devs) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devs))
	}
	for _, d := range devs {
		if d.VMName != "vm-gpu" {
			t.Errorf("device %s owner = %q, want vm-gpu", d.Address, d.VMName)
		}
	}
}

// TestResolveDeviceIntents_PureAddressSelector proves resolveDeviceIntents is a
// PURE resolver: an address-selector intent resolves to the BDF + its IOMMU-group
// siblings as ordered members, while leaving host_pci_devices ownership UNCHANGED
// and performing NO vfio bind.
func TestResolveDeviceIntents_PureAddressSelector(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	fake := newPCIBindFakeFS()
	restore := vfio.SetFS(fake)
	defer restore()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:42:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: 21,
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:42:00.1", Type: "gpu", VendorID: "10de", IOMMUGroup: 21,
	})

	key := "0000:42:00.0"
	members, err := s.resolveDeviceIntents(ctx, "vm-pure", []corrosion.PCIIntentRecord{{
		VMName: "vm-pure", DeviceID: "dev0", HostName: "test-host",
		SelectorKind: "address", ExclusiveKey: &key,
	}})
	if err != nil {
		t.Fatalf("resolveDeviceIntents: %v", err)
	}

	if len(members) != 2 {
		t.Fatalf("members = %d, want 2", len(members))
	}
	if members[0].Address != "0000:42:00.0" || members[0].Ordinal != 0 || members[0].DeviceID != "dev0" {
		t.Errorf("member[0] = %+v, want BDF primary (ordinal 0, dev0)", members[0])
	}
	if members[1].Address != "0000:42:00.1" || members[1].Ordinal != 1 {
		t.Errorf("member[1] = %+v, want IOMMU sibling (ordinal 1)", members[1])
	}

	// PURE: no vfio bind.
	if fake.binds != 0 {
		t.Errorf("resolveDeviceIntents performed %d vfio binds; want 0", fake.binds)
	}
	// PURE: no ownership mutation.
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.VMName != "" {
			t.Errorf("device %s owner = %q after pure resolve; want unassigned", d.Address, d.VMName)
		}
	}
}

// TestResolveDeviceIntents_PureTypeSelector proves the portable (type/vendor)
// selector path is likewise pure: it selects a matching unassigned device from
// inventory without claiming it or binding.
func TestResolveDeviceIntents_PureTypeSelector(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	fake := newPCIBindFakeFS()
	restore := vfio.SetFS(fake)
	defer restore()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:43:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1,
	})

	payload, err := protojson.Marshal(&pb.DeviceSpec{Type: "gpu", Vendor: "10de", Count: 1})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	members, err := s.resolveDeviceIntents(ctx, "vm-type", []corrosion.PCIIntentRecord{{
		VMName: "vm-type", DeviceID: "dev0", HostName: "test-host",
		SelectorKind: "type", SelectorPayload: string(payload),
	}})
	if err != nil {
		t.Fatalf("resolveDeviceIntents: %v", err)
	}
	if len(members) != 1 || members[0].Address != "0000:43:00.0" {
		t.Fatalf("members = %+v, want single 0000:43:00.0", members)
	}
	if fake.binds != 0 {
		t.Errorf("pure resolve performed %d vfio binds; want 0", fake.binds)
	}
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.VMName != "" {
			t.Errorf("device %s owner = %q after pure resolve; want unassigned", d.Address, d.VMName)
		}
	}
}

// TestAllocateDevices_MultiTypeSpec_DistinctDevices pins the cross-spec
// pool-shrinking invariant: two separate type-based specs on a host with two free
// GPUs must resolve to two DISTINCT devices (one each), not the same device twice.
// The old fused allocateDevices assigned each spec inline, so the second spec's
// GetAvailableDevicesByType saw a shrunk pool; the resolve/acquire split must
// reproduce that via a cross-spec exclusion set. A duplicate here would emit two
// identical <hostdev> entries and fail DefineDomain on a create that used to work.
func TestAllocateDevices_MultiTypeSpec_DistinctDevices(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()

	// Two free GPUs, distinct IOMMU groups (no siblings).
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:44:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1,
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:45:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1,
	})

	addrs, finish, err := s.allocateDevices(ctx, "vm-2gpu", []*pb.DeviceSpec{
		{Type: "gpu"}, {Type: "gpu"},
	}, deviceLeaseStageBound)
	if err != nil {
		t.Fatalf("allocateDevices: %v", err)
	}
	defer finish()

	if len(addrs) != 2 {
		t.Fatalf("addresses = %v, want 2", addrs)
	}
	if addrs[0] == addrs[1] {
		t.Fatalf("addresses = %v, want two DISTINCT devices (second type spec re-picked the first)", addrs)
	}
}

// TestAllocateDevices_AddressPinThenTypeSpec_NoRepick pins that an exact-address
// spec's device is excluded from a later same-type spec's candidate pool: the type
// spec must NOT re-pick the already-pinned BDF.
func TestAllocateDevices_AddressPinThenTypeSpec_NoRepick(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:44:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1,
	})
	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:45:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1,
	})

	addrs, finish, err := s.allocateDevices(ctx, "vm-pin-type", []*pb.DeviceSpec{
		{Address: "0000:44:00.0"}, {Type: "gpu"},
	}, deviceLeaseStageBound)
	if err != nil {
		t.Fatalf("allocateDevices: %v", err)
	}
	defer finish()

	if len(addrs) != 2 {
		t.Fatalf("addresses = %v, want 2", addrs)
	}
	if addrs[0] != "0000:44:00.0" {
		t.Fatalf("addresses[0] = %q, want the pinned 0000:44:00.0", addrs[0])
	}
	if addrs[1] == "0000:44:00.0" {
		t.Fatalf("addresses = %v, type spec re-picked the pinned BDF", addrs)
	}
}

// TestAllocateDevices_MappingSpec_FreezesAddress pins that allocateDevices writes
// the resolved concrete BDF back onto a resource-mapping spec's Address, so
// CreateVM's json.Marshal(spec) persists the pinned device (behavior-preserving;
// the pure resolveDeviceSpec must NOT mutate the spec — allocateDevices does).
func TestAllocateDevices_MappingSpec_FreezesAddress(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()

	corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:46:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1,
	})
	if err := corrosion.CreateResourceMapping(ctx, s.db, "gpu-map", "test mapping"); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, s.db, "gpu-map", "test-host", "0000:46:00.0", "10de", ""); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}

	spec := &pb.DeviceSpec{Mapping: "gpu-map"}
	addrs, finish, err := s.allocateDevices(ctx, "vm-map", []*pb.DeviceSpec{spec}, deviceLeaseStageBound)
	if err != nil {
		t.Fatalf("allocateDevices: %v", err)
	}
	defer finish()

	if len(addrs) != 1 || addrs[0] != "0000:46:00.0" {
		t.Fatalf("addresses = %v, want [0000:46:00.0]", addrs)
	}
	if spec.Address != "0000:46:00.0" {
		t.Fatalf("spec.Address = %q after allocateDevices, want frozen 0000:46:00.0", spec.Address)
	}
}

func TestRescanHost_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.RescanHost(ctx, &pb.RescanHostRequest{Name: "other-host"})
	if err == nil {
		t.Fatal("expected error")
	}
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}

func TestListHostDevices_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.ListHostDevices(ctx, &pb.ListHostDevicesRequest{})
	if err != nil {
		t.Fatalf("ListHostDevices: %v", err)
	}
	if len(resp.Devices) != 0 {
		t.Errorf("expected 0 devices, got %d", len(resp.Devices))
	}
}

func TestListHostDevices_DefaultHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Empty Name should default to s.hostName.
	resp, err := s.ListHostDevices(ctx, &pb.ListHostDevicesRequest{Name: ""})
	if err != nil {
		t.Fatalf("ListHostDevices: %v", err)
	}
	_ = resp
}

func TestPCIDeviceToProto(t *testing.T) {
	d := corrosion.PCIDeviceRecord{
		HostName:   "h1",
		Address:    "0000:01:00.0",
		VendorID:   "10de",
		DeviceID:   "1234",
		VendorName: "NVIDIA",
		DeviceName: "Tesla T4",
		Type:       "gpu",
		IOMMUGroup: 5,
		LinkPeers:  "0000:01:00.1, 0000:01:00.2",
	}

	pb := pciDeviceToProto(d)
	if pb.Address != "0000:01:00.0" {
		t.Errorf("Address = %q", pb.Address)
	}
	if pb.VendorName != "NVIDIA" {
		t.Errorf("VendorName = %q", pb.VendorName)
	}
	if pb.IommuGroup != 5 {
		t.Errorf("IommuGroup = %d", pb.IommuGroup)
	}
	if len(pb.LinkPeers) != 2 {
		t.Errorf("LinkPeers = %v, want 2 entries", pb.LinkPeers)
	}
}

func TestPCIDeviceToProto_EmptyLinkPeers(t *testing.T) {
	d := corrosion.PCIDeviceRecord{
		Address: "0000:00:00.0",
	}
	pb := pciDeviceToProto(d)
	if len(pb.LinkPeers) != 0 {
		t.Errorf("LinkPeers = %v, want empty", pb.LinkPeers)
	}
}
