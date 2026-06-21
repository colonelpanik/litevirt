package grpcapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ── splitCIDR ───────────────────────────────────────────────────────────────

func TestSplitCIDR_WithPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  [2]string
	}{
		{"10.0.0.0/24", [2]string{"10.0.0.0", "24"}},
		{"192.168.1.0/16", [2]string{"192.168.1.0", "16"}},
		{"10.200.0.10/32", [2]string{"10.200.0.10", "32"}},
		{"fd00::1/64", [2]string{"fd00::1", "64"}},
		{"0.0.0.0/0", [2]string{"0.0.0.0", "0"}},
	}
	for _, tt := range tests {
		got := splitCIDR(tt.input)
		if got != tt.want {
			t.Errorf("splitCIDR(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestSplitCIDR_NoPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  [2]string
	}{
		{"10.0.0.1", [2]string{"10.0.0.1", ""}},
		{"", [2]string{"", ""}},
		{"192.168.1.5", [2]string{"192.168.1.5", ""}},
	}
	for _, tt := range tests {
		got := splitCIDR(tt.input)
		if got != tt.want {
			t.Errorf("splitCIDR(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestSplitCIDR_MultipleSlashes(t *testing.T) {
	// Only the first slash matters.
	got := splitCIDR("10.0.0.0/24/extra")
	if got[0] != "10.0.0.0" {
		t.Errorf("IP = %q, want 10.0.0.0", got[0])
	}
	if got[1] != "24/extra" {
		t.Errorf("prefix = %q, want 24/extra", got[1])
	}
}

// ── buildIsolatedNetworkConfig ──────────────────────────────────────────────

func TestBuildIsolatedNetworkConfig_Empty(t *testing.T) {
	got := buildIsolatedNetworkConfig(nil)
	if got != "" {
		t.Errorf("expected empty string for nil input, got %q", got)
	}
	got = buildIsolatedNetworkConfig([]isolatedIface{})
	if got != "" {
		t.Errorf("expected empty string for empty slice, got %q", got)
	}
}

func TestBuildIsolatedNetworkConfig_SingleInterface(t *testing.T) {
	ifaces := []isolatedIface{
		{
			MAC:     "52:54:00:01:01:01",
			Address: "10.100.0.10/24",
			Gateway: "10.100.0.1",
			DNS:     []string{"8.8.8.8", "8.8.4.4"},
		},
	}
	got := buildIsolatedNetworkConfig(ifaces)

	if !strings.Contains(got, "version: 1") {
		t.Error("missing version header")
	}
	if !strings.Contains(got, "name: eth0") {
		t.Error("missing eth0 interface name")
	}
	if !strings.Contains(got, `"52:54:00:01:01:01"`) {
		t.Error("missing MAC address")
	}
	if !strings.Contains(got, "address: 10.100.0.10/24") {
		t.Error("missing address")
	}
	if !strings.Contains(got, "gateway: 10.100.0.1") {
		t.Error("missing gateway")
	}
	if !strings.Contains(got, "- 8.8.8.8") || !strings.Contains(got, "- 8.8.4.4") {
		t.Error("missing DNS entries")
	}
}

func TestBuildIsolatedNetworkConfig_MultipleInterfaces(t *testing.T) {
	ifaces := []isolatedIface{
		{MAC: "52:54:00:01:01:01", Address: "10.100.0.10/24"},
		{MAC: "52:54:00:02:02:02", Address: "10.200.0.10/24", Gateway: "10.200.0.1"},
	}
	got := buildIsolatedNetworkConfig(ifaces)

	if !strings.Contains(got, "name: eth0") {
		t.Error("missing eth0")
	}
	if !strings.Contains(got, "name: eth1") {
		t.Error("missing eth1")
	}
	// First iface has no gateway.
	if strings.Count(got, "gateway:") != 1 {
		t.Errorf("expected exactly 1 gateway line, got %d", strings.Count(got, "gateway:"))
	}
}

func TestBuildIsolatedNetworkConfig_NoGatewayNoDNS(t *testing.T) {
	ifaces := []isolatedIface{
		{MAC: "52:54:00:aa:bb:cc", Address: "192.168.0.5/24"},
	}
	got := buildIsolatedNetworkConfig(ifaces)

	if strings.Contains(got, "gateway:") {
		t.Error("should not contain gateway when empty")
	}
	if strings.Contains(got, "dns_nameservers:") {
		t.Error("should not contain dns_nameservers when empty")
	}
}

// ── lookupNetworkDef ────────────────────────────────────────────────────────

func TestLookupNetworkDef_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	def := lookupNetworkDef(ctx, s.db, "nonexistent-net")
	if def != nil {
		t.Errorf("expected nil for nonexistent network, got %+v", def)
	}
}

func TestLookupNetworkDef_Found(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	config := `{"interface":"lv-br100","vni":100}`
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "test-net",
		Type:   "vxlan",
		Config: config,
	}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}

	def := lookupNetworkDef(ctx, s.db, "test-net")
	if def == nil {
		t.Fatal("expected non-nil for existing network")
	}
	if def.Type != "vxlan" {
		t.Errorf("type = %q, want vxlan", def.Type)
	}
	if def.Interface != "lv-br100" {
		t.Errorf("interface = %q, want lv-br100", def.Interface)
	}
}

func TestLookupNetworkDef_BadJSON(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "bad-json-net",
		Type:   "bridge",
		Config: "not valid json",
	}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}

	def := lookupNetworkDef(ctx, s.db, "bad-json-net")
	if def != nil {
		t.Errorf("expected nil for invalid JSON config, got %+v", def)
	}
}

// ── resolveBridge ───────────────────────────────────────────────────────────

func TestResolveBridge_NoNetworkRecord(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// When no network record exists, returns the name as-is (flat bridge mode).
	got := resolveBridge(ctx, s.db, "my-bridge")
	if got != "my-bridge" {
		t.Errorf("resolveBridge = %q, want my-bridge", got)
	}
}

func TestResolveBridge_BridgeType(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "br-net",
		Type:   "bridge",
		Config: `{"interface":"lv-br0"}`,
	})

	got := resolveBridge(ctx, s.db, "br-net")
	if got != "lv-br0" {
		t.Errorf("resolveBridge = %q, want lv-br0", got)
	}
}

func TestResolveBridge_VXLANType(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "overlay-net",
		Type:   "vxlan",
		Config: `{"interface":"br-vni500"}`,
	})

	got := resolveBridge(ctx, s.db, "overlay-net")
	if got != "br-vni500" {
		t.Errorf("resolveBridge = %q, want br-vni500", got)
	}
}

func TestResolveBridge_SRIOVType(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "sriov-net",
		Type:   "sriov",
		Config: `{"pf":"ens3f0"}`,
	})

	got := resolveBridge(ctx, s.db, "sriov-net")
	if got != "ens3f0" {
		t.Errorf("resolveBridge = %q, want ens3f0 (PF)", got)
	}
}

func TestResolveBridge_DirectType(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "direct-net",
		Type:   "direct",
		Config: `{"interface":"bond0.206"}`,
	})

	got := resolveBridge(ctx, s.db, "direct-net")
	if got != "direct:bond0.206" {
		t.Errorf("resolveBridge = %q, want direct:bond0.206", got)
	}
}

func TestResolveBridge_EmptyInterface(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// Network exists but has empty interface — falls back to network name.
	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "empty-iface",
		Type:   "bridge",
		Config: `{}`,
	})

	got := resolveBridge(ctx, s.db, "empty-iface")
	if got != "empty-iface" {
		t.Errorf("resolveBridge = %q, want empty-iface (fallback)", got)
	}
}

func TestResolveBridge_SRIOVEmptyPF(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name:   "sriov-empty",
		Type:   "sriov",
		Config: `{}`,
	})

	got := resolveBridge(ctx, s.db, "sriov-empty")
	if got != "sriov-empty" {
		t.Errorf("resolveBridge = %q, want sriov-empty (fallback)", got)
	}
}

// ── highestDependencyCondition ──────────────────────────────────────────────

func TestHighestDependencyCondition_NoDependencies(t *testing.T) {
	ops := []compose.Op{
		{VMName: "web-1", DependsOn: nil},
	}
	got := highestDependencyCondition("db-1", ops)
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestHighestDependencyCondition_VMStarted(t *testing.T) {
	ops := []compose.Op{
		{VMName: "web-1", DependsOn: compose.DependsOn{
			"db": {Condition: "vm_started"},
		}},
	}
	got := highestDependencyCondition("db-1", ops)
	if got != "vm_started" {
		t.Errorf("expected vm_started, got %q", got)
	}
}

func TestHighestDependencyCondition_VMHealthy(t *testing.T) {
	ops := []compose.Op{
		{VMName: "web-1", DependsOn: compose.DependsOn{
			"db": {Condition: "vm_started"},
		}},
		{VMName: "api-1", DependsOn: compose.DependsOn{
			"db": {Condition: "vm_healthy"},
		}},
	}
	got := highestDependencyCondition("db-1", ops)
	if got != "vm_healthy" {
		t.Errorf("expected vm_healthy (highest), got %q", got)
	}
}

func TestHighestDependencyCondition_ExactNameMatch(t *testing.T) {
	ops := []compose.Op{
		{VMName: "worker-1", DependsOn: compose.DependsOn{
			"db": {Condition: "vm_started"},
		}},
	}
	// Exact name match (no replica suffix).
	got := highestDependencyCondition("db", ops)
	if got != "vm_started" {
		t.Errorf("expected vm_started for exact match, got %q", got)
	}
}

func TestHighestDependencyCondition_NoMatch(t *testing.T) {
	ops := []compose.Op{
		{VMName: "web-1", DependsOn: compose.DependsOn{
			"cache": {Condition: "vm_started"},
		}},
	}
	got := highestDependencyCondition("db-1", ops)
	if got != "" {
		t.Errorf("expected empty for no match, got %q", got)
	}
}

// ── ResizeDisk ──────────────────────────────────────────────────────────────

func TestResizeDisk_MissingFields(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	tests := []struct {
		name string
		req  *pb.ResizeDiskRequest
	}{
		{"empty_vm", &pb.ResizeDiskRequest{DiskName: "root", Size: "50G"}},
		{"empty_disk", &pb.ResizeDiskRequest{VmName: "vm1", Size: "50G"}},
		{"empty_size", &pb.ResizeDiskRequest{VmName: "vm1", DiskName: "root"}},
	}
	for _, tt := range tests {
		_, err := s.ResizeDisk(ctx, tt.req)
		if err == nil {
			t.Errorf("%s: expected error", tt.name)
			continue
		}
		if c := status.Code(err); c != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", tt.name, c)
		}
	}
}

func TestResizeDisk_VMNotFound(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.ResizeDisk(ctx, &pb.ResizeDiskRequest{
		VmName: "ghost", DiskName: "root", Size: "50G",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestResizeDisk_WrongHost(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "stopped")

	_, err := s.ResizeDisk(ctx, &pb.ResizeDiskRequest{
		VmName: "remote-vm", DiskName: "root", Size: "50G",
	})
	if err == nil {
		t.Fatal("expected error for wrong host")
	}
	c := status.Code(err)
	if c != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", c)
	}
}

func TestResizeDisk_DiskNotFound(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "vm-no-disk", "test-host", "stopped")

	_, err := s.ResizeDisk(ctx, &pb.ResizeDiskRequest{
		VmName: "vm-no-disk", DiskName: "nonexistent", Size: "50G",
	})
	if err == nil {
		t.Fatal("expected error for missing disk")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestResizeDisk_InvalidSize(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "vm-resize", "test-host", "stopped")
	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm-resize", DiskName: "root", HostName: "test-host",
		Path: "/data/root.qcow2", SizeBytes: 10 * 1024 * 1024 * 1024,
	})

	_, err := s.ResizeDisk(ctx, &pb.ResizeDiskRequest{
		VmName: "vm-resize", DiskName: "root", Size: "abc",
	})
	if err == nil {
		t.Fatal("expected error for invalid size")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestResizeDisk_ShrinkRejected(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "vm-shrink", "test-host", "stopped")
	corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: "vm-shrink", DiskName: "root", HostName: "test-host",
		Path: "/data/root.qcow2", SizeBytes: 50 * 1024 * 1024 * 1024,
	})

	_, err := s.ResizeDisk(ctx, &pb.ResizeDiskRequest{
		VmName: "vm-shrink", DiskName: "root", Size: "20G",
	})
	if err == nil {
		t.Fatal("expected error for shrink attempt")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestResizeDisk_RBAC(t *testing.T) {
	s := testServerWithLocks(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.ResizeDisk(viewerCtx, &pb.ResizeDiskRequest{
		VmName: "vm1", DiskName: "root", Size: "50G",
	})
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

// ── UpdateVM deeper paths ───────────────────────────────────────────────────

func TestUpdateVM_RBAC(t *testing.T) {
	s := testServer(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.UpdateVM(viewerCtx, &pb.UpdateVMRequest{Name: "vm1", Cpu: 4})
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestUpdateVM_StoppedWithSpec_PassesValidation(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	// Insert a VM with a stored spec.
	spec := &pb.VMSpec{Name: "spec-vm", Cpu: 2, MemoryMib: 4096}
	specJSON, _ := json.Marshal(spec)
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:      "spec-vm",
		HostName:  "test-host",
		State:     "stopped",
		CPUActual: 2,
		MemActual: 4096,
		Spec:      string(specJSON),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// UpdateVM gets past validation and spec parsing but panics on nil virt
	// when calling UndefineDomain. The panic confirms we reached the libvirt
	// code path — all validation, spec parsing, and disk/interface resolution passed.
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic from nil virt, but UpdateVM returned normally")
		}
	}()

	s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name: "spec-vm", Cpu: 8, MemoryMib: 16384,
	})
}

func TestUpdateVM_BadStoredSpec(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name:     "bad-spec-vm",
		HostName: "test-host",
		State:    "stopped",
		Spec:     "not valid json",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name: "bad-spec-vm", Cpu: 4,
	})
	if err == nil {
		t.Fatal("expected error for bad spec JSON")
	}
	if c := status.Code(err); c != codes.Internal {
		t.Errorf("code = %v, want Internal", c)
	}
}

// ── AttachDevice / DetachDevice deeper paths ────────────────────────────────

func TestAttachDevice_RBAC(t *testing.T) {
	s := testServer(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.AttachDevice(viewerCtx, &pb.AttachDeviceRequest{
		VmName: "vm1",
		Disk:   &pb.DiskSpec{Name: "data", Size: "10G"},
	})
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestDetachDevice_RBAC(t *testing.T) {
	s := testServer(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.DetachDevice(viewerCtx, &pb.DetachDeviceRequest{
		VmName:   "vm1",
		DiskName: "root",
	})
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestAttachDevice_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "remote-vm",
		Disk:   &pb.DiskSpec{Name: "data", Size: "10G"},
	})
	if err == nil {
		t.Fatal("expected error for wrong host")
	}
	if c := status.Code(err); c != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", c)
	}
}

func TestDetachDevice_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName:   "remote-vm",
		DiskName: "root",
	})
	if err == nil {
		t.Fatal("expected error for wrong host")
	}
	if c := status.Code(err); c != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", c)
	}
}

func TestDetachDisk_DiskNotFoundLocal(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "local-vm", "test-host", "running")

	// Call detachDisk directly — the disk doesn't exist.
	_, err := s.detachDisk(ctx, "local-vm", "nonexistent-disk")
	if err == nil {
		t.Fatal("expected error for missing disk")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestAttachDisk_InvalidSize(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	// Call attachDisk directly with invalid size.
	_, err := s.attachDisk(ctx, "vm1", &pb.DiskSpec{Name: "data", Size: "abc"})
	if err == nil {
		t.Fatal("expected error for invalid size")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestAttachDisk_EmptySize(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.attachDisk(ctx, "vm1", &pb.DiskSpec{Name: "data", Size: ""})
	if err == nil {
		t.Fatal("expected error for empty size")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

// ── StartVM / StopVM / DeleteVM deeper coverage ─────────────────────────────

func TestStartVM_RBAC(t *testing.T) {
	s := testServer(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.StartVM(viewerCtx, &pb.StartVMRequest{Name: "vm1"})
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestStopVM_RBAC(t *testing.T) {
	s := testServerWithLocks(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.StopVM(viewerCtx, &pb.StopVMRequest{Name: "vm1"})
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestDeleteVM_RBAC(t *testing.T) {
	s := testServerWithLocks(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.DeleteVM(viewerCtx, &pb.DeleteVMRequest{Name: "vm1"})
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestStopVM_NotFoundT1(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.StopVM(ctx, &pb.StopVMRequest{Name: "ghost-t1"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestDeleteVM_EmptyName(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: ""})
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

// ── RebuildVM coverage ──────────────────────────────────────────────────────

func TestRebuildVM_RBAC(t *testing.T) {
	s := testServerWithLocks(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.RebuildVM(viewerCtx, &pb.RebuildVMRequest{Name: "vm1"})
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

func TestRebuildVM_EmptyName(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestRebuildVM_NotFoundT1(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "ghost"})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestRebuildVM_WrongHostT1(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "stopped")

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "remote-vm"})
	if err == nil {
		t.Fatal("expected error for wrong host")
	}
	if c := status.Code(err); c != codes.Unavailable {
		t.Errorf("code = %v, want Unavailable", c)
	}
}

func TestRebuildVM_BadStoredSpec(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "bad-spec", HostName: "test-host", State: "stopped",
		Spec: "not json",
	}, nil, nil)

	_, err := s.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "bad-spec"})
	if err == nil {
		t.Fatal("expected error for bad spec")
	}
	if c := status.Code(err); c != codes.Internal {
		t.Errorf("code = %v, want Internal", c)
	}
}

// ── CreateVM validation paths ───────────────────────────────────────────────

func TestCreateVM_DuplicateNameT1(t *testing.T) {
	s := testServerWithLocks(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "existing-vm", "test-host", "running")

	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{Name: "existing-vm", Cpu: 2, MemoryMib: 4096},
	})
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
	if c := status.Code(err); c != codes.AlreadyExists {
		t.Errorf("code = %v, want AlreadyExists", c)
	}
}

func TestCreateVM_RBAC(t *testing.T) {
	s := testServerWithLocks(t)
	viewerCtx := context.WithValue(context.Background(), ctxKeyUsername, "viewer")
	viewerCtx = context.WithValue(viewerCtx, ctxKeyRole, "viewer")

	_, err := s.CreateVM(viewerCtx, &pb.CreateVMRequest{
		Spec: &pb.VMSpec{Name: "new-vm", Cpu: 2, MemoryMib: 4096},
	})
	if err == nil {
		t.Fatal("expected permission denied")
	}
	if c := status.Code(err); c != codes.PermissionDenied {
		t.Errorf("code = %v, want PermissionDenied", c)
	}
}

// ── resolveStopTimeout ──────────────────────────────────────────────────────

func TestResolveStopTimeout_Defaults(t *testing.T) {
	// reqTimeout=0, empty spec → default.
	got := resolveStopTimeout(0, "")
	if got != 30 {
		t.Errorf("default timeout = %d, want 30", got)
	}
}

func TestResolveStopTimeout_FromRequest(t *testing.T) {
	got := resolveStopTimeout(60, "")
	if got != 60 {
		t.Errorf("timeout = %d, want 60", got)
	}
}

func TestResolveStopTimeout_FromSpec(t *testing.T) {
	spec := `{"stop_timeout_sec": 120}`
	got := resolveStopTimeout(0, spec)
	if got != 120 {
		t.Errorf("timeout = %d, want 120", got)
	}
}

func TestResolveStopTimeout_RequestOverridesSpec(t *testing.T) {
	spec := `{"stop_timeout_sec": 120}`
	got := resolveStopTimeout(45, spec)
	if got != 45 {
		t.Errorf("timeout = %d, want 45 (request overrides spec)", got)
	}
}
