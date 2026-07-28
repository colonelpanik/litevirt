package grpcapi

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/placement"
	"github.com/litevirt/litevirt/internal/vfio"
)

const testCapacityAdmissionCapability = "capacity_admission_v1"

type createForwardClient struct {
	pb.LiteVirtClient
	createCalls  int
	executeCalls int
	createReq    *pb.CreateVMRequest
	executeReq   *pb.ExecuteCreateVMRequest
	createCtx    context.Context
	executeCtx   context.Context
	createErr    error
	executeErr   error
}

func (c *createForwardClient) CreateVM(ctx context.Context, req *pb.CreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.createCalls++
	c.createCtx = ctx
	c.createReq = req
	if c.createErr != nil {
		return nil, c.createErr
	}
	return &pb.VM{Name: req.GetSpec().GetName(), HostName: "target"}, nil
}

func (c *createForwardClient) ExecuteCreateVM(ctx context.Context, req *pb.ExecuteCreateVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	c.executeCalls++
	c.executeCtx = ctx
	c.executeReq = req
	if c.executeErr != nil {
		return nil, c.executeErr
	}
	return &pb.VM{Name: req.GetRequest().GetSpec().GetName(), HostName: req.GetResolvedHost()}, nil
}

func capacityFingerprintForServer(t *testing.T, s *Server) string {
	t.Helper()
	hosts, err := corrosion.ListHosts(context.Background(), s.db)
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	fingerprint, err := corrosion.CapacityPolicyFingerprint(s.capacity, corrosion.HostCapacityOverrides(hosts))
	if err != nil {
		t.Fatalf("CapacityPolicyFingerprint: %v", err)
	}
	return fingerprint
}

func insertPlacementExecutorHost(t *testing.T, s *Server, name string, cpu, mem int, labels map[string]string) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: name, Address: "10.0.0.1", State: "active",
		CPUTotal: cpu, MemTotal: mem, Labels: labels,
	}); err != nil {
		t.Fatalf("InsertHost(%s): %v", name, err)
	}
}

func TestExecuteCreateVMRejectsInvalidEnvelope(t *testing.T) {
	s := testServerR2(t)
	insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
	insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)
	ctx := mtlsAdminCtx("entry")
	fingerprint := capacityFingerprintForServer(t, s)

	tests := []struct {
		name string
		req  *pb.ExecuteCreateVMRequest
		code codes.Code
	}{
		{"nil envelope", nil, codes.InvalidArgument},
		{"nil request", &pb.ExecuteCreateVMRequest{ResolvedHost: "test-host", PlacementFingerprint: fingerprint}, codes.InvalidArgument},
		{"nil spec", &pb.ExecuteCreateVMRequest{Request: &pb.CreateVMRequest{}, ResolvedHost: "test-host", PlacementFingerprint: fingerprint}, codes.InvalidArgument},
		{"empty resolved host", &pb.ExecuteCreateVMRequest{Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "vm1"}}, PlacementFingerprint: fingerprint}, codes.InvalidArgument},
		{"wrong owner", &pb.ExecuteCreateVMRequest{Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "vm1"}}, ResolvedHost: "other", PlacementFingerprint: fingerprint}, codes.FailedPrecondition},
		{"pin mismatch", &pb.ExecuteCreateVMRequest{Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "vm1", Placement: &pb.PlacementSpec{Host: "other"}}}, ResolvedHost: "test-host", PlacementFingerprint: fingerprint}, codes.FailedPrecondition},
		{"hop too large", &pb.ExecuteCreateVMRequest{Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "vm1"}}, ResolvedHost: "test-host", PlacementFingerprint: fingerprint, HopCount: 2}, codes.FailedPrecondition},
		{"stale fingerprint", &pb.ExecuteCreateVMRequest{Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "vm1"}}, ResolvedHost: "test-host", PlacementFingerprint: "stale", HopCount: 1}, codes.FailedPrecondition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.ExecuteCreateVM(ctx, tt.req)
			if got := status.Code(err); got != tt.code {
				t.Fatalf("code = %v, want %v (err=%v)", got, tt.code, err)
			}
		})
	}
}

func TestExecuteCreateVMRevalidatesHardConstraints(t *testing.T) {
	s := testServerR2(t)
	insertPlacementExecutorHost(t, s, "test-host", 8, 16384, map[string]string{"zone": "west"})
	insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)

	_, err := s.ExecuteCreateVM(mtlsAdminCtx("entry"), &pb.ExecuteCreateVMRequest{
		Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: "vm1",
			Placement: &pb.PlacementSpec{
				Host: "test-host", Require: map[string]string{"zone": "east"},
			},
		}},
		ResolvedHost:         "test-host",
		PlacementFingerprint: capacityFingerprintForServer(t, s),
		HopCount:             1,
	})
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted (err=%v)", got, err)
	}
}

func TestCreateVMPinnedPolicySpreadStrictRejectsPressure(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	s.capacity = corrosion.CapacityPolicy{
		CPUOvercommit: 1, MemOvercommit: 1,
		CPUReserve: 0, MemReserveMiB: 0, MemReservePct: 0,
		VMMemOverheadMiB: 0,
	}
	insertPlacementExecutorHost(t, s, "test-host", 8, 8192, nil)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "busy", HostName: "test-host", State: "running",
		CPUActual: 4, MemActual: 4096,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM(busy): %v", err)
	}

	_, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "vm1", Cpu: 1, MemoryMib: 512,
		Placement: &pb.PlacementSpec{
			Host: "test-host", Policy: "spread-strict",
		},
	}})
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted from protobuf spread-strict policy (err=%v)", got, err)
	}
}

func TestExecuteCreateVMRevalidatesProtobufSpreadStrictPolicy(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	s.capacity = corrosion.CapacityPolicy{
		CPUOvercommit: 1, MemOvercommit: 1,
		CPUReserve: 0, MemReserveMiB: 0, MemReservePct: 0,
		VMMemOverheadMiB: 0,
	}
	insertPlacementExecutorHost(t, s, "test-host", 8, 8192, nil)
	insertPlacementExecutorHost(t, s, "entry", 8, 8192, nil)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "busy", HostName: "test-host", State: "running",
		CPUActual: 4, MemActual: 4096,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM(busy): %v", err)
	}

	_, err := s.ExecuteCreateVM(mtlsAdminCtx("entry"), &pb.ExecuteCreateVMRequest{
		Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: "vm1", Cpu: 1, MemoryMib: 512,
			Placement: &pb.PlacementSpec{
				Host: "test-host", Policy: "spread-strict",
			},
		}},
		ResolvedHost:         "test-host",
		PlacementFingerprint: capacityFingerprintForServer(t, s),
		HopCount:             1,
	})
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted from executor spread-strict revalidation (err=%v)", got, err)
	}
}

func TestExecuteCreateVMUsesResolvedHostWithoutGlobalRescoring(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
	insertPlacementExecutorHost(t, s, "large-host", 64, 131072, nil)
	insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)

	vm, err := s.ExecuteCreateVM(mtlsAdminCtx("entry"), &pb.ExecuteCreateVMRequest{
		Request:              &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "vm1"}},
		ResolvedHost:         "test-host",
		PlacementFingerprint: capacityFingerprintForServer(t, s),
		HopCount:             1,
	})
	if err != nil {
		t.Fatalf("ExecuteCreateVM: %v", err)
	}
	if vm.GetHostName() != "test-host" {
		t.Fatalf("VM host = %q, want resolved owner test-host", vm.GetHostName())
	}
	record, err := corrosion.GetVM(context.Background(), s.db, "vm1")
	if err != nil || record == nil || record.HostName != "test-host" {
		t.Fatalf("persisted VM = %+v, err=%v; want test-host", record, err)
	}
}

func TestPlacementDeviceRequestPreservesSelectorPrecedence(t *testing.T) {
	tests := []struct {
		name string
		spec *pb.DeviceSpec
		want placement.DeviceRequest
	}{
		{
			name: "mapping outranks sriov type and frozen address",
			spec: &pb.DeviceSpec{
				Mapping: "accelerator", Sriov: true, Type: "network",
				Vendor: "15b3", Model: "ConnectX", Address: "0000:41:00.0", Count: 2,
			},
			want: placement.DeviceRequest{Mapping: "accelerator", Count: 2},
		},
		{
			name: "sriov outranks frozen address",
			spec: &pb.DeviceSpec{
				Sriov: true, Type: "network", Vendor: "15b3", Model: "ConnectX",
				Parent: "41:00.0", Address: "0000:42:00.0", Count: 3,
			},
			want: placement.DeviceRequest{
				Type: "network", Vendor: "15b3", Model: "ConnectX",
				Parent: "41:00.0", Sriov: true, Count: 3,
			},
		},
		{
			name: "type preserves model and outranks frozen address",
			spec: &pb.DeviceSpec{
				Type: "gpu", Vendor: "10de", Model: "H100",
				Address: "0000:43:00.0",
			},
			want: placement.DeviceRequest{Type: "gpu", Vendor: "10de", Model: "H100"},
		},
		{
			name: "exact address canonicalized",
			spec: &pb.DeviceSpec{Address: "41:00.0"},
			want: placement.DeviceRequest{Address: "0000:41:00.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := placementDeviceRequest(tt.spec); got != tt.want {
				t.Fatalf("placementDeviceRequest() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPlacementValidationErrorDistinguishesInfrastructure(t *testing.T) {
	// A closed backend makes ValidatePinned fail before it can evaluate host
	// eligibility and therefore must not be surfaced as ResourceExhausted.
	s := testServerR2(t)
	if err := s.db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := placement.ValidatePinned(context.Background(), s.db, placement.Request{VMName: "vm1"}, "test-host")
	if got := status.Code(placementValidationError(err)); got != codes.Internal {
		t.Fatalf("code = %v, want Internal (err=%v)", got, err)
	}
	if got := status.Code(placementValidationError(fmt.Errorf("wrapped: %w", context.Canceled))); got != codes.Canceled {
		t.Fatalf("cancellation code = %v, want Canceled", got)
	}
	if got := status.Code(placementValidationError(fmt.Errorf("wrapped: %w", context.DeadlineExceeded))); got != codes.DeadlineExceeded {
		t.Fatalf("deadline code = %v, want DeadlineExceeded", got)
	}
}

func TestCreateVMPlacementInfrastructureFailureIsInternal(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	if err := s.db.Execute(context.Background(), `DROP TABLE hosts`); err != nil {
		t.Fatalf("DROP TABLE hosts: %v", err)
	}

	_, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{
		Spec: &pb.VMSpec{Name: "backend-down"},
	})
	if got := status.Code(err); got != codes.Internal {
		t.Fatalf("code = %v, want Internal for placement backend failure (err=%v)", got, err)
	}
}

func TestCreateVMMappingOnlySelectsMappedHost(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()

	insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
	insertPlacementExecutorHost(t, s, "unmapped", 64, 131072, nil)
	for _, host := range []string{"test-host", "unmapped"} {
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: host, Address: "0000:41:00.0", Type: "gpu",
			VendorID: "10de", DeviceName: "A100", IOMMUGroup: -1,
		}); err != nil {
			t.Fatalf("UpsertPCIDevice(%s): %v", host, err)
		}
	}
	if err := corrosion.CreateResourceMapping(ctx, s.db, "accelerator", "test"); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, s.db, "accelerator", "test-host", "0000:41:00.0", "10de", "A100"); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}

	vm, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name:    "mapped-vm",
		Devices: []*pb.DeviceSpec{{Mapping: "accelerator"}},
	}})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if vm.GetHostName() != "test-host" {
		t.Fatalf("host = %q, want mapped host test-host", vm.GetHostName())
	}
}

func TestExecuteCreateVMMappingOutranksSRIOV(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
	insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceName: "A100", IOMMUGroup: -1,
	}); err != nil {
		t.Fatalf("UpsertPCIDevice: %v", err)
	}
	if err := corrosion.CreateResourceMapping(ctx, s.db, "accelerator", "test"); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, s.db, "accelerator", "test-host", "0000:41:00.0", "10de", "A100"); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}

	vm, err := s.ExecuteCreateVM(mtlsAdminCtx("entry"), &pb.ExecuteCreateVMRequest{
		Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: "mapped-exec",
			Devices: []*pb.DeviceSpec{{
				Mapping: "accelerator", Sriov: true, Type: "network",
				Address: "0000:99:00.0",
			}},
		}},
		ResolvedHost:         "test-host",
		PlacementFingerprint: capacityFingerprintForServer(t, s),
		HopCount:             1,
	})
	if err != nil {
		t.Fatalf("ExecuteCreateVM: %v", err)
	}
	if vm.GetHostName() != "test-host" {
		t.Fatalf("host = %q, want test-host", vm.GetHostName())
	}
}

func TestExecuteCreateVMMappingOnly(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	restore := vfio.SetFS(newPCIBindFakeFS())
	defer restore()
	ctx := adminCtx()
	insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
	insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:41:00.0", Type: "gpu",
		VendorID: "10de", DeviceName: "A100", IOMMUGroup: -1,
	}); err != nil {
		t.Fatalf("UpsertPCIDevice: %v", err)
	}
	if err := corrosion.CreateResourceMapping(ctx, s.db, "accelerator", "test"); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, s.db, "accelerator", "test-host", "0000:41:00.0", "10de", "A100"); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}

	vm, err := s.ExecuteCreateVM(mtlsAdminCtx("entry"), &pb.ExecuteCreateVMRequest{
		Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name:    "mapping-only-exec",
			Devices: []*pb.DeviceSpec{{Mapping: "accelerator"}},
		}},
		ResolvedHost:         "test-host",
		PlacementFingerprint: capacityFingerprintForServer(t, s),
		HopCount:             1,
	})
	if err != nil {
		t.Fatalf("ExecuteCreateVM: %v", err)
	}
	if vm.GetHostName() != "test-host" {
		t.Fatalf("host = %q, want test-host", vm.GetHostName())
	}
}

func invokeDeviceSelectorCreate(t *testing.T, s *Server, execute bool, spec *pb.VMSpec) {
	t.Helper()
	if !execute {
		if _, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{Spec: spec}); err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		return
	}
	if _, err := s.ExecuteCreateVM(mtlsAdminCtx("entry"), &pb.ExecuteCreateVMRequest{
		Request:              &pb.CreateVMRequest{Spec: spec},
		ResolvedHost:         "test-host",
		PlacementFingerprint: capacityFingerprintForServer(t, s),
		HopCount:             1,
	}); err != nil {
		t.Fatalf("ExecuteCreateVM: %v", err)
	}
}

func assertOnlyOwnedPCIAddress(t *testing.T, s *Server, vmName, want string) {
	t.Helper()
	devices, err := corrosion.ListPCIDevices(context.Background(), s.db, s.hostName, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	var owned []string
	for _, device := range devices {
		if device.VMName == vmName {
			owned = append(owned, device.Address)
		}
	}
	if len(owned) != 1 || owned[0] != want {
		t.Fatalf("PCI addresses owned by %q = %v, want [%s]", vmName, owned, want)
	}
}

func TestCreateAndExecuteSRIOVSelectorIgnoreFrozenAddress(t *testing.T) {
	for _, execute := range []bool{false, true} {
		name := "CreateVM"
		if execute {
			name = "ExecuteCreateVM"
		}
		t.Run(name, func(t *testing.T) {
			s := testServerR2(t)
			s.virt = libvirtfake.New()
			restore := vfio.SetFS(newPCIBindFakeFS())
			defer restore()
			insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
			insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)

			pf := "0000:41:00.0"
			vfs := fakeSysfsPF(t, pf, 8, 1)
			seedPCIDevice(t, context.Background(), s, pf, true)
			seedPCIDevice(t, context.Background(), s, vfs[0], false)
			// This is a valid, claimable BDF so the old address-first allocator
			// succeeds with the wrong device instead of merely erroring.
			stale := "0000:42:00.0"
			seedPCIDevice(t, context.Background(), s, stale, false)

			vmName := "sriov-create"
			if execute {
				vmName = "sriov-execute"
			}
			invokeDeviceSelectorCreate(t, s, execute, &pb.VMSpec{
				Name: vmName,
				Placement: &pb.PlacementSpec{
					Host: "test-host",
				},
				Devices: []*pb.DeviceSpec{{
					Sriov: true, Type: "network", Parent: pf,
					Address: stale,
				}},
			})
			assertOnlyOwnedPCIAddress(t, s, vmName, vfs[0])
		})
	}
}

func TestCreateAndExecuteTypeModelSelectorIgnoreFrozenAddress(t *testing.T) {
	for _, execute := range []bool{false, true} {
		name := "CreateVM"
		if execute {
			name = "ExecuteCreateVM"
		}
		t.Run(name, func(t *testing.T) {
			s := testServerR2(t)
			s.virt = libvirtfake.New()
			restore := vfio.SetFS(newPCIBindFakeFS())
			defer restore()
			insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
			insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)

			stale := "0000:41:00.0"
			matched := "0000:42:00.0"
			for _, device := range []corrosion.PCIDeviceRecord{
				{
					HostName: "test-host", Address: stale, Type: "gpu",
					VendorID: "10de", DeviceName: "A100", IOMMUGroup: -1,
				},
				{
					HostName: "test-host", Address: matched, Type: "gpu",
					VendorID: "10de", DeviceName: "H100", IOMMUGroup: -1,
				},
			} {
				if err := corrosion.UpsertPCIDevice(context.Background(), s.db, device); err != nil {
					t.Fatalf("UpsertPCIDevice(%s): %v", device.Address, err)
				}
			}

			vmName := "type-create"
			if execute {
				vmName = "type-execute"
			}
			invokeDeviceSelectorCreate(t, s, execute, &pb.VMSpec{
				Name: vmName,
				Placement: &pb.PlacementSpec{
					Host: "test-host",
				},
				Devices: []*pb.DeviceSpec{{
					Type: "gpu", Vendor: "10de", Model: "H100",
					Address: stale,
				}},
			})
			assertOnlyOwnedPCIAddress(t, s, vmName, matched)
		})
	}
}

func TestCreateAndExecuteVendorOnlySelectorAcrossDeviceTypes(t *testing.T) {
	for _, execute := range []bool{false, true} {
		name := "CreateVM"
		if execute {
			name = "ExecuteCreateVM"
		}
		t.Run(name, func(t *testing.T) {
			s := testServerR2(t)
			s.virt = libvirtfake.New()
			restore := vfio.SetFS(newPCIBindFakeFS())
			defer restore()
			insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
			insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)

			stale := "0000:41:00.0"
			matched := "0000:43:00.0"
			for _, device := range []corrosion.PCIDeviceRecord{
				{
					HostName: "test-host", Address: stale, Type: "gpu",
					VendorID: "1002", DeviceName: "stale-amd", IOMMUGroup: -1,
				},
				{
					HostName: "test-host", Address: "0000:42:00.0", Type: "network",
					VendorID: "8086", DeviceName: "unrelated-nic", IOMMUGroup: -1,
				},
				{
					HostName: "test-host", Address: matched, Type: "nvme",
					VendorID: "10de", DeviceName: "vendor-match", IOMMUGroup: -1,
				},
			} {
				if err := corrosion.UpsertPCIDevice(context.Background(), s.db, device); err != nil {
					t.Fatalf("UpsertPCIDevice(%s): %v", device.Address, err)
				}
			}

			vmName := "vendor-create"
			if execute {
				vmName = "vendor-execute"
			}
			invokeDeviceSelectorCreate(t, s, execute, &pb.VMSpec{
				Name:      vmName,
				Placement: &pb.PlacementSpec{Host: "test-host"},
				Devices: []*pb.DeviceSpec{{
					Vendor:  "10de",
					Address: stale,
				}},
			})
			assertOnlyOwnedPCIAddress(t, s, vmName, matched)
		})
	}
}

func TestCreateAndExecuteRejectWrongDeviceModel(t *testing.T) {
	newServer := func(t *testing.T) *Server {
		t.Helper()
		s := testServerR2(t)
		s.virt = libvirtfake.New()
		insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
		if err := corrosion.UpsertPCIDevice(context.Background(), s.db, corrosion.PCIDeviceRecord{
			HostName: "test-host", Address: "0000:41:00.0", Type: "gpu",
			VendorID: "10de", DeviceName: "A100", IOMMUGroup: -1,
		}); err != nil {
			t.Fatalf("UpsertPCIDevice: %v", err)
		}
		return s
	}
	spec := func(name string) *pb.VMSpec {
		return &pb.VMSpec{
			Name: name, Placement: &pb.PlacementSpec{Host: "test-host"},
			Devices: []*pb.DeviceSpec{{Type: "gpu", Model: "H100"}},
		}
	}

	t.Run("CreateVM", func(t *testing.T) {
		s := newServer(t)
		_, err := s.CreateVM(adminCtx(), &pb.CreateVMRequest{Spec: spec("wrong-model-create")})
		if got := status.Code(err); got != codes.ResourceExhausted {
			t.Fatalf("code = %v, want ResourceExhausted (err=%v)", got, err)
		}
	})
	t.Run("ExecuteCreateVM", func(t *testing.T) {
		s := newServer(t)
		insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)
		_, err := s.ExecuteCreateVM(mtlsAdminCtx("entry"), &pb.ExecuteCreateVMRequest{
			Request:              &pb.CreateVMRequest{Spec: spec("wrong-model-exec")},
			ResolvedHost:         "test-host",
			PlacementFingerprint: capacityFingerprintForServer(t, s),
			HopCount:             1,
		})
		if got := status.Code(err); got != codes.ResourceExhausted {
			t.Fatalf("code = %v, want ResourceExhausted (err=%v)", got, err)
		}
	})
}

func TestExecuteCreateVMRejectsExactAddressIOMMUConflictDuringPlacement(t *testing.T) {
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	insertPlacementExecutorHost(t, s, "test-host", 8, 16384, nil)
	insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)
	for _, device := range []corrosion.PCIDeviceRecord{
		{HostName: "test-host", Address: "0000:41:00.0", Type: "gpu", IOMMUGroup: 9},
		{HostName: "test-host", Address: "0000:41:00.1", Type: "network", IOMMUGroup: 9, VMName: "other-vm"},
	} {
		if err := corrosion.UpsertPCIDevice(context.Background(), s.db, device); err != nil {
			t.Fatalf("UpsertPCIDevice(%s): %v", device.Address, err)
		}
	}

	_, err := s.ExecuteCreateVM(mtlsAdminCtx("entry"), &pb.ExecuteCreateVMRequest{
		Request: &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name:    "iommu-conflict",
			Devices: []*pb.DeviceSpec{{Address: "0000:41:00.0"}},
		}},
		ResolvedHost:         "test-host",
		PlacementFingerprint: capacityFingerprintForServer(t, s),
		HopCount:             1,
	})
	if got := status.Code(err); got != codes.ResourceExhausted {
		t.Fatalf("code = %v, want placement ResourceExhausted (err=%v)", got, err)
	}
}

func TestCreateVMForwardCompatibilityCutover(t *testing.T) {
	newSource := func(t *testing.T, latched bool, peer *createForwardClient) *Server {
		t.Helper()
		s := testServerR2(t)
		s.hostName = "entry"
		insertPlacementExecutorHost(t, s, "entry", 8, 16384, nil)
		insertPlacementExecutorHost(t, s, "target", 8, 16384, nil)
		s.SetGate(fakeServerGate{enforcedTok: map[string]bool{
			testCapacityAdmissionCapability: latched,
		}})
		s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
			return peer, func() {}, nil
		}
		return s
	}
	request := func(name string) *pb.CreateVMRequest {
		return &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: name, Placement: &pb.PlacementSpec{Host: "target"},
		}}
	}

	t.Run("pre-latch legacy forward is hop bounded", func(t *testing.T) {
		peer := &createForwardClient{}
		s := newSource(t, false, peer)
		if _, err := s.CreateVM(adminCtx(), request("legacy")); err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		if peer.createCalls != 1 || peer.executeCalls != 0 {
			t.Fatalf("legacy calls create=%d execute=%d, want 1/0", peer.createCalls, peer.executeCalls)
		}
		md, _ := metadata.FromOutgoingContext(peer.createCtx)
		if got := md.Get(createVMForwardHopMetadata); len(got) != 1 || got[0] != "1" {
			t.Fatalf("forward hop metadata = %v, want [1]", got)
		}
	})

	t.Run("post-latch uses executor", func(t *testing.T) {
		peer := &createForwardClient{}
		s := newSource(t, true, peer)
		if _, err := s.CreateVM(adminCtx(), request("executor")); err != nil {
			t.Fatalf("CreateVM: %v", err)
		}
		if peer.createCalls != 0 || peer.executeCalls != 1 {
			t.Fatalf("latched calls create=%d execute=%d, want 0/1", peer.createCalls, peer.executeCalls)
		}
		if peer.executeReq.GetResolvedHost() != "target" ||
			peer.executeReq.GetHopCount() != 1 ||
			peer.executeReq.GetPlacementFingerprint() == "" {
			t.Fatalf("executor envelope = %+v", peer.executeReq)
		}
	})

	t.Run("post-latch unimplemented does not fall back", func(t *testing.T) {
		peer := &createForwardClient{
			executeErr: status.Error(codes.Unimplemented, "old peer"),
		}
		s := newSource(t, true, peer)
		_, err := s.CreateVM(adminCtx(), request("no-fallback"))
		if got := status.Code(err); got != codes.FailedPrecondition {
			t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
		}
		if peer.createCalls != 0 || peer.executeCalls != 1 {
			t.Fatalf("fallback occurred: create=%d execute=%d", peer.createCalls, peer.executeCalls)
		}
	})
}

func TestCreateVMRejectsForwardHopAboveOne(t *testing.T) {
	s := testServerR2(t)
	ctx := metadata.NewIncomingContext(adminCtx(), metadata.Pairs(createVMForwardHopMetadata, "2"))
	_, err := s.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{Name: "loop"}})
	if got := status.Code(err); got != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
	}
}
