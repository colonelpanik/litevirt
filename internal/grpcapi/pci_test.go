package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

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
