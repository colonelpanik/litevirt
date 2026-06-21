package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestAttachDevice_EmptyName(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestAttachDevice_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "ghost",
		Disk:   &pb.DiskSpec{Name: "data", Size: "10G"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestAttachDevice_NotRunning(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "stopped-vm", "test-host", "stopped")

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "stopped-vm",
		Disk:   &pb.DiskSpec{Name: "data", Size: "10G"},
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestAttachDevice_NoDeviceSpecified(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "running-vm", "test-host", "running")

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "running-vm",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestDetachDevice_EmptyName(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestDetachDevice_NotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName:   "ghost",
		DiskName: "data",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestDetachDevice_NotRunning(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "stopped-vm", "test-host", "stopped")

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName:   "stopped-vm",
		DiskName: "data",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Errorf("code = %v, want FailedPrecondition", c)
	}
}

func TestDetachDevice_NoDeviceSpecified(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "running-vm", "test-host", "running")

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{
		VmName: "running-vm",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestParseDiskSize(t *testing.T) {
	tests := []struct {
		input   string
		wantGB  int
		wantErr bool
	}{
		{"20G", 20, false},
		{"100GB", 100, false},
		{"1T", 1024, false},
		{"512M", 1, false}, // rounds up
		{"50", 50, false},
		{"", 0, true},
		{"abc", 0, true},
	}
	for _, tt := range tests {
		got, err := parseDiskSize(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("parseDiskSize(%q): expected error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseDiskSize(%q): %v", tt.input, err)
			continue
		}
		if got != tt.wantGB {
			t.Errorf("parseDiskSize(%q) = %d, want %d", tt.input, got, tt.wantGB)
		}
	}
}

func TestCountVMDisks(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	// No disks.
	if n := countVMDisks(ctx, s.db, "nonexistent"); n != 0 {
		t.Errorf("countVMDisks = %d, want 0", n)
	}
}
