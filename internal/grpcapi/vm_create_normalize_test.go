package grpcapi

import (
	"math"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestNormalizeCreateVMSpecRejectsNilSpec(t *testing.T) {
	_, err := normalizeCreateVMSpec(nil)
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("status code = %v, want InvalidArgument (err = %v)", got, err)
	}
}

func TestNormalizeCreateVMSpecDefaults(t *testing.T) {
	got, err := normalizeCreateVMSpec(&pb.VMSpec{Name: "vm1"})
	if err != nil {
		t.Fatalf("normalizeCreateVMSpec: %v", err)
	}
	if got.Cpu != 2 || got.MemoryMib != 4096 || got.Machine != "q35" || got.Firmware != "uefi" {
		t.Fatalf("normalized spec = %+v, want cpu=2 memory_mib=4096 machine=q35 firmware=uefi", got)
	}
}

func TestNormalizeCreateVMSpecRejectsNegativeResources(t *testing.T) {
	for _, spec := range []*pb.VMSpec{
		{Name: "negative-cpu", Cpu: -1, MemoryMib: 512},
		{Name: "negative-memory", Cpu: 1, MemoryMib: -1},
	} {
		t.Run(spec.Name, func(t *testing.T) {
			_, err := normalizeCreateVMSpec(spec)
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Fatalf("status code = %v, want InvalidArgument (err = %v)", got, err)
			}
		})
	}
}

func TestNormalizeCreateVMSpecClonesInput(t *testing.T) {
	in := &pb.VMSpec{
		Name:   "vm1",
		Labels: map[string]string{"environment": "test"},
	}
	wantInput := proto.Clone(in).(*pb.VMSpec)

	got, err := normalizeCreateVMSpec(in)
	if err != nil {
		t.Fatalf("normalizeCreateVMSpec: %v", err)
	}
	if got == in {
		t.Fatal("normalized spec aliases input")
	}
	got.Labels["environment"] = "changed"
	if !proto.Equal(in, wantInput) {
		t.Fatalf("input mutated: got %+v, want %+v", in, wantInput)
	}
}

func TestNormalizeCreateVMSpecAcceptsInt32ResourceMaximum(t *testing.T) {
	got, err := normalizeCreateVMSpec(&pb.VMSpec{
		Name:      "large-vm",
		Cpu:       math.MaxInt32,
		MemoryMib: math.MaxInt32,
	})
	if err != nil {
		t.Fatalf("normalizeCreateVMSpec: %v", err)
	}
	if got.Cpu != math.MaxInt32 || got.MemoryMib != math.MaxInt32 {
		t.Fatalf("normalized resources = cpu=%d memory_mib=%d, want int32 max", got.Cpu, got.MemoryMib)
	}
}
