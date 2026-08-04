package grpcapi

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
)

// normalizeCreateVMSpec returns a cloned create spec with the API defaults
// materialized. Server-owned fields, such as UUID, are assigned by local create.
func normalizeCreateVMSpec(in *pb.VMSpec) (*pb.VMSpec, error) {
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "spec is required")
	}

	spec := proto.Clone(in).(*pb.VMSpec)
	if spec.Cpu < 0 || spec.MemoryMib < 0 {
		return nil, status.Error(codes.InvalidArgument, "cpu and memory_mib must be non-negative")
	}
	// Same defaults compose.NormalizeVMSpecResources applies before admission.
	// Sharing the constants is load-bearing: if the two drifted, admission would
	// charge one figure and the domain would run on another.
	if spec.Cpu == 0 {
		spec.Cpu = compose.DefaultVMCPU
	}
	if spec.MemoryMib == 0 {
		spec.MemoryMib = compose.DefaultVMMemoryMiB
	}
	if spec.Machine == "" {
		spec.Machine = "q35"
	}
	if spec.Firmware == "" {
		spec.Firmware = "uefi"
	}
	return spec, nil
}
