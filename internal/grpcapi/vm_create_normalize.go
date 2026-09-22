package grpcapi

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// normalizeCreateVMSpec returns a cloned create spec with the API defaults
// materialized. Server-owned fields, such as UUID, are assigned by local create.
//
// defaultCPUMode is the node's configured cpu_mode default (vm.default_cpu_mode);
// empty means "use libvirt.DefaultCPUMode". It is materialized HERE, into the
// stored spec, and deliberately not in the renderer: a VM already persisted with
// an empty cpu_mode must keep rendering with no <cpu> element, so a rolling
// upgrade can never move a running guest's CPU model underneath it.
func normalizeCreateVMSpec(in *pb.VMSpec, defaultCPUMode string) (*pb.VMSpec, error) {
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
	// A new VM gets a real CPU model. Without this the domain carries no <cpu>
	// element and the guest lands on QEMU's qemu64 — no SSE4.2, no AVX, no AVX2 —
	// which modern guest binaries increasingly refuse to run on.
	if spec.CpuMode == "" && spec.CpuModel == "" {
		if defaultCPUMode == "" {
			defaultCPUMode = lv.DefaultCPUMode
		}
		spec.CpuMode = defaultCPUMode
	}
	if err := lv.ValidateCPUMode(spec.CpuMode, spec.CpuModel); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return spec, nil
}
