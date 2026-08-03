package compose

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestNormalizeVMSpecResources: 0 means "use the create default", and the
// normalization has to happen BEFORE admission reads these fields — every
// admission check is a no-op at zero, so a zero spec used to be admitted free and
// then run at the defaults.
func TestNormalizeVMSpecResources(t *testing.T) {
	for _, c := range []struct {
		name             string
		in               *pb.VMSpec
		wantCPU, wantMem int32
	}{
		{"both zero take defaults", &pb.VMSpec{}, DefaultVMCPU, DefaultVMMemoryMiB},
		{"explicit values are untouched", &pb.VMSpec{Cpu: 1, MemoryMib: 512}, 1, 512},
		{"only cpu zero", &pb.VMSpec{MemoryMib: 512}, DefaultVMCPU, 512},
		{"only memory zero", &pb.VMSpec{Cpu: 1}, 1, DefaultVMMemoryMiB},
		// A spec that already equals the defaults must be indistinguishable from
		// one that was defaulted — the function has to be idempotent, because the
		// forwarded owner leg and a replan both call it again.
		{"already defaulted is idempotent", &pb.VMSpec{Cpu: DefaultVMCPU, MemoryMib: DefaultVMMemoryMiB}, DefaultVMCPU, DefaultVMMemoryMiB},
	} {
		t.Run(c.name, func(t *testing.T) {
			NormalizeVMSpecResources(c.in)
			if c.in.Cpu != c.wantCPU {
				t.Errorf("Cpu = %d, want %d", c.in.Cpu, c.wantCPU)
			}
			if c.in.MemoryMib != c.wantMem {
				t.Errorf("MemoryMib = %d, want %d", c.in.MemoryMib, c.wantMem)
			}
			// Second call must change nothing.
			NormalizeVMSpecResources(c.in)
			if c.in.Cpu != c.wantCPU || c.in.MemoryMib != c.wantMem {
				t.Errorf("not idempotent: second call gave %d/%d, want %d/%d",
					c.in.Cpu, c.in.MemoryMib, c.wantCPU, c.wantMem)
			}
		})
	}

	// Must not panic on a nil spec — callers pass req.Spec straight through.
	NormalizeVMSpecResources(nil)
}
