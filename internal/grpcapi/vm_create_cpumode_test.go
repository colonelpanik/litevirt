package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A create that names no CPU mode must land on a real one. Without this the
// stored spec keeps an empty cpu_mode, the domain gets no <cpu> element, and the
// guest runs on QEMU's qemu64 — no SSE4.2, no AVX, no AVX2.
func TestNormalizeCreateVMSpecDefaultsCPUMode(t *testing.T) {
	got, err := normalizeCreateVMSpec(&pb.VMSpec{Name: "vm1"}, "")
	if err != nil {
		t.Fatalf("normalizeCreateVMSpec: %v", err)
	}
	if got.CpuMode != lv.DefaultCPUMode {
		t.Fatalf("cpu_mode = %q, want %q", got.CpuMode, lv.DefaultCPUMode)
	}
	if got.CpuModel != "" {
		t.Fatalf("cpu_model = %q, want empty for a host-derived mode", got.CpuModel)
	}
}

// The node's configured default wins over the built-in one — that is the opt-out
// for a fleet that cannot take a host-derived CPU.
func TestNormalizeCreateVMSpecHonorsConfiguredDefault(t *testing.T) {
	got, err := normalizeCreateVMSpec(&pb.VMSpec{Name: "vm1"}, lv.CPUModeHostPassthrough)
	if err != nil {
		t.Fatalf("normalizeCreateVMSpec: %v", err)
	}
	if got.CpuMode != lv.CPUModeHostPassthrough {
		t.Fatalf("cpu_mode = %q, want the configured %q", got.CpuMode, lv.CPUModeHostPassthrough)
	}
}

// An explicit per-VM choice beats both defaults.
func TestNormalizeCreateVMSpecKeepsExplicitCPUMode(t *testing.T) {
	got, err := normalizeCreateVMSpec(
		&pb.VMSpec{Name: "vm1", CpuMode: lv.CPUModeCustom, CpuModel: "x86-64-v3"},
		lv.CPUModeHostModel)
	if err != nil {
		t.Fatalf("normalizeCreateVMSpec: %v", err)
	}
	if got.CpuMode != lv.CPUModeCustom || got.CpuModel != "x86-64-v3" {
		t.Fatalf("cpu_mode/cpu_model = %q/%q, want custom/x86-64-v3", got.CpuMode, got.CpuModel)
	}
}

// An invalid pair is refused at the API boundary, not at libvirt define time.
func TestNormalizeCreateVMSpecRejectsInvalidCPUPairs(t *testing.T) {
	for _, tc := range []struct{ name, mode, model string }{
		{"custom without model", lv.CPUModeCustom, ""},
		{"model without custom", lv.CPUModeHostModel, "x86-64-v3"},
		{"unknown mode", "host-passthru", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeCreateVMSpec(
				&pb.VMSpec{Name: "vm1", CpuMode: tc.mode, CpuModel: tc.model}, "")
			if got := status.Code(err); got != codes.InvalidArgument {
				t.Fatalf("status code = %v, want InvalidArgument (err = %v)", got, err)
			}
		})
	}
}

// A create that names ONLY a model is not silently defaulted into an invalid
// pair: defaulting the mode to host-model there would produce host-model +
// model, which ValidateCPUMode rejects. It must be refused with the model
// error, not turned into something the operator did not ask for.
func TestNormalizeCreateVMSpecRejectsModelWithoutMode(t *testing.T) {
	_, err := normalizeCreateVMSpec(&pb.VMSpec{Name: "vm1", CpuModel: "x86-64-v3"}, "")
	if got := status.Code(err); got != codes.InvalidArgument {
		t.Fatalf("status code = %v, want InvalidArgument (err = %v)", got, err)
	}
}
