package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// reconfigure tests cover the v1.0.x "live reconfigure" behavior of UpdateVM:
// lifecycle/metadata fields (restart policy, onboot, startup ordering) apply
// while the VM runs (no redefine); redefine-class fields (cpu/memory/machine/
// firmware/mem-bounds/guest-agent) require the VM stopped.

func reconfigServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	s.virt = libvirtfake.New() // metadata path uses vmToProto; redefine path uses Define/Undefine
	return s
}

func loadStoredSpec(t *testing.T, s *Server, name string) *pb.VMSpec {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), s.db, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM(%s): err=%v nil=%v", name, err, vm == nil)
	}
	spec := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			t.Fatalf("unmarshal spec for %s: %v", name, err)
		}
	}
	return spec
}

func seedSpecJSON(t *testing.T, spec *pb.VMSpec) string {
	t.Helper()
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatalf("marshal seed spec: %v", err)
	}
	return string(b)
}

// (1) Restart policy applies LIVE to a running VM — no stop, no redefine.
func TestUpdateVM_RestartPolicy_LiveOnRunning(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "rp-live", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "rp-live", Cpu: 2, MemoryMib: 4096}))

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name:    "rp-live",
		Restart: &pb.RestartPolicy{Condition: "on-failure", Delay: "5s", MaxAttempts: 3, Window: "1h"},
	})
	if err != nil {
		t.Fatalf("metadata update on running VM should succeed, got: %v", err)
	}
	spec := loadStoredSpec(t, s, "rp-live")
	if spec.Restart == nil {
		t.Fatal("spec.Restart not persisted")
	}
	if spec.Restart.Condition != "on-failure" || spec.Restart.Delay != "5s" ||
		spec.Restart.MaxAttempts != 3 || spec.Restart.Window != "1h" {
		t.Errorf("restart policy = %+v, want on-failure/5s/3/1h", spec.Restart)
	}
	// CPU/memory must be untouched (not part of this update).
	if spec.Cpu != 2 || spec.MemoryMib != 4096 {
		t.Errorf("cpu/mem changed unexpectedly: %d/%d", spec.Cpu, spec.MemoryMib)
	}
}

// (2) condition "none" clears an existing policy.
func TestUpdateVM_RestartPolicy_ClearWithNone(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "rp-clear", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "rp-clear", Restart: &pb.RestartPolicy{Condition: "always"}}))

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name:    "rp-clear",
		Restart: &pb.RestartPolicy{Condition: "none"},
	})
	if err != nil {
		t.Fatalf("clear update should succeed: %v", err)
	}
	if spec := loadStoredSpec(t, s, "rp-clear"); spec.Restart != nil {
		t.Errorf("restart policy not cleared: %+v", spec.Restart)
	}
}

// (3) onboot / startup ordering optional fields persist; nil = unchanged.
func TestUpdateVM_LifecycleFields_Persist(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "lc", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "lc"}))

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name:          "lc",
		Onboot:        proto.Bool(true),
		StartupOrder:  proto.Int32(5),
		StartDelaySec: proto.Int32(3),
		StopDelaySec:  proto.Int32(7),
	})
	if err != nil {
		t.Fatalf("lifecycle update should succeed: %v", err)
	}
	spec := loadStoredSpec(t, s, "lc")
	if !spec.Onboot || spec.StartupOrder != 5 || spec.StartDelaySec != 3 || spec.StopDelaySec != 7 {
		t.Errorf("lifecycle fields = onboot:%v order:%d start:%d stop:%d, want true/5/3/7",
			spec.Onboot, spec.StartupOrder, spec.StartDelaySec, spec.StopDelaySec)
	}
}

// (4) redefine-class fields on a RUNNING VM are rejected before any libvirt call.
func TestUpdateVM_RedefineOnRunning_Rejected(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "rd-run", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "rd-run", Cpu: 2}))

	cases := []struct {
		name string
		req  *pb.UpdateVMRequest
	}{
		{"machine", &pb.UpdateVMRequest{Name: "rd-run", Machine: "q35"}},
		{"firmware", &pb.UpdateVMRequest{Name: "rd-run", Firmware: "uefi"}},
		{"cpu", &pb.UpdateVMRequest{Name: "rd-run", Cpu: 4}},
		{"min-mem", &pb.UpdateVMRequest{Name: "rd-run", MinMemoryMib: proto.Int32(512)}},
		{"guest-agent", &pb.UpdateVMRequest{Name: "rd-run", GuestAgent: proto.Bool(true)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.UpdateVM(ctx, tc.req)
			if status.Code(err) != codes.FailedPrecondition {
				t.Errorf("code = %v, want FailedPrecondition", status.Code(err))
			}
		})
	}
}

// (5) redefine-class fields on a STOPPED VM persist + redefine the domain.
func TestUpdateVM_RedefineOnStopped_Persists(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "rd-stop", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "rd-stop", Cpu: 2, MemoryMib: 4096, Machine: "pc"}))

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name:         "rd-stop",
		Cpu:          4,
		MemoryMib:    2048,
		Machine:      "q35",
		Firmware:     "uefi",
		GuestAgent:   proto.Bool(true),
		MinMemoryMib: proto.Int32(1024),
		MaxMemoryMib: proto.Int32(8192),
	})
	if err != nil {
		t.Fatalf("stopped redefine should succeed: %v", err)
	}
	spec := loadStoredSpec(t, s, "rd-stop")
	if spec.Cpu != 4 || spec.MemoryMib != 2048 || spec.Machine != "q35" ||
		spec.Firmware != "uefi" || !spec.GuestAgent ||
		spec.MinMemoryMib != 1024 || spec.MaxMemoryMib != 8192 {
		t.Errorf("redefine fields not persisted: %+v", spec)
	}
}

// (6) absent fields are left unchanged (a metadata-only update preserves resources).
func TestUpdateVM_AbsentFieldsUnchanged(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "keep", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{
			Name: "keep", Cpu: 8, MemoryMib: 16384,
			Restart: &pb.RestartPolicy{Condition: "on-failure"},
		}))

	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "keep", Onboot: proto.Bool(true)}); err != nil {
		t.Fatalf("update should succeed: %v", err)
	}
	spec := loadStoredSpec(t, s, "keep")
	if spec.Cpu != 8 || spec.MemoryMib != 16384 {
		t.Errorf("resources changed by metadata-only update: cpu=%d mem=%d", spec.Cpu, spec.MemoryMib)
	}
	if spec.Restart == nil || spec.Restart.Condition != "on-failure" {
		t.Errorf("restart policy clobbered: %+v", spec.Restart)
	}
	if !spec.Onboot {
		t.Error("onboot not applied")
	}
}

// (7) a mixed live+redefine update on a RUNNING VM is rejected atomically — the
// live field must NOT be applied when the redefine guard fires.
func TestUpdateVM_MixedOnRunning_RejectedAtomically(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "mixed", "test-host", "running",
		seedSpecJSON(t, &pb.VMSpec{Name: "mixed", Cpu: 2}))

	_, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{
		Name:    "mixed",
		Restart: &pb.RestartPolicy{Condition: "always"},
		Cpu:     4, // redefine-class → whole call rejected
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
	if spec := loadStoredSpec(t, s, "mixed"); spec.Restart != nil {
		t.Errorf("restart policy was applied despite rejection: %+v", spec.Restart)
	}
}
