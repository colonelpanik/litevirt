package grpcapi

import (
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A rolling in-place update of a recreate-class change fails fast and NEVER deletes
// the VM — the executor propagates the error (so Deploy skips UpsertStack) and the
// VM survives.
func TestExecuteWithRollingUpdates_InPlaceRecreate_FailsNoDelete(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	seedRunningVM(t, s, "web", &pb.VMSpec{Name: "web", Cpu: 2, MaxCpu: 8, MemoryMib: 2048}, 2, 2048)

	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 2, Update: &compose.UpdateDef{Strategy: "in-place"}},
	}}
	resolved := &planner.ResolvedPlan{StackName: "st", VMs: []planner.VMAction{{
		Kind: planner.OpUpdate, VMName: "web", TargetHost: "test-host",
		Spec: &pb.VMSpec{Name: "web", Cpu: 2, Image: "debian-12"},
		Plan: compose.ChangePlan{RecreateReasons: []string{"image change recreates"}},
	}}}
	stream := &progressStream[pb.DeployProgress]{ctx: ctx}

	if err := s.executeWithRollingUpdates(ctx, f, resolved, stream); err == nil {
		t.Fatal("in-place of a recreate-class change must fail")
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm == nil {
		t.Fatal("VM was deleted by a failed in-place update — must never happen")
	}
}

// A rolling in-place update whose live resize fails propagates the error and does not
// delete the VM.
func TestExecuteWithRollingUpdates_InPlaceResizeError_Propagates(t *testing.T) {
	s := coordResizeServer(t)
	ctx := adminCtx()
	seedRunningVM(t, s, "web", &pb.VMSpec{Name: "web", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, MaxMemoryMib: 8192}, 2, 2048)
	s.virt.(*libvirtfake.Fake).FailSetVCPUs = func(string, int) error { return errors.New("inject vcpu failure") }

	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{
		"web": {Image: "ubuntu", CPU: 4, Update: &compose.UpdateDef{Strategy: "in-place"}},
	}}
	resolved := &planner.ResolvedPlan{StackName: "st", VMs: []planner.VMAction{{
		Kind: planner.OpUpdate, VMName: "web", TargetHost: "test-host",
		Spec: &pb.VMSpec{Name: "web", Cpu: 4, MemoryMib: 2048},
		Plan: compose.ChangePlan{ResourceChanges: []compose.Delta{{Field: "cpu", Old: "2", New: "4"}}},
	}}}
	stream := &progressStream[pb.DeployProgress]{ctx: ctx}

	if err := s.executeWithRollingUpdates(ctx, f, resolved, stream); err == nil {
		t.Fatal("a live-resize failure must propagate from the executor")
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm == nil {
		t.Fatal("VM deleted by a failed in-place resize")
	}
}

func TestUseRollingUpdate_Recreate(t *testing.T) {
	f := &compose.File{
		Name: "test-stack",
		VMs: map[string]compose.VMDef{
			"web": {
				CPU: 2,
				Update: &compose.UpdateDef{
					Strategy: "recreate",
				},
			},
			"db": {
				CPU: 4,
				Update: &compose.UpdateDef{
					Strategy: "recreate",
				},
			},
		},
	}
	got := useRollingUpdate(f)
	if got != "" {
		t.Errorf("useRollingUpdate() = %q, want %q", got, "")
	}
}

func TestUseRollingUpdate_StartFirst(t *testing.T) {
	f := &compose.File{
		Name: "test-stack",
		VMs: map[string]compose.VMDef{
			"web": {
				CPU: 2,
				Update: &compose.UpdateDef{
					Strategy: "start-first",
				},
			},
		},
	}
	got := useRollingUpdate(f)
	if got != "start-first" {
		t.Errorf("useRollingUpdate() = %q, want %q", got, "start-first")
	}
}

func TestUseRollingUpdate_NoUpdate(t *testing.T) {
	f := &compose.File{
		Name: "test-stack",
		VMs: map[string]compose.VMDef{
			"web": {
				CPU: 2,
			},
			"db": {
				CPU: 4,
			},
		},
	}
	got := useRollingUpdate(f)
	if got != "" {
		t.Errorf("useRollingUpdate() = %q, want %q", got, "")
	}
}

func TestUseRollingUpdate_Empty(t *testing.T) {
	f := &compose.File{
		Name: "test-stack",
		VMs: map[string]compose.VMDef{
			"web": {
				CPU: 2,
				Update: &compose.UpdateDef{
					Strategy: "",
				},
			},
		},
	}
	got := useRollingUpdate(f)
	if got != "" {
		t.Errorf("useRollingUpdate() = %q, want %q", got, "")
	}
}
