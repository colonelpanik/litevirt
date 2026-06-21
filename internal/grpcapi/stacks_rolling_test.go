package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

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
