package hooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func stubVM(name, host string, state pb.VMState) *pb.VM {
	return &pb.VM{Name: name, HostName: host, State: state}
}

func TestRun_NilSpec(t *testing.T) {
	// Must not panic with nil spec.
	Run(context.Background(), PreStart, stubVM("vm1", "host1", pb.VMState_VM_STARTING), nil)
}

func TestRun_EmptyCmd(t *testing.T) {
	spec := &pb.HooksSpec{PreStart: ""}
	// No-op — should not panic or execute.
	Run(context.Background(), PreStart, stubVM("vm1", "host1", pb.VMState_VM_STARTING), spec)
}

func TestRun_CommandSucceeds(t *testing.T) {
	tmpDir := t.TempDir()
	markerFile := filepath.Join(tmpDir, "ran")

	spec := &pb.HooksSpec{
		PostStart: "touch " + markerFile,
	}
	Run(context.Background(), PostStart, stubVM("vm1", "host1", pb.VMState_VM_RUNNING), spec)

	// Give the subprocess a moment (Run is synchronous, so this is just a safety check).
	time.Sleep(50 * time.Millisecond)

	if _, err := os.Stat(markerFile); err != nil {
		t.Errorf("hook did not run: marker file missing: %v", err)
	}
}

func TestRun_CommandWithEnvVars(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "env.txt")

	spec := &pb.HooksSpec{
		PreStop: "echo $LV_VM_NAME > " + outFile,
	}
	Run(context.Background(), PreStop, stubVM("myvm", "host1", pb.VMState_VM_STOPPING), spec)

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("hook output file missing: %v", err)
	}
	content := string(data)
	if content == "" || content == "\n" {
		t.Errorf("LV_VM_NAME env var not set in hook: got %q", content)
	}
}

func TestRun_CommandFails_NoError(t *testing.T) {
	// Failing hook must not propagate an error (hooks are non-blocking).
	spec := &pb.HooksSpec{
		PreStart: "exit 1",
	}
	// Should not panic or cause test to fail.
	Run(context.Background(), PreStart, stubVM("vm1", "host1", pb.VMState_VM_STARTING), spec)
}

func TestRun_UnknownEvent(t *testing.T) {
	spec := &pb.HooksSpec{PreStart: "exit 1"}
	// Unknown event has no matching command — must be a no-op.
	Run(context.Background(), "unknown_event", stubVM("vm1", "host1", pb.VMState_VM_RUNNING), spec)
}

func TestHookCmd(t *testing.T) {
	spec := &pb.HooksSpec{
		PreStart:    "pre-start-cmd",
		PostStart:   "post-start-cmd",
		PreStop:     "pre-stop-cmd",
		PostStop:    "post-stop-cmd",
		PreMigrate:  "pre-migrate-cmd",
		PostMigrate: "post-migrate-cmd",
	}
	tests := []struct {
		event string
		want  string
	}{
		{PreStart, "pre-start-cmd"},
		{PostStart, "post-start-cmd"},
		{PreStop, "pre-stop-cmd"},
		{PostStop, "post-stop-cmd"},
		{PreMigrate, "pre-migrate-cmd"},
		{PostMigrate, "post-migrate-cmd"},
		{"unknown", ""},
	}
	for _, tt := range tests {
		got := hookCmd(spec, tt.event)
		if got != tt.want {
			t.Errorf("hookCmd(%q) = %q, want %q", tt.event, got, tt.want)
		}
	}
}

func TestBuildEnv_ContainsRequiredVars(t *testing.T) {
	vm := &pb.VM{
		Name:     "test-vm",
		HostName: "node1",
		State:    pb.VMState_VM_RUNNING,
		Interfaces: []*pb.VMInterface{
			{Ip: "10.0.0.5"},
		},
	}
	env := buildEnv(PostStart, vm)

	check := map[string]bool{
		"LV_EVENT=post_start":  false,
		"LV_VM_NAME=test-vm":   false,
		"LV_VM_HOST=node1":     false,
		"LV_VM_STATE=running":  false,
		"LV_VM_IP=10.0.0.5":   false,
	}
	for _, e := range env {
		check[e] = true
	}
	for k, found := range check {
		if !found {
			t.Errorf("env missing %q", k)
		}
	}
}

func TestVMStateString(t *testing.T) {
	tests := []struct {
		state pb.VMState
		want  string
	}{
		{pb.VMState_VM_RUNNING, "running"},
		{pb.VMState_VM_STOPPED, "stopped"},
		{pb.VMState_VM_STARTING, "starting"},
		{pb.VMState_VM_STOPPING, "stopping"},
		{pb.VMState_VM_MIGRATING, "migrating"},
		{pb.VMState_VM_ERROR, "error"},
		{pb.VMState_VM_UNKNOWN, "unknown"},
	}
	for _, tt := range tests {
		got := vmStateString(tt.state)
		if got != tt.want {
			t.Errorf("vmStateString(%v) = %q, want %q", tt.state, got, tt.want)
		}
	}
}
