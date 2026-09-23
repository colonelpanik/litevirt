package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
)

// projectionClient answers ListVMs the way the daemon does — with a PROJECTION
// of each spec that carries no image and no cloud-init — and InspectVM with the
// full spec. `lv compose diff` used to build its current state off the
// projection alone, so every VM in a cloud-init stack read as "image →X
// cloud-init added" even when nothing had changed.
type projectionClient struct {
	pb.LiteVirtClient
	full []*pb.VM
}

func (p *projectionClient) ListVMs(_ context.Context, in *pb.ListVMsRequest, _ ...grpc.CallOption) (*pb.ListVMsResponse, error) {
	var out []*pb.VM
	for _, vm := range p.full {
		if vm.StackName != in.StackName {
			continue
		}
		out = append(out, &pb.VM{
			Name: vm.Name, StackName: vm.StackName, HostName: vm.HostName, State: vm.State,
			CpuActual: vm.CpuActual, MemActualMib: vm.MemActualMib,
			Spec: &pb.VMSpec{Uuid: vm.Spec.Uuid, Machine: vm.Spec.Machine},
		})
	}
	return &pb.ListVMsResponse{Vms: out}, nil
}

func (p *projectionClient) InspectVM(_ context.Context, in *pb.InspectVMRequest, _ ...grpc.CallOption) (*pb.VM, error) {
	for _, vm := range p.full {
		if vm.Name == in.Name {
			return vm, nil
		}
	}
	return nil, os.ErrNotExist
}

func TestComposeDiff_UnchangedCloudInitStackIsNoChange(t *testing.T) {
	userdata := "#cloud-config\nusers:\n  - name: ubuntu\n"
	yaml := "name: devs\nvms:\n  box-1:\n    image: LTS-24.04\n    cpu: 4\n    memory: 8192\n" +
		"    cloud-init:\n      userdata: |\n        #cloud-config\n        users:\n          - name: ubuntu\n"
	file := filepath.Join(t.TempDir(), "litevirt.yaml")
	if err := os.WriteFile(file, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}

	origConnect := cli.Connect
	t.Cleanup(func() { cli.Connect = origConnect })
	cli.Connect = func(_ context.Context) (pb.LiteVirtClient, func(), error) {
		return &projectionClient{full: []*pb.VM{{
			Name: "box-1", StackName: "devs", HostName: "h1", State: pb.VMState_VM_RUNNING,
			CpuActual: 4, MemActualMib: 8192,
			Spec: &pb.VMSpec{
				Name: "box-1", Image: "LTS-24.04", Cpu: 4, MemoryMib: 8192, Uuid: "u-1", Machine: "q35",
				GuestAgent: true, Boot: "disk", CpuMode: "host-model",
				CloudInit: &pb.CloudInitSpec{Userdata: userdata},
			},
		}}}, func() {}, nil
	}

	out := captureStdout(t, func() {
		cmd := newDiffCmd()
		cmd.SetArgs([]string{"-f", file})
		if err := cmd.Execute(); err != nil {
			t.Errorf("diff: %v", err)
		}
	})
	if !strings.Contains(out, "0 to update") || !strings.Contains(out, "1 unchanged") {
		t.Errorf("diff of an unchanged cloud-init stack should be a no-op, got:\n%s", out)
	}
	if strings.Contains(out, "cloud-init added") || strings.Contains(out, "image →") {
		t.Errorf("diff reports phantom changes from the ListVMs projection:\n%s", out)
	}
}

// The daemon plans a retry (an update, delete + recreate by default) for a VM
// in error state. The CLI diff fed the planner the proto enum name
// ("VM_ERROR") where it expects the stored state ("error"), so the same VM
// read as unchanged — hiding a destructive step the server would take.
func TestComposeDiff_ErrorStateVMIsRetried(t *testing.T) {
	yaml := "name: devs\nvms:\n  box-1:\n    image: LTS-24.04\n    cpu: 4\n    memory: 8192\n"
	file := filepath.Join(t.TempDir(), "litevirt.yaml")
	if err := os.WriteFile(file, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	origConnect := cli.Connect
	t.Cleanup(func() { cli.Connect = origConnect })
	cli.Connect = func(_ context.Context) (pb.LiteVirtClient, func(), error) {
		return &projectionClient{full: []*pb.VM{{
			Name: "box-1", StackName: "devs", HostName: "h1", State: pb.VMState_VM_ERROR,
			CpuActual: 4, MemActualMib: 8192,
			Spec: &pb.VMSpec{Name: "box-1", Image: "LTS-24.04", Cpu: 4, MemoryMib: 8192, Uuid: "u-1", GuestAgent: true, Boot: "disk"},
		}}}, func() {}, nil
	}
	out := captureStdout(t, func() {
		cmd := newDiffCmd()
		cmd.SetArgs([]string{"-f", file})
		if err := cmd.Execute(); err != nil {
			t.Errorf("diff: %v", err)
		}
	})
	if !strings.Contains(out, "1 to update") || !strings.Contains(out, "retry box-1") {
		t.Errorf("an error-state VM must show as a retry, got:\n%s", out)
	}
}

// With cpu/memory/image/cloud-init unchanged, an edit to any other spec field
// (cpu-mode here) must still show as an update in the diff.
func TestComposeDiff_CPUModeEditIsUpdate(t *testing.T) {
	yaml := "name: devs\nvms:\n  box-1:\n    image: LTS-24.04\n    cpu: 4\n    memory: 8192\n    cpu-mode: host-passthrough\n"
	file := filepath.Join(t.TempDir(), "litevirt.yaml")
	if err := os.WriteFile(file, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	origConnect := cli.Connect
	t.Cleanup(func() { cli.Connect = origConnect })
	cli.Connect = func(_ context.Context) (pb.LiteVirtClient, func(), error) {
		return &projectionClient{full: []*pb.VM{{
			Name: "box-1", StackName: "devs", HostName: "h1", State: pb.VMState_VM_RUNNING,
			CpuActual: 4, MemActualMib: 8192,
			Spec: &pb.VMSpec{Name: "box-1", Image: "LTS-24.04", Cpu: 4, MemoryMib: 8192, Uuid: "u-1",
				GuestAgent: true, Boot: "disk", CpuMode: "host-model", Machine: "q35"},
		}}}, func() {}, nil
	}
	out := captureStdout(t, func() {
		cmd := newDiffCmd()
		cmd.SetArgs([]string{"-f", file})
		if err := cmd.Execute(); err != nil {
			t.Errorf("diff: %v", err)
		}
	})
	if !strings.Contains(out, "1 to update") || !strings.Contains(out, "cpu-mode") {
		t.Errorf("a cpu-mode edit must show as an update naming the reason, got:\n%s", out)
	}
}
