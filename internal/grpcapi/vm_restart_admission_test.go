package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestRestartVM_StoppedVM_IsAnAdmittedStart: restarting a STOPPED VM brings
// its full consumption (guest memory + qemu overhead) onto the host — exactly
// what StartVM admits — and must not slip through as an unadmitted start.
func TestRestartVM_StoppedVM_IsAnAdmittedStart(t *testing.T) {
	s := testServerWithLocks(t)
	admissionHost(t, s) // allocatable 1536 MiB
	fake := libvirtfake.New()
	s.virt = fake
	fake.SetState("cold-big", "stopped") // defined but not running
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "cold-big", HostName: "test-host", State: "stopped",
		Spec: `{"name":"cold-big","cpu":2,"memory_mib":2048}`, CPUActual: 2, MemActual: 2048,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	_, err := s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "cold-big"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("restarting a stopped 2048 MiB VM on a host with 1536 MiB allocatable: got %v, "+
			"want ResourceExhausted — a restart of a stopped VM is a start", err)
	}
	if st, _ := s.virt.DomainState("cold-big"); st == "running" {
		t.Fatal("refused restart still started the domain")
	}
}

// TestRestartVM_RunningVM_NotAdmitted: a restart of a RUNNING VM is net-zero —
// its consumption is already counted, overhead included — so a full host must
// always be able to restart what it already runs.
func TestRestartVM_RunningVM_NotAdmitted(t *testing.T) {
	s := testServerWithLocks(t)
	admissionHost(t, s) // allocatable 1536 MiB
	fake := libvirtfake.New()
	s.virt = fake
	ctx := context.Background()
	// The running VM occupies more than the host's remaining headroom — an
	// erroneous re-admission would compute 1400+overhead against ~136 free.
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "hot-vm", HostName: "test-host", State: "running",
		Spec: `{"name":"hot-vm","cpu":2,"memory_mib":1400}`, CPUActual: 2, MemActual: 1400,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetState("hot-vm", "running")

	if _, err := s.RestartVM(adminCtx(), &pb.RestartVMRequest{Name: "hot-vm"}); err != nil {
		t.Fatalf("restart of a running VM on a full host: %v — net-zero restarts must not be re-admitted", err)
	}
	if st, _ := fake.DomainState("hot-vm"); st != "running" {
		t.Fatalf("restarted domain state = %q, want running", st)
	}
}
