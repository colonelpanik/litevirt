package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func TestCheckVMRuntime(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	// A registered host so the peer-cert gate passes.
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	peer := mtlsAdminCtx("peer-1")

	fake.SetState("run-vm", libvirtfake.StateRunning)
	fake.SetState("stopped-vm", libvirtfake.StateDefined)

	cases := []struct {
		name, vm, want string
	}{
		{"running", "run-vm", health.RuntimeRunning},
		{"defined-stopped", "stopped-vm", health.RuntimeDefinedStopped},
		{"absent", "ghost-vm", health.RuntimeAbsent},
	}
	for _, tc := range cases {
		resp, err := s.CheckVMRuntime(peer, &pb.CheckVMRuntimeRequest{Name: tc.vm})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if resp.GetState() != tc.want {
			t.Errorf("%s: state = %q, want %q", tc.name, resp.GetState(), tc.want)
		}
	}

	// Peer-only: an operator/non-peer caller is rejected (it must never probe
	// runtime state with a bearer credential).
	if _, err := s.CheckVMRuntime(adminCtx(), &pb.CheckVMRuntimeRequest{Name: "run-vm"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-peer caller: want PermissionDenied, got %v", err)
	}
}
