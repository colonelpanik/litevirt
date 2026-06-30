package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

func TestCheckContainerRuntime(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.SetContainerRuntime(&fakeCTRuntime{
		listNames:   []string{"run-ct", "stopped-ct"},
		stateByName: map[string]string{"run-ct": "running", "stopped-ct": "stopped"},
	})
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "peer-1", Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	peer := mtlsAdminCtx("peer-1")

	cases := []struct{ name, ct, want string }{
		{"running", "run-ct", health.RuntimeRunning},
		{"defined-stopped", "stopped-ct", health.RuntimeDefinedStopped},
		{"absent", "ghost-ct", health.RuntimeAbsent},
	}
	for _, tc := range cases {
		resp, err := s.CheckContainerRuntime(peer, &pb.CheckContainerRuntimeRequest{Name: tc.ct})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if resp.GetState() != tc.want {
			t.Errorf("%s: state = %q, want %q", tc.name, resp.GetState(), tc.want)
		}
	}

	// Peer-only.
	if _, err := s.CheckContainerRuntime(adminCtx(), &pb.CheckContainerRuntimeRequest{Name: "run-ct"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-peer caller: want PermissionDenied, got %v", err)
	}
}
