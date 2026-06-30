package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/health"
)

// CheckContainerRuntime reports THIS host's local LXC view of a container —
// absent / defined_stopped / running / unknown — and never consults the DB. It
// is the container analogue of CheckVMRuntime: the runtime re-key reconciler
// corroborates against it on every workload-capable peer before reclaiming a
// container it runs locally. Peer-only (host-cert mTLS).
func (s *Server) CheckContainerRuntime(ctx context.Context, req *pb.CheckContainerRuntimeRequest) (*pb.CheckContainerRuntimeResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	return &pb.CheckContainerRuntimeResponse{State: s.localContainerRuntime(ctx, req.GetName())}, nil
}

func (s *Server) localContainerRuntime(ctx context.Context, name string) string {
	if s.containerRuntime == nil {
		return health.RuntimeUnknown
	}
	names, err := s.containerRuntime.ListContainers(ctx)
	if err != nil {
		return health.RuntimeUnknown
	}
	present := false
	for _, n := range names {
		if n == name {
			present = true
			break
		}
	}
	if !present {
		return health.RuntimeAbsent
	}
	state, err := s.containerRuntime.StateContainer(ctx, name)
	if err != nil {
		return health.RuntimeUnknown
	}
	switch state {
	case "running":
		return health.RuntimeRunning
	case "stopped":
		return health.RuntimeDefinedStopped
	default:
		// starting/stopping/error/"" — transient or unreadable → ambiguous.
		return health.RuntimeUnknown
	}
}

// CheckPeerContainerRuntime dials a peer for its local LXC view of a container.
func (s *Server) CheckPeerContainerRuntime(ctx context.Context, host, name string) (string, error) {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	resp, err := client.CheckContainerRuntime(ctx, &pb.CheckContainerRuntimeRequest{Name: name})
	if err != nil {
		return "", err
	}
	return resp.GetState(), nil
}
