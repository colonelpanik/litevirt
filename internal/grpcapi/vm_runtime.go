package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/health"
)

// CheckVMRuntime reports THIS host's local libvirt view of a VM — and nothing
// else. It never consults or forwards through the cluster DB: the DB host_name
// is exactly the disputed value the caller (the runtime owner-assert reconciler)
// is corroborating against ground truth. Peer-only (host-cert mTLS), so an
// operator bearer credential can't probe runtime state.
func (s *Server) CheckVMRuntime(ctx context.Context, req *pb.CheckVMRuntimeRequest) (*pb.CheckVMRuntimeResponse, error) {
	if err := s.requirePeerCert(ctx); err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	return &pb.CheckVMRuntimeResponse{State: s.localVMRuntime(req.GetName())}, nil
}

// localVMRuntime maps this host's libvirt state to the shared runtime vocabulary.
func (s *Server) localVMRuntime(name string) string {
	if s.virt == nil {
		return health.RuntimeUnknown
	}
	if !s.virt.DomainExists(name) {
		return health.RuntimeAbsent
	}
	state, err := s.virt.DomainState(name)
	if err != nil {
		return health.RuntimeUnknown
	}
	if state == "running" {
		return health.RuntimeRunning
	}
	return health.RuntimeDefinedStopped
}

// CheckPeerVMRuntime dials a peer and asks for its local libvirt view of a VM.
// It is the hook the reconciler uses (via SetPeerRuntimeChecker) to corroborate
// ownership against runtime truth on every workload-capable peer.
func (s *Server) CheckPeerVMRuntime(ctx context.Context, host, name string) (string, error) {
	client, conn, err := s.peerClient(ctx, host)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	resp, err := client.CheckVMRuntime(ctx, &pb.CheckVMRuntimeRequest{Name: name})
	if err != nil {
		return "", err
	}
	return resp.GetState(), nil
}
