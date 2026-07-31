package grpcapi

import (
	"context"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// PublishCRL installs a CA-signed revocation list locally and hands it to the
// cluster, where replication carries it to every other node.
//
// Verification comes first and decides everything. Storing an unverified CRL
// would put a list any caller can compose in front of every peer, and the move
// it enables is not subtle: a host that has just been removed publishes a CRL
// omitting its own serial, and the nodes that install it go back to accepting the
// certificate the removal was supposed to end. Only the cluster CA's signature
// separates that from a genuine revocation, so nothing is stored until it holds.
func (s *Server) PublishCRL(ctx context.Context, req *pb.PublishCRLRequest) (*pb.PublishCRLResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.CrlPem == "" {
		return nil, status.Error(codes.InvalidArgument, "no CRL supplied")
	}
	version, err := pki.VerifiedCRLNumber(s.pkiDir, []byte(req.CrlPem))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "refusing this CRL: %v", err)
	}
	// Published even when this node already had it: the reason to publish is the
	// peers that do not, and the row is keyed by the CRL's own bytes so a repeat is
	// genuinely inert rather than a primary-key collision reported as a failure.
	if err := corrosion.PublishCRL(ctx, s.db, req.CrlPem); err != nil {
		return nil, status.Errorf(codes.Internal, "publish CRL to the cluster: %v", err)
	}
	installedVersion, err := corrosion.SyncClusterCRL(ctx, s.db, s.pkiDir)
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"CRL was published but could not be installed locally; retry after repairing the PKI directory: %v",
			err)
	}
	installed := installedVersion != 0
	slog.Warn("cluster CRL published", "version", version, "installed_locally", installed)
	s.publish("cluster.crl.published", "", fmt.Sprintf("version=%d", version))
	return &pb.PublishCRLResponse{Version: version}, nil
}
