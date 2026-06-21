package grpcapi

import (
	"context"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// verifyChainImpl is a thin shim around corrosion.VerifyAuditChain so
// the gRPC handler in audit_chain.go can stay focused on the RPC
// wrapping rather than the verification logic.
func verifyChainImpl(ctx context.Context, s *Server) (int, string, error) {
	return corrosion.VerifyAuditChain(ctx, s.db)
}
