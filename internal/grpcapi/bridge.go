package grpcapi

import (
	"net"

	"github.com/litevirt/litevirt/internal/network"
)

func (s *Server) ensureBridge(name string) error {
	if s.bridgeEnsure != nil {
		return s.bridgeEnsure(name)
	}
	if _, err := net.InterfaceByName(name); err != nil {
		return network.EnsureBridge(name)
	}
	return nil
}
