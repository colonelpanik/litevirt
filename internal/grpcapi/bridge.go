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

// bridgeExistsHere answers, for THIS host, the one host-local fact the NetBox
// bind-time DHCP refusal needs: whether the bridge already exists.
//
// It is a seam because the answer decides a refusal. A unit test that let the
// real host answer would pass or fail on which interfaces the test machine
// happens to carry, and the interesting cases are exactly the two answers.
func (s *Server) bridgeExistsHere(name string) bool {
	if s.bridgeExists != nil {
		return s.bridgeExists(name)
	}
	return network.BridgeExists(name)
}
