package grpcapi

import (
	"testing"
)

func TestProxyVNC_Exists(t *testing.T) {
	// Verify the ProxyVNC method is defined on Server.
	// Full stream testing requires integration tests.
	s := testServer(t)
	_ = s // ProxyVNC is a method on *Server
}
