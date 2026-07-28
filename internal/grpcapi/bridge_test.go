package grpcapi

import (
	"net"
	"testing"
)

func TestEnsureBridgeNilSeamAcceptsExistingInterface(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("Interfaces: %v", err)
	}
	if len(interfaces) == 0 {
		t.Skip("host has no network interfaces")
	}

	s := &Server{}
	if err := s.ensureBridge(interfaces[0].Name); err != nil {
		t.Fatalf("ensureBridge(%q): %v", interfaces[0].Name, err)
	}
}
