package grpcapi

import "testing"

func TestPeerTarget(t *testing.T) {
	for _, tc := range []struct {
		name string
		addr string
		port int
		want string
	}{
		{"ipv4 explicit port", "10.0.0.5", 9443, "10.0.0.5:9443"},
		{"ipv4 default port", "10.0.0.5", 0, "10.0.0.5:7443"},
		{"ipv6 bracketed", "fd00::1", 9443, "[fd00::1]:9443"},
		{"ipv6 default port", "::1", 0, "[::1]:7443"},
	} {
		if got := peerTarget(tc.addr, tc.port); got != tc.want {
			t.Errorf("%s: peerTarget(%q,%d) = %q, want %q", tc.name, tc.addr, tc.port, got, tc.want)
		}
	}
}
