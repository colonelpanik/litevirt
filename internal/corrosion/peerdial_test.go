package corrosion

import (
	"context"
	"testing"
)

func TestResolvePeerTarget(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// IPv6 host with grpc_port 0 → bracketed address + default port 7443
	// (exercises both net.JoinHostPort IPv6 handling and the port default).
	if err := c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, grpc_port, state, cert_serial, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"ip6", "fd00::1", "root", 0, "active", "s-ip6", "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert ip6 host: %v", err)
	}
	// IPv4 host with an explicit gRPC port.
	if err := c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, grpc_port, state, cert_serial, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"ip4", "10.0.0.5", "root", 9443, "active", "s-ip4", "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert ip4 host: %v", err)
	}

	for _, tc := range []struct{ name, want string }{
		{"ip6", "[fd00::1]:7443"},
		{"ip4", "10.0.0.5:9443"},
	} {
		got, err := resolvePeerTarget(ctx, c, tc.name)
		if err != nil {
			t.Fatalf("resolvePeerTarget(%q): %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("resolvePeerTarget(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}

	// Unknown host with no gossip member → error (Members() is nil-safe here).
	if _, err := resolvePeerTarget(ctx, c, "nope"); err == nil {
		t.Error("expected error for unknown host with no gossip address")
	}
}
