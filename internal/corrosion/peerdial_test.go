package corrosion

import (
	"context"
	"net"
	"testing"
)

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
		{"hostname", "node-b.example", 7443, "node-b.example:7443"},
	} {
		got := PeerTarget(tc.addr, tc.port)
		if got != tc.want {
			t.Errorf("%s: PeerTarget(%q,%d) = %q, want %q", tc.name, tc.addr, tc.port, got, tc.want)
		}
		// Every target must round-trip through SplitHostPort — that is the
		// property a raw Sprintf("%s:%d") silently violates for IPv6.
		if _, _, err := net.SplitHostPort(got); err != nil {
			t.Errorf("%s: PeerTarget(%q,%d) = %q is not a parseable target: %v",
				tc.name, tc.addr, tc.port, got, err)
		}
	}
}

func TestURIHost(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"ipv4 untouched", "10.0.0.5", "10.0.0.5"},
		{"hostname untouched", "node-b.example", "node-b.example"},
		{"ipv6 bracketed", "fd00::1", "[fd00::1]"},
		{"ipv6 loopback", "::1", "[::1]"},
		{"already bracketed is not double-bracketed", "[fd00::1]", "[fd00::1]"},
		{"v4-mapped v6 is an IPv4 address", "::ffff:10.0.0.5", "::ffff:10.0.0.5"},
		{"empty untouched", "", ""},
	} {
		if got := URIHost(tc.in); got != tc.want {
			t.Errorf("%s: URIHost(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

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

// TestResolvePeerTarget_FallsBackToGossip.
//
// The branch the whole bootstrap fix rests on, and it had no coverage: a peer whose
// hosts row has not replicated here yet is dialled at its gossip membership address
// instead of being refused. Without it a freshly provisioned cluster cannot make the
// outbound peer RPCs it needs in order to converge — which is exactly the state four
// lab nodes sat in.
func TestResolvePeerTarget_FallsBackToGossip(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	c.SetMembersForTests(func() []PeerInfo {
		return []PeerInfo{{Name: "unreplicated", Addr: "10.0.0.9:7946"}}
	})

	// No hosts row for this peer at all — only gossip knows it.
	got, err := resolvePeerTarget(ctx, c, "unreplicated")
	if err != nil {
		t.Fatalf("a peer known only to gossip could not be resolved: %v\n"+
			"its hosts row has not replicated yet, which is every peer on a cluster that "+
			"has just been provisioned", err)
	}
	// The gossip address carries the GOSSIP port; the target must use the gRPC one.
	if got != "10.0.0.9:7443" {
		t.Fatalf("resolved to %q, want 10.0.0.9:7443 — the gossip port must not be "+
			"carried into the gRPC target", got)
	}

	// A replicated row still wins over gossip.
	if err := c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, grpc_port, state, cert_serial, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		"unreplicated", "10.0.0.9", "root", 9443, "active", "s", "2025-01-01T00:00:00Z", "2025-01-01T00:00:00Z"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if got, err := resolvePeerTarget(ctx, c, "unreplicated"); err != nil || got != "10.0.0.9:9443" {
		t.Fatalf("once the row replicates it must win: got %q, %v", got, err)
	}
}
