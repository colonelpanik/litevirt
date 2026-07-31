package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func newHostTestClient(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// TestRegisterHost_CorrectsAStaleAddress.
//
// Found rebuilding the lab. A node registers itself on first start with
// getOutboundIP(), which on a multi-homed host is the source IP toward the
// DEFAULT route — the NAT interface, not the cluster network. Setting
// advertise_address afterwards is the documented fix and it did nothing: the row
// already existed, InsertHost is a plain INSERT, and nothing ever rewrote address.
//
// It is not cosmetic. Peers dial hosts.address, and `lv host add` seeds a new
// node's join_peers from ListHosts — so one wrong row propagates into every later
// node's gossip configuration. In the lab all four nodes ended up with the same
// NAT address, each dialling itself, which is exactly the failure CLAUDE.md
// describes as a cluster that "never converges".
func TestRegisterHost_CorrectsAStaleAddress(t *testing.T) {
	ctx := context.Background()
	c := newHostTestClient(t)

	// First start: no advertise_address, so the auto-detected NAT address lands.
	if err := corrosion.InsertHost(ctx, c, corrosion.HostRecord{
		Name: "node-1", Address: "10.0.2.15", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CertSerial: "x",
	}); err != nil {
		t.Fatalf("seed the host row: %v", err)
	}

	// Operator sets advertise_address and restarts.
	d := &Daemon{db: c, cfg: &Config{
		HostName: "node-1", AdvertiseAddress: "10.77.0.11", GRPCPort: 7443,
	}}
	if err := d.reconcileHostAddress(ctx); err != nil {
		t.Fatalf("reconcileHostAddress: %v", err)
	}

	h, err := corrosion.GetHost(ctx, c, "node-1")
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if h.Address != "10.77.0.11" {
		t.Fatalf("hosts.address is still %q after advertise_address was set to 10.77.0.11\n"+
			"peers dial this value and `lv host add` copies it into the next node's "+
			"join_peers, so a stale one spreads to every host added afterwards", h.Address)
	}
}

// TestRegisterHost_LeavesACorrectAddressAlone confirms the reconcile is a no-op
// when nothing changed, so it cannot churn updated_at and win LWW against a real
// write from another node on every restart.
func TestRegisterHost_LeavesACorrectAddressAlone(t *testing.T) {
	ctx := context.Background()
	c := newHostTestClient(t)
	if err := corrosion.InsertHost(ctx, c, corrosion.HostRecord{
		Name: "node-1", Address: "10.77.0.11", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CertSerial: "x",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	before, err := corrosion.GetHost(ctx, c, "node-1")
	if err != nil || before == nil {
		t.Fatalf("GetHost: %v", err)
	}
	d := &Daemon{db: c, cfg: &Config{
		HostName: "node-1", AdvertiseAddress: "10.77.0.11", GRPCPort: 7443,
	}}
	if err := d.reconcileHostAddress(ctx); err != nil {
		t.Fatalf("reconcileHostAddress: %v", err)
	}
	after, err := corrosion.GetHost(ctx, c, "node-1")
	if err != nil || after == nil {
		t.Fatalf("GetHost: %v", err)
	}
	if after.UpdatedAt != before.UpdatedAt {
		t.Errorf("an unchanged address still restamped updated_at (%q -> %q); every restart "+
			"would then win LWW against a genuine concurrent write from another node",
			before.UpdatedAt, after.UpdatedAt)
	}
}
