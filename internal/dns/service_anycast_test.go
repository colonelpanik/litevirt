package dns

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestLookupService_BareNameFQDNQuery is the real-world case the older test
// missed: `lv region anycast add --name api` stores the BARE service name, but
// clients query the FQDN "api.litevirt.local". The lookup must strip the domain
// to match. (Before the fix, this returned nothing — anycast never resolved
// for a normal DNS query.)
func TestLookupService_BareNameFQDNQuery(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer db.Close()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, e := range []corrosion.ServiceEndpoint{
		{ServiceName: "api", IP: "10.0.0.1", Region: "ny", Weight: 1}, // BARE name, as the CLI writes it
		{ServiceName: "api", IP: "10.0.0.2", Region: "ny", Weight: 1},
	} {
		if err := corrosion.UpsertServiceEndpoint(ctx, db, e); err != nil {
			t.Fatalf("Upsert %s: %v", e.IP, err)
		}
	}
	s := NewServer("litevirt.local", 0, db)
	if got := s.lookupService("api.litevirt.local."); len(got) != 2 {
		t.Fatalf("FQDN query of a bare-named service: got %d ips, want 2 (%v)", len(got), got)
	}
	// Bare query must still work too.
	if got := s.lookupService("api."); len(got) != 2 {
		t.Fatalf("bare query: got %d ips, want 2", len(got))
	}
}

func TestLookupService_RoundRobinAndWeight(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer db.Close()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, e := range []corrosion.ServiceEndpoint{
		{ServiceName: "api.litevirt.local", IP: "10.0.0.1", Region: "ny", Weight: 1},
		{ServiceName: "api.litevirt.local", IP: "10.0.0.2", Region: "lon", Weight: 2},
	} {
		if err := corrosion.UpsertServiceEndpoint(ctx, db, e); err != nil {
			t.Fatalf("Upsert %s: %v", e.IP, err)
		}
	}
	s := NewServer("litevirt.local", 0, db)

	// Three lookups: weight-expansion is [10.0.0.1, 10.0.0.2, 10.0.0.2].
	// rrCounter starts at 0; Add(1)→1, Add(1)→2, Add(1)→0 (mod 3).
	got := [][]string{
		s.lookupService("api.litevirt.local."),
		s.lookupService("api.litevirt.local."),
		s.lookupService("api.litevirt.local."),
	}
	for i, g := range got {
		if len(g) != 3 {
			t.Fatalf("query %d: got %d ips, want 3", i, len(g))
		}
	}
	// First IPs across the three queries should not all be identical —
	// the rotation must move.
	if got[0][0] == got[1][0] && got[1][0] == got[2][0] {
		t.Errorf("expected rotation across queries, got %v / %v / %v", got[0], got[1], got[2])
	}
	// Weighted endpoint (10.0.0.2) appears twice in each expansion.
	count2 := 0
	for _, ip := range got[0] {
		if ip == "10.0.0.2" {
			count2++
		}
	}
	if count2 != 2 {
		t.Errorf("weight=2 endpoint should appear twice per rotation, got %d in %v", count2, got[0])
	}
}

func TestLookupService_DeletedEndpointFiltered(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer db.Close()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.UpsertServiceEndpoint(ctx, db, corrosion.ServiceEndpoint{
		ServiceName: "api", IP: "10.0.0.1",
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := corrosion.DeleteServiceEndpoint(ctx, db, "api", "10.0.0.1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	s := NewServer("litevirt.local", 0, db)
	if got := s.lookupService("api."); len(got) != 0 {
		t.Errorf("deleted endpoint returned: %v", got)
	}
}
