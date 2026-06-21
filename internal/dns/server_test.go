package dns

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func newTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func TestVMRecordName(t *testing.T) {
	cases := []struct {
		vm, stack, domain, want string
	}{
		{"web", "mystack", "litevirt.local", "web.mystack.litevirt.local"},
		{"web", "", "litevirt.local", "web.litevirt.local"},
		{"db", "prod", "litevirt.local.", "db.prod.litevirt.local"},
	}
	for _, tc := range cases {
		got := VMRecordName(tc.vm, tc.stack, tc.domain)
		if got != tc.want {
			t.Errorf("VMRecordName(%q,%q,%q) = %q, want %q", tc.vm, tc.stack, tc.domain, got, tc.want)
		}
	}
}

func TestUpsertAndLookup(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	s := NewServer("litevirt.local", 5354, db)

	if err := UpsertRecord(ctx, db, "web.mystack.litevirt.local", "10.0.0.5"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}

	ip := s.lookup("web.mystack.litevirt.local.")
	if ip != "10.0.0.5" {
		t.Errorf("expected 10.0.0.5, got %q", ip)
	}
}

func TestUpsertAndDelete(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	s := NewServer("litevirt.local", 5354, db)

	if err := UpsertRecord(ctx, db, "gone.litevirt.local", "10.0.0.9"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}
	if err := DeleteRecord(ctx, db, "gone.litevirt.local"); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}

	ip := s.lookup("gone.litevirt.local.")
	if ip != "" {
		t.Errorf("expected empty after delete, got %q", ip)
	}
}

func TestUpsertRecord_UpdatesExisting(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	s := NewServer("litevirt.local", 5354, db)

	if err := UpsertRecord(ctx, db, "vm1.litevirt.local", "10.0.0.1"); err != nil {
		t.Fatalf("UpsertRecord initial: %v", err)
	}
	if err := UpsertRecord(ctx, db, "vm1.litevirt.local", "10.0.0.2"); err != nil {
		t.Fatalf("UpsertRecord update: %v", err)
	}

	ip := s.lookup("vm1.litevirt.local.")
	if ip != "10.0.0.2" {
		t.Errorf("expected updated IP 10.0.0.2, got %q", ip)
	}
}

func TestLookup_NotFound(t *testing.T) {
	db := newTestDB(t)
	s := NewServer("litevirt.local", 5354, db)

	ip := s.lookup("nonexistent.litevirt.local.")
	if ip != "" {
		t.Errorf("expected empty for missing name, got %q", ip)
	}
}
