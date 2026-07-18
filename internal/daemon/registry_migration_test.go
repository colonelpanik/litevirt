package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestRegistryMigrationStep drives the H2 controller step: not-latched publishes not-ready and
// leaves legacy rows; latched consolidates legacy rows and publishes writer-readiness (which
// advertises the phase-2 token that switches the writer cluster-wide); de-latching un-publishes.
func TestRegistryMigrationStep(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	defer db.Close()
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	db.SetCanonicalRegistryLatched(func() bool { return true }) // consolidation's accept-latch precondition

	// Seed a legacy live credential (random id).
	if err := corrosion.UpsertRegistryCredential(ctx, db, corrosion.RegistryCredential{
		ID: "rand-1", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice", Secret: "s1"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	d := &Daemon{db: db, cfg: &Config{Enforcement: EnforcementConfig{CanonicalRegistry: true}}}

	// Not latched ⇒ no consolidation, writer stays legacy.
	d.registryMigrationStep(ctx, false)
	if d.registryLocallyReady.Load() {
		t.Fatal("must not be ready while not latched")
	}
	if rows, _ := db.Query(ctx, "SELECT id FROM registry_credentials WHERE id='rand-1' AND deleted_at IS NULL"); len(rows) != 1 {
		t.Fatal("legacy row must be untouched while not latched")
	}

	// Latched ⇒ consolidate + activate.
	d.registryMigrationStep(ctx, true)
	if !d.registryLocallyReady.Load() {
		t.Fatal("must publish ready once locally consolidated")
	}
	detID := corrosion.RegistryCredentialID("user", "alice", "ghcr.io")
	live, _ := db.Query(ctx, "SELECT id FROM registry_credentials WHERE scope='user' AND owner='alice' AND registry='ghcr.io' AND deleted_at IS NULL")
	if len(live) != 1 || live[0].String("id") != detID {
		t.Fatalf("expected one canonical live row, got %v", live)
	}

	// De-latch ⇒ deactivate (reversible).
	d.registryMigrationStep(ctx, false)
	if d.registryLocallyReady.Load() {
		t.Fatal("must un-publish ready when de-latched")
	}
}
