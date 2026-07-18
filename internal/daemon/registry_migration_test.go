package daemon

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestRegistryMigrationStep drives the H2 controller step: not-latched leaves legacy rows and clears
// the consolidation diagnostic; latched idempotently consolidates legacy rows to their deterministic
// ids and publishes the consolidation diagnostic; de-latching clears it (reversible). The controller
// NEVER switches the writer — that is the deferred operator transition.
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
	// RegPreparing: phase-1 latched (accept canonical + consolidate). The seed uses the direct legacy
	// writer, which is how a pre-migration login was recorded.
	db.SetRegistryMigrationState(func() corrosion.RegistryMigrationState { return corrosion.RegPreparing })

	// Seed a legacy live credential (random id).
	if err := corrosion.UpsertRegistryCredential(ctx, db, corrosion.RegistryCredential{
		ID: "rand-1", Scope: "user", Owner: "alice", Registry: "ghcr.io", Username: "alice", Secret: "s1"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	d := &Daemon{db: db, cfg: &Config{Enforcement: EnforcementConfig{CanonicalRegistry: true}}}

	// Not latched ⇒ no consolidation, diagnostic clear, legacy row untouched.
	d.registryMigrationStep(ctx, false)
	if d.registryConsolidated.Load() {
		t.Fatal("must not report consolidated while not latched")
	}
	if rows, _ := db.Query(ctx, "SELECT id FROM registry_credentials WHERE id='rand-1' AND deleted_at IS NULL"); len(rows) != 1 {
		t.Fatal("legacy row must be untouched while not latched")
	}

	// Latched ⇒ consolidate to the deterministic id + publish the consolidation diagnostic.
	d.registryMigrationStep(ctx, true)
	detID := corrosion.RegistryCredentialID("user", "alice", "ghcr.io")
	live, _ := db.Query(ctx, "SELECT id FROM registry_credentials WHERE scope='user' AND owner='alice' AND registry='ghcr.io' AND deleted_at IS NULL")
	if len(live) != 1 || live[0].String("id") != detID {
		t.Fatalf("expected one canonical live row, got %v", live)
	}
	if !d.registryConsolidated.Load() {
		t.Fatal("must report consolidated once no legacy live row remains")
	}

	// De-latch ⇒ clear the diagnostic (reversible accept gate).
	d.registryMigrationStep(ctx, false)
	if d.registryConsolidated.Load() {
		t.Fatal("must clear the consolidation diagnostic when de-latched")
	}
}
