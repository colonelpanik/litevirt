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
	// RegPreparing: phase-1 latched (accept canonical + consolidate), writer frozen. The seed below
	// uses the direct legacy writer (ungated), which is how a pre-migration login was recorded.
	db.SetRegistryMigrationState(func() corrosion.RegistryMigrationState { return corrosion.RegPreparing })

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

	// Latched ⇒ consolidate. But readiness ALSO requires the legacy WAL to have drained (no legacy
	// INSERT left in the mutation/relay log): the seed's legacy INSERT is still logged, so this pass
	// consolidates the row yet must NOT yet publish readiness — closing finding 1's drain gap.
	d.registryMigrationStep(ctx, true)
	detID := corrosion.RegistryCredentialID("user", "alice", "ghcr.io")
	live, _ := db.Query(ctx, "SELECT id FROM registry_credentials WHERE scope='user' AND owner='alice' AND registry='ghcr.io' AND deleted_at IS NULL")
	if len(live) != 1 || live[0].String("id") != detID {
		t.Fatalf("expected one canonical live row, got %v", live)
	}
	if d.registryLocallyReady.Load() {
		t.Fatal("must not publish ready while the legacy WAL has not drained")
	}

	// Simulate peers consuming (and the log pruning) the legacy WAL entries → the drain barrier is
	// crossed. Now a step publishes readiness (which advertises the phase-2 token).
	if err := db.Execute(ctx, "DELETE FROM mutation_log WHERE stmts LIKE '%INSERT INTO registry_credentials%' AND stmts NOT LIKE '%ON CONFLICT(id)%'"); err != nil {
		t.Fatalf("prune legacy WAL: %v", err)
	}
	d.registryMigrationStep(ctx, true)
	if !d.registryLocallyReady.Load() {
		t.Fatal("must publish ready once consolidated AND drained")
	}

	// De-latch ⇒ un-publish readiness (the phase-2 ADVERTISEMENT is reversible; the WRITER, once
	// phase-2 has latched cluster-wide, is not — that is the daemon's ResolveRegistryMigrationState).
	d.registryMigrationStep(ctx, false)
	if d.registryLocallyReady.Load() {
		t.Fatal("must un-publish ready when de-latched")
	}
}
