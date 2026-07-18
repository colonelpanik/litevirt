package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// registryMigrationInterval is how often the Part H2 controller re-evaluates. A var so tests can
// shrink it.
var registryMigrationInterval = 30 * time.Second

// runRegistryMigrationController drives the Part H2 registry-credential migration on this node. Once
// canonical_registry_v1 is latched (phase 1 — the accept gate, so peers apply the canonical writes)
// it idempotently consolidates legacy random-id rows to their deterministic ids and publishes this
// node's consolidation DIAGNOSTIC (registryConsolidated = RegistryWriterReady). It does NOT switch
// the writer or drive any advertisement: the writer activation (with its drain/barrier proof,
// convergence proof, and node admission/reseed rules) is a single deferred operator-run contract
// transition, not an auto-latch. So new API writes stay on the legacy writer; consolidation merely
// keeps the canonical rows populated and reconciles duplicates to their deterministic ids.
func (d *Daemon) runRegistryMigrationController(ctx context.Context) {
	t := time.NewTicker(registryMigrationInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		d.registryMigrationStep(ctx, d.cfg.Enforcement.CanonicalRegistry && d.checker.Latched(capabilities.CanonicalRegistryV1))
	}
}

// registryMigrationStep is one controller iteration, taking the resolved phase-1 accept-latch so it
// can be unit-tested without a Checker. It consolidates legacy rows and publishes this node's
// consolidation diagnostic. It never switches the writer.
func (d *Daemon) registryMigrationStep(ctx context.Context, latched bool) {
	if !latched {
		// Not accepting canonical writes (flag off / not latched) ⇒ don't consolidate; clear the
		// diagnostic (reversible — this is a plain accept gate).
		d.registryConsolidated.Store(false)
		return
	}
	// Idempotently consolidate any legacy live rows (including ones replicated from a lagging peer).
	if n, err := corrosion.ConsolidateRegistryCredentials(ctx, d.db); err != nil {
		slog.Warn("registry migration: consolidation error", "error", err)
	} else if n > 0 {
		slog.Info("registry migration: consolidated legacy credentials to canonical ids", "count", n)
	}
	// Publish the consolidation diagnostic (no legacy live row remains). This is informational for the
	// deferred operator transition — it does not switch the writer or advertise anything.
	ready, err := corrosion.RegistryWriterReady(ctx, d.db)
	if err != nil {
		slog.Warn("registry migration: consolidation-readiness check failed", "error", err)
		return
	}
	if d.registryConsolidated.CompareAndSwap(!ready, ready) && ready {
		slog.Info("registry migration: node consolidated (no legacy live credential rows remain)")
	}
}
