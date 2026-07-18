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

// runRegistryMigrationController drives the Part H2 registry-credential online migration on this
// node. Once canonical_registry_v1 is latched (the accept gate — peers apply the canonical writes)
// it idempotently consolidates legacy random-id rows to their deterministic ids, and — once no
// legacy live row remains locally (RegistryWriterReady) — activates the canonical WRITER. It is
// REVERSIBLE: if the flag is turned off or the token de-latches, the writer is deactivated. The
// CONTRACT (partial→non-partial index swap) is a separate, more-strongly-gated step.
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

// registryMigrationStep is one controller iteration, taking the resolved accept-latch so it can be
// unit-tested without a Checker.
func (d *Daemon) registryMigrationStep(ctx context.Context, latched bool) {
	if !latched {
		// Not accepting canonical writes (flag off / not latched) ⇒ keep the writer on legacy.
		if d.registryWriterActive.CompareAndSwap(true, false) {
			slog.Info("registry migration: canonical writer deactivated (capability off / de-latched)")
		}
		return
	}
	// Idempotently consolidate any legacy live rows (including ones replicated from a lagging peer).
	if n, err := corrosion.ConsolidateRegistryCredentials(ctx, d.db); err != nil {
		slog.Warn("registry migration: consolidation error", "error", err)
	} else if n > 0 {
		slog.Info("registry migration: consolidated legacy credentials to canonical ids", "count", n)
	}
	// Activate the canonical writer once no legacy live row remains locally. Once activated it stays
	// active (a later legacy row from a lagging peer is consolidated on the next tick).
	ready, err := corrosion.RegistryWriterReady(ctx, d.db)
	if err != nil {
		slog.Warn("registry migration: writer-readiness check failed", "error", err)
		return
	}
	if ready && d.registryWriterActive.CompareAndSwap(false, true) {
		slog.Info("registry migration: canonical writer activated (local legacy rows consolidated)")
	}
}
