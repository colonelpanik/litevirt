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
// node. Once canonical_registry_v1 is latched (phase 1 — the accept gate, so peers apply the
// canonical writes) it idempotently consolidates legacy random-id rows to their deterministic ids
// and PUBLISHES this node's writer-readiness (registryLocallyReady = RegistryWriterReady). Whether
// the WRITER actually switches to canonical is decided cluster-wide by the phase-2 latch
// (canonical_registry_active_v1), which latches only when EVERY node publishes readiness — so no
// node originates canonical writes for a triple a peer still holds as legacy-live. The index
// contract is deferred.
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
// writer-readiness; it does NOT switch the writer (the phase-2 latch does).
func (d *Daemon) registryMigrationStep(ctx context.Context, latched bool) {
	if !latched {
		// Not accepting canonical writes (flag off / not latched) ⇒ not ready, don't consolidate.
		d.registryLocallyReady.Store(false)
		return
	}
	// Idempotently consolidate any legacy live rows (including ones replicated from a lagging peer).
	// The local writer is FROZEN in this phase (RegPreparing/RegReady), so no new legacy row races
	// the consolidation; consolidation itself is exempt (it uses the guarded batch path directly).
	if n, err := corrosion.ConsolidateRegistryCredentials(ctx, d.db); err != nil {
		slog.Warn("registry migration: consolidation error", "error", err)
	} else if n > 0 {
		slog.Info("registry migration: consolidated legacy credentials to canonical ids", "count", n)
	}
	// Publish local readiness = consolidated (no legacy live row) AND drained (no legacy INSERT left
	// in this node's mutation/relay log, i.e. every peer consumed our legacy writes). The phase-2
	// token is advertised only while this holds, so it latches (and the writer switches) only when
	// EVERY node has both consolidated and drained past the legacy barrier — finding 1's TOCTOU +
	// drain gap. With the writer frozen, both conditions are monotone, so readiness can't regress.
	ready, err := corrosion.RegistryWriterReady(ctx, d.db)
	if err != nil {
		slog.Warn("registry migration: writer-readiness check failed", "error", err)
		return
	}
	if ready {
		drained, dErr := corrosion.RegistryLegacyDrained(ctx, d.db)
		if dErr != nil {
			slog.Warn("registry migration: legacy-drain check failed", "error", dErr)
			return
		}
		ready = drained
	}
	if d.registryLocallyReady.CompareAndSwap(!ready, ready) && ready {
		slog.Info("registry migration: node writer-ready (consolidated + legacy WAL drained) — advertising canonical_registry_active_v1")
	}
}
