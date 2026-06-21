package corrosion

import (
	"context"
	"log/slog"
	"time"
)

// fallbackLoop monitors relay reachability for leaf nodes.
// If no relay push succeeds within FallbackTimeout, fallback mode activates
// and syncPeers adds random leaf peers to the replication target set.
// This ensures no leaf is ever cut off from the replication graph.
func (r *Replicator) fallbackLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.checkFallback()
		}
	}
}

func (r *Replicator) checkFallback() {
	r.mu.Lock()
	isRelay := r.isRelay
	r.mu.Unlock()

	// Relays don't need fallback — they push to everyone already.
	if isRelay {
		if r.fallbackActive.Load() {
			r.fallbackActive.Store(false)
		}
		return
	}

	lastPush := r.lastRelayPush.Load()
	elapsed := time.Since(time.UnixMilli(lastPush))

	if elapsed > r.relayCfg.FallbackTimeout {
		if !r.fallbackActive.Load() {
			r.fallbackActive.Store(true)
			slog.Warn("replicator: fallback activated — no relay reachable",
				"timeout", r.relayCfg.FallbackTimeout, "elapsed", elapsed)
			// Trigger immediate peer re-sync to add fallback targets.
			r.syncPeers()
		}
	} else {
		if r.fallbackActive.Load() {
			r.fallbackActive.Store(false)
			slog.Info("replicator: fallback deactivated — relay reachable again")
			// Re-sync to remove fallback targets.
			r.syncPeers()
		}
	}
}
