package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// crlSyncInterval is how often a node looks for a revocation it has not installed.
// Revocations are rare and replication is fast, so this is a backstop rather than
// the delivery mechanism — but it is the backstop that decides how long a removed
// host keeps working on a node that was down when the removal happened.
const crlSyncInterval = 30 * time.Second

// runCRLSync installs the newest cluster CRL this node can verify. The choosing
// and the verifying live in corrosion.SyncClusterCRL, which is also what a fleet
// test drives — a distribution mechanism tested through a reimplementation of
// itself proves nothing about the one that ships.
func (d *Daemon) runCRLSync(ctx context.Context) {
	sync := func() {
		if _, err := corrosion.SyncClusterCRL(ctx, d.db, d.cfg.PKIDir); err != nil {
			slog.Warn("could not read the cluster CRL; revocations may not be enforced here", "error", err)
		}
	}
	sync()
	ticker := time.NewTicker(crlSyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sync()
		}
	}
}
