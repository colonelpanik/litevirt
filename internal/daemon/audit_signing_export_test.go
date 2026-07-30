package daemon

import "context"

// finishAuditKeyLifecycleNow runs the deferred lifecycle step without its settle
// wait.
//
// Test-only, and in a _test.go file so it cannot be reached from production. The
// wait exists so a restarted node sees its own replicated history before it
// records a permanent sequence boundary, which is not a thing a single-process
// test can be behind on.
func (d *Daemon) finishAuditKeyLifecycleNow(ctx context.Context) {
	if d.cfg.Enforcement.AuditSignature {
		if keyring := d.db.AuditKeyringOf(); keyring.CanSign() {
			adoptAuditKey(ctx, d, keyring)
		}
		return
	}
	rotated := false
	if shouldCompleteAuditKeyRotation(d.cfg) {
		if err := d.completeAuditKeyRotation(ctx); err == nil {
			rotated = true
		}
	}
	if !rotated {
		d.retireOwnAuditKeyOnRollback(ctx)
	}
}
