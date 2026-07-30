package daemon

import "context"

// finishAuditKeyLifecycleNow runs the deferred lifecycle step without its settle
// wait.
//
// It calls the production function, so a test that goes through it exercises the
// real branching. An earlier version restated that branching here instead, and
// mutation showed the cost: the guard stopping a rotation from being undone by the
// rollback retirement could be deleted from production with every test still
// green. The wait is all that is skipped — a single-process test cannot be behind
// on its own replicated history, which is the only thing the wait is for.
func (d *Daemon) finishAuditKeyLifecycleNow(ctx context.Context) {
	d.recordAuditKeyLifecycle(ctx)
}
