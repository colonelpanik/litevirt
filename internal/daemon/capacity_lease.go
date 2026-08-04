package daemon

import "time"

// capacityLeaseMaxAge is how long an admission lease may sit nonterminal before the
// sweep treats it as orphaned.
//
// These leases are held for the duration of ONE RPC — seconds — so this is orders
// of magnitude above any legitimate lifetime, which is the point: expiring early
// would free capacity a live admission is still deciding against, and that is the
// one thing worse than leaking it. Long-running work (resize, migration) is never
// affected because the sweep is scoped to capacity leases.
const capacityLeaseMaxAge = 15 * time.Minute
