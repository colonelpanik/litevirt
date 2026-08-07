package daemon

import "time"

// capacityLeaseMaxAge is how long an admission lease may sit nonterminal before the
// sweep treats it as orphaned.
//
// Most leases are held for the duration of ONE RPC — seconds — so this is orders
// of magnitude above any legitimate lifetime, which is the point: expiring early
// would free capacity a live admission is still deciding against, and that is the
// one thing worse than leaking it. Resize is never affected (its lease rides the
// workload operation id, outside the capacity kind); migration/drain leases span
// the whole transfer and age against corrosion.TransferCapacityLeaseMaxAge
// inside the sweep instead of this RPC-scoped ceiling.
const capacityLeaseMaxAge = 15 * time.Minute
