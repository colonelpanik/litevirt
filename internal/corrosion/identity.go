package corrosion

// Natural-key identity resolution (Part H1). Some tables mint a random-UUID PRIMARY KEY but
// carry a UNIQUE natural key, so two nodes can independently create DIFFERENT ids for one
// logical object; the replicated rows then collide on the secondary UNIQUE and the fail-closed
// apply path back-pressures. Under canonical_identity_v1 an upgraded receiver resolves these
// tables by their NATURAL key: it picks one deterministic winning id for the natural-key group,
// keeps that row, and rewrites any reference (e.g. a child's parent_id) from the losing id to
// the winner — converging to a single logical row across the cluster.

// tableIdentityKeys maps such a table to the columns of its UNIQUE natural key.
var tableIdentityKeys = map[string][]string{
	"snapshots":           {"vm_name", "name"},
	"container_snapshots": {"host_name", "ct_name", "name"},
}

// identityReferenceColumns maps a table to the columns that reference its OWN primary key, so a
// collapse can atomically rewrite them from a losing id to the winning id. snapshots.parent_id
// points at snapshots.id (a snapshot chain); container_snapshots has no self-reference.
var identityReferenceColumns = map[string][]string{
	"snapshots": {"parent_id"},
}

// hasIdentityKey reports whether a table is resolved by natural-key identity.
func hasIdentityKey(table string) bool {
	_, ok := tableIdentityKeys[table]
	return ok
}

// identityWinner imposes a STRICT, DETERMINISTIC total order on two rows sharing a natural key,
// so resolving a natural-key group is associative, commutative, and idempotent regardless of the
// order or three-node topology in which the rows arrive. The order is (updated_at DESC, id ASC):
// the newer row by instant wins; on an exact-instant tie the lexicographically SMALLER id wins.
// Returns +1 when A wins, -1 when B wins; never 0 for distinct ids (two identical ids return +1,
// a stable no-op). A minimal deterministic tiebreak — not the content resolver — is used on
// purpose: identity resolution MUST collapse to exactly one id, and the natural-key group is one
// logical object, so a total order guarantees convergence where a content tie could not.
func identityWinner(aUpdatedAt, aID, bUpdatedAt, bID string) int {
	switch lwwOrder(aUpdatedAt, bUpdatedAt) {
	case 1:
		return 1 // A strictly newer
	case -1:
		return -1 // B strictly newer
	}
	// Exact-instant tie → deterministic id tiebreak.
	switch {
	case aID < bID:
		return 1
	case aID > bID:
		return -1
	default:
		return 1 // identical ids: stable (idempotent re-delivery of the same row)
	}
}
