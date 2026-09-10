package corrosion

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// clusterRecordID is the fixed primary key every node's heal writes.
//
// The `cluster` table is `id TEXT PRIMARY KEY DEFAULT 'default'` — a
// SINGLE-column key — so N nodes healing concurrently all address the SAME row
// and LWW resolves them into one. A generated id would give each node its own
// row, and `SELECT ... FROM cluster LIMIT 1` would then return whichever the
// storage engine felt like: a cluster fingerprint that differed per node, which
// is precisely the split-identity the fingerprint exists to prevent.
const clusterRecordID = "default"

// EnsureClusterRecord derives the `cluster` row from this node's CA certificate
// when the cluster does not have one yet.
//
// WHY THIS EXISTS AT ALL: nothing ever wrote that row. `lv host init` mints the
// PKI and pushes it; the daemon applies the schema and registers a host; no path
// anywhere inserted a `cluster` row. Everything that READS it —
// ClusterFingerprint, ClusterName, the cluster name in monitoring — therefore
// found nothing on every real installation. The fingerprint is the first
// component of every NetBox identity litevirt mints, so an absent row meant no
// binding, no claim, no mirror, no orphan sweep and no re-key: the whole
// integration was inert outside tests, which seeded the row themselves.
//
// It is DERIVE-AND-HEAL, presence-gated, exactly like the schema ledger: it asks
// whether the row is there, not what version wrote it or when. That one shape
// covers a cluster freshly `host init`ed and a cluster that has been running for
// a year, in one place, with no CLI change and nothing for an operator to run.
//
// The value is the CA certificate on disk because every node in a cluster shares
// one CA, so whichever node heals first writes what every other node would have
// written and the derived fingerprint is stable cluster-wide.
//
// It NEVER overwrites an existing row. Three reasons, and they compound:
//   - the row is replicated, so a rewrite is a cluster-wide event, and a heal
//     that rewrote on every start would make the fingerprint depend on which
//     node restarted last;
//   - `name` is operator-visible and this function has no operator-supplied
//     value for it (nothing takes a cluster name — the mirror falls back to its
//     own configured one), so healing over a row would silently blank a name
//     somebody set;
//   - a node whose `ca.crt` genuinely differs is mid CA-replacement, and two
//     nodes writing the row in turn would make the cluster's identity namespace
//     depend on which of them restarted last. Which one "wins" is not the
//     question — the row must not move at all.
//
// THE INVARIANT, POSITIVELY: the cluster fingerprint is a stable NAMESPACE, not
// a liveness check on the CA. It is minted ONCE, from whatever `ca.crt` the
// first node to heal held, and it deliberately never tracks `ca.crt` again.
// Nothing in production rewrites `cluster.ca_cert` — the INSERT below is that
// column's only non-test writer — so on a live cluster the fingerprint does not
// move, and no code may be written as though it might.
//
// That is the intended behaviour, not a gap. A fingerprint that tracked the live
// CA would, the moment one was replaced, make the inventory mirror's
// actual-state read see zero objects it owns: it would duplicate the entire
// inventory into NetBox under fresh ids while revalidation suspended every
// binding fleet-wide, and the re-key that repairs a fingerprint move would have
// two states to reconcile instead of one.
//
// A CA-rotation path, if one is built, must move the fingerprint EXPLICITLY and
// re-key the objects still carrying the old one (`lv netbox rekey` is the
// re-stamping half; the deliberate move is the part that does not exist yet). It
// must NOT be built by relaxing this heal into an upsert — that gives the move
// no ordering, no operator, and no re-key between the two namespaces.
//
// A missing or empty `ca.crt` writes NOTHING and is not an error. A node can be
// running before it has been enrolled, and the daemon must still come up; the
// NetBox paths simply stay fail-closed on "cluster row not found" until it has.
// Writing a row with a blank `ca_cert` would be strictly worse than writing
// none: `ca_cert` is NOT NULL so the blank row satisfies every presence check
// while fingerprintFromCert still refuses it, and this heal — being
// presence-gated — would never replace it.
//
// THE WRITE IS LOCAL-ONLY (execLocal — no mutation_log row, nothing pushed to a
// peer), and that is a rolling-upgrade requirement, not an optimisation.
//
// This heal runs on EVERY daemon start, unconditionally: no capability gate, no
// config flag, before any NetBox feature exists. And `cluster` had no replicated
// statement shape at all at the previous release — nothing ever wrote the row,
// which is the entire reason this file exists. So a REPLICATED write here is a
// first-ever fingerprint for that table, emitted by every node the moment it is
// upgraded, into peers still running the previous binary. A peer's ledger lookup
// misses, the apply fails closed ("unregistered replicated statement shape"),
// the whole batch rolls back and its watermark stops advancing — head-of-line
// blocking on the WAL stream into every not-yet-rolled node. It bites the
// RECOMMENDED rollout specifically, because pre-staging equalises the schema
// first, so the schema-skew refusal sees no gap and accepts the stream, leaving
// the binary-resident ledger as the only cross-version gate.
//
// LOCAL-ONLY STILL CONVERGES, by construction rather than by replication:
//
//   - every node in a cluster shares ONE CA (`lv host init` mints it and pushes
//     it), so every node's heal derives the SAME `ca_cert` — the only column
//     anything downstream reads — under the same fixed `id`. There is no value
//     for two nodes to disagree about;
//   - `cluster` is in the anti-entropy table set (tableNames in sync.go), and
//     anti-entropy performs NO ledger check, so the row is repaired onto a node
//     that could not derive it — one that has not been enrolled yet, or whose
//     `ca.crt` read failed — exactly as a replicated write would have been, and
//     without a shape on the wire;
//   - the write is presence-gated and conflict-guarded, so a row that arrives
//     from a peer mid-heal wins and this node writes nothing.
//
// Gating it behind the NetBox capability latch instead would be circular: the
// row is what every NetBox identity is minted FROM, so it must exist before any
// NetBox feature can work, while the latch requires `netbox.enabled` on every
// node before it forms. The heal would never run on a cluster that had not
// already run it.
func EnsureClusterRecord(ctx context.Context, c *Client, pkiDir string) error {
	rows, err := c.Query(ctx, `SELECT id FROM cluster LIMIT 1`)
	if err != nil {
		return fmt.Errorf("read cluster row: %w", err)
	}
	if len(rows) > 0 {
		// Present. Nothing to derive, and nothing to write — this is what makes
		// the heal idempotent across restarts rather than churning updated_at on
		// a replicated row every node touches.
		return nil
	}

	caPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read cluster CA certificate: %w", err)
	}
	if strings.TrimSpace(string(caPEM)) == "" {
		return nil
	}

	// DO NOTHING, not DO UPDATE: the presence check above is a read, and a peer's
	// row can arrive through anti-entropy in between it and this write. The
	// conflict clause is what makes losing that race a no-op instead of an
	// overwrite — the same "never rewrite a row we did not create" rule the doc
	// comment states, enforced at the statement rather than only at the branch.
	now := c.NowTS()
	return c.execLocal(ctx,
		`INSERT INTO cluster (id, name, domain, ca_cert, created_at, updated_at)
		 VALUES (?, '', '', ?, ?, ?)
		 ON CONFLICT(id) DO NOTHING`,
		clusterRecordID, string(caPEM), now, now)
}
