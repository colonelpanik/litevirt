package corrosion

import (
	"context"
	"testing"
)

func tableDigest(t *testing.T, c *Client, table string) TableDigest {
	t.Helper()
	ds, err := c.StateDigest(context.Background())
	if err != nil {
		t.Fatalf("StateDigest: %v", err)
	}
	for _, d := range ds {
		if d.Name == table {
			return d
		}
	}
	t.Fatalf("table %q not present in digest", table)
	return TableDigest{}
}

// TestStateDigest_ContentStableAndSensitive guards the anti-entropy digest
// (surfaced by the chaos drill): it must be a function of row CONTENT, not
// node-local rowids.
//
//   - Identical content reached via a different insertion order / rowid pattern
//     must yield the SAME digest — otherwise anti-entropy re-syncs already
//     converged peers forever.
//   - Equal row counts with DIFFERENT content must yield DIFFERENT digests —
//     otherwise real drift goes undetected (the old rowid hash of "1,2,…,N" is
//     content-blind).
func TestStateDigest_ContentStableAndSensitive(t *testing.T) {
	ctx := context.Background()
	const ts = "1000000000000-0000-n"
	put := func(c *Client, k, v string) {
		if err := c.Execute(ctx,
			`INSERT OR REPLACE INTO host_labels (host_name, key, value, updated_at) VALUES (?, ?, ?, ?)`,
			"h1", k, v, ts); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("content-stable across rowid divergence", func(t *testing.T) {
		a := mustTestClient(t)
		b := mustTestClient(t)
		put(a, "k1", "v1")
		put(a, "k2", "v2")
		put(a, "k3", "v3") // a: rowids 1,2,3
		// b reaches identical content but with churned rowids, exactly as an
		// INSERT-OR-REPLACE merge does in the cluster: re-applying k1 deletes
		// rowid 1 and re-inserts it at rowid 4, so b holds {2,3,4} for the same
		// three logical rows.
		put(b, "k1", "v1")
		put(b, "k2", "v2")
		put(b, "k3", "v3")
		put(b, "k1", "v1") // replace-churn → k1 moves to a fresh rowid

		da, db := tableDigest(t, a, "host_labels"), tableDigest(t, b, "host_labels")
		if da.Count != db.Count {
			t.Fatalf("counts differ: %d vs %d", da.Count, db.Count)
		}
		if da.Hash != db.Hash {
			t.Errorf("identical content gave different digests (rowid leak): a=%s b=%s", da.Hash, db.Hash)
		}
	})

	t.Run("content-sensitive at equal row count", func(t *testing.T) {
		a := mustTestClient(t)
		b := mustTestClient(t)
		put(a, "k1", "v1")
		put(a, "k2", "v2")
		put(b, "k1", "DIFFERENT")
		put(b, "k2", "v2")

		da, db := tableDigest(t, a, "host_labels"), tableDigest(t, b, "host_labels")
		if da.Count != db.Count {
			t.Fatalf("setup error: counts differ %d vs %d", da.Count, db.Count)
		}
		if da.Hash == db.Hash {
			t.Error("digest failed to distinguish differing content at equal row count (silent-drift false 'in sync')")
		}
	})
}
