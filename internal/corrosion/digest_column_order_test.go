package corrosion

import (
	"context"
	"slices"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// A replica founded at an older schema and upgraded holds its ALTER-added
// columns after deleted_at; a fresh replica of the same build holds them where
// CREATE TABLE declares them. Same rows, different SELECT * order. The
// positional v1 digest therefore disagreed for those tables on every pass,
// whatever the rows: `lv cluster converge` reported them DIVERGENT and
// anti-entropy pulled them, every cycle, from every differently-founded peer.
//
// A client left at its defaults must not report that as disagreement — the
// order-invariant digest_v2 is on unless a node switches it off.
//
// Mutation: make digestV2On default to false for an unset predicate — every
// skewed table goes red here.

// skewedTables refounds every replicated table on b as if b had been founded
// at schema 0 and upgraded, and returns the tables whose physical column order
// then differs from a fresh database's.
func skewedTables(t *testing.T, a, b *Client) []string {
	t.Helper()
	ctx := context.Background()
	var out []string
	for _, table := range append(append([]string{}, tableNames...), sensitiveTableNames...) {
		fresh := tableColumnOrder(t, a, table)
		if len(fresh) == 0 {
			continue
		}
		got, err := b.RefoundTableForTest(ctx, table, 0)
		if err != nil {
			t.Fatalf("refound %s: %v", table, err)
		}
		if !slices.Equal(fresh, got) {
			out = append(out, table)
		}
	}
	return out
}

// insertSyntheticRow writes the same row, by column name, into table on c: a
// value derived from each column's name and declared type.
func insertSyntheticRow(t *testing.T, c *Client, table string) {
	t.Helper()
	rows, err := c.db.Query(`SELECT name, type FROM pragma_table_info(?) ORDER BY name`, table)
	if err != nil {
		t.Fatal(err)
	}
	var cols, marks []string
	var vals []any
	for rows.Next() {
		var name, typ string
		if err := rows.Scan(&name, &typ); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, name)
		marks = append(marks, "?")
		switch strings.ToUpper(typ) {
		case "INTEGER":
			vals = append(vals, int64(len(name)))
		case "REAL":
			vals = append(vals, float64(len(name))+0.5)
		default:
			vals = append(vals, "v-"+name)
		}
	}
	rows.Close()
	if _, err := c.db.Exec(`INSERT INTO `+table+` (`+strings.Join(cols, ", ")+`) VALUES (`+strings.Join(marks, ", ")+`)`, vals...); err != nil {
		t.Fatalf("insert %s: %v", table, err)
	}
}

func digestByName(t *testing.T, c *Client, table string) TableDigest {
	t.Helper()
	ds, err := c.StateDigest(context.Background())
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	for _, d := range ds {
		if d.Name == table {
			return d
		}
	}
	t.Fatalf("no digest for %s", table)
	return TableDigest{}
}

func wireDigest(d TableDigest) *pb.TableDigest {
	return &pb.TableDigest{Name: d.Name, Count: int32(d.Count), Hash: d.Hash, HashV2: d.HashV2}
}

func TestStateDigest_OlderFoundedReplicaAgreesByDefault(t *testing.T) {
	fresh, upgraded := testClient(t), testClient(t)
	skewed := skewedTables(t, fresh, upgraded)
	if !slices.Contains(skewed, "hosts") {
		t.Fatalf("precondition: refounding at schema 0 should skew hosts; skewed = %v", skewed)
	}
	t.Logf("tables whose column order depends on the founding schema: %v", skewed)

	for _, table := range skewed {
		t.Run(table, func(t *testing.T) {
			insertSyntheticRow(t, fresh, table)
			insertSyntheticRow(t, upgraded, table)
			a, b := digestByName(t, fresh, table), digestByName(t, upgraded, table)
			if a.Hash == b.Hash {
				t.Fatalf("precondition: the positional v1 hashes should differ across column orders, both %s", a.Hash)
			}
			if !TableDigestsAgree(a, wireDigest(b)) || !TableDigestsAgree(b, wireDigest(a)) {
				t.Fatalf("identical rows in two column orders read as disagreement: fresh=%+v upgraded=%+v", a, b)
			}
		})
	}
}

// The kill switch still means v1: a node that switched digest_v2 off emits no
// v2 hash, so any peer compares it positionally — the pre-fix behavior, and
// never a v1 hash against a v2 one.
func TestStateDigest_DigestV2OffIsPositional(t *testing.T) {
	fresh, upgraded := testClient(t), testClient(t)
	if _, err := upgraded.RefoundTableForTest(context.Background(), "hosts", 0); err != nil {
		t.Fatal(err)
	}
	upgraded.SetDigestV2Enabled(func() bool { return false })
	insertSyntheticRow(t, fresh, "hosts")
	insertSyntheticRow(t, upgraded, "hosts")
	a, b := digestByName(t, fresh, "hosts"), digestByName(t, upgraded, "hosts")
	if b.HashV2 != "" {
		t.Fatalf("digest_v2 off still emitted a v2 hash %q", b.HashV2)
	}
	if a.HashV2 == "" {
		t.Fatal("a default client emitted no v2 hash")
	}
	if TableDigestsAgree(a, wireDigest(b)) {
		t.Fatal("against a v1-only peer the comparison must be positional, and these column orders differ")
	}

	// Same column order, one side v1-only: the v1 hashes agree, so the
	// tables agree. Reading a's v2 hash against b's v1 would disagree here.
	same := testClient(t)
	same.SetDigestV2Enabled(func() bool { return false })
	insertSyntheticRow(t, same, "hosts")
	c := digestByName(t, same, "hosts")
	if !TableDigestsAgree(a, wireDigest(c)) || !TableDigestsAgree(c, wireDigest(a)) {
		t.Fatalf("a v2 hash was judged against a v1 one: default=%+v v1-only=%+v", a, c)
	}
}
