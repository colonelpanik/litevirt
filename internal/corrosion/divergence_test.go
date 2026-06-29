package corrosion

import (
	"strings"
	"testing"
)

// snap builds a NodeSnapshot for one table from pkLabel→RowMeta.
func snap(host, table string, cols []string, rows map[string]RowMeta) NodeSnapshot {
	return NodeSnapshot{Host: host, Tables: map[string]TableSnapshot{table: {Columns: cols, Rows: rows}}}
}

func classOf(t *testing.T, table string, nodes []string, snaps map[string]NodeSnapshot, pk string) DivergenceClass {
	t.Helper()
	for _, d := range ClassifyTable(table, nodes, snaps) {
		if d.PKLabel == pk {
			return d.Class
		}
	}
	return "" // converged / not reported
}

func TestClassifyTable_Classes(t *testing.T) {
	nodes := []string{"a", "b"}
	cols := []string{"name", "state", "updated_at", "deleted_at"}

	cases := []struct {
		name string
		a, b RowMeta
		want DivergenceClass
	}{
		{"converged", RowMeta{UpdatedAt: "t1", RowHash: "h1"}, RowMeta{UpdatedAt: "t1", RowHash: "h1"}, ""},
		{"equal-ts-different-content",
			RowMeta{UpdatedAt: "t1", RowHash: "h1"}, RowMeta{UpdatedAt: "t1", RowHash: "h2"},
			ClassEqualUpdatedAtDifferentContent},
		{"different-ts",
			RowMeta{UpdatedAt: "t1", RowHash: "h1"}, RowMeta{UpdatedAt: "t2", RowHash: "h2"},
			ClassDifferentUpdatedAt},
		{"tombstone-vs-live",
			RowMeta{UpdatedAt: "t1", RowHash: "h1", Deleted: true}, RowMeta{UpdatedAt: "t2", RowHash: "h2"},
			ClassTombstoneVsLive},
		{"terminal-vs-live",
			RowMeta{UpdatedAt: "t1", RowHash: "h1", State: "stopped"}, RowMeta{UpdatedAt: "t2", RowHash: "h2", State: "running"},
			ClassTerminalVsLive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snaps := map[string]NodeSnapshot{
				"a": snap("a", "vms", cols, map[string]RowMeta{"vm1": tc.a}),
				"b": snap("b", "vms", cols, map[string]RowMeta{"vm1": tc.b}),
			}
			if got := classOf(t, "vms", nodes, snaps, "vm1"); got != tc.want {
				t.Fatalf("class = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyTable_MissingRow(t *testing.T) {
	nodes := []string{"a", "b"}
	cols := []string{"name", "updated_at"}
	snaps := map[string]NodeSnapshot{
		"a": snap("a", "vms", cols, map[string]RowMeta{"vm1": {UpdatedAt: "t1", RowHash: "h1"}}),
		"b": snap("b", "vms", cols, map[string]RowMeta{}),
	}
	if got := classOf(t, "vms", nodes, snaps, "vm1"); got != ClassMissingRow {
		t.Fatalf("class = %q, want missing_row", got)
	}
}

func TestClassifyTable_SchemaShapeMismatch(t *testing.T) {
	nodes := []string{"a", "b"}
	snaps := map[string]NodeSnapshot{
		"a": snap("a", "vms", []string{"name", "updated_at"}, map[string]RowMeta{"vm1": {RowHash: "h1"}}),
		"b": snap("b", "vms", []string{"name", "updated_at", "project"}, map[string]RowMeta{"vm1": {RowHash: "h1"}}),
	}
	ds := ClassifyTable("vms", nodes, snaps)
	if len(ds) != 1 || ds[0].Class != ClassSchemaShapeMismatch {
		t.Fatalf("want one schema_shape_mismatch, got %+v", ds)
	}
}

// equal-content rows do not appear even when present on every node.
func TestClassifyTable_ConvergedOmitted(t *testing.T) {
	nodes := []string{"a", "b", "c"}
	cols := []string{"name", "updated_at"}
	rows := map[string]RowMeta{"vm1": {UpdatedAt: "t1", RowHash: "h1"}}
	snaps := map[string]NodeSnapshot{
		"a": snap("a", "vms", cols, rows), "b": snap("b", "vms", cols, rows), "c": snap("c", "vms", cols, rows),
	}
	if ds := ClassifyTable("vms", nodes, snaps); len(ds) != 0 {
		t.Fatalf("converged table should report nothing, got %+v", ds)
	}
}

// The cross-PK container split: two live rows (host-a,ct) + (host-b,ct), present
// (converged) on every node, is flagged by the semantic invariant even though the
// row resolver sees no tie.
func TestCheckLiveContainerNames_CrossHostSplit(t *testing.T) {
	rows := []OwnedRow{
		{Host: "host-a", Name: "web"}, {Host: "host-b", Name: "web"}, // the split
		{Host: "host-a", Name: "web"},                                // duplicate report from another node — deduped by (host,name) grouping
		{Host: "host-a", Name: "db"},                                 // fine: single host
	}
	v := CheckLiveContainerNames(rows)
	if len(v) != 1 || v[0].Key != "web" || v[0].Kind != "duplicate_live_container" {
		t.Fatalf("want one duplicate_live_container for web, got %+v", v)
	}
	if strings.Join(v[0].Hosts, ",") != "host-a,host-b" {
		t.Fatalf("hosts = %v, want [host-a host-b]", v[0].Hosts)
	}
}

func TestCheckDuplicateIPOwners(t *testing.T) {
	rows := []OwnedRow{
		{Name: "vm1", IP: "10.0.0.5"},
		{Name: "vm2", IP: "10.0.0.5"}, // same IP, different owner
		{Name: "vm3", IP: "10.0.0.6"},
		{Name: "vm3", IP: "10.0.0.6"}, // dup of the same owner — fine
	}
	v := CheckDuplicateIPOwners(rows)
	if len(v) != 1 || v[0].Key != "10.0.0.5" {
		t.Fatalf("want one duplicate_ip_owner for 10.0.0.5, got %+v", v)
	}
}

// The sensitive lane's HMACs are domain-separated (a PK label can't alias a row
// hash), deterministic for the same key (cross-node matching), and key-dependent
// (no cross-scan equality leak).
func TestScanHMAC_DomainSeparationAndDeterminism(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	table, val := "recovery_codes", "alice"

	pk := ScanPKLabel(key, table, val)
	row := ScanRowHash(key, table, val)
	if pk == row {
		t.Fatal("pk label and row hash must not alias for the same input")
	}
	// Deterministic: same key+input on a "different node" yields the same HMAC.
	if ScanPKLabel(key, table, val) != pk {
		t.Fatal("HMAC not deterministic for the same key/input")
	}
	// Different per-scan key → different HMAC (no cross-scan equality leak).
	key2 := []byte("ffffffffffffffffffffffffffffffff")
	if ScanPKLabel(key2, table, val) == pk {
		t.Fatal("HMAC must depend on the scan key")
	}
	// Table is part of the domain: same value under a different table differs.
	if ScanPKLabel(key, "user_2fa", val) == pk {
		t.Fatal("HMAC must be table-scoped")
	}
	// Never the raw value.
	if strings.Contains(pk, val) || strings.Contains(row, val) {
		t.Fatal("HMAC must not contain the plaintext input")
	}
}

// The extracted encoder is byte-frozen — these vectors must never change (a change
// re-fingerprints every row and triggers a cluster-wide resync storm).
func TestEncodeRowCells_GoldenVectors(t *testing.T) {
	cases := []struct {
		in   []interface{}
		want string
	}{
		{nil, ""},
		{[]interface{}{nil}, "N;"},
		{[]interface{}{"hello"}, "5:hello"},
		{[]interface{}{int64(42)}, "2:42"},
		{[]interface{}{"a", nil, "bc"}, "1:aN;2:bc"},
		{[]interface{}{"2026-06-29T10:00:00Z"}, "20:2026-06-29T10:00:00Z"},
		{[]interface{}{""}, "0:"},
	}
	for _, tc := range cases {
		if got := EncodeRowCells(tc.in); got != tc.want {
			t.Errorf("EncodeRowCells(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
