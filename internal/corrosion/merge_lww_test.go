package corrosion

import (
	"context"
	"fmt"
	"testing"

	"github.com/litevirt/litevirt/internal/hlc"
)

func hostAddr(t *testing.T, c *Client, name string) string {
	t.Helper()
	rows, err := c.Query(context.Background(), "SELECT address FROM hosts WHERE name = ?", name)
	if err != nil || len(rows) == 0 {
		t.Fatalf("lookup host %q: err=%v rows=%d", name, err, len(rows))
	}
	return rows[0].String("address")
}

func labelVal(t *testing.T, c *Client, host, key string) string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		"SELECT value FROM host_labels WHERE host_name = ? AND key = ?", host, key)
	if err != nil || len(rows) == 0 {
		t.Fatalf("lookup label %s/%s: err=%v rows=%d", host, key, err, len(rows))
	}
	return rows[0].String("value")
}

// TestMergeLWW_HLCBeatsLegacyRFC3339 is the live-path bug fix: a legacy RFC3339
// local timestamp sorts lexically ABOVE any HLC ("2099…" > "17…"), so the old
// shouldSkipMergeLWW would wrongly keep it; the engine now uses localWinsLWW, so
// the incoming HLC row wins.
func TestMergeLWW_HLCBeatsLegacyRFC3339(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	cols := []string{"name", "address", "ssh_user", "cert_serial", "created_at", "updated_at"}

	if err := c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, cert_serial, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"h1", "10.0.0.1", "root", "s1", "2099-01-01T00:00:00Z", "2099-01-01T00:00:00Z"); err != nil {
		t.Fatalf("seed host: %v", err)
	}

	incomingHLC := hlc.NewClock("n2").Now().String()
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "hosts",
		Columns: cols,
		Rows:    [][]interface{}{{"h1", "10.9.9.9", "root", "s1", "2099-01-01T00:00:00Z", incomingHLC}},
	}}})

	if got := hostAddr(t, c, "h1"); got != "10.9.9.9" {
		t.Errorf("address = %q, want 10.9.9.9 (incoming HLC must beat legacy RFC3339 local)", got)
	}
}

// TestMergeLWW_CompositePK exercises the batched prefetch over a composite PK
// (host_labels: host_name+key). It only produces the right per-row LWW decisions
// if the prefetch map keyed each tuple correctly — which also proves PK
// canonicalization matches DB-side ([]byte) and incoming-side (string) values.
func TestMergeLWW_CompositePK(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	const hlcOld = "1000000000000-0000-n1"
	const hlcNew = "2000000000000-0000-n1"

	if err := c.Execute(ctx,
		`INSERT INTO host_labels (host_name, key, value, updated_at) VALUES (?, ?, ?, ?)`,
		"h1", "env", "prod", hlcNew); err != nil {
		t.Fatalf("seed env: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO host_labels (host_name, key, value, updated_at) VALUES (?, ?, ?, ?)`,
		"h1", "tier", "silver", hlcOld); err != nil {
		t.Fatalf("seed tier: %v", err)
	}

	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "host_labels",
		Columns: []string{"host_name", "key", "value", "updated_at"},
		Rows: [][]interface{}{
			{"h1", "env", "staging", hlcOld}, // older → skipped, local "prod" kept
			{"h1", "tier", "gold", hlcNew},   // newer → wins, local "silver" replaced
		},
	}}})

	if v := labelVal(t, c, "h1", "env"); v != "prod" {
		t.Errorf("env = %q, want prod (older incoming should be skipped)", v)
	}
	if v := labelVal(t, c, "h1", "tier"); v != "gold" {
		t.Errorf("tier = %q, want gold (newer incoming should win)", v)
	}
}

// TestPKKey_Canonicalization locks the []byte-vs-string equivalence the prefetch
// relies on (DB scans may return []byte; incoming dump rows carry string).
func TestPKKey_Canonicalization(t *testing.T) {
	a := pkKey([]interface{}{"h1", "env"})
	b := pkKey([]interface{}{[]byte("h1"), []byte("env")})
	c := pkKey([]interface{}{"h1", []byte("env")})
	if a != b || a != c {
		t.Errorf("pkKey not canonical across []byte/string: %q / %q / %q", a, b, c)
	}
	// Distinct tuples must not collide, even with separator-like content.
	if pkKey([]interface{}{"a", "b"}) == pkKey([]interface{}{"ab"}) {
		t.Error("pkKey collision between (\"a\",\"b\") and (\"a\\x1fb\")")
	}
}

// TestMergeLWW_RejectsUnknownTableAndColumns confirms peer-supplied table names
// and columns are validated before any dynamic SQL runs.
func TestMergeLWW_RejectsUnknownTableAndColumns(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// Unknown (and injection-shaped) table name → skipped, no SQL executed.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "evil; DROP TABLE hosts;--",
		Columns: []string{"x"},
		Rows:    [][]interface{}{{"1"}},
	}}})

	// Known table, but a column the local schema doesn't have → whole table skipped.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "hosts",
		Columns: []string{"name", "bogus"},
		Rows:    [][]interface{}{{"h1", "x"}},
	}}})

	rows, err := c.Query(ctx, "SELECT count(*) AS n FROM hosts")
	if err != nil {
		t.Fatalf("hosts table should be intact and queryable: %v", err)
	}
	if n := rows[0].Int("n"); n != 0 {
		t.Errorf("no rows should have been inserted, got %d", n)
	}
}

// TestMergeLWW_RejectsMissingPKColumn: a dump for a table with a known PK that
// omits a PK column can't be LWW-merged, so the whole table is skipped (no
// PK-less rows inserted).
func TestMergeLWW_RejectsMissingPKColumn(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// hosts PK is "name"; omit it.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "hosts",
		Columns: []string{"address", "ssh_user", "cert_serial", "created_at", "updated_at"},
		Rows:    [][]interface{}{{"10.0.0.1", "root", "s1", "t", "t"}},
	}}})

	rows, err := c.Query(ctx, "SELECT count(*) AS n FROM hosts")
	if err != nil {
		t.Fatalf("query hosts: %v", err)
	}
	if n := rows[0].Int("n"); n != 0 {
		t.Errorf("table missing its PK column should be skipped, but %d rows inserted", n)
	}
}

func TestMergeLWW_RejectsMissingUpdatedAtColumn(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := c.Execute(ctx,
		`INSERT INTO hosts (name, address, ssh_user, cert_serial, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		"h1", "10.0.0.1", "root", "s1", "2026-01-02T00:00:00Z", "2026-01-02T00:00:00Z"); err != nil {
		t.Fatalf("seed host: %v", err)
	}

	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "hosts",
		Columns: []string{"name", "address", "ssh_user", "cert_serial", "created_at"},
		Rows:    [][]interface{}{{"h1", "10.9.9.9", "root", "s1", "2026-01-01T00:00:00Z"}},
	}}})

	if got := hostAddr(t, c, "h1"); got != "10.0.0.1" {
		t.Errorf("address = %q, want 10.0.0.1 (dump missing updated_at must not blind-replace)", got)
	}
}

// TestMergeLWW_MultipleChunks forces the prefetch to span several row-value IN
// chunks (shrinking the param budget), proving correctness across chunk
// boundaries and no bind-variable overflow. host_labels has a 2-column PK.
func TestMergeLWW_MultipleChunks(t *testing.T) {
	old := mergePrefetchMaxParams
	mergePrefetchMaxParams = 4 // 2 PK cols → chunkSize 2
	defer func() { mergePrefetchMaxParams = old }()

	c := mustTestClient(t)
	ctx := context.Background()
	const hlcOld = "1000000000000-0000-n1"
	const hlcNew = "2000000000000-0000-n1"

	const n = 5 // > chunkSize → ≥3 chunks
	var rows [][]interface{}
	for i := 0; i < n; i++ {
		key := fmt.Sprintf("k%d", i)
		if err := c.Execute(ctx,
			`INSERT INTO host_labels (host_name, key, value, updated_at) VALUES (?, ?, ?, ?)`,
			"h1", key, "old", hlcOld); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
		rows = append(rows, []interface{}{"h1", key, "new", hlcNew})
	}

	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "host_labels",
		Columns: []string{"host_name", "key", "value", "updated_at"},
		Rows:    rows,
	}}})

	for i := 0; i < n; i++ {
		if v := labelVal(t, c, "h1", fmt.Sprintf("k%d", i)); v != "new" {
			t.Errorf("k%d = %q, want new (newer incoming should win across chunks)", i, v)
		}
	}
}

func labelTombstoned(t *testing.T, c *Client, host, key string) bool {
	t.Helper()
	rows, err := c.Query(context.Background(),
		"SELECT (deleted_at IS NOT NULL) AS dead FROM host_labels WHERE host_name = ? AND key = ?", host, key)
	if err != nil || len(rows) == 0 {
		t.Fatalf("lookup tombstone %s/%s: err=%v rows=%d", host, key, err, len(rows))
	}
	return rows[0].Int("dead") == 1
}

// TestMergeLWW_Tombstone: a soft-delete is just a row with deleted_at set and a
// newer updated_at, so LWW applies normally.
func TestMergeLWW_Tombstone(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	const hlcOld = "1000000000000-0000-n1"
	const hlcNew = "2000000000000-0000-n1"
	cols := []string{"host_name", "key", "value", "updated_at", "deleted_at"}

	// (h1,a): live local (old) vs incoming tombstone (new) → tombstone wins.
	// (h1,b): tombstone local (new) vs incoming live (old) → local tombstone kept.
	if err := c.Execute(ctx,
		`INSERT INTO host_labels (host_name, key, value, updated_at, deleted_at) VALUES (?,?,?,?,?)`,
		"h1", "a", "v", hlcOld, nil); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	if err := c.Execute(ctx,
		`INSERT INTO host_labels (host_name, key, value, updated_at, deleted_at) VALUES (?,?,?,?,?)`,
		"h1", "b", "v", hlcNew, hlcNew); err != nil {
		t.Fatalf("seed b: %v", err)
	}

	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "host_labels",
		Columns: cols,
		Rows: [][]interface{}{
			{"h1", "a", "v", hlcNew, hlcNew}, // newer tombstone → wins
			{"h1", "b", "v", hlcOld, nil},    // older live → loses to local tombstone
		},
	}}})

	if !labelTombstoned(t, c, "h1", "a") {
		t.Error("newer incoming tombstone should win over older live local row")
	}
	if !labelTombstoned(t, c, "h1", "b") {
		t.Error("older incoming live row must not resurrect a newer local tombstone")
	}
}

// TestMergeLWW_EmptyUpdatedAtSemantics pins current (intentional) behavior:
// an incoming row with an empty updated_at skips the LWW comparison and is
// applied; a real incoming HLC also wins over a NULL/empty local timestamp.
func TestMergeLWW_EmptyUpdatedAtSemantics(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	hlcNew := "2000000000000-0000-n1"

	// Local has a real HLC; incoming has empty updated_at → incoming still wins
	// (preserved semantics — empty incoming bypasses the LWW check).
	if err := c.Execute(ctx,
		`INSERT INTO host_labels (host_name, key, value, updated_at) VALUES (?,?,?,?)`,
		"h1", "a", "local", hlcNew); err != nil {
		t.Fatalf("seed a: %v", err)
	}
	// Local has empty updated_at; incoming has a real HLC → incoming wins.
	if err := c.Execute(ctx,
		`INSERT INTO host_labels (host_name, key, value, updated_at) VALUES (?,?,?,?)`,
		"h1", "b", "local", ""); err != nil {
		t.Fatalf("seed b: %v", err)
	}

	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "host_labels",
		Columns: []string{"host_name", "key", "value", "updated_at"},
		Rows: [][]interface{}{
			{"h1", "a", "incoming", ""},     // empty incoming ts → applied
			{"h1", "b", "incoming", hlcNew}, // HLC beats empty local ts
		},
	}}})

	if v := labelVal(t, c, "h1", "a"); v != "incoming" {
		t.Errorf("a = %q, want incoming (empty incoming updated_at should apply)", v)
	}
	if v := labelVal(t, c, "h1", "b"); v != "incoming" {
		t.Errorf("b = %q, want incoming (real HLC should beat empty local ts)", v)
	}
}

func digestByTable(t *testing.T, c *Client) map[string]TableDigest {
	t.Helper()
	ds, err := c.StateDigest(context.Background())
	if err != nil {
		t.Fatalf("StateDigest: %v", err)
	}
	m := make(map[string]TableDigest, len(ds))
	for _, d := range ds {
		m[d.Name] = d
	}
	return m
}

// TestMergeLWW_FullDumpParity dumps a populated DB and merges it into an empty
// one across a spread of replicated tables (incl. composite-PK ones), then
// asserts identical per-table digests — end-to-end dump↔merge parity.
func TestMergeLWW_FullDumpParity(t *testing.T) {
	src := mustTestClient(t)
	dst := mustTestClient(t)
	ctx := context.Background()

	if err := InsertHost(ctx, src, HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", CertSerial: "s1",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := InsertImage(ctx, src, ImageRecord{Name: "ubuntu", Format: "qcow2", SizeBytes: 1000}); err != nil {
		t.Fatalf("InsertImage: %v", err)
	}
	if err := InsertVM(ctx, src, VMRecord{Name: "vm1", HostName: "node1", Spec: "{}", State: "running"},
		[]InterfaceRecord{{VMName: "vm1", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:cc"}},
		[]DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "node1", Path: "/d/vm1.qcow2", SizeBytes: 1 << 30, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := InsertSecurityGroup(ctx, src, SecurityGroup{ID: "sg1", Name: "web", StackName: "default"}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}
	if err := InsertSGRule(ctx, src, SGRule{ID: "r1", SGID: "sg1", Direction: "ingress", Proto: "tcp", PortRange: "443", Action: "allow"}); err != nil {
		t.Fatalf("InsertSGRule: %v", err)
	}
	if err := InsertAuditLog(ctx, src, AuditRecord{ID: "a1", Username: "admin", Action: "create_vm", Target: "vm1", Result: "success"}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}

	dst.MergeStateBytesLWW(src.DumpStateBytes())

	srcD, dstD := digestByTable(t, src), digestByTable(t, dst)
	if len(srcD) != len(dstD) {
		t.Fatalf("digest table count differs: src=%d dst=%d", len(srcD), len(dstD))
	}
	for name, sd := range srcD {
		dd, ok := dstD[name]
		if !ok {
			t.Errorf("table %q present in src digest, missing in dst", name)
			continue
		}
		if sd.Count != dd.Count || sd.Hash != dd.Hash {
			t.Errorf("table %q diverged after dump+merge: src{n=%d,h=%s} dst{n=%d,h=%s}",
				name, sd.Count, sd.Hash, dd.Count, dd.Hash)
		}
	}
}

// TestMergeLWW_RejectsMalformedRowLength: a peer dump whose row is shorter than
// its declared columns must not panic (reading row[updatedAtIdx] out of range) —
// the malformed row is skipped.
func TestMergeLWW_RejectsMalformedRowLength(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	// Columns declares 4 (updated_at at index 3) but the row carries only 2.
	c.mergeStatePayloadLWW(&syncPayload{Tables: []syncTable{{
		Name:    "host_labels",
		Columns: []string{"host_name", "key", "value", "updated_at"},
		Rows: [][]interface{}{
			{"h1", "k1"},                       // malformed (too short) — must be skipped, not panic
			{"h1", "k2", "good", "100-0000-n"}, // well-formed — should still apply
		},
	}}})

	if v := labelVal(t, c, "h1", "k2"); v != "good" {
		t.Errorf("well-formed row should apply alongside a skipped malformed one, got %q", v)
	}
	rows, err := c.Query(ctx, "SELECT count(*) AS n FROM host_labels")
	if err != nil {
		t.Fatal(err)
	}
	if n := rows[0].Int("n"); n != 1 {
		t.Errorf("expected only the well-formed row, got %d", n)
	}
}
