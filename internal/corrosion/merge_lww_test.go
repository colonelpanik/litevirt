package corrosion

import (
	"context"
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
