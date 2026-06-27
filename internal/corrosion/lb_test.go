package corrosion

import (
	"context"
	"testing"
)

func setupLBSchema(t *testing.T, c *Client) {
	t.Helper()
	ctx := context.Background()
	_ = c.execLocal(ctx, `DROP TABLE IF EXISTS lb_configs`)
	_ = c.execLocal(ctx, `CREATE TABLE lb_configs (
		name       TEXT PRIMARY KEY,
		stack_name TEXT,
		vip        TEXT NOT NULL,
		algorithm  TEXT NOT NULL DEFAULT '',
		hosts      TEXT NOT NULL DEFAULT '[]',
		ports      TEXT NOT NULL DEFAULT '[]',
		enabled    INTEGER NOT NULL DEFAULT 1,
		updated_at TEXT NOT NULL,
		deleted_at TEXT
	)`)
	_ = c.execLocal(ctx, `DROP TABLE IF EXISTS lb_backends`)
	_ = c.execLocal(ctx, `CREATE TABLE lb_backends (
		lb_name    TEXT NOT NULL,
		name       TEXT NOT NULL,
		address    TEXT NOT NULL,
		is_vm      INTEGER NOT NULL DEFAULT 0,
		vm_name    TEXT,
		enabled    INTEGER NOT NULL DEFAULT 1,
		updated_at TEXT NOT NULL,
		deleted_at TEXT,
		PRIMARY KEY (lb_name, name)
	)`)
}

// TestLBStore_SQLMetacharactersRoundTrip is the F1 regression: names/values
// containing SQL metacharacters (quotes, semicolons, comment markers, a UNION
// attempt) must round-trip intact through the parameterized LB store and must
// NOT corrupt the query or leak other rows. Before the fix these were built
// with fmt.Sprintf and a single quote broke (or exploited) the statement.
func TestLBStore_SQLMetacharactersRoundTrip(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	// A decoy row that a UNION/injection might try to surface.
	if err := UpsertLBConfig(ctx, c, LBConfigRecord{Name: "secret-lb", VIP: "10.9.9.9", Algorithm: "rr", Hosts: "[]", Enabled: true}); err != nil {
		t.Fatalf("seed decoy: %v", err)
	}

	evil := `x'; DROP TABLE lb_configs;-- UNION SELECT * FROM sessions`
	rec := LBConfigRecord{
		Name:      evil,
		VIP:       "10.0.0.50",
		Algorithm: `o'rr`,
		Hosts:     `["a'b","c"]`,
		Ports:     "[]",
		Enabled:   true,
	}
	if err := UpsertLBConfig(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBConfig with metachars: %v", err)
	}

	// Backend with metachars under the same evil LB name.
	if err := UpsertLBBackend(ctx, c, LBBackendRecord{LBName: evil, Name: `b'1`, Address: "10.0.0.51", Enabled: true}); err != nil {
		t.Fatalf("UpsertLBBackend with metachars: %v", err)
	}

	// The table still exists (DROP didn't execute) and the evil row round-trips verbatim.
	got, err := ListLBConfigs(ctx, c)
	if err != nil {
		t.Fatalf("ListLBConfigs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 configs (decoy + evil), got %d — injection may have run", len(got))
	}
	var found *LBConfigRecord
	for i := range got {
		if got[i].Name == evil {
			found = &got[i]
		}
	}
	if found == nil {
		t.Fatal("evil-named LB did not round-trip")
	}
	if found.Algorithm != `o'rr` || found.Hosts != `["a'b","c"]` {
		t.Errorf("values corrupted: alg=%q hosts=%q", found.Algorithm, found.Hosts)
	}

	bes, err := ListLBBackends(ctx, c, evil)
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	if len(bes) != 1 || bes[0].Name != `b'1` {
		t.Errorf("backend with metachars did not round-trip: %+v", bes)
	}

	// Lookup by the evil name must not also return the decoy.
	if len(bes) > 0 && bes[0].Address != "10.0.0.51" {
		t.Errorf("backend address = %q", bes[0].Address)
	}

	// Delete by evil name leaves the decoy untouched.
	if err := SoftDeleteLBConfig(ctx, c, evil); err != nil {
		t.Fatalf("DeleteLBConfig: %v", err)
	}
	after, _ := ListLBConfigs(ctx, c)
	if len(after) != 1 || after[0].Name != "secret-lb" {
		t.Errorf("delete-by-evil-name affected the wrong rows: %+v", after)
	}
}

func TestUpsertLBConfig(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	rec := LBConfigRecord{
		Name:      "web-lb",
		VIP:       "10.0.0.100",
		Algorithm: "round-robin",
		Hosts:     `["node1","node2"]`,
		Ports:     `[{"listen":80,"target":8080}]`,
		Enabled:   true,
	}
	if err := UpsertLBConfig(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	rows, err := c.Query(ctx, `SELECT name, vip, algorithm, hosts, ports, enabled FROM lb_configs WHERE name = ?`, "web-lb")
	if err != nil {
		t.Fatalf("Query lb_configs: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	r := rows[0]
	if r.String("name") != "web-lb" {
		t.Errorf("name = %q, want web-lb", r.String("name"))
	}
	if r.String("vip") != "10.0.0.100" {
		t.Errorf("vip = %q, want 10.0.0.100", r.String("vip"))
	}
	if r.String("algorithm") != "round-robin" {
		t.Errorf("algorithm = %q, want round-robin", r.String("algorithm"))
	}
	if r.String("hosts") != `["node1","node2"]` {
		t.Errorf("hosts = %q", r.String("hosts"))
	}
	if r.String("ports") != `[{"listen":80,"target":8080}]` {
		t.Errorf("ports = %q", r.String("ports"))
	}
}

func TestUpsertLBConfig_WithStackName(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	rec := LBConfigRecord{
		Name:      "mystack-lb",
		StackName: "mystack",
		VIP:       "10.0.0.50",
		Algorithm: "roundrobin",
		Hosts:     `["node1"]`,
		Enabled:   true,
	}
	if err := UpsertLBConfig(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	rows, _ := c.Query(ctx, `SELECT stack_name FROM lb_configs WHERE name = ?`, "mystack-lb")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].String("stack_name") != "mystack" {
		t.Errorf("stack_name = %q, want mystack", rows[0].String("stack_name"))
	}
}

func TestUpsertLBConfig_Update(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	rec := LBConfigRecord{
		Name:      "web-lb",
		VIP:       "10.0.0.100",
		Algorithm: "round-robin",
		Hosts:     `["node1"]`,
		Enabled:   true,
	}
	if err := UpsertLBConfig(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	rec.VIP = "10.0.0.200"
	rec.Algorithm = "least-conn"
	rec.Hosts = `["node1","node2","node3"]`
	rec.Enabled = false
	if err := UpsertLBConfig(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBConfig update: %v", err)
	}

	rows, _ := c.Query(ctx, `SELECT vip, algorithm, hosts, enabled FROM lb_configs WHERE name = ?`, "web-lb")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].String("vip") != "10.0.0.200" {
		t.Errorf("vip = %q after update, want 10.0.0.200", rows[0].String("vip"))
	}
	if rows[0].String("algorithm") != "least-conn" {
		t.Errorf("algorithm = %q after update, want least-conn", rows[0].String("algorithm"))
	}
}

func TestDeleteLBConfig(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	rec := LBConfigRecord{
		Name:      "web-lb",
		VIP:       "10.0.0.100",
		Algorithm: "round-robin",
		Hosts:     `["node1"]`,
		Enabled:   true,
	}
	if err := UpsertLBConfig(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	if err := SoftDeleteLBConfig(ctx, c, "web-lb"); err != nil {
		t.Fatalf("SoftDeleteLBConfig: %v", err)
	}

	// Soft-delete keeps a tombstone row (so the delete survives anti-entropy) but
	// the LB is gone from the active listing.
	if cfgs, _ := ListLBConfigs(ctx, c); len(cfgs) != 0 {
		t.Errorf("expected web-lb absent from ListLBConfigs after delete, got %+v", cfgs)
	}
	rows, _ := c.Query(ctx, `SELECT deleted_at FROM lb_configs WHERE name = ?`, "web-lb")
	if len(rows) != 1 || rows[0].String("deleted_at") == "" {
		t.Errorf("expected a tombstone row with deleted_at set, got %+v", rows)
	}
}

// SoftDeleteLBConfig on a nonexistent LB is a no-op (UPDATE 0 rows) — it must NOT
// manufacture a tombstone for an LB that never existed (the cleanup-path case).
func TestSoftDeleteLBConfig_NonExistentNoTombstone(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	if err := SoftDeleteLBConfig(ctx, c, "nonexistent"); err != nil {
		t.Fatalf("SoftDeleteLBConfig for nonexistent: %v", err)
	}
	rows, _ := c.Query(ctx, `SELECT name FROM lb_configs WHERE name = ?`, "nonexistent")
	if len(rows) != 0 {
		t.Errorf("soft-delete of a nonexistent LB manufactured a tombstone: %+v", rows)
	}
}

func TestUpsertLBConfig_Disabled(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	rec := LBConfigRecord{
		Name:      "api-lb",
		VIP:       "10.0.0.50",
		Algorithm: "ip-hash",
		Hosts:     `["node1"]`,
		Enabled:   false,
	}
	if err := UpsertLBConfig(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBConfig: %v", err)
	}

	rows, _ := c.Query(ctx, `SELECT enabled FROM lb_configs WHERE name = ?`, "api-lb")
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].Int("enabled") != 0 {
		t.Errorf("enabled = %d, want 0 for disabled", rows[0].Int("enabled"))
	}
}

// ── LB Backend Tests ─────────────────────────────────────────────────────────

func TestUpsertLBBackend(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	rec := LBBackendRecord{
		LBName:  "web-lb",
		Name:    "web1",
		Address: "10.0.1.10:8080",
		IsVM:    false,
		Enabled: true,
	}
	if err := UpsertLBBackend(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}

	backends, err := ListLBBackends(ctx, c, "web-lb")
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("expected 1 backend, got %d", len(backends))
	}
	if backends[0].Name != "web1" || backends[0].Address != "10.0.1.10:8080" {
		t.Errorf("unexpected backend: %+v", backends[0])
	}
}

func TestUpsertLBBackend_VMBackend(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	rec := LBBackendRecord{
		LBName:  "web-lb",
		Name:    "myvm-1",
		Address: "10.0.1.20",
		IsVM:    true,
		VMName:  "myvm-1",
		Enabled: true,
	}
	if err := UpsertLBBackend(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}

	backends, err := ListLBBackends(ctx, c, "web-lb")
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	if len(backends) != 1 {
		t.Fatalf("expected 1, got %d", len(backends))
	}
	if !backends[0].IsVM || backends[0].VMName != "myvm-1" {
		t.Errorf("expected VM backend, got %+v", backends[0])
	}
}

func TestUpsertLBBackend_Update(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	rec := LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.1", Enabled: true}
	if err := UpsertLBBackend(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBBackend: %v", err)
	}

	rec.Address = "10.0.0.2"
	if err := UpsertLBBackend(ctx, c, rec); err != nil {
		t.Fatalf("UpsertLBBackend update: %v", err)
	}

	backends, _ := ListLBBackends(ctx, c, "lb1")
	if len(backends) != 1 {
		t.Fatalf("expected 1, got %d", len(backends))
	}
	if backends[0].Address != "10.0.0.2" {
		t.Errorf("address not updated: %q", backends[0].Address)
	}
}

func TestDeleteLBBackend(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	_ = UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.1", Enabled: true})
	_ = UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b2", Address: "10.0.0.2", Enabled: true})

	if err := TombstoneLBBackend(ctx, c, "lb1", "b1"); err != nil {
		t.Fatalf("DeleteLBBackend: %v", err)
	}

	backends, _ := ListLBBackends(ctx, c, "lb1")
	if len(backends) != 1 {
		t.Fatalf("expected 1, got %d", len(backends))
	}
	if backends[0].Name != "b2" {
		t.Errorf("wrong backend remaining: %q", backends[0].Name)
	}
}

func TestDeleteLBBackends(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	_ = UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b1", Address: "10.0.0.1", Enabled: true})
	_ = UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb1", Name: "b2", Address: "10.0.0.2", Enabled: true})
	_ = UpsertLBBackend(ctx, c, LBBackendRecord{LBName: "lb2", Name: "b3", Address: "10.0.0.3", Enabled: true})

	if err := SoftDeleteLBBackends(ctx, c, "lb1"); err != nil {
		t.Fatalf("DeleteLBBackends: %v", err)
	}

	backends, _ := ListLBBackends(ctx, c, "lb1")
	if len(backends) != 0 {
		t.Errorf("expected 0 backends for lb1, got %d", len(backends))
	}

	// lb2 backends should be untouched.
	backends2, _ := ListLBBackends(ctx, c, "lb2")
	if len(backends2) != 1 {
		t.Errorf("expected 1 backend for lb2, got %d", len(backends2))
	}
}

func TestListLBBackends_Empty(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	setupLBSchema(t, c)

	backends, err := ListLBBackends(ctx, c, "nonexistent")
	if err != nil {
		t.Fatalf("ListLBBackends: %v", err)
	}
	if len(backends) != 0 {
		t.Errorf("expected 0, got %d", len(backends))
	}
}
