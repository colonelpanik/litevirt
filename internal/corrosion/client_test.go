package corrosion

import (
	"context"
	"testing"
)

func testClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	// Init schema so tables exist
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func TestQuery_Success(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Insert a host
	err := c.Execute(ctx, `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, cpu_total, mem_total, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"host-a", "10.0.50.10", "root", 22, 7443, "active", "abc123", 16, 32768, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("Execute insert: %v", err)
	}

	rows, err := c.Query(ctx, "SELECT name, address, cpu_total FROM hosts")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}

	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].String("name") != "host-a" {
		t.Errorf("name = %s, want host-a", rows[0].String("name"))
	}
	if rows[0].String("address") != "10.0.50.10" {
		t.Errorf("address = %s", rows[0].String("address"))
	}
	if rows[0].Int("cpu_total") != 16 {
		t.Errorf("cpu_total = %d, want 16", rows[0].Int("cpu_total"))
	}
}

func TestQuery_WithParams(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	c.Execute(ctx, `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"host-a", "10.0.50.10", "root", 22, 7443, "active", "abc", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	c.Execute(ctx, `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"host-b", "10.0.50.11", "root", 22, 7443, "active", "def", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")

	rows, err := c.Query(ctx, "SELECT name FROM hosts WHERE name = ?", "host-a")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0].String("name") != "host-a" {
		t.Errorf("name = %s", rows[0].String("name"))
	}
}

func TestQuery_EmptyResults(t *testing.T) {
	c := testClient(t)

	rows, err := c.Query(context.Background(), "SELECT * FROM hosts")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if rows != nil {
		t.Errorf("expected nil rows for empty result, got %v", rows)
	}
}

func TestExecute_Success(t *testing.T) {
	c := testClient(t)

	err := c.Execute(context.Background(),
		`INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"host-a", "10.0.50.10", "root", 22, 7443, "active", "abc", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}

	// Verify it was written
	rows, _ := c.Query(context.Background(), "SELECT name FROM hosts WHERE name = ?", "host-a")
	if len(rows) != 1 {
		t.Errorf("expected 1 row after insert, got %d", len(rows))
	}
}

func TestExecute_InvalidSQL(t *testing.T) {
	c := testClient(t)

	err := c.Execute(context.Background(), "INSERT INTO nonexistent_table (x) VALUES (?)", "bad")
	if err == nil {
		t.Fatal("expected error for invalid SQL")
	}
}

func TestExecuteBatch_Success(t *testing.T) {
	c := testClient(t)

	err := c.ExecuteBatch(context.Background(), []Statement{
		{SQL: `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{"host-a", "10.0.50.10", "root", 22, 7443, "active", "a", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"}},
		{SQL: `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{"host-b", "10.0.50.11", "root", 22, 7443, "active", "b", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"}},
	})
	if err != nil {
		t.Fatalf("ExecuteBatch: %v", err)
	}

	rows, _ := c.Query(context.Background(), "SELECT name FROM hosts ORDER BY name")
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(rows))
	}
}

func TestExecuteBatch_Rollback(t *testing.T) {
	c := testClient(t)

	// Second statement has invalid SQL
	err := c.ExecuteBatch(context.Background(), []Statement{
		{SQL: `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			Params: []interface{}{"host-a", "10.0.50.10", "root", 22, 7443, "active", "a", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z"}},
		{SQL: `INSERT INTO nonexistent_table (x) VALUES (?)`, Params: []interface{}{"bad"}},
	})
	if err == nil {
		t.Fatal("expected error for invalid batch")
	}

	// First insert should have been rolled back
	rows, _ := c.Query(context.Background(), "SELECT name FROM hosts")
	if rows != nil {
		t.Errorf("expected no rows after rollback, got %d", len(rows))
	}
}

func TestInitSchema(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer c.Close()

	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Verify a table exists by querying it
	_, err = c.Query(context.Background(), "SELECT * FROM hosts")
	if err != nil {
		t.Errorf("hosts table should exist: %v", err)
	}
	_, err = c.Query(context.Background(), "SELECT * FROM vms")
	if err != nil {
		t.Errorf("vms table should exist: %v", err)
	}
}

// ═══════════ Row typed accessors ═══════════

func TestRow_String(t *testing.T) {
	r := Row{Columns: []string{"name", "addr"}, Values: []interface{}{"host-a", "10.0.0.1"}}

	if got := r.String("name"); got != "host-a" {
		t.Errorf("String(name) = %q, want host-a", got)
	}
	if got := r.String("addr"); got != "10.0.0.1" {
		t.Errorf("String(addr) = %q, want 10.0.0.1", got)
	}
	// Missing column
	if got := r.String("missing"); got != "" {
		t.Errorf("String(missing) = %q, want empty", got)
	}
	// Nil value
	r2 := Row{Columns: []string{"x"}, Values: []interface{}{nil}}
	if got := r2.String("x"); got != "" {
		t.Errorf("String(nil) = %q, want empty", got)
	}
	// Non-string value
	r3 := Row{Columns: []string{"n"}, Values: []interface{}{float64(42)}}
	if got := r3.String("n"); got != "42" {
		t.Errorf("String(float) = %q, want 42", got)
	}
}

func TestRow_Int(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  int
	}{
		{"float64", float64(42), 42},
		{"int", int(7), 7},
		{"int64", int64(99), 99},
		{"nil", nil, 0},
		{"string", "not a number", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Row{Columns: []string{"v"}, Values: []interface{}{tt.value}}
			if got := r.Int("v"); got != tt.want {
				t.Errorf("Int() = %d, want %d", got, tt.want)
			}
		})
	}

	// Missing column
	r := Row{Columns: []string{"a"}, Values: []interface{}{float64(1)}}
	if got := r.Int("missing"); got != 0 {
		t.Errorf("Int(missing) = %d, want 0", got)
	}
}

func TestRow_Int64(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  int64
	}{
		{"float64", float64(1e12), int64(1e12)},
		{"int64", int64(999999), 999999},
		{"nil", nil, 0},
		{"string", "not a number", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := Row{Columns: []string{"v"}, Values: []interface{}{tt.value}}
			if got := r.Int64("v"); got != tt.want {
				t.Errorf("Int64() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestRow_get_OutOfBounds(t *testing.T) {
	// More columns than values
	r := Row{Columns: []string{"a", "b", "c"}, Values: []interface{}{"x"}}
	if got := r.get("b"); got != nil {
		t.Errorf("get(b) with short values should be nil, got %v", got)
	}
	if got := r.get("c"); got != nil {
		t.Errorf("get(c) with short values should be nil, got %v", got)
	}
	// First column is still accessible
	if got := r.get("a"); got != "x" {
		t.Errorf("get(a) = %v, want x", got)
	}
}
