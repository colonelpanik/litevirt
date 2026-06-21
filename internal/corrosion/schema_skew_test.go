package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/hlc"
)

func TestIsSchemaMissingError(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"no such table: backup_schedules", true},
		{"no such column: region", true},
		{"table hosts has no column named region", true},
		{"NO SUCH TABLE: Service_Endpoints", true},
		{"some other constraint failure", false},
		{"UNIQUE constraint failed: hosts.name", false},
		{"", false},
	}
	for _, tc := range cases {
		got := isSchemaMissingError(errors.New(tc.msg))
		if got != tc.want {
			t.Errorf("isSchemaMissingError(%q) = %v, want %v", tc.msg, got, tc.want)
		}
	}
	if isSchemaMissingError(nil) {
		t.Error("isSchemaMissingError(nil) must be false")
	}
}

// TestApplyRemoteMutations_BackPressureOnSchemaMissing exercises the
// rolling-upgrade safety path: when a peer pushes a mutation targeting
// a table this node doesn't yet have, the receiver MUST return an
// error so the sender's watermark stalls and the mutation is retried
// after the receiver is upgraded. Silently dropping it loses data.
func TestApplyRemoteMutations_BackPressureOnSchemaMissing(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	// Simulate "old receiver, new sender" by dropping a table the
	// sender's mutation references. This is exactly the rolling-
	// upgrade window where new-binary host pushes mutations for a
	// table the old-binary host doesn't have yet.
	if err := c.Execute(ctx, "DROP TABLE service_endpoints"); err != nil {
		t.Fatalf("DROP TABLE: %v", err)
	}
	r := NewReplicator(c, "", RelayConfig{})

	clock := hlc.NewClock("origin-node")
	ts := clock.Now()

	entries := []*pb.MutationEntry{{
		Seq:    1,
		Hlc:    ts.String(),
		Origin: "origin-node",
		Stmts: `[{"SQL":"INSERT INTO service_endpoints (service_name, ip, region, weight, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)","Params":["api","10.0.0.1","ny",1,"2026-05-11T00:00:00Z","2026-05-11T00:00:00Z"]}]`,
	}}

	_, err := r.ApplyRemoteMutations(ctx, entries)
	if err == nil {
		t.Fatal("expected back-pressure error for schema-missing receiver")
	}
	if !strings.Contains(err.Error(), "schema-missing") {
		t.Errorf("error %q should mention schema-missing", err.Error())
	}

	// The dedup table must NOT contain this entry — if we marked it
	// seen, the sender would never retry and the row would be lost
	// after the receiver upgrades.
	seen, qerr := c.Query(ctx, "SELECT COUNT(*) AS n FROM mutation_seen WHERE origin = 'origin-node'")
	if qerr != nil {
		t.Fatalf("query mutation_seen: %v", qerr)
	}
	if len(seen) > 0 && seen[0].Int("n") != 0 {
		t.Errorf("mutation_seen has rows after schema-missing rejection: %d (should be 0 — sender must retry)", seen[0].Int("n"))
	}
}
