package corrosion

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestApplyRemoteMutations_UndecodableEntryBackpressures (review 5a): a malformed Stmts JSON in a
// batch back-pressures — it returns an error and NO acknowledgement, rolls back an earlier statement
// applied in the SAME transaction, and records nothing in mutation_seen. So a corrupt/truncated entry
// stalls the watermark instead of being silently acknowledged with a row lost.
func TestApplyRemoteMutations_UndecodableEntryBackpressures(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	// entry1 is a valid, ledger-registered images INSERT; entry2 is undecodable. Both in ONE call,
	// so entry1's write shares entry2's transaction and must roll back with it.
	e1 := &pb.MutationEntry{Seq: 1, Hlc: "1000000000000-0000-n1", Origin: "peer", Stmts: `[{"SQL":"INSERT OR REPLACE INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)","Params":["img1","qcow2","","",1,"2020-01-01T00:00:00Z","1000000000000-0000-n1"]}]`}
	e2 := &pb.MutationEntry{Seq: 2, Hlc: "2000000000000-0000-n2", Origin: "peer", Stmts: `{not valid json`}

	seq, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{e1, e2})
	if err == nil {
		t.Fatal("an undecodable mutation entry must back-pressure (return an error)")
	}
	if seq != 0 {
		t.Fatalf("no acknowledgement on back-pressure: applied_up_to = %d, want 0", seq)
	}
	if rows, _ := c.Query(ctx, "SELECT name FROM images WHERE name = ?", "img1"); len(rows) != 0 {
		t.Fatal("an earlier statement in the same batch must roll back on a later undecodable entry")
	}
	if rows, _ := c.Query(ctx, "SELECT hlc FROM mutation_seen WHERE origin = ?", "peer"); len(rows) != 0 {
		t.Fatalf("no mutation_seen row must be inserted on back-pressure, got %d", len(rows))
	}
}

// TestApplyBulkUpdate_RejectsNonPerRowLWWCategory (review 5b): the DispBulkUpdate dispatch applies
// ONLY CatPerRowLWW; CatUnsupported, CatNone, and an unknown category all back-pressure (return an
// error) and leave the row unchanged.
func TestApplyBulkUpdate_RejectsNonPerRowLWWCategory(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)
	if err := c.Execute(ctx,
		`INSERT INTO vm_disks (vm_name, disk_name, host_name, path, updated_at) VALUES (?, ?, ?, ?, ?)`,
		"vm1", "d0", "h1", "/p", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	r := NewReplicator(c, "", RelayConfig{})
	// A valid per-row-LWW-shaped bulk update (binds updated_at), dispatched under a BAD category.
	s := Statement{SQL: "UPDATE vm_disks SET host_name = ?, updated_at = ? WHERE vm_name = ?",
		Params: []interface{}{"h2", "3000000000000-0000-n2", "vm1"}}
	sh, err := parseStmtShape(s.SQL, tablePrimaryKeys["vm_disks"])
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, cat := range []ConcurrencyCategory{CatUnsupported, CatNone, ConcurrencyCategory("mystery")} {
		tx, err := c.db.Begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		aerr := r.applyBulkUpdate(ctx, tx, s, sh, "vm_disks", tablePrimaryKeys["vm_disks"], cat)
		_ = tx.Rollback()
		if aerr == nil {
			t.Errorf("category %q must back-pressure (error), got nil", cat)
		}
	}
	// The row is unchanged (every bad category rejected before touching it).
	rows, _ := c.Query(ctx, "SELECT host_name FROM vm_disks WHERE vm_name = ?", "vm1")
	if len(rows) != 1 || rows[0].String("host_name") != "h1" {
		t.Fatalf("row must be unchanged after rejected bulk updates, got %v", rows)
	}
}
