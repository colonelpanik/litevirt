package corrosion

import (
	"context"
	"testing"
)

// A caller that leaves AuditRecord.ID empty must still get a row per call.
//
// audit_log's primary key is id and the insert is INSERT OR IGNORE, so every
// row after the first one with id "" was dropped without an error. Worse, the
// cached sub-chain tail advanced anyway, so the NEXT row from any caller on
// that host linked to a row that does not exist: the drop left a sequence gap
// and a hash mismatch, and `lv audit verify` reported a clean cluster as
// tampered. The web UI's security-group audit helper was such a caller, which
// meant every UI firewall change after the first went unrecorded.
func TestInsertAuditLog_EmptyIDStillRecordsEveryRow(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	for _, action := range []string{"sg.add", "sg.rule.add", "sg.rule.rm"} {
		if err := InsertAuditLog(ctx, c, AuditRecord{
			Username: "alice", HostName: "node-0", Action: action, Target: "sg-1", Result: "ok",
		}); err != nil {
			t.Fatalf("InsertAuditLog(%s): %v", action, err)
		}
	}
	// A row from a caller that does set an id, after the ones that did not.
	if err := InsertAuditLog(ctx, c, AuditRecord{
		ID: "explicit", Username: "alice", HostName: "node-0", Action: "vm.start", Target: "vm-1", Result: "ok",
	}); err != nil {
		t.Fatalf("InsertAuditLog(vm.start): %v", err)
	}

	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM audit_log WHERE host_name = 'node-0'`)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n := rows[0].Int("n"); n != 4 {
		t.Errorf("audit_log holds %d rows for node-0, want 4: rows with no id were dropped", n)
	}
	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if res.Tampered() {
		t.Errorf("an untouched chain verifies as tampered: broken_at=%q seq_gaps=%v", res.BrokenAt, res.SeqGaps)
	}
}
