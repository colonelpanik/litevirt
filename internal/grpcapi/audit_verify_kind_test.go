package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestVerifyAuditChain_CarriesTheKindOfBreak: the RPC passes the verifier's
// classification of the first broken link through, so `lv audit verify`, the
// web UI and the REST poller can name a forked chain as one instead of as an
// edited row.
func TestVerifyAuditChain_CarriesTheKindOfBreak(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
		ID: "orig-1", Username: "u", HostName: "node-3", Action: "vm.start", Target: "x", Result: "ok",
		Timestamp: "2026-10-03T22:16:00.000000000Z",
	}); err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	// A second genesis row under the same name, correctly hashed: the shape a
	// host rebuilt on an empty database wrote before its history replicated back.
	fork := corrosion.AuditRecord{
		ID: "fork-1", Username: "u", HostName: "node-3", Action: "vm.start", Target: "x", Result: "ok",
		Timestamp: "2026-10-03T22:16:30.767241380Z",
	}
	if err := s.db.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
		 result, prev_hash, content_hash, key_id, signature, seq)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, '', ?, '', '', 1)`,
		fork.ID, fork.Timestamp, fork.Username, fork.HostName, fork.Action, fork.Target, fork.Result,
		corrosion.HashAuditRow(fork)); err != nil {
		t.Fatalf("insert fork: %v", err)
	}
	resp, err := s.VerifyAuditChain(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if resp.BrokenAtId != "fork-1" || resp.BrokenAtKind != corrosion.AuditBrokenForked {
		t.Fatalf("broken_at_id=%q broken_at_kind=%q, want fork-1 / %q",
			resp.BrokenAtId, resp.BrokenAtKind, corrosion.AuditBrokenForked)
	}
	if !resp.Tampered {
		t.Error("a forked chain must still fail verification")
	}
	if !resp.Forked {
		t.Error("a fork-only chain must be reported forked, so a client does not call it tampered")
	}
}

// Re-review m-3: the RPC names the rows that lost their predecessor on a
// forked host (orphaned_rows), so `lv audit verify` and the UI can show the
// deletion a fork hides.
//
// Mutation: OrphanedRows not mapped — red.
func TestVerifyAuditChain_NamesOrphanedRows(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	for i, id := range []string{"orig-1", "orig-2", "orig-3"} {
		if err := corrosion.InsertAuditLog(ctx, s.db, corrosion.AuditRecord{
			ID: id, Username: "u", HostName: "node-3", Action: "vm.start", Target: "x", Result: "ok",
			Timestamp: "2026-10-03T22:16:0" + string(rune('1'+i)) + ".000000000Z",
		}); err != nil {
			t.Fatalf("InsertAuditLog: %v", err)
		}
	}
	prev := ""
	for i, id := range []string{"fork-1", "fork-2", "fork-3"} {
		f := corrosion.AuditRecord{
			ID: id, Username: "u", HostName: "node-3", Action: "vm.start", Target: "x", Result: "ok",
			Timestamp: "2026-10-03T22:16:3" + string(rune('1'+i)) + ".000000000Z", PrevHash: prev,
		}
		h := corrosion.HashAuditRow(f)
		if err := s.db.Execute(ctx,
			`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
			 result, prev_hash, content_hash, key_id, signature, seq)
			 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?, '', '', ?)`,
			f.ID, f.Timestamp, f.Username, f.HostName, f.Action, f.Target, f.Result, prev, h, i+1); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		prev = h
	}
	if err := s.db.Execute(ctx, `DELETE FROM audit_log WHERE id = 'orig-2'`); err != nil {
		t.Fatal(err)
	}
	resp, err := s.VerifyAuditChain(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("VerifyAuditChain: %v", err)
	}
	if len(resp.OrphanedRows) != 1 || !strings.Contains(resp.OrphanedRows[0], "row orig-3 (seq 3)") {
		t.Fatalf("orphaned_rows = %v, want orig-3 named", resp.OrphanedRows)
	}
	if resp.Forked {
		t.Error("a fork that hides a deletion is not a fork alone: forked must be false")
	}
}
