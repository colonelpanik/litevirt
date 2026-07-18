package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// replayEntry builds a mutation entry replaying the exact statements a prior release emitted.
func replayEntry(t *testing.T, origin, hlc string, stmts ...Statement) []*pb.MutationEntry {
	t.Helper()
	b, err := json.Marshal(stmts)
	if err != nil {
		t.Fatalf("marshal stmts: %v", err)
	}
	return []*pb.MutationEntry{{Seq: 1, Hlc: hlc, Origin: origin, Stmts: string(b)}}
}

// TestApplyRemoteMutations_LegacyCRLVersions replays v1.3.0's exact datetime('now') crl_versions
// write: it must be normalized (not parse-error/back-pressure), stamped with the mutation's
// bound HLC (never a receiver-evaluated clock), and counted by the legacy metric.
func TestApplyRemoteMutations_LegacyCRLVersions(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	sm := &fakeSyncMetrics{}
	c.SetSyncMetrics(sm)
	r := NewReplicator(c, "", RelayConfig{})
	const ts = "2000000000000-0000-n2"

	legacy := Statement{
		SQL:    "INSERT OR REPLACE INTO crl_versions (host, version, updated_at)\n\t\t\t\t VALUES (?, ?, datetime('now'))",
		Params: []interface{}{"host-a", float64(7)},
	}
	if _, err := r.ApplyRemoteMutations(ctx, replayEntry(t, "origin-node", ts, legacy)); err != nil {
		t.Fatalf("legacy crl_versions must apply, got: %v", err)
	}
	rows, err := c.Query(ctx, "SELECT version, updated_at FROM crl_versions WHERE host = ?", "host-a")
	if err != nil || len(rows) == 0 {
		t.Fatalf("row not written: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].Int("version"); got != 7 {
		t.Errorf("version = %d, want 7", got)
	}
	if got := rows[0].String("updated_at"); got != ts {
		t.Errorf("updated_at = %q, want the mutation HLC %q (not datetime('now'))", got, ts)
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.legacyTransformed) != 1 || sm.legacyTransformed[0] != "crl_versions_datetime_now" {
		t.Errorf("legacyTransformed = %v, want [crl_versions_datetime_now]", sm.legacyTransformed)
	}
}

// TestApplyRemoteMutations_LegacyGCReap replays v1.3.0's exact spent-proof GC (tsMs CASE
// predicate): it must apply through the custom-merge path (tombstone the terminal proof), not
// back-pressure, and be counted by the legacy metric.
func TestApplyRemoteMutations_LegacyGCReap(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	sm := &fakeSyncMetrics{}
	c.SetSyncMetrics(sm)
	if err := c.Execute(ctx,
		`INSERT INTO runtime_action_proofs (id, action, target_kind, target_name, dest_host, coordinator, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, 'completed', ?, ?)`,
		"p1", "reschedule", "vm", "vm1", "host-a", "host-b", "2020-01-01T00:00:00Z", "1000000000000-0000-n1"); err != nil {
		t.Fatalf("seed proof: %v", err)
	}
	r := NewReplicator(c, "", RelayConfig{})
	const ts = "2000000000000-0000-n2"
	reap := Statement{
		SQL: "UPDATE runtime_action_proofs\n\t\t    SET deleted_at = ?, updated_at = ?\n\t\t  WHERE deleted_at IS NULL\n\t\t    AND status IN ('completed','failed')\n\t\t    AND " + tsMsSQL("updated_at") + " < ?",
		// updated_at 1e12 ms < cutoff 1.5e12 → matches.
		Params: []interface{}{"2026-01-01T00:00:00Z", ts, float64(1500000000000)},
	}
	if _, err := r.ApplyRemoteMutations(ctx, replayEntry(t, "origin-node", ts, reap)); err != nil {
		t.Fatalf("legacy gc-reap must apply, got: %v", err)
	}
	rows, err := c.Query(ctx, "SELECT deleted_at FROM runtime_action_proofs WHERE id = ?", "p1")
	if err != nil || len(rows) == 0 {
		t.Fatalf("query: err=%v rows=%d", err, len(rows))
	}
	if rows[0].String("deleted_at") == "" {
		t.Error("spent proof must be tombstoned by the legacy gc-reap")
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(sm.legacyTransformed) != 1 || sm.legacyTransformed[0] != "gc_spent_proof_tsms" {
		t.Errorf("legacyTransformed = %v, want [gc_spent_proof_tsms]", sm.legacyTransformed)
	}
}

// TestApplyBulkPerRowLWW_GatesByRowClock proves the per-row-LWW expansion: a single bulk
// tombstone keyed by a parent column only tombstones the matching rows whose local clock is
// OLDER than the incoming write — a concurrently-newer row on this node is kept.
func TestApplyBulkPerRowLWW_GatesByRowClock(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	const oldTS = "1000000000000-0000-n1"
	const futureTS = "3000000000000-0000-n1"
	for i, iface := range []struct{ net, ua string }{{"neta", oldTS}, {"netb", futureTS}} {
		if err := c.Execute(ctx,
			`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at) VALUES (?, ?, ?, ?, ?)`,
			"vm1", iface.net, i, "00:11:22:33:44:5"+fmt.Sprint(i), iface.ua); err != nil {
			t.Fatalf("seed %s: %v", iface.net, err)
		}
	}

	r := NewReplicator(c, "", RelayConfig{})
	const midTS = "2000000000000-0000-n2"
	stmts := fmt.Sprintf(
		`[{"SQL":"UPDATE vm_interfaces SET deleted_at = ?, updated_at = ? WHERE vm_name = ?","Params":["%s","%s","vm1"]}]`, midTS, midTS)
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: midTS, Origin: "origin-node", Stmts: stmts}}
	if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("apply: %v", err)
	}

	deletedAt := func(net string) string {
		rows, err := c.Query(ctx, "SELECT deleted_at FROM vm_interfaces WHERE vm_name = ? AND network_name = ?", "vm1", net)
		if err != nil || len(rows) == 0 {
			t.Fatalf("query %s: err=%v rows=%d", net, err, len(rows))
		}
		return rows[0].String("deleted_at")
	}
	if deletedAt("neta") == "" {
		t.Error("neta (older clock) must be tombstoned by the bulk update")
	}
	if deletedAt("netb") != "" {
		t.Error("netb (newer local clock) must be KEPT — per-row LWW must not clobber it")
	}
}

// TestApplyBulkPerRowLWW_KeepsLocalOnTie: an exact-clock bulk update must NOT overwrite the
// local row — a bulk SET is a partial projection, not a full row image (finding 3).
func TestApplyBulkPerRowLWW_KeepsLocalOnTie(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	const ts = "2000000000000-0000-n1"
	if err := c.Execute(ctx,
		`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"vm1", "neta", 0, "00:11:22:33:44:55", "10.0.0.5", ts); err != nil {
		t.Fatalf("seed: %v", err)
	}
	r := NewReplicator(c, "", RelayConfig{})
	// Bulk tombstone at the SAME clock as the local row.
	stmts := fmt.Sprintf(
		`[{"SQL":"UPDATE vm_interfaces SET deleted_at = ?, updated_at = ? WHERE vm_name = ?","Params":["%s","%s","vm1"]}]`, ts, ts)
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: ts, Origin: "origin-node", Stmts: stmts}}
	if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("apply: %v", err)
	}
	rows, err := c.Query(ctx, "SELECT deleted_at FROM vm_interfaces WHERE vm_name = ? AND network_name = ?", "vm1", "neta")
	if err != nil || len(rows) == 0 {
		t.Fatalf("query: err=%v rows=%d", err, len(rows))
	}
	if rows[0].String("deleted_at") != "" {
		t.Error("equal-clock bulk update must keep local (not tombstone)")
	}
}

// TestApplyRemoteMutations_NoClockFullPKUpdate: a full-PK UPDATE on a table with NO updated_at
// column (audit_log reseal) must apply verbatim, not back-pressure trying to LWW-gate on a
// nonexistent column (finding 2).
func TestApplyRemoteMutations_NoClockFullPKUpdate(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, action, target, result) VALUES (?, ?, ?, ?, ?)`,
		"a1", "2020-01-01T00:00:00Z", "login", "user", "ok"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	r := NewReplicator(c, "", RelayConfig{})
	stmts := `[{"SQL":"UPDATE audit_log SET prev_hash = ?, content_hash = ? WHERE id = ?","Params":["ph","ch","a1"]}]`
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: "2000000000000-0000-n2", Origin: "origin-node", Stmts: stmts}}
	if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("no-clock full-PK update must apply, got: %v", err)
	}
	rows, err := c.Query(ctx, "SELECT content_hash FROM audit_log WHERE id = ?", "a1")
	if err != nil || len(rows) == 0 {
		t.Fatalf("query: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].String("content_hash"); got != "ch" {
		t.Errorf("content_hash = %q, want ch (reseal must have applied verbatim)", got)
	}
}

// TestApplyRemoteMutations_UnregisteredDeleteRejected: a hard DELETE whose shape is not a
// registered retention template must back-pressure, never be applied on a derived disposition.
func TestApplyRemoteMutations_UnregisteredDeleteRejected(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	r := NewReplicator(c, "", RelayConfig{})
	// The registered vms delete is `WHERE name = ? AND deleted_at IS NOT NULL`; this shape is
	// different, so it is unregistered.
	stmts := `[{"SQL":"DELETE FROM vms WHERE host_name = ?","Params":["host-x"]}]`
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: "2000000000000-0000-n2", Origin: "origin-node", Stmts: stmts}}
	if _, err := r.ApplyRemoteMutations(ctx, entries); err == nil {
		t.Fatal("expected back-pressure for an unregistered DELETE shape")
	}
	assertNotSeen(t, c, "origin-node")
}

// TestApplyRemoteMutations_DerivesUnregisteredInsert: a column-subset INSERT (an older
// sender's shape, absent from this build's ledger) is applied by its derived disposition
// rather than back-pressured — the mixed-version horizon. (Column preservation itself is
// covered elsewhere; here we assert the derive path applies at all.)
func TestApplyRemoteMutations_DerivesUnregisteredInsert(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	r := NewReplicator(c, "", RelayConfig{})
	// A minimal hosts INSERT — not a shape any current builder emits verbatim.
	stmts := `[{"SQL":"INSERT INTO hosts (name, address, ssh_user, cert_serial, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)","Params":["h9","10.0.0.9","root","s9","2020-01-01T00:00:00Z","2000000000000-0000-n2"]}]`
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: "2000000000000-0000-n2", Origin: "origin-node", Stmts: stmts}}
	if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("derived-disposition apply must succeed, got: %v", err)
	}
	rows, err := c.Query(ctx, "SELECT address FROM hosts WHERE name = ?", "h9")
	if err != nil || len(rows) == 0 {
		t.Fatalf("row not inserted: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].String("address"); got != "10.0.0.9" {
		t.Errorf("address = %q, want 10.0.0.9", got)
	}
}
