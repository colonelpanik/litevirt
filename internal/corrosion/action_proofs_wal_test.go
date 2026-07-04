package corrosion

import (
	"context"
	"encoding/json"
	"testing"
)

// The proof table merges MONOTONICALLY on the WAL apply path (not LWW): a
// replicated INSERT can't clobber a progressed row (INSERT OR IGNORE), and a
// guarded status UPDATE no-ops on a peer that is already terminal — so a
// newer-timestamped non-terminal copy can NOT resurrect a spent proof.
func TestWAL_ActionProofMonotone(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	// Local row is already terminal (completed).
	p := ActionProof{ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1", DestHost: "h", Coordinator: "h"}
	if err := WriteActionProof(ctx, c, p); err != nil {
		t.Fatalf("WriteActionProof: %v", err)
	}
	if err := ClaimActionProof(ctx, c, "p1", "h"); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := c.Execute(ctx, `UPDATE runtime_action_proofs SET status='completed', updated_at=? WHERE id='p1'`, c.NowTS()); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// A stale peer replays, with a FAR-FUTURE hlc/updated_at:
	//   (1) the original prepared INSERT, and
	//   (2) an in_progress guarded UPDATE.
	// Neither may regress the local completed row.
	const newer = "2999-01-01T00:00:00Z"
	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	ins := Statement{SQL: insertProofSQL, Params: proofInsertParams(p, newer)}
	if err := r.applyStatementLWW(ctx, tx, ins, newer); err != nil {
		t.Fatalf("apply insert: %v", err)
	}
	upd := Statement{
		SQL: `UPDATE runtime_action_proofs SET status='in_progress', updated_at=? ` +
			`WHERE id=? AND deleted_at IS NULL AND status IN ('prepared','in_progress')`,
		Params: []interface{}{newer, "p1"},
	}
	if err := r.applyStatementLWW(ctx, tx, upd, newer); err != nil {
		t.Fatalf("apply update: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	pr, ok, err := GetActionProof(ctx, c, "p1")
	if err != nil || !ok {
		t.Fatalf("GetActionProof: ok=%v err=%v", ok, err)
	}
	if pr.Status != ProofCompleted {
		t.Fatalf("status=%q; want completed — a newer non-terminal replica must not resurrect a spent proof", pr.Status)
	}
}

// A well-formed peer's proof dump always carries the status column; an incoming AE
// dump that OMITS it can't be checked against the monotone lifecycle, so
// proofMergeKeepLocalRow must FAIL CLOSED (keep local) rather than fall back to plain
// LWW — otherwise a newer-timestamped, status-less row could resurrect a spent proof.
func TestProofMergeKeepLocalRow_NoStatusColumnFailsClosed(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	// Local row is terminal (completed).
	p := ActionProof{ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1", DestHost: "h", Coordinator: "h"}
	if err := WriteActionProof(ctx, c, p); err != nil {
		t.Fatalf("WriteActionProof: %v", err)
	}
	if err := ClaimActionProof(ctx, c, "p1", "h"); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := c.Execute(ctx, `UPDATE runtime_action_proofs SET status='completed', updated_at=? WHERE id='p1'`, c.NowTS()); err != nil {
		t.Fatalf("complete: %v", err)
	}

	// Incoming AE dump omits the status column entirely, with a FAR-FUTURE updated_at
	// that would win a plain LWW compare.
	tbl := syncTable{Name: "runtime_action_proofs", Columns: []string{"id", "updated_at"}}
	row := []interface{}{"p1", "2999-01-01T00:00:00Z"}

	tx, err := c.db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	keepLocal := c.proofMergeKeepLocalRow(tx, tbl, row, []string{"id"}, []int{0}, 1)
	if !keepLocal {
		t.Fatal("no-status dump: keepLocal=false; want true — a status-less proof dump must fail closed, not LWW-resurrect a terminal proof")
	}
}

// A runtime_action_proofs AE dump that OMITS the status column is refused at the CHUNK level
// — including for an ABSENT local row — so a malformed/hostile dump can't INSERT a status-less
// row that defaults to 'prepared' and manufactures a live proof.
func TestMergeChunk_RefusesStatuslessProofDump(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	merged, skipped := c.mergeChunk(
		syncTable{Name: "runtime_action_proofs", Columns: []string{"id", "updated_at"}},
		[][]interface{}{{"ghost", "2999-01-01T00:00:00Z"}},
		"INSERT OR REPLACE INTO runtime_action_proofs (id, updated_at) VALUES (?, ?)",
		[]string{"id"}, []int{0}, 1,
	)
	if merged != 0 || skipped != 1 {
		t.Fatalf("status-less proof dump: merged=%d skipped=%d; want 0/1 (chunk refused)", merged, skipped)
	}
	if _, ok, err := GetActionProof(ctx, c, "ghost"); err != nil || ok {
		t.Fatalf("status-less dump inserted a proof: ok=%v err=%v; want no row (refused)", ok, err)
	}
}

// proofMergeKeepLocal is the monotone anti-entropy decision: rank wins over
// timestamp, and a completed⊕failed conflict keeps local.
func TestProofMergeKeepLocal(t *testing.T) {
	const older, newer = "2027-01-01T00:00:00Z", "2029-01-01T00:00:00Z"
	cases := []struct {
		name                       string
		lStatus, lTS, iStatus, iTS string
		wantKeepLocal              bool
	}{
		{"terminal beats newer prepared", "completed", older, "prepared", newer, true},
		{"newer forward transition applies", "prepared", older, "completed", newer, false},
		{"in_progress beats newer prepared", "in_progress", older, "prepared", newer, true},
		{"completed vs failed keeps local", "completed", older, "failed", newer, true},
		{"same status LWW takes newer", "in_progress", older, "in_progress", newer, false},
		{"same status LWW keeps newer-local", "in_progress", newer, "in_progress", older, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := proofMergeKeepLocal(tc.lStatus, tc.lTS, tc.iStatus, tc.iTS); got != tc.wantKeepLocal {
				t.Fatalf("keepLocal=%v; want %v", got, tc.wantKeepLocal)
			}
		})
	}
}

// entryTouchesCustomMerge flags any entry carrying a runtime_action_proofs
// statement so the WAL push DROPS the WHOLE entry for an unready peer — a proof
// write and its co-batched vms.pending_action_id marker must never be split (a
// marker without its proof would dangle on the peer, and a pre-v38 peer can't
// apply the marker column either). The dropped proof reconverges via sensitive AE.
func TestEntryTouchesCustomMerge(t *testing.T) {
	mustJSON := func(ss []Statement) string {
		b, _ := json.Marshal(ss)
		return string(b)
	}
	proofStmt := Statement{SQL: `INSERT INTO runtime_action_proofs (id) VALUES (?)`, Params: []interface{}{"p1"}}
	vmStmt := Statement{SQL: `UPDATE vms SET state='pending' WHERE name=?`, Params: []interface{}{"vm1"}}
	markerStmt := Statement{SQL: `UPDATE vms SET pending_action_id=? WHERE name=?`, Params: []interface{}{"p1", "vm1"}}

	// A batch co-mingling the proof and its marker is proof-bearing → drop whole.
	if !entryTouchesCustomMerge(mustJSON([]Statement{proofStmt, markerStmt})) {
		t.Fatal("proof+marker batch must be flagged (drop whole entry)")
	}
	// Proof-only batch is proof-bearing.
	if !entryTouchesCustomMerge(mustJSON([]Statement{proofStmt})) {
		t.Fatal("proof-only batch must be flagged")
	}
	// A proof-free batch replicates normally.
	if entryTouchesCustomMerge(mustJSON([]Statement{vmStmt})) {
		t.Fatal("a proof-free batch must NOT be flagged")
	}
	// Malformed JSON is treated conservatively as proof-bearing.
	if !entryTouchesCustomMerge("{not json") {
		t.Fatal("unparseable entry must be treated as proof-bearing (dropped)")
	}
}

// unionSteps merges step_state forward-only: no step is ever dropped, duplicates
// collapse, order is preserved. (A merge must not lose "started".)
func TestUnionSteps(t *testing.T) {
	cases := []struct{ a, b, want string }{
		{"disk_built started", "disk_built", "disk_built started"},
		{"disk_built", "disk_built started", "disk_built started"},
		{"", "started", "started"},
		{"disk_built started", "", "disk_built started"},
		{"", "", ""},
	}
	for _, tc := range cases {
		if got := unionSteps(tc.a, tc.b); got != tc.want {
			t.Fatalf("unionSteps(%q,%q)=%q; want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// A forward transition replicated from the executor DOES apply on a peer that is
// behind (prepared → in_progress → completed), so the lifecycle still converges.
func TestWAL_ActionProofForwardConverges(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	r := NewReplicator(c, "", RelayConfig{})

	p := ActionProof{ID: "p1", Action: ActionReschedule, TargetKind: "vm", TargetName: "vm1", DestHost: "h", Coordinator: "h"}
	if err := WriteActionProof(ctx, c, p); err != nil { // local is prepared
		t.Fatalf("WriteActionProof: %v", err)
	}

	const t1 = "2027-01-01T00:00:00Z"
	tx, _ := c.db.Begin()
	upd := Statement{
		SQL: `UPDATE runtime_action_proofs SET status='completed', completed_at=?, updated_at=? ` +
			`WHERE id=? AND deleted_at IS NULL AND status IN ('prepared','in_progress')`,
		Params: []interface{}{t1, t1, "p1"},
	}
	if err := r.applyStatementLWW(ctx, tx, upd, t1); err != nil {
		t.Fatalf("apply: %v", err)
	}
	_ = tx.Commit()

	pr, _, _ := GetActionProof(ctx, c, "p1")
	if pr.Status != ProofCompleted {
		t.Fatalf("status=%q; want completed — a forward transition must converge", pr.Status)
	}
}
