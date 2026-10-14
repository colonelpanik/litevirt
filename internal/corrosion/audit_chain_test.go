package corrosion

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func newAuditTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestAuditChain_IntactAcrossInserts confirms each new row chains
// off the prior one and VerifyAuditChain runs clean.
func TestAuditChain_IntactAcrossInserts(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	for i, action := range []string{"vm.create", "vm.start", "vm.stop"} {
		if err := InsertAuditLog(ctx, c, AuditRecord{
			ID:       "row-" + string(rune('a'+i)),
			Username: "alice",
			HostName: "node-0",
			Action:   action,
			Target:   "vm-1",
			Detail:   "test",
			Result:   "ok",
		}); err != nil {
			t.Fatalf("Insert %d: %v", i, err)
		}
	}
	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("chain broken at %q", res.BrokenAt)
	}
	if res.RowsChecked != 3 {
		t.Errorf("checked %d rows, want 3", res.RowsChecked)
	}
}

// TestAuditChain_StampsSortAsTextInTimeOrder pins the contract the chain
// relies on: InsertAuditLog stamps a row from the client's clock, and the
// tail read and the verifier both walk a host's rows in timestamp TEXT order,
// so that order has to be the time order. A stamp that trims trailing zeros
// breaks it — ".12Z" sorts after ".125Z", and a whole second "01Z" after
// "01.5Z" — and the verifier then checks rows out of insert order and reports
// an intact chain as broken.
func TestAuditChain_StampsSortAsTextInTimeOrder(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	instants := []time.Time{
		time.Date(2026, 1, 1, 0, 0, 0, 120_000_000, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 0, 125_000_000, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC),
		time.Date(2026, 1, 1, 0, 0, 1, 500_000_000, time.UTC),
	}
	for i, at := range instants {
		c.nowFn = func() time.Time { return at }
		ins(t, c, fmt.Sprintf("row-%d", i), "node-0", "")
	}

	rows, err := c.Query(ctx, `SELECT id, timestamp FROM audit_log ORDER BY timestamp ASC, id ASC`)
	if err != nil {
		t.Fatalf("list audit rows: %v", err)
	}
	if len(rows) != len(instants) {
		t.Fatalf("got %d rows, want %d", len(rows), len(instants))
	}
	for i, r := range rows {
		if want := fmt.Sprintf("row-%d", i); r.String("id") != want {
			t.Errorf("position %d in timestamp order is %s (stamped %q), want %s",
				i, r.String("id"), r.String("timestamp"), want)
			continue
		}
		got, perr := time.Parse(time.RFC3339Nano, r.String("timestamp"))
		if perr != nil || !got.Equal(instants[i]) {
			t.Errorf("%s stamped %q, want the client clock's %s",
				r.String("id"), r.String("timestamp"), instants[i].Format(time.RFC3339Nano))
		}
	}

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("chain broken at %q", res.BrokenAt)
	}
}

// TestAuditChain_DetectsRowTampering proves the verifier catches a
// post-insert mutation. We bypass InsertAuditLog to forge the row.
func TestAuditChain_DetectsRowTampering(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	// Insert one legitimate row.
	if err := InsertAuditLog(ctx, c, AuditRecord{
		ID: "row-1", Username: "alice", HostName: "node-0",
		Action: "vm.start", Target: "vm-1", Detail: "", Result: "ok",
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}

	// Tamper: bypass the chain code and rewrite the row's detail
	// field directly. The content_hash stays at its now-stale value.
	if err := c.Execute(ctx,
		`UPDATE audit_log SET detail = 'tampered' WHERE id = 'row-1'`); err != nil {
		t.Fatalf("UPDATE: %v", err)
	}

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "row-1" {
		t.Errorf("broken_at = %q, want row-1 (checked=%d)", res.BrokenAt, res.RowsChecked)
	}
}

// TestAuditChain_NullHashIsResetPoint lets pre-3.4 rows (NULL hashes)
// coexist with chained rows without failing the verify.
func TestAuditChain_NullHashIsResetPoint(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	// Bypass InsertAuditLog so the row lands with NULL hashes —
	// simulates an audit_log row that pre-dates the
	// migration.
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, action, target, result)
		 VALUES ('legacy', '2025-01-01T00:00:00Z', 'vm.start', 'vm-old', 'ok')`); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if err := InsertAuditLog(ctx, c, AuditRecord{
		ID: "modern", Username: "alice", HostName: "node-0",
		Action: "vm.stop", Target: "vm-old", Result: "ok",
	}); err != nil {
		t.Fatalf("Insert modern: %v", err)
	}
	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("legacy + modern coexistence should be clean; broken at %q", res.BrokenAt)
	}
	if res.RowsChecked < 2 {
		t.Errorf("expected at least 2 rows checked, got %d", res.RowsChecked)
	}
}

// ins is a test helper that appends one audit row for the named host,
// at an explicit timestamp, through the real chain code.
func ins(t *testing.T, c *Client, id, host, ts string) {
	t.Helper()
	if err := InsertAuditLog(context.Background(), c, AuditRecord{
		ID: id, Username: "u", HostName: host,
		Action: "vm.start", Target: "x", Result: "ok", Timestamp: ts,
	}); err != nil {
		t.Fatalf("InsertAuditLog %s: %v", id, err)
	}
}

// globalChainedRow forges a row the way the pre-per-host model wrote them:
// linked to the tail of a DIFFERENT host's row (afterID), which is what made
// those chains unverifiable per-host. InsertAuditLog can no longer produce this
// shape, so a test that needs one has to write it directly.
func globalChainedRow(t *testing.T, c *Client, id, host, ts, afterID string) {
	t.Helper()
	ctx := context.Background()
	rows, err := c.Query(ctx, `SELECT content_hash FROM audit_log WHERE id = ?`, afterID)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s: %v (rows=%d)", afterID, err, len(rows))
	}
	rec := AuditRecord{
		ID: id, Timestamp: ts, Username: "u", HostName: host,
		Action: "vm.start", Target: "x", Result: "ok",
		PrevHash: rows[0].String("content_hash"),
	}
	rec.ContentHash = HashAuditRow(rec)
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash)
		 VALUES (?, ?, ?, ?, ?, ?, '', ?, ?, ?)`,
		rec.ID, rec.Timestamp, rec.Username, rec.HostName,
		rec.Action, rec.Target, rec.Result, rec.PrevHash, rec.ContentHash); err != nil {
		t.Fatalf("seed global-chained row %s: %v", id, err)
	}
}

// TestAuditChain_MultiHost_InterleavedTimestamps_Clean is the core
// regression: two daemons (two processes) append concurrently, so their
// rows interleave by global timestamp (a1,b1,a2,b2). A single global
// chain would break at the first cross-host row; per-host sub-chains must
// verify clean. No reset is needed between the two hosts: the tails are keyed
// by host_name, so writing for hostB never disturbs hostA's position.
func TestAuditChain_MultiHost_InterleavedTimestamps_Clean(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// Host A's daemon writes a1@:01, a2@:03.
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	ins(t, c, "a2", "hostA", "2026-06-23T10:00:03Z")
	// Host B's daemon writes b1@:02, b2@:04 — interleaved.
	ins(t, c, "b1", "hostB", "2026-06-23T10:00:02Z")
	ins(t, c, "b2", "hostB", "2026-06-23T10:00:04Z")

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("interleaved multi-host chain should verify per-host; broke at %q", res.BrokenAt)
	}
	if res.RowsChecked != 4 {
		t.Errorf("checked %d rows, want 4", res.RowsChecked)
	}
}

// TestAuditChain_ResealFixesLegacyGlobalChain simulates the old global
// model (one process chains host B's row off host A's tail) and proves
// VerifyAuditChain flags it, then ResealAuditChain re-bases host B's
// sub-chain so the verify passes.
func TestAuditChain_ResealFixesLegacyGlobalChain(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// Old bug: one shared tail across hosts, so b1 chains off a1's hash. That
	// is no longer reachable through InsertAuditLog, so forge it directly —
	// what matters is that such rows exist in the field and must still heal.
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	globalChainedRow(t, c, "b1", "hostB", "2026-06-23T10:00:02Z", "a1")

	if res, _ := VerifyAuditChain(ctx, c); res.BrokenAt != "b1" {
		t.Fatalf("expected per-host verify to break at b1 (legacy global link), got %q", res.BrokenAt)
	}

	n, err := ResealAuditChain(ctx, c, "hostB")
	if err != nil {
		t.Fatalf("ResealAuditChain: %v", err)
	}
	if n != 1 {
		t.Errorf("resealed %d rows, want 1 (b1 re-based to genesis)", n)
	}
	if res, _ := VerifyAuditChain(ctx, c); res.BrokenAt != "" {
		t.Errorf("after reseal the chain should be clean; broke at %q", res.BrokenAt)
	}
}

// TestAuditChain_EmptyHostRowIsResetPoint reproduces the live v1.0.15 failure:
// a background-context audit row with no host_name (e.g. failover.promote) sorts
// first under per-host verify and carries a global-model hash, so a naive
// per-host verify breaks at row 0. Such rows belong to no host's sub-chain and
// must be treated as reset points, not chain links.
func TestAuditChain_EmptyHostRowIsResetPoint(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	// An orphan row with empty host_name and a non-NULL, arbitrary content_hash
	// (as the old global chain would have produced) — bypass InsertAuditLog.
	if err := c.Execute(ctx,
		`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, result, prev_hash, content_hash)
		 VALUES ('orphan', '2026-06-08T14:10:41Z', 'failover-coordinator', '', 'failover.promote', 'vm1', 'ok', 'deadbeef', 'cafebabe')`); err != nil {
		t.Fatalf("seed orphan row: %v", err)
	}
	// A normal per-host chain alongside it.
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	ins(t, c, "a2", "hostA", "2026-06-23T10:00:02Z")

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("empty-host orphan should be a reset point, not a break; broke at %q", res.BrokenAt)
	}
	if res.RowsChecked != 3 {
		t.Errorf("checked %d, want 3 (orphan + a1 + a2)", res.RowsChecked)
	}
}

// TestResealAuditChain_Idempotent: re-sealing an already-consistent
// per-host chain rewrites nothing.
func TestResealAuditChain_Idempotent(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)
	ins(t, c, "a1", "hostA", "2026-06-23T10:00:01Z")
	ins(t, c, "a2", "hostA", "2026-06-23T10:00:02Z")
	ins(t, c, "a3", "hostA", "2026-06-23T10:00:03Z")

	n, err := ResealAuditChain(ctx, c, "hostA")
	if err != nil {
		t.Fatalf("ResealAuditChain: %v", err)
	}
	if n != 0 {
		t.Errorf("reseal of an already-consistent chain rewrote %d rows, want 0", n)
	}
}

// TestAuditChain_IntactWhenStampsRegress pins that a host's sub-chain is walked
// in the order its rows were AUTHORED, not the order their stamps happen to
// sort in.
//
// seq is the authoring host's own counter, assigned under the chain mutex in
// the same critical section as prev_hash, so it is the one record of append
// order a wall clock cannot contradict. The stamp can: InsertAuditLog reads the
// clock BEFORE taking that mutex, so two goroutines on one host can stamp in
// one order and chain in the other, and an NTP step-back or a restored snapshot
// moves the clock under a single writer. Either way a row lands whose stamp
// sorts before its predecessor's.
//
// Walking by stamp then checks that row against the wrong prev_hash and reports
// BrokenAt plus a seq gap — a tamper verdict on a chain nothing touched. Because
// both rows are signed, ResealAuditChain refuses to rewrite them, so the
// accusation is permanent on every node that replicates it. That is exactly the
// unclearable false alarm the comment above VerifyAuditChain says must never
// happen.
func TestAuditChain_IntactWhenStampsRegress(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	ins(t, c, "row-a", "node-0", "2026-01-01T00:00:02.000000000Z")
	// The clock steps back between the two appends. row-b is authored second
	// and chains onto row-a, but its stamp sorts first.
	ins(t, c, "row-b", "node-0", "2026-01-01T00:00:01.000000000Z")

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("chain broken at %q; a backward clock step is not tampering", res.BrokenAt)
	}
	if len(res.SeqGaps) != 0 {
		t.Errorf("seq gaps %v; both rows were authored in order", res.SeqGaps)
	}
	if res.RowsChecked != 2 {
		t.Errorf("checked %d rows, want 2", res.RowsChecked)
	}
}

// TestAuditChain_TailAfterRestartIsTheLastAuthoredRow covers the write path's
// half of the same ordering question.
//
// The cached tail is per-process, so a daemon restart re-reads it from the log
// through loadHostTail. If that read picks the row with the latest STAMP rather
// than the last one authored, the first row written after the restart chains
// onto the wrong predecessor — and unlike a mis-ordered walk, this one writes a
// genuinely broken link into the table, where it stays after the clock is
// corrected and every later verify reports it.
//
// Dropping the cache is how a restart is spelled in-process: the next insert
// takes the loadHostTail path exactly as a fresh daemon would.
func TestAuditChain_TailAfterRestartIsTheLastAuthoredRow(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	ins(t, c, "row-a", "node-0", "2026-01-01T00:00:02.000000000Z")
	ins(t, c, "row-b", "node-0", "2026-01-01T00:00:01.000000000Z") // clock stepped back

	c.ResetAuditChainForTests()

	ins(t, c, "row-c", "node-0", "2026-01-01T00:00:03.000000000Z")

	rows, err := c.Query(ctx, `SELECT prev_hash FROM audit_log WHERE id = 'row-c'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read row-c: %v (%d rows)", err, len(rows))
	}
	want, werr := c.Query(ctx, `SELECT content_hash FROM audit_log WHERE id = 'row-b'`)
	if werr != nil || len(want) != 1 {
		t.Fatalf("read row-b: %v (%d rows)", werr, len(want))
	}
	if got, exp := rows[0].String("prev_hash"), want[0].String("content_hash"); got != exp {
		t.Errorf("row-c chained onto %q, want row-b's %q", got, exp)
	}

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("chain broken at %q after a restart across a clock step", res.BrokenAt)
	}
}

// TestAuditChain_ResealLeavesAGoodChainAlone covers the third walk over the
// same rows.
//
// Reseal re-bases rows written before signing was enabled, so it recomputes the
// chain from whatever order it reads them in and UPDATEs any row whose stored
// hash differs. That makes its order a WRITE, not just a reading: walk these
// rows by stamp while the verifier walks them by seq and reseal does not repair
// the chain, it rewrites a correct one into an order the verifier then rejects
// — and the rewrite replicates.
//
// The rows here are unsigned (the test client has no keyring), which is exactly
// the population reseal is allowed to touch.
func TestAuditChain_ResealLeavesAGoodChainAlone(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	ins(t, c, "row-a", "node-0", "2026-01-01T00:00:02.000000000Z")
	ins(t, c, "row-b", "node-0", "2026-01-01T00:00:01.000000000Z") // clock stepped back

	resealed, err := ResealAuditChain(ctx, c, "node-0")
	if err != nil {
		t.Fatalf("ResealAuditChain: %v", err)
	}
	if resealed != 0 {
		t.Errorf("reseal rewrote %d rows; the chain was already correct", resealed)
	}

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("chain broken at %q after a reseal that should have been a no-op", res.BrokenAt)
	}
}

// TestAuditChain_GeneratedStampsNeverRegress pins the write-path half: a stamp
// this node generates is never older than the last one it wrote for that host.
//
// The walk changes above make a regressed stamp survivable. This makes it not
// happen in the first place, which is the difference between a chain that
// verifies and a chain that verifies only because something downstream repairs
// the order. client.go's NowTS already took this trade for replication keys —
// it clamps to lastTS+1ns against a durable ceiling — and audit rows simply did
// not use it.
//
// Only GENERATED stamps are clamped. A caller-supplied timestamp is stored
// verbatim: rewriting it would alter data this node did not author, and the
// replicated and legacy rows that carry one are exactly the population the walk
// ordering exists to handle.
func TestAuditChain_GeneratedStampsNeverRegress(t *testing.T) {
	ctx := context.Background()
	c := newAuditTestClient(t)

	at := time.Date(2026, 1, 1, 0, 0, 2, 0, time.UTC)
	c.nowFn = func() time.Time { return at }
	insNow(t, c, "row-a", "node-0")

	// NTP corrects backwards, or a snapshot is restored.
	at = time.Date(2026, 1, 1, 0, 0, 1, 0, time.UTC)
	insNow(t, c, "row-b", "node-0")

	first := stampOf(t, c, "row-a")
	second := stampOf(t, c, "row-b")
	if !second.After(first) {
		t.Errorf("row-b stamped %s, not after row-a's %s",
			second.Format(time.RFC3339Nano), first.Format(time.RFC3339Nano))
	}

	res, err := VerifyAuditChain(ctx, c)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.BrokenAt != "" {
		t.Errorf("chain broken at %q", res.BrokenAt)
	}
}

// insNow appends a row with no timestamp, so InsertAuditLog stamps it from the
// client's clock — the path a real caller takes.
func insNow(t *testing.T, c *Client, id, host string) {
	t.Helper()
	if err := InsertAuditLog(context.Background(), c, AuditRecord{
		ID: id, Username: "u", HostName: host,
		Action: "vm.start", Target: "x", Result: "ok",
	}); err != nil {
		t.Fatalf("InsertAuditLog %s: %v", id, err)
	}
}

// stampOf reads back the timestamp a row was actually stored with.
func stampOf(t *testing.T, c *Client, id string) time.Time {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT timestamp FROM audit_log WHERE id = ?`, id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read %s: %v (%d rows)", id, err, len(rows))
	}
	ts, perr := time.Parse(time.RFC3339Nano, rows[0].String("timestamp"))
	if perr != nil {
		t.Fatalf("parse %s stamp %q: %v", id, rows[0].String("timestamp"), perr)
	}
	return ts
}

// TestAuditChain_ACallerStampDoesNotBecomeTheClock isolates one of the two
// protections around the clamp.
//
// The clamp only ever raises its ceiling, so anything able to push it FORWARD
// moves every later stamp with it until wall time catches up. A caller-supplied
// timestamp is stored verbatim — this node did not author it — and must not also
// become the floor for rows this node writes afterwards, or any caller gets a
// lever on the whole host's timeline.
//
// The offset here is one minute: inside maxClampSkew, so the far-future bound
// does not engage and this test pins the generated-only rule on its own.
func TestAuditChain_ACallerStampDoesNotBecomeTheClock(t *testing.T) {
	c := newAuditTestClient(t)

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return at }

	ins(t, c, "supplied", "node-0", at.Add(time.Minute).Format(nowTSLayout))
	insNow(t, c, "after-supplied", "node-0")

	if got := stampOf(t, c, "after-supplied"); got.After(at.Add(time.Second)) {
		t.Errorf("a generated stamp landed at %s, past the clock's %s: a caller-supplied "+
			"timestamp became the ceiling", got.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano))
	}
}

// TestAuditChain_AFutureTailDoesNotDragTheClockForward isolates the other.
//
// After a restart the ceiling is read back out of the table, so it is whatever
// the host's highest-seq row carries — including a row written by something that
// is not a daemon, which is exactly what an audit log exists to reveal. A stamp
// a year ahead is not a smaller problem than one a millisecond behind: it breaks
// timestamp-window exports and makes `lv audit ls` lie about when things
// happened, and unlike a backward step nothing corrects it.
//
// The offset is an hour, past maxClampSkew, so only the far-future bound stands
// between that row and every stamp this host writes from then on.
func TestAuditChain_AFutureTailDoesNotDragTheClockForward(t *testing.T) {
	c := newAuditTestClient(t)

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return at }

	insNow(t, c, "normal", "node-0")
	// Highest seq on the host, so this is the row the tail read picks up.
	ins(t, c, "future", "node-0", at.Add(time.Hour).Format(nowTSLayout))

	c.ResetAuditChainForTests()
	insNow(t, c, "after-restart", "node-0")

	if got := stampOf(t, c, "after-restart"); got.After(at.Add(time.Second)) {
		t.Errorf("after a restart a generated stamp landed at %s, past the clock's %s: "+
			"a future row in the table became the ceiling",
			got.Format(time.RFC3339Nano), at.Format(time.RFC3339Nano))
	}
}
