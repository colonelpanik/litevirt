package corrosion

import (
	"context"
	"strings"
	"testing"
)

// TestVerifyAuditChain_NamesWhatKindOfBreak pins what the first broken link IS,
// not only where it is.
//
// The verifier reported every broken link as "row content does not match its
// recorded hash". On lab 1 the broken row was the first row of a FORKED chain:
// a host rebuilt under its old name appended at seq 1 with an empty prev_hash
// before its history had replicated back. That row hashes correctly against its own stored
// prev_hash and its signature verifies; nothing about its content is wrong.
// Labelling it an edit sent the investigation looking for tampering that had
// not happened. It is still a verification failure — a fork is a finding — it
// just has to be called what it is.
func TestVerifyAuditChain_NamesWhatKindOfBreak(t *testing.T) {
	seed := func(t *testing.T) (context.Context, *Client) {
		t.Helper()
		ctx := context.Background()
		c := newAuditTestClient(t)
		for i, id := range []string{"r1", "r2", "r3"} {
			if err := InsertAuditLog(ctx, c, AuditRecord{
				ID: id, Username: "admin", HostName: "node-3", Action: "vm.start",
				Target: "vm-1", Result: "ok", Timestamp: "2026-10-03T22:16:0" + string(rune('1'+i)) + ".000000000Z",
			}); err != nil {
				t.Fatalf("InsertAuditLog %s: %v", id, err)
			}
		}
		return ctx, c
	}
	insertRaw := func(t *testing.T, ctx context.Context, c *Client, r AuditRecord, seq int64) {
		t.Helper()
		if err := c.Execute(ctx,
			`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
			 result, prev_hash, content_hash, key_id, signature, seq)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?)`,
			r.ID, r.Timestamp, r.Username, r.HostName, r.Action, r.Target, r.Detail, r.Result,
			r.PrevHash, r.ContentHash, seq); err != nil {
			t.Fatalf("insert %s: %v", r.ID, err)
		}
	}
	fork := AuditRecord{
		ID: "fork-1", Timestamp: "2026-10-03T22:16:30.767241380Z", Username: "admin", HostName: "node-3",
		Action: "cluster.lease_term_tie.acknowledge", Target: "failover:1", Result: "ok",
	}

	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, ctx context.Context, c *Client)
		at     string
		kind   string
	}{
		{"a second chain opened under the same name", func(t *testing.T, ctx context.Context, c *Client) {
			f := fork
			f.ContentHash = HashAuditRow(f) // PrevHash "": a genesis row, correctly hashed
			insertRaw(t, ctx, c, f, 1)
		}, "fork-1", AuditBrokenForked},
		{"an edited row", func(t *testing.T, ctx context.Context, c *Client) {
			if err := c.Execute(ctx, `UPDATE audit_log SET detail = 'tampered' WHERE id = 'r2'`); err != nil {
				t.Fatal(err)
			}
		}, "r2", AuditBrokenContent},
		{"an edited fork row is an edit, not a fork", func(t *testing.T, ctx context.Context, c *Client) {
			f := fork
			f.ContentHash = HashAuditRow(f)
			f.Detail = "tampered"
			insertRaw(t, ctx, c, f, 1)
		}, "fork-1", AuditBrokenContent},
		// An edit to an unsigned row mid-chain that also blanks prev_hash and
		// recomputes the hash is self-consistent, like a fork. It is not a
		// second genesis (seq 2, no repeated seq 1), and it must not be given
		// the label that says no row was edited.
		{"a mid-chain row rewritten with its prev_hash blanked", func(t *testing.T, ctx context.Context, c *Client) {
			rows, err := c.Query(ctx, `SELECT id, timestamp, username, host_name, action, target, detail, result FROM audit_log WHERE id = 'r2'`)
			if err != nil || len(rows) != 1 {
				t.Fatalf("read r2: %v", err)
			}
			r := rows[0]
			ed := AuditRecord{ID: "r2", Timestamp: r.String("timestamp"), Username: r.String("username"),
				HostName: r.String("host_name"), Action: r.String("action"), Target: r.String("target"),
				Detail: "rewritten", Result: r.String("result")}
			if err := c.Execute(ctx, `UPDATE audit_log SET detail = ?, prev_hash = '', content_hash = ? WHERE id = 'r2'`,
				ed.Detail, HashAuditRow(ed)); err != nil {
				t.Fatal(err)
			}
		}, "r2", AuditBrokenUnlinked},
		{"a row missing before it", func(t *testing.T, ctx context.Context, c *Client) {
			if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id = 'r2'`); err != nil {
				t.Fatal(err)
			}
		}, "r3", AuditBrokenUnlinked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, c := seed(t)
			tc.mutate(t, ctx, c)
			res, err := VerifyAuditChain(ctx, c)
			if err != nil {
				t.Fatalf("VerifyAuditChain: %v", err)
			}
			if res.BrokenAt != tc.at {
				t.Fatalf("BrokenAt = %q, want %q", res.BrokenAt, tc.at)
			}
			if res.BrokenKind != tc.kind {
				t.Errorf("BrokenKind = %q, want %q", res.BrokenKind, tc.kind)
			}
			if !res.Tampered() {
				t.Errorf("a broken link must still fail verification")
			}
			if res.Forked() != (tc.kind == AuditBrokenForked) {
				t.Errorf("Forked() = %v for a %s break", res.Forked(), tc.kind)
			}
		})
	}

	// A fork beside a deleted row is not a fork alone: the jump in seq is a
	// deletion, and the verdict stays tampering.
	//
	// Mutation: Forked not checking the seq jumps — red.
	t.Run("a fork beside a deleted row is not a fork alone", func(t *testing.T) {
		ctx, c := seed(t)
		f := fork
		f.ContentHash = HashAuditRow(f)
		insertRaw(t, ctx, c, f, 1)
		if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id = 'r2'`); err != nil {
			t.Fatal(err)
		}
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.BrokenKind != AuditBrokenForked || res.SeqDuplicates != 1 || len(res.SeqGaps) != 2 {
			t.Fatalf("setup: kind %q, %d duplicates of %v", res.BrokenKind, res.SeqDuplicates, res.SeqGaps)
		}
		if res.Forked() || !res.Tampered() {
			t.Errorf("Forked() = %v, Tampered() = %v: want a tamper verdict, not a fork alone", res.Forked(), res.Tampered())
		}
	})

	// A seq-1 row with an empty prev_hash is a fork only when it REPEATS a seq 1
	// the host already has. The first numbered row after a host's seq-0 legacy
	// rows, rewritten with its prev_hash blanked and its hash recomputed, is
	// seq 1 with an empty prev_hash too, and it is not a second genesis.
	t.Run("a first numbered row rewritten with its prev_hash blanked", func(t *testing.T) {
		ctx := context.Background()
		c := newAuditTestClient(t)
		prev := ""
		for i, id := range []string{"legacy-1", "legacy-2"} {
			r := AuditRecord{ID: id, Timestamp: "2026-09-15T06:39:0" + string(rune('1'+i)) + "Z", Username: "admin",
				HostName: "node-3", Action: "vm.start", Target: "vm-1", Result: "ok", PrevHash: prev}
			r.ContentHash = HashAuditRow(r)
			insertRaw(t, ctx, c, r, 0)
			prev = r.ContentHash
		}
		r1 := AuditRecord{ID: "r1", Timestamp: "2026-10-03T22:16:01.000000000Z", Username: "admin",
			HostName: "node-3", Action: "vm.start", Target: "vm-1", Detail: "rewritten", Result: "ok"}
		r1.ContentHash = HashAuditRow(r1) // PrevHash "" where legacy-2's hash belongs
		insertRaw(t, ctx, c, r1, 1)
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.BrokenAt != "r1" || res.BrokenKind != AuditBrokenUnlinked {
			t.Errorf("BrokenAt=%q BrokenKind=%q, want r1 / %q", res.BrokenAt, res.BrokenKind, AuditBrokenUnlinked)
		}
	})

	// Review I-2: a fork on one host must not hide an edited row on another.
	// Only the first break gets BrokenAt; every break is classified. The
	// fork is node-3's (walked first); node-4's edited row is a content break,
	// and the verdict is tampering, not a fork.
	//
	// Mutation: classify only the first break (drop ContentBreaks) — Forked()
	// is true: red.
	t.Run("a fork on one host and an edited row on another", func(t *testing.T) {
		ctx, c := seed(t)
		f := fork
		f.ContentHash = HashAuditRow(f)
		insertRaw(t, ctx, c, f, 1)
		for i, id := range []string{"b1", "b2"} {
			if err := InsertAuditLog(ctx, c, AuditRecord{
				ID: id, Username: "admin", HostName: "node-4", Action: "vm.stop",
				Target: "vm-2", Result: "ok", Timestamp: "2026-10-03T22:17:0" + string(rune('1'+i)) + ".000000000Z",
			}); err != nil {
				t.Fatal(err)
			}
		}
		if err := c.Execute(ctx, `UPDATE audit_log SET detail = 'tampered' WHERE id = 'b1'`); err != nil {
			t.Fatal(err)
		}
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.BrokenKind != AuditBrokenForked || len(res.ForkedHosts) != 1 || res.ContentBreaks != 1 {
			t.Fatalf("kind %q, forked hosts %v, content breaks %d; want the fork first and one content break", res.BrokenKind, res.ForkedHosts, res.ContentBreaks)
		}
		if res.Forked() {
			t.Error("Forked() = true: an edited row on another host was hidden behind a fork")
		}
	})

	// A row deleted on a host with no fork, beside a fork on another: an
	// unlinked row outside the forked hosts is not part of the fork.
	t.Run("a fork on one host and a deleted row on another", func(t *testing.T) {
		ctx, c := seed(t)
		f := fork
		f.ContentHash = HashAuditRow(f)
		insertRaw(t, ctx, c, f, 1)
		for i, id := range []string{"b1", "b2", "b3"} {
			if err := InsertAuditLog(ctx, c, AuditRecord{
				ID: id, Username: "admin", HostName: "node-4", Action: "vm.stop",
				Target: "vm-2", Result: "ok", Timestamp: "2026-10-03T22:17:0" + string(rune('1'+i)) + ".000000000Z",
			}); err != nil {
				t.Fatal(err)
			}
		}
		// Rewritten in place with its own prev_hash blanked: self-consistent,
		// so not a content break, and on a host with no second genesis.
		rows, err := c.Query(ctx, `SELECT timestamp FROM audit_log WHERE id = 'b2'`)
		if err != nil || len(rows) != 1 {
			t.Fatal(err)
		}
		ed := AuditRecord{ID: "b2", Timestamp: rows[0].String("timestamp"), Username: "admin", HostName: "node-4",
			Action: "vm.stop", Target: "vm-2", Detail: "rewritten", Result: "ok"}
		if err := c.Execute(ctx, `UPDATE audit_log SET detail = ?, prev_hash = '', content_hash = ? WHERE id = 'b2'`,
			ed.Detail, HashAuditRow(ed)); err != nil {
			t.Fatal(err)
		}
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.UnlinkedOutsideForks == 0 || res.Forked() {
			t.Errorf("unlinked outside forks %d, Forked() %v: want a break outside the fork, not a fork alone", res.UnlinkedOutsideForks, res.Forked())
		}
	})

	// Re-review I-3: a forked host's two chains interleave by seq, so its
	// rows are unlinked against the walk's tail as a matter of course. A row
	// deleted inside the seq range the second chain covers leaves no seq
	// jump; its successor's prev_hash then names no row, an orphan, and the
	// verdict is tampering, not a fork.
	//
	// Mutation: excuse every unlinked row on a forked host (no orphan check)
	// — the deletion reads as a fork: red.
	secondChain := func(t *testing.T, ctx context.Context, c *Client) {
		t.Helper()
		prev := ""
		for i, id := range []string{"fork-1", "fork-2", "fork-3"} {
			f := fork
			f.ID, f.PrevHash = id, prev
			f.Timestamp = "2026-10-03T22:16:3" + string(rune('1'+i)) + ".000000000Z"
			f.ContentHash = HashAuditRow(f)
			insertRaw(t, ctx, c, f, int64(i+1))
			prev = f.ContentHash
		}
	}
	t.Run("a fork of several rows is a fork", func(t *testing.T) {
		ctx, c := seed(t)
		secondChain(t, ctx, c)
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if !res.Forked() || res.Orphaned != 0 || res.SeqDuplicates != 3 {
			t.Errorf("Forked() = %v, orphaned %d, duplicates %d (gaps %v): want a fork alone", res.Forked(), res.Orphaned, res.SeqDuplicates, res.SeqGaps)
		}
	})
	t.Run("a row deleted inside a fork's seq range is not a fork", func(t *testing.T) {
		ctx, c := seed(t)
		secondChain(t, ctx, c)
		if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id = 'r2'`); err != nil {
			t.Fatal(err)
		}
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.SeqGaps) != res.SeqDuplicates {
			t.Fatalf("setup: the deletion left a seq jump %v; it must hide in the fork's range", res.SeqGaps)
		}
		if res.Orphaned == 0 || res.Forked() || !res.Tampered() {
			t.Errorf("orphaned %d, Forked() %v, Tampered() %v: want the deletion reported as tampering", res.Orphaned, res.Forked(), res.Tampered())
		}
		// Re-review m-3: the orphan is named — r3, whose predecessor r2 is gone.
		if len(res.Orphans) != res.Orphaned || !strings.Contains(strings.Join(res.Orphans, "\n"), "row r3 (seq 3)") {
			t.Errorf("orphans %v, want r3 named", res.Orphans)
		}
		// Re-review 3 m-2: no row of node-3 has r3's prev_hash, so it reads as a deletion.
		if got := strings.Join(res.Orphans, "\n"); !strings.Contains(got, "is the hash of no row of node-3 at seq 2 — the row before it was deleted (or rewritten)") {
			t.Errorf("orphans %v, want r3's predecessor reported deleted", res.Orphans)
		}
	})

	// Re-review 3 m-2: an orphan whose prev_hash names a row of its host at
	// another seq was renumbered or relinked, not orphaned by a deletion; a
	// seq-0 orphan has no seq before it to name.
	//
	// Mutation: one "deleted ... at seq N-1" message for every orphan: red.
	orphanLines := func(t *testing.T, ctx context.Context, c *Client) []string {
		t.Helper()
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.Forked() || !res.Tampered() || len(res.Orphans) != res.Orphaned {
			t.Fatalf("Forked() %v, Tampered() %v, orphans %v: want orphans reported as tampering", res.Forked(), res.Tampered(), res.Orphans)
		}
		return res.Orphans
	}
	t.Run("a row relinked to a row at another seq is named relinked", func(t *testing.T) {
		ctx, c := seed(t)
		secondChain(t, ctx, c)
		rows, err := c.Query(ctx, `SELECT id, timestamp, content_hash FROM audit_log WHERE id IN ('r1', 'r3') ORDER BY id`)
		if err != nil || len(rows) != 2 {
			t.Fatal(err)
		}
		r1Hash := rows[0].String("content_hash")
		ed := AuditRecord{ID: "r3", Timestamp: rows[1].String("timestamp"), Username: "admin", HostName: "node-3",
			Action: "vm.start", Target: "vm-1", Result: "ok", PrevHash: r1Hash}
		if err := c.Execute(ctx, `UPDATE audit_log SET prev_hash = ?, content_hash = ? WHERE id = 'r3'`, r1Hash, HashAuditRow(ed)); err != nil {
			t.Fatal(err)
		}
		got := strings.Join(orphanLines(t, ctx, c), "\n")
		if !strings.Contains(got, "row r3 (seq 3) follows prev_hash "+r1Hash+", which is the hash of row seq 1 of node-3, not seq 2 — renumbered or relinked") {
			t.Errorf("orphans %q, want r3 named as linking to seq 1", got)
		}
		if strings.Contains(got, "row r3 (seq 3) follows prev_hash "+r1Hash+", which is the hash of no row") {
			t.Errorf("orphans %q: r3's predecessor exists at seq 1, yet it is reported deleted", got)
		}
	})
	t.Run("a seq-0 orphan names no seq before it", func(t *testing.T) {
		ctx, c := seed(t)
		secondChain(t, ctx, c)
		z := fork
		z.ID, z.PrevHash = "zero", strings.Repeat("ab", 32)
		z.Timestamp = "2026-10-03T22:15:00.000000000Z"
		z.ContentHash = HashAuditRow(z)
		insertRaw(t, ctx, c, z, 0)
		got := strings.Join(orphanLines(t, ctx, c), "\n")
		if !strings.Contains(got, "row zero (seq 0) follows prev_hash "+z.PrevHash+", which is the hash of no row of node-3 — a seq-0 row whose predecessor is gone") {
			t.Errorf("orphans %q, want the seq-0 row named without a seq before it", got)
		}
		if strings.Contains(got, "seq -1") {
			t.Errorf("orphans %q name seq -1", got)
		}
	})

	t.Run("an intact chain has no kind", func(t *testing.T) {
		ctx, c := seed(t)
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.BrokenAt != "" || res.BrokenKind != "" {
			t.Errorf("intact chain: BrokenAt=%q BrokenKind=%q", res.BrokenAt, res.BrokenKind)
		}
	})
}
