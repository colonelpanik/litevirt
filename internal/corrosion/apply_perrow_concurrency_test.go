package corrosion

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Gap 2 — concurrent local mutation between enumeration and application of a per-row-LWW
// bulk expansion.
//
// applyBulkPerRowLWW does two steps: (1) enumerate the matched rows' PK + local updated_at
// with the original predicate, then (2) apply the SET to each row where the incoming clock
// beats the ENUMERATED local clock, scoped to the exact PK. The per-row UPDATE does NOT
// re-check updated_at at write time — it trusts the clock read during enumeration. That is
// safe only because the whole expansion runs inside the caller's write transaction AND under
// the Client write mutex (ApplyRemoteMutations holds c.mu; so does every local Execute), so no
// local writer can commit between the two steps and make the enumerated clock stale.
//
// This test drives a concurrent local write into the exact enumerate→apply window (via a test
// seam) and proves it is BLOCKED for the duration — i.e. the window is atomic. A regression
// that released the mutex, or split enumeration and application into separate transactions,
// would let the concurrent write complete inside the window (a lost update); this test would
// then fail on `blockedDuringExpansion`.
func TestApplyBulkPerRowLWW_ConcurrentWriteBlockedAcrossExpansion(t *testing.T) {
	c, err := NewLocalClient(t.TempDir(), "node-1")
	if err != nil {
		t.Fatalf("NewLocalClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// One matched row at an OLD clock — the bulk (mid clock) would tombstone it, and the
	// concurrent write (new clock) must ultimately win.
	const oldTS = "1000000000000-0000-n1"
	const midTS = "2000000000000-0000-n2"
	const concTS = "3000000000000-0000-n1"
	if err := c.Execute(ctx,
		`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, ip, updated_at) VALUES (?, ?, ?, ?, ?, ?)`,
		"vm1", "neta", 0, "00:11:22:33:44:55", "orig", oldTS); err != nil {
		t.Fatalf("seed: %v", err)
	}

	concDone := make(chan error, 1)
	var blockedDuringExpansion bool
	testHookBulkMidExpansion = func() {
		// Fire a concurrent local full-PK write (newest clock) on another goroutine. It calls
		// c.Execute → executeBatchInternal → c.mu.Lock(), which the in-flight apply holds, so it
		// must block until the apply commits.
		go func() {
			concDone <- c.Execute(ctx,
				`UPDATE vm_interfaces SET ip = ?, deleted_at = NULL, updated_at = ? WHERE vm_name = ? AND network_name = ?`,
				"CONCURRENT", concTS, "vm1", "neta")
		}()
		select {
		case <-concDone:
			// Completed inside the expansion window ⇒ NOT serialized ⇒ the enumerated clock
			// could go stale under the per-row write. Push the error back so the goroutine's
			// result is still drained after the apply returns.
			blockedDuringExpansion = false
			concDone <- nil
		case <-time.After(300 * time.Millisecond):
			blockedDuringExpansion = true // still blocked ⇒ the window is atomic
		}
	}
	t.Cleanup(func() { testHookBulkMidExpansion = nil })

	r := NewReplicator(c, "", RelayConfig{})
	stmts := fmt.Sprintf(
		`[{"SQL":"UPDATE vm_interfaces SET deleted_at = ?, updated_at = ? WHERE vm_name = ?","Params":["%s","%s","vm1"]}]`,
		midTS, midTS)
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: midTS, Origin: "origin-node", Stmts: stmts}}
	if _, err := r.ApplyRemoteMutations(ctx, entries); err != nil {
		t.Fatalf("apply: %v", err)
	}

	if cerr := <-concDone; cerr != nil {
		t.Fatalf("concurrent write failed: %v", cerr)
	}
	if !blockedDuringExpansion {
		t.Fatal("a concurrent local write completed DURING the per-row-LWW enumerate→apply window — the expansion is not atomic; the enumerated clock could be stale at write time (lost update)")
	}

	// The concurrent, newer write ran after the apply committed and must have won: the row is
	// not tombstoned and carries the concurrent value/clock.
	rows, err := c.Query(ctx,
		"SELECT ip, deleted_at, updated_at FROM vm_interfaces WHERE vm_name = ? AND network_name = ?", "vm1", "neta")
	if err != nil || len(rows) == 0 {
		t.Fatalf("query: err=%v rows=%d", err, len(rows))
	}
	if got := rows[0].String("deleted_at"); got != "" {
		t.Fatalf("row was tombstoned (deleted_at=%q) — the older incoming bulk clobbered the newer concurrent write", got)
	}
	if ip, ts := rows[0].String("ip"), rows[0].String("updated_at"); ip != "CONCURRENT" || ts != concTS {
		t.Fatalf("expected the concurrent write to win (ip=CONCURRENT, updated_at=%s); got ip=%q updated_at=%q", concTS, ip, ts)
	}
}
