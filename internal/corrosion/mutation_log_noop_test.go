package corrosion

import (
	"context"
	"testing"
)

// A create-only statement that changed nothing locally must not be relayed.
//
// mutation_log carries the statements a peer will REPLAY. An INSERT OR IGNORE
// that matched an existing primary key changed nothing here, so relaying it
// asks every peer to apply content this node rejected — and a peer that has not
// yet received the genuine row applies it, keeps it (INSERT OR IGNORE then drops
// the genuine row on the PK when it arrives), and the two nodes disagree
// permanently on an append-only table that has no LWW rule to heal them.
//
// The caller-supplied id is what makes it reachable rather than theoretical:
// vm_events ids come in over the wire, and the same shape appears at 50-odd
// other INSERT OR IGNORE sites, several of them audit tables.
func TestExecute_ACreateOnlyNoOpIsNotRelayed(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	genuine := VMEventRecord{
		ID: "e1", VMName: "vm1", HostName: "host-a",
		Type: "start", Detail: "genuine",
	}
	if err := InsertVMEvent(ctx, c, genuine); err != nil {
		t.Fatalf("seed the genuine event: %v", err)
	}
	before := mutationLogCount(t, c)
	if before == 0 {
		t.Fatal("premise: the genuine insert logged nothing, so this test cannot " +
			"tell a suppressed relay from a client that never replicates")
	}

	// The same id, different content. INSERT OR IGNORE keeps the genuine row.
	forged := genuine
	forged.Detail = "forged"
	if err := InsertVMEvent(ctx, c, forged); err != nil {
		t.Fatalf("second insert: %v", err)
	}

	if after := mutationLogCount(t, c); after != before {
		t.Errorf("a create-only no-op queued %d statement(s) for replication; a peer that "+
			"has not yet received the genuine row would apply the forged content and then "+
			"drop the real row on the primary key", after-before)
	}

	got, err := ListVMEvents(ctx, c, "vm1", 10, "")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(got) != 1 || got[0].Detail != "genuine" {
		t.Errorf("local rows = %+v, want exactly the genuine one", got)
	}
}

// The narrowing must not cost a real create its replication. This is the case
// that makes the filter safe to apply at all: suppress a statement that DID
// change a row and the row exists on one node only, healed by nothing, since
// append-only tables carry no LWW rule.
func TestExecute_ACreateThatChangedARowStillReplicates(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	before := mutationLogCount(t, c)
	if err := InsertVMEvent(ctx, c, VMEventRecord{
		ID: "e1", VMName: "vm1", HostName: "host-a", Type: "start",
	}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if after := mutationLogCount(t, c); after <= before {
		t.Fatal("a genuine create was not relayed; the row would exist on this node only, " +
			"and an append-only table has no LWW rule that would ever heal that")
	}

	// A DIFFERENT id is a different row, not a no-op, even on the same VM.
	before = mutationLogCount(t, c)
	if err := InsertVMEvent(ctx, c, VMEventRecord{
		ID: "e2", VMName: "vm1", HostName: "host-a", Type: "stop",
	}); err != nil {
		t.Fatalf("second insert: %v", err)
	}
	if after := mutationLogCount(t, c); after <= before {
		t.Error("a second event on the same VM was suppressed; only a PK COLLISION is a no-op")
	}
}

// The filter is scoped to create-only shapes, and nothing else changes.
//
// An UPDATE that matches no row is left alone deliberately. Its disposition is
// LWW-gated or bulk, so a receiver already decides for itself whether to apply
// it, and a row this node lacks is exactly the row a peer may need the statement
// for. Widening the suppression to every zero-row statement would change
// replication semantics for shapes that were never part of this defect.
func TestExecute_ANonCreateNoOpIsUnaffected(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	before := mutationLogCount(t, c)
	// hosts.state is a full-PK LWW update; no such host exists, so it changes
	// no row here.
	if err := c.Execute(ctx,
		`UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`,
		"active", c.NowTS(), "no-such-host"); err != nil {
		t.Fatalf("update: %v", err)
	}
	if after := mutationLogCount(t, c); after <= before {
		t.Error("a zero-row UPDATE was suppressed. Only create-only shapes are in scope: " +
			"an LWW-gated update is judged by the receiver, and the row it targets may be " +
			"one this node simply does not have")
	}
}

// createOnlyStatement's classification path, asserted directly: real builder
// SQL → fingerprint → ledger → disposition. The behavioural tests above can
// only show that SOME statement is suppressed; this shows which, and it fails
// if a builder's SQL drifts away from its registered shape.
//
// The DispositionAfter arm of the predicate has no shape in the ledger today
// (nothing is registered append-only only after a capability activates), so it
// is deliberately unexercised rather than covered — see the comment there.
func TestCreateOnlyStatement_ClassifiesRegisteredShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		sql  string
		want bool
	}{
		{"vm_events append-only insert", `INSERT OR IGNORE INTO vm_events
		   (id, vm_name, host_name, type, result, severity, detail, username, ts)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, true},
		{"hosts full-PK LWW update", `UPDATE hosts SET state = ?, updated_at = ? WHERE name = ?`, false},
		{"unparseable sql", `NOT SQL AT ALL`, false},
		{"unregistered shape", `INSERT OR IGNORE INTO no_such_table (a) VALUES (?)`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := createOnlyStatement(tc.sql); got != tc.want {
				t.Errorf("createOnlyStatement = %v, want %v", got, tc.want)
			}
		})
	}
}
