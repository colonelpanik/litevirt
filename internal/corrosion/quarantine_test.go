package corrosion

import (
	"context"
	"strings"
	"testing"
)

// A node that has been rolled back below a capability token it already latched
// must stop emitting replicated writes. The residual exposure the whole
// isolated-node problem reduces to is a node left UP AND WRITING while the rest of
// the cluster has moved past it.
//
// The refusal has to fail the whole transaction, not merely skip the mutation-log
// row. Committing the application statements while dropping the log entry produces
// exactly that state — local writes nobody else will ever see — which is worse
// than either extreme.

// TestWriteQuarantine_RefusesReplicatedWrites pins that a quarantined client
// writes NOTHING: not the row, not the mutation-log entry.
func TestWriteQuarantine_RefusesReplicatedWrites(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	before := mutationLogLen(t, db)
	db.SetWriteQuarantine(func() string { return "rolled back below latched token(s): future_v9" })

	err := InsertProject(ctx, db, ProjectRecord{Name: "acme"})
	if err == nil {
		t.Fatal("a quarantined client accepted a replicated write; the node would keep " +
			"diverging from a cluster that has moved past it")
	}
	if !strings.Contains(err.Error(), "quarantine") {
		t.Errorf("error %q does not name the quarantine, so an operator cannot tell this "+
			"apart from an ordinary write failure", err)
	}

	p, gerr := GetProject(ctx, db, "acme")
	if gerr != nil {
		t.Fatalf("GetProject: %v", gerr)
	}
	if p != nil {
		t.Error("the row landed locally despite the refusal — this is the exact " +
			"write-without-replicating state the quarantine exists to prevent")
	}
	if got := mutationLogLen(t, db); got != before {
		t.Errorf("mutation log grew from %d to %d while quarantined", before, got)
	}
}

// TestWriteQuarantine_LiftsWhenTheReasonClears: the quarantine is a predicate, not
// a latch. An operator who reseeds (or an upgrade back to a binary that knows the
// token) must get a working node back without a restart being the only remedy.
func TestWriteQuarantine_LiftsWhenTheReasonClears(t *testing.T) {
	ctx := context.Background()
	db := newTestDB(t)

	quarantined := true
	db.SetWriteQuarantine(func() string {
		if quarantined {
			return "rolled back below latched token(s): future_v9"
		}
		return ""
	})

	if err := InsertProject(ctx, db, ProjectRecord{Name: "acme"}); err == nil {
		t.Fatal("write accepted while quarantined")
	}
	quarantined = false
	if err := InsertProject(ctx, db, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("write refused after the quarantine cleared: %v", err)
	}
}

// TestWriteQuarantine_LeavesReplicationApplyWorking is the constraint that makes
// the quarantine recoverable at all. Incoming replication and the reseed itself go
// through the local-only exec path, which must NOT be gated — a node that cannot
// receive can never be repaired, only rebuilt.
func TestWriteQuarantine_LeavesReplicationApplyWorking(t *testing.T) {
	ctx := context.Background()
	source, receiver := newTestDB(t), newTestDB(t)

	if err := InsertProject(ctx, source, ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("seed source: %v", err)
	}
	receiver.SetWriteQuarantine(func() string { return "rolled back below latched token(s): future_v9" })

	if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
		t.Fatalf("a quarantined node could not accept incoming state: %v", err)
	}
	p, err := GetProject(ctx, receiver, "acme")
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if p == nil {
		t.Fatal("the quarantined node did not apply replicated state; it could never be " +
			"reseeded, only rebuilt")
	}
}

// TestWriteQuarantine_UnsetIsANoop guards the default: every node that is not
// rolled back has no predicate at all.
func TestWriteQuarantine_UnsetIsANoop(t *testing.T) {
	if err := InsertProject(context.Background(), newTestDB(t), ProjectRecord{Name: "acme"}); err != nil {
		t.Fatalf("write refused with no quarantine predicate set: %v", err)
	}
}

func mutationLogLen(t *testing.T, c *Client) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT seq FROM mutation_log`)
	if err != nil {
		t.Fatalf("count mutation log: %v", err)
	}
	return len(rows)
}
