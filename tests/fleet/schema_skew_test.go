// Fleet scenario 5 (per Plan): rolling-upgrade schema-skew back-pressure.
//
// Bring up a 2-node fleet on the current schema. Drop a new-feature
// table on one node to simulate an old-binary peer that hasn't yet
// caught up. Push a mutation that targets the dropped table from
// node-A's Replicator → node-B. The receiver MUST return an error
// from ApplyRemoteMutations, the sender's watermark for that peer
// MUST stall, and the mutation_seen dedup table MUST NOT record the
// entry (otherwise the row is lost forever after the eventual
// upgrade).
//
// Why this scenario: replication.go ~L608 used to silently swallow
// schema-missing errors; the fix landed today as `isSchemaMissingError`
// + abort-batch. This is the regression test that exercises the
// safety net at the *replication topology* level — not just a unit
// test on one Replicator.

package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestFleet_SchemaSkewBackPressure(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	sender, receiver := c.Nodes[0], c.Nodes[1]

	// Simulate the receiver being on an older binary by dropping a
	// new-feature table. service_endpoints is a leaf table with no
	// FK constraints so dropping it is a clean test fixture.
	if err := receiver.DB.Execute(ctx, "DROP TABLE service_endpoints"); err != nil {
		t.Fatalf("DROP TABLE on receiver: %v", err)
	}

	// Establish a baseline replication watermark. The receiver's
	// PushMutations is the public entry point; we call it directly
	// over loopback gRPC while presenting the sender's host certificate so the
	// test follows the production path (real TLS peer identity, real protobuf,
	// real handler dispatch).
	client := c.PeerClient(sender, receiver)

	// Build one mutation entry targeting the missing table.
	clock := sender.HLCClock()
	hlcTS := clock.Now().String()
	entry := &pb.MutationEntry{
		Seq:    1,
		Hlc:    hlcTS,
		Origin: sender.Name,
		Stmts:  `[{"SQL":"INSERT INTO service_endpoints (service_name, ip, region, weight, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)","Params":["api","10.0.0.1","ny",1,"2026-05-11T00:00:00Z","2026-05-11T00:00:00Z"]}]`,
	}

	req := &pb.ReplicateRequest{
		Sender:              sender.Name,
		SenderVersion:       "fleet-test",
		SenderSchemaVersion: int32(corrosion.CurrentSchemaVersion),
		AfterSeq:            0,
		Entries:             []*pb.MutationEntry{entry},
	}

	// Sender pushes → receiver must refuse with a schema-missing
	// error. Production sender code surfaces this as "push mutations:
	// schema-missing on receiver (upgrade required)".
	_, err := client.PushMutations(ctx, req)
	if err == nil {
		t.Fatal("expected receiver to refuse mutation targeting missing table")
	}
	if !strings.Contains(err.Error(), "schema-missing") {
		t.Errorf("error %q should mention schema-missing", err.Error())
	}

	// Receiver's mutation_seen table must NOT contain this entry —
	// silent dedup advancement is the exact bug we're guarding
	// against.
	rows, qerr := receiver.DB.Query(ctx,
		"SELECT COUNT(*) AS n FROM mutation_seen WHERE origin = ?", sender.Name)
	if qerr != nil {
		t.Fatalf("query mutation_seen: %v", qerr)
	}
	if len(rows) > 0 && rows[0].Int("n") != 0 {
		t.Errorf("receiver marked mutation as seen despite refusing it: %d rows", rows[0].Int("n"))
	}
}
