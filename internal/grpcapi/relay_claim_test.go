package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The claim has to survive the RPC, not merely exist in the replicator.
//
// ApplyRemoteMutationsFrom is covered in internal/corrosion, but that proves
// nothing about whether PushMutations passes req.ReceiverIsRelay through. A
// handler that dropped the field would leave every corrosion test green and the
// fix inert on the wire -- the same shape of gap as a guard with no test.
func TestPushMutations_HonoursTheSendersRelayClaim(t *testing.T) {
	s := testServer(t)
	s.replicator = corrosion.NewReplicator(s.db, "", corrosion.RelayConfig{})
	ctx := replicationPeerCtx("node-a")

	const hlc = "2000000000002-0000-n9"
	stmts, err := json.Marshal([]corrosion.Statement{{
		SQL:    "INSERT OR REPLACE INTO crl_versions (host, version, updated_at)\n\t\t\t\t VALUES (?, ?, ?)",
		Params: []interface{}{"relay-claim", float64(3), hlc},
	}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	entries := []*pb.MutationEntry{{Seq: 1, Hlc: hlc, Origin: "origin-node", Stmts: string(stmts)}}

	// This node is NOT a relay by its own reckoning; the sender says otherwise.
	if _, err := s.PushMutations(ctx, &pb.ReplicateRequest{
		Sender:          "node-a",
		Entries:         entries,
		ReceiverIsRelay: true,
	}); err != nil {
		t.Fatalf("PushMutations: %v", err)
	}

	rows, err := s.db.Query(context.Background(),
		`SELECT origin FROM mutation_log WHERE hlc = ?`, hlc)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("mutation_log rows = %d, want 1: PushMutations dropped the sender's relay "+
			"claim, so the fix is inert on the wire and every leaf behind this node stops receiving",
			len(rows))
	}
	if got := rows[0].String("origin"); got != "origin-node" {
		t.Errorf("forwarded origin = %q, want %q", got, "origin-node")
	}
}
