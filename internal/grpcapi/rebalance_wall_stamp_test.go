package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hlc"
)

// Every rebalance_proposals writer here stamps updated_at as an RFC3339 instant
// even once the cluster has latched hlc_lww: an older release mid-roll reads
// that column lexically (its reaper, its prune, the receiver-side bulk reap),
// and an HLC "17…" stamp sorts below every RFC3339 cutoff. See NowWallTS.

func proposalUpdatedAt(t *testing.T, ctx context.Context, db *corrosion.Client, id string) string {
	t.Helper()
	rows, err := db.Query(ctx, `SELECT updated_at FROM rebalance_proposals WHERE id=?`, id)
	if err != nil || len(rows) == 0 {
		t.Fatalf("read proposal %s: err=%v rows=%d", id, err, len(rows))
	}
	return rows[0].String("updated_at")
}

func requireProposalWallStamp(t *testing.T, what, ts string) {
	t.Helper()
	if hlc.IsHLC(ts) {
		t.Errorf("%s: updated_at = %q is an HLC string", what, ts)
		return
	}
	if _, err := time.Parse(time.RFC3339, ts); err != nil {
		t.Errorf("%s: updated_at = %q is not RFC3339: %v", what, ts, err)
	}
}

func latchHLCEmissionOn(t *testing.T, db *corrosion.Client) {
	t.Helper()
	db.SetHLCEmit(func() bool { return true })
	if ts := db.NowTS(); !hlc.IsHLC(ts) {
		t.Fatalf("precondition: NowTS = %q with HLC emission on, want an HLC string", ts)
	}
}

func TestRebalanceOperatorTransitions_StampWallTimeUnderHLC(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	insertProposal(t, ctx, s.db, "p-approve", "vm-a", "src", "dst", "pending")
	insertProposal(t, ctx, s.db, "p-reject", "vm-b", "src", "dst", "pending")
	latchHLCEmissionOn(t, s.db)

	if _, err := s.ApproveRebalanceProposal(ctx, &pb.ApproveRebalanceProposalRequest{Id: "p-approve"}); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := s.RejectRebalanceProposal(ctx, &pb.RejectRebalanceProposalRequest{Id: "p-reject"}); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if st, _, _ := proposalStatus(t, ctx, s.db, "p-approve"); st != "approved" {
		t.Fatalf("p-approve is %q, want approved", st)
	}
	if st, _, _ := proposalStatus(t, ctx, s.db, "p-reject"); st != "rejected" {
		t.Fatalf("p-reject is %q, want rejected", st)
	}
	requireProposalWallStamp(t, "approve", proposalUpdatedAt(t, ctx, s.db, "p-approve"))
	requireProposalWallStamp(t, "reject", proposalUpdatedAt(t, ctx, s.db, "p-reject"))
}

func TestRebalanceExecutorTransitions_StampWallTimeUnderHLC(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	insertTestHostR2(t, ctx, s.db, "src", "active")
	insertTestHostR2(t, ctx, s.db, "dst", "active")
	insertTestVMR2WithSpec(t, ctx, s.db, "vm-a", "src", "running", budgetSpec(2, 10))
	insertProposal(t, ctx, s.db, "p-apply", "vm-a", "src", "dst", "approved")
	// No such VM: claimed, then failed by validation.
	insertProposal(t, ctx, s.db, "p-fail", "vm-gone", "src", "dst", "approved")
	latchHLCEmissionOn(t, s.db)

	// The claim's stamp is read while the migration is in flight, before the
	// terminal status overwrites it.
	claimed := make(chan string, 1)
	e := NewRebalanceExecutor(s, "exec-host", s.db)
	e.migrateOverride = func(ctx context.Context, _, _ string) error {
		rows, err := s.db.Query(ctx, `SELECT updated_at FROM rebalance_proposals WHERE id='p-apply'`)
		if err == nil && len(rows) == 1 {
			claimed <- rows[0].String("updated_at")
		} else {
			claimed <- ""
		}
		return nil
	}
	e.RunOnce(ctx)

	eventually(t, func() bool {
		a, _, _ := proposalStatus(t, ctx, s.db, "p-apply")
		f, _, _ := proposalStatus(t, ctx, s.db, "p-fail")
		return a == "applied" && f == "failed"
	})
	select {
	case ts := <-claimed:
		requireProposalWallStamp(t, "claim", ts)
	case <-time.After(2 * time.Second):
		t.Fatal("the migration never ran, so the claim was never observed")
	}
	requireProposalWallStamp(t, "markApplied", proposalUpdatedAt(t, ctx, s.db, "p-apply"))
	requireProposalWallStamp(t, "markFailed", proposalUpdatedAt(t, ctx, s.db, "p-fail"))
}
