package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The receiver-side shape of the defect. A coordinator whose ledger latch has
// formed carries a stamped proof to an upgraded receiver whose own latch is
// still closed. The receiver used to seed the row through the released insert,
// silently dropping lease_term and lease_key; the claim succeeded, and the
// retry of the identical proof — how an interrupted action recovers — was
// refused as "persisted proof does not match the carried proof" with
// FailedPrecondition, which no caller retries.
//
// The receiver must instead refuse RETRYABLY before persisting anything. Its
// latch forms from the same peer set the coordinator's did, so the retry lands.
func TestClaimCarriedProof_AStampedProofBeforeTheLocalLatchIsRetryableNotDivergent(t *testing.T) {
	ctx := context.Background()
	s := apServer(t)
	open := false
	s.db.SetLeaseTermLedgerGate(func() bool { return open })

	p := &pb.RuntimeActionProof{
		Id: "p1", Action: corrosion.ActionPromote, TargetKind: "vm",
		TargetName: "vm1", DestHost: "host-a", Coordinator: "coord",
		LeaseTerm: 5, LeaseKey: corrosion.LeaseKeyFailover,
	}

	_, err := s.claimCarriedProof(ctx, p, corrosion.ActionPromote, "vm", "vm1")
	if err == nil {
		t.Fatal("a stamped proof was claimed by a receiver whose ledger latch is closed; the row " +
			"it seeded cannot carry the stamp, so the retry of this same proof will be " +
			"refused as divergent")
	}
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("refusal code = %v (%v), want Unavailable so the coordinator retries once "+
			"this receiver's latch forms", status.Code(err), err)
	}
	if _, ok, _ := corrosion.GetActionProof(ctx, s.db, "p1"); ok {
		t.Fatal("a row was persisted by the refused claim")
	}

	// The latch forms. The same carried proof claims, and the retry of it is
	// the spent-proof refusal a completed action gets — not a divergence.
	open = true
	if id, err := s.claimCarriedProof(ctx, p, corrosion.ActionPromote, "vm", "vm1"); err != nil || id != "p1" {
		t.Fatalf("post-latch claim: id=%q err=%v", id, err)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, s.db, "p1")
	if err != nil || !ok {
		t.Fatalf("GetActionProof: ok=%v err=%v", ok, err)
	}
	if pr.LeaseTerm != 5 || pr.LeaseKey != corrosion.LeaseKeyFailover {
		t.Fatalf("persisted stamp = (%d, %q), want the carried (5, %q)",
			pr.LeaseTerm, pr.LeaseKey, corrosion.LeaseKeyFailover)
	}
}
