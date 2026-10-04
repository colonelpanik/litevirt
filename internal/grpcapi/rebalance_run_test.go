package grpcapi

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedAutoImbalance piles auto-mode VMs on one host and leaves a second host
// empty, so a rebalance cycle has moves to propose and every one of them is
// for a VM whose resolved mode is auto.
func seedAutoImbalance(t *testing.T, ctx context.Context, db *corrosion.Client) {
	t.Helper()
	insertTestHostR2(t, ctx, db, "loaded", "active")
	insertTestHostR2(t, ctx, db, "empty", "active")
	for i := 0; i < 4; i++ {
		insertTestVMR2WithSpec(t, ctx, db, fmt.Sprintf("vm-%d", i), "loaded", "running", budgetSpec(4, 10))
	}
}

// `lv rebalance run --dry-run` (and the UI's Dry-run button) promise that
// every proposal is recorded as pending whatever each VM's mode is. RunRebalance
// used to ignore req.DryRun, so auto-mode VMs were auto-approved and the
// executor then live-migrated them: a dry run moved workloads.
func TestRunRebalance_DryRunApprovesNothing(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	seedAutoImbalance(t, ctx, s.db)

	resp, err := s.RunRebalance(ctx, &pb.RunRebalanceRequest{DryRun: true})
	if err != nil {
		t.Fatalf("RunRebalance(dry_run): %v", err)
	}
	if resp.GetProposalsEmitted() == 0 {
		t.Fatal("dry run emitted no proposals on an imbalanced cluster; the test proves nothing")
	}
	if n := countProposalStatus(t, ctx, s.db, "approved"); n != 0 {
		t.Fatalf("dry run left %d proposal(s) approved; want 0 (all pending)", n)
	}
	if n := countProposalStatus(t, ctx, s.db, "pending"); n != int(resp.GetProposalsEmitted()) {
		t.Fatalf("pending = %d, want every emitted proposal (%d)", n, resp.GetProposalsEmitted())
	}

	// And nothing moves: the executor finds no approved row to claim.
	var migrations atomic.Int32
	e := NewRebalanceExecutor(s, s.hostName, s.db)
	e.migrateOverride = func(context.Context, string, string) error {
		migrations.Add(1)
		return nil
	}
	e.RunOnce(ctx)
	time.Sleep(50 * time.Millisecond)
	if n := migrations.Load(); n != 0 {
		t.Fatalf("executor ran %d migration(s) after a dry run; want 0", n)
	}
	for i := 0; i < 4; i++ {
		vm, err := corrosion.GetVM(ctx, s.db, fmt.Sprintf("vm-%d", i))
		if err != nil || vm == nil {
			t.Fatalf("GetVM vm-%d: vm=%v err=%v", i, vm, err)
		}
		if vm.HostName != "loaded" {
			t.Errorf("vm-%d moved to %q during a dry run", i, vm.HostName)
		}
	}
}

// Without --dry-run the per-VM mode still decides: an auto-mode VM's proposal
// is approved, exactly as before.
func TestRunRebalance_NonDryRunStillAutoApproves(t *testing.T) {
	s := testServerR2(t)
	ctx := adminContext(context.Background())
	seedAutoImbalance(t, ctx, s.db)

	resp, err := s.RunRebalance(ctx, &pb.RunRebalanceRequest{})
	if err != nil {
		t.Fatalf("RunRebalance: %v", err)
	}
	if resp.GetProposalsEmitted() == 0 {
		t.Fatal("no proposals emitted on an imbalanced cluster")
	}
	if n := countProposalStatus(t, ctx, s.db, "approved"); n != int(resp.GetProposalsEmitted()) {
		t.Fatalf("approved = %d, want every emitted auto-mode proposal (%d)", n, resp.GetProposalsEmitted())
	}
}
