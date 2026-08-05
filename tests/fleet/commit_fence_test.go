// Fleet scenarios for the COMMIT FENCE on long-running operations.
//
// CreateVM, CreateContainer, UpdateVM and Resize re-validate their quota
// authority immediately before the durable write (reservationLease.allowCommit),
// because an authority handoff mid-request lets the successor re-admit the same
// quota — aborting before anything durable exists is the only sound resolution.
// Clone, live restore, and container restore are the admissions with the WIDEST
// grant-to-commit gap (disk copy, overlay boot, archive import), yet they had no
// fence at all.
//
// Each scenario latches delegated quota enforcement, then uses the test-only
// commit-fence hook to move the project's authority AFTER admission but BEFORE
// the durable write — the only way to produce a mid-flight handoff
// deterministically (a lesson bought previously: without the hook these tests
// pass against unfenced code, asserting nothing). The operation must abort with
// nothing durable and nothing running, and the same operation must succeed once
// the hook is cleared.

package fleet

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// quotaOnlyGate is a serverGate with EXACTLY project_authority_v1 latched:
// quorum present, peers supportive, and no other enforcement. Latching only
// the capability under test matters twice over — the real health.Checker's
// ExecutionGate would refuse the container restore for want of peer-probe
// quorum the fleet harness doesn't run, and an everything-latched fake would
// drag split_brain_gate_v1 in, whose proof requirement refuses a peer-cert
// restore before the fence is ever reached.
type quotaOnlyGate struct{}

func (quotaOnlyGate) ExecutionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}
func (quotaOnlyGate) DecisionGate(context.Context) health.GateResult {
	return health.GateResult{OK: true}
}
func (quotaOnlyGate) CapabilityActive(_ context.Context, token string) (bool, string) {
	return token == capabilities.ProjectAuthorityV1, ""
}
func (quotaOnlyGate) CapabilityActiveForHealth(_ context.Context, token string) (bool, string) {
	return token == capabilities.ProjectAuthorityV1, ""
}
func (quotaOnlyGate) Enforced(_ context.Context, token string) bool {
	return token == capabilities.ProjectAuthorityV1
}
func (quotaOnlyGate) Latched(token string) bool                              { return token == capabilities.ProjectAuthorityV1 }
func (quotaOnlyGate) PeerSupportsFresh(context.Context, string, string) bool { return true }
func (quotaOnlyGate) HealthyPeers(context.Context) []string                  { return nil }

// fenceSetup latches delegated quota admission and seeds a project whose
// authority (epoch 1) is held by holder. Returns a hook that performs a planned
// takeover to newHolder (epoch 2), to be installed on the EXECUTING node.
func fenceSetup(t *testing.T, c *Cluster, project string, holder, newHolder *Node) func(string) {
	t.Helper()
	for _, n := range c.Nodes {
		n.Server.SetGate(quotaOnlyGate{})
		n.Server.SetProjectAuthorityEnforce(true)
	}
	roomyHosts(t, c)
	// One write reaches every node: these scenarios run SharedCRDT (the disk /
	// archive fixtures need the executing host's rows visible immediately), so
	// the per-node seeding helpers would double-insert.
	ctx := context.Background()
	db := c.Nodes[0].DB
	if err := corrosion.InsertProject(ctx, db, corrosion.ProjectRecord{Name: project}); err != nil {
		t.Fatalf("InsertProject: %v", err)
	}
	if err := corrosion.UpsertProjectQuota(ctx, db, corrosion.ProjectQuotaRecord{
		ProjectName: project, VCPULimit: 64,
	}); err != nil {
		t.Fatalf("UpsertProjectQuota: %v", err)
	}
	if applied, err := corrosion.ClaimInitialProjectAuthority(ctx, db, project, holder.Name); err != nil || !applied {
		t.Fatalf("ClaimInitialProjectAuthority: applied=%v err=%v", applied, err)
	}
	return func(string) {
		if _, ok, err := corrosion.TakeoverProjectAuthority(context.Background(), c.Nodes[0].DB,
			project, newHolder.Name, "planned", "", 1); err != nil || !ok {
			t.Errorf("mid-flight TakeoverProjectAuthority: ok=%v err=%v", ok, err)
		}
	}
}

func TestFleet_CloneVM_FenceAbortsOnMidFlightAuthorityMove(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	entry, src := c.Nodes[0], c.Nodes[1]
	moveAuthority := fenceSetup(t, c, "tenant", src, entry)
	seedCloneSource(t, c, src, "tpl", "tenant", 2, 2048)

	// The clone executes on the SOURCE's host; the fence fires there.
	src.Server.SetCommitFenceHook(moveAuthority)
	_, err := cloneAt(t, c, entry, "tpl", "fenced-clone")
	src.Server.SetCommitFenceHook(nil)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("clone whose quota authority moved mid-copy: got %v, want Aborted", err)
	}
	if vm, gerr := corrosion.GetVM(ctx, src.DB, "fenced-clone"); gerr == nil && vm != nil {
		t.Errorf("aborted clone still left a VM row behind (state %q)", vm.State)
	}
	if src.Virt.DomainExists("fenced-clone") {
		t.Error("aborted clone left a defined domain — the fence must tear the clone down")
	}

	// Control: the identical clone commits once nothing moves the authority.
	// (Authority is now at epoch 2 held by entry; the fresh admission grants
	// under it and the fence agrees.)
	if _, err := cloneAt(t, c, entry, "tpl", "clone-ok"); err != nil {
		t.Fatalf("clone with a stable authority: %v", err)
	}
}

func TestFleet_RestoreLive_FenceAbortsOnMidFlightAuthorityMove(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	target, other := c.Nodes[0], c.Nodes[1]
	moveAuthority := fenceSetup(t, c, "tenant", target, other)
	repo, ts := seedVMBackup(t, "backed-up", "tenant", 2, 2048)

	target.Server.SetCommitFenceHook(moveAuthority)
	err := restoreLiveAt(t, c, target, repo, "backed-up", ts, "fenced-restore")
	target.Server.SetCommitFenceHook(nil)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("live restore whose quota authority moved mid-flight: got %v, want Aborted", err)
	}
	if rec, gerr := corrosion.GetVM(ctx, target.DB, "fenced-restore"); gerr == nil && rec != nil {
		t.Errorf("aborted live restore still left a VM row behind (state %q)", rec.State)
	}
	// The VM was RUNNING off the overlay when the fence refused — it must not
	// stay running untracked. That is strictly worse than the quota overrun the
	// fence prevents.
	if target.Virt.DomainExists("fenced-restore") {
		t.Error("aborted live restore left the domain behind — a running VM with no cluster row is unmanageable")
	}

	if err := restoreLiveAt(t, c, target, repo, "backed-up", ts, "restore-ok"); err != nil {
		t.Fatalf("live restore with a stable authority: %v", err)
	}
}

func TestFleet_RestoreContainer_FenceAbortsOnMidFlightAuthorityMove(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	moveAuthority := fenceSetup(t, c, "tenant", dst, src)
	createSizedContainer(t, c, src, "ct-backed", "tenant", 1, 1024)
	repo, ts := backupContainer(t, c, src, "ct-backed")

	dst.Server.SetCommitFenceHook(moveAuthority)
	err := restoreContainerAt(t, c, dst, repo, "ct-backed", ts)
	dst.Server.SetCommitFenceHook(nil)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("container restore whose quota authority moved mid-import: got %v, want Aborted", err)
	}
	if rec, gerr := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct-backed"); gerr == nil && rec != nil {
		t.Errorf("aborted restore still wrote a container row: %+v", rec)
	}
	// The import ran (the fence sits at the commit, not the admission) and the
	// imported runtime container must be torn down again.
	if got := len(dst.CT.ImportCalls()); got == 0 {
		t.Error("fence fired before the import — it must guard the durable write, not re-run admission")
	}

	if err := restoreContainerAt(t, c, dst, repo, "ct-backed", ts); err != nil {
		t.Fatalf("container restore with a stable authority: %v", err)
	}
}
