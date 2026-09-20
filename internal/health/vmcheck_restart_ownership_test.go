package health

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedRestartPolicyVM inserts a VM owned by owner, stopped with a CRASH cause,
// and carrying an always-restart policy — the exact shape maybeRestartVM acts
// on. v.virt is nil in these tests, so the destructive half cannot run; the
// observable is the restart COUNTER, which maybeRestartVM increments as its
// record that it is going ahead.
func seedRestartPolicyVM(t *testing.T, db *corrosion.Client, name, owner string) {
	t.Helper()
	spec, err := json.Marshal(&pb.VMSpec{
		Name:    name,
		Restart: &pb.RestartPolicy{Condition: "always", MaxAttempts: 10, Window: "1h", Delay: "0s"},
	})
	if err != nil {
		t.Fatalf("marshal spec: %v", err)
	}
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name: name, HostName: owner, State: "stopped",
		StateDetail: "crashed", Spec: string(spec),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
}

func restartAttempts(t *testing.T, db *corrosion.Client, name string) int {
	t.Helper()
	rs, err := corrosion.GetRestartState(context.Background(), db, name)
	if err != nil {
		t.Fatalf("GetRestartState: %v", err)
	}
	return safeAttemptCount(rs)
}

// TestMaybeRestartVM_RefusesAVMThisHostNoLongerOwns is the #189 regression.
//
// maybeRestartVM went from the quorum gate straight to DestroyDomain +
// StartDomain with no fresh-row ownership re-read. Every sibling start path has
// one: takeAction re-reads and refuses on fresh.HostName != v.hostName,
// startPendingVM takes the per-VM lock whose own comment warns "the same
// physical disk gets two QEMU writers -> guaranteed corruption", and the
// self-heal path checks the owner epoch.
//
// ExecutionGate proves QUORUM, not OWNERSHIP — and a rejoined node holding a
// stale replica is precisely the case that has quorum. Ownership was only
// consulted afterwards, by publishRunning, which declines to publish once the
// guest is already booted: by then the second QEMU is writing.
func TestMaybeRestartVM_RefusesAVMThisHostNoLongerOwns(t *testing.T) {
	db := testStartDB(t)
	seedRestartPolicyVM(t, db, "vm1", "node2") // owned elsewhere
	v := NewVMChecker("node1", db, nil)

	// The stale snapshot this host is acting on still names itself as owner —
	// that is what makes the re-read load-bearing.
	stale := corrosion.VMRecord{Name: "vm1", HostName: "node1", State: "stopped", StateDetail: "crashed"}
	v.maybeRestartVM(context.Background(), stale, time.Now())

	if got := restartAttempts(t, db, "vm1"); got != 0 {
		t.Fatalf("restart attempts = %d, want 0 — this host acted on a VM node2 owns", got)
	}
}

// A VM this host does own is still restarted; the guard must not stop the
// feature working.
func TestMaybeRestartVM_RestartsAVMThisHostOwns(t *testing.T) {
	db := testStartDB(t)
	seedRestartPolicyVM(t, db, "vm1", "node1")
	v := NewVMChecker("node1", db, nil)

	vm, err := corrosion.GetVM(context.Background(), db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v %v", vm, err)
	}
	v.maybeRestartVM(context.Background(), *vm, time.Now())

	if got := restartAttempts(t, db, "vm1"); got != 1 {
		t.Fatalf("restart attempts = %d, want 1 — an owned crashed VM must restart", got)
	}
}

// The per-VM lock is the guard that stops THIS host's reconciler and its
// restart policy starting the same VM at once. A lock held by another holder
// must stop the restart.
func TestMaybeRestartVM_RefusesWhileAnotherHolderHasTheVMLock(t *testing.T) {
	db := testStartDB(t)
	ctx := context.Background()
	seedRestartPolicyVM(t, db, "vm1", "node1")

	// node2 holds a live lock on vm1.
	expires := time.Now().Add(vmLockTTL).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at) VALUES (?, ?, ?, ?)`,
		"vm1", "node2", expires, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("seed vm_lock: %v", err)
	}

	v := NewVMChecker("node1", db, nil)
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	v.maybeRestartVM(ctx, *vm, time.Now())

	if got := restartAttempts(t, db, "vm1"); got != 0 {
		t.Fatalf("restart attempts = %d, want 0 — node2 holds the vm_lock", got)
	}
}

// The lock must be released again, or one restart-policy start would block
// that VM's reconciliation for the whole vmLockTTL.
func TestMaybeRestartVM_ReleasesTheVMLock(t *testing.T) {
	db := testStartDB(t)
	ctx := context.Background()
	seedRestartPolicyVM(t, db, "vm1", "node1")
	v := NewVMChecker("node1", db, nil)

	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	v.maybeRestartVM(ctx, *vm, time.Now())

	rows, err := db.Query(ctx, `SELECT holder FROM vm_locks WHERE vm_name = ?`, "vm1")
	if err != nil {
		t.Fatalf("query vm_locks: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("vm_lock still held by %q after the restart returned; the VM is "+
			"blocked from reconciliation for up to %s", rows[0].String("holder"), vmLockTTL)
	}
}

// A VM whose row has vanished between the snapshot and now must not be
// restarted — there is nothing left to own.
func TestMaybeRestartVM_RefusesAVanishedVM(t *testing.T) {
	db := testStartDB(t)
	v := NewVMChecker("node1", db, nil)

	stale := corrosion.VMRecord{Name: "ghost", HostName: "node1", State: "stopped", StateDetail: "crashed"}
	v.maybeRestartVM(context.Background(), stale, time.Now())

	if got := restartAttempts(t, db, "ghost"); got != 0 {
		t.Fatalf("restart attempts = %d, want 0 for a VM with no row", got)
	}
}
