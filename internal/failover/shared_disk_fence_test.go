package failover

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedVMWithDisk inserts a VM (restart-any, no auto-promote) with a single disk of
// the given storage type, for the shared-vs-local decision-gate matrix.
func seedVMWithDisk(t *testing.T, ctx context.Context, db *corrosion.Client, name, host, storageType string) {
	t.Helper()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: name, HostName: host, State: "running",
			Spec: `{"on_host_failure":"restart-any"}`, CPUActual: 1, MemActual: 512},
		nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: host,
			Path: "/d/" + name + ".img", SizeBytes: 1 << 30, StorageType: storageType, StorageVolume: "pool"}},
	); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

// TestCoordinator_SharedDiskRefusedWithoutProofGradeFence: with the shared-storage
// fence enforced and only a best-effort (non-proof-grade) fence available
// (fenceEpoch==""), the coordinator refuses to CREATE a transfer for a VM with a
// writable shared disk — failing closed at the SOURCE so a config-skewed/regressed
// target can never receive an unfenced shared-disk transfer. A local-disk VM on the
// same fenced host still reschedules (no shared-write hazard).
func TestCoordinator_SharedDiskRefusedWithoutProofGradeFence(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for _, h := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	seedVMWithDisk(t, ctx, db, "sd", "bad", "nfs")   // shared → needs proof-grade fence
	seedVMWithDisk(t, ctx, db, "ld", "bad", "local") // local → unaffected

	fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")

	c := newTestCoordinator("coordinator", db) // stubFencer(method="test") ⇒ not proof-grade ⇒ fenceEpoch ""
	c.SharedStorageFenceEnforce = true
	c.Gate = gateEnforcing(capabilities.SharedStorageFenceV1)
	c.run(ctx)

	if sd, _ := corrosion.GetVM(ctx, db, "sd"); sd == nil || sd.HostName != "bad" {
		t.Errorf("shared-disk VM without a proof-grade fence must be refused at source (stay on 'bad'), got %+v", sd)
	}
	if ld, _ := corrosion.GetVM(ctx, db, "ld"); ld == nil || ld.HostName == "bad" {
		t.Errorf("local-disk VM must still reschedule off 'bad', got %+v", ld)
	}
}

// TestProofGradeFenceRef: the coordinator binds a transfer proof to the newest
// PROOF-GRADE fence of the old owner, and returns "" when only a non-proof-grade
// (best-effort/SSH) fence exists — so the executor fails a shared-disk transfer
// closed rather than trusting an unconfirmed power-off.
func TestProofGradeFenceRef(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	c := newTestCoordinator("coordinator", db)

	// No fence at all ⇒ "".
	if got := c.proofGradeFenceRef(ctx, "h"); got != "" {
		t.Errorf("no fence ⇒ want empty, got %q", got)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	seed := func(id, method, result string) {
		if err := db.Execute(ctx,
			`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail)
			 VALUES (?, 'h', ?, ?, ?, '')`, id, method, result, now); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Only a best-effort SSH fence ⇒ still "" (not proof-grade).
	seed("ssh1", "best-effort-ssh", "fenced")
	if got := c.proofGradeFenceRef(ctx, "h"); got != "" {
		t.Errorf("best-effort-only ⇒ want empty, got %q", got)
	}

	// Add an IPMI-confirmed fence ⇒ bound epoch referencing it.
	seed("ipmi1", "ipmi", "fenced")
	got := c.proofGradeFenceRef(ctx, "h")
	ref, ok := corrosion.ParseFenceEpoch(got)
	if !ok || ref.Host != "h" || ref.FenceID != "ipmi1" {
		t.Errorf("ipmi fence ⇒ want epoch binding fence_id=ipmi1 host=h, got %q (parsed %+v)", got, ref)
	}
}

// TestCoordinator_AutoPromote_RetryableFallsThroughToReschedule: a retryable
// Unavailable from auto-promote (e.g. the fence_epoch fencing_log row hasn't
// replicated to the replica host yet) must NOT strand the VM. A fenced host is
// processed only once, so the coordinator falls through to the reschedule path —
// which carries the same fence_epoch and is re-gated by the TARGET reconciler
// (whose retry loop does handle a not-yet-replicated fence). The VM must end up
// re-pointed off the fenced source (pending on a healthy host), not left behind.
func TestCoordinator_AutoPromote_RetryableFallsThroughToReschedule(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	for _, h := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: h, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "manual",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, db, corrosion.BackupScheduleRecord{
		VMName: "vm1", Repo: "dr", Scope: "vm", Cron: "* * * * *", Enabled: true,
		Type: "replication", TargetPool: "dr", TargetHost: "good", KeepReplicas: 3,
		Incremental: true, AutoPromote: true,
	}); err != nil {
		t.Fatalf("UpsertBackupSchedule: %v", err)
	}

	fenceQuorum(t, ctx, db, []string{"coordinator", "good"}, "bad")

	prom := &dbPromoter{db: db, failUnavailable: true}
	c := newTestCoordinator("coordinator", db)
	c.Promoter = prom
	c.run(ctx)

	if len(prom.promoted) != 1 {
		t.Fatalf("expected one auto-promote attempt, got %v", prom.promoted)
	}
	// The retryable promote error falls through to reschedule, so the VM must be
	// re-pointed off the fenced source onto a healthy host — never stranded on 'bad'
	// (a fenced host is processed only once, so a `continue` here would strand it).
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.HostName == "bad" {
		t.Errorf("retryable auto-promote must fall through to reschedule off 'bad', got %+v", vm)
	}
	if vm.HostName != "good" {
		t.Errorf("want vm1 rescheduled to 'good', got host=%q", vm.HostName)
	}
}
