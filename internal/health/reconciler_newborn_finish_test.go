package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A create inserts its row "creating" and publishes it running only after the
// first owner epoch is assigned and a marker names it. When that finish fails —
// a store fault on the graduation, no marker landing — the row stays
// "creating" with the guest already running, and the owner's reconciler is what
// finishes it. These tests pin both halves: it finishes a stranded newborn, and
// it leaves alone every "creating" row something else legitimately holds.

// newbornFixture seeds vm1 owned by node-a in state "creating" at epoch 0, with
// the domain in the given libvirt state, and returns the reconciler for node-a.
func newbornFixture(t *testing.T, domain libvirtfake.State) (*Reconciler, *corrosion.Client, *libvirtfake.Fake, string) {
	t.Helper()
	db := testReconcilerDB(t)
	if err := corrosion.InsertVM(context.Background(), db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "creating"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", domain)
	dataDir := t.TempDir()
	return NewReconciler("node-a", dataDir, db, fake), db, fake, dataDir
}

func newbornRow(t *testing.T, db *corrosion.Client) *corrosion.VMRecord {
	t.Helper()
	row, err := corrosion.GetVM(context.Background(), db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM: %v (row=%v)", err, row)
	}
	return row
}

func TestReconciler_FinishesAStrandedNewborn(t *testing.T) {
	r, db, fake, dataDir := newbornFixture(t, libvirtfake.StateRunning)

	r.ReconcileOnce(context.Background())

	row := newbornRow(t, db)
	if row.State != "running" || row.OwnerEpoch != 1 {
		t.Fatalf("after one pass: state=%q epoch=%d, want running at 1 — a newborn whose "+
			"domain runs here is the owner's to finish", row.State, row.OwnerEpoch)
	}
	if epoch, ok, err := fake.GetDomainOwnerEpoch("vm1"); err != nil || !ok || epoch != 1 {
		t.Errorf("domain marker = (%d,%v,%v), want (1,true,nil)", epoch, ok, err)
	}
	if epoch, ok, err := ReadVMOwnerEpochMarker(dataDir, "vm1"); err != nil || !ok || epoch != 1 {
		t.Errorf("file marker = (%d,%v,%v), want (1,true,nil)", epoch, ok, err)
	}
}

// A graduated row whose flip failed after the markers landed is the same
// newborn one step further on; the finish completes it rather than stranding it.
func TestReconciler_FinishesAGraduatedButUnpublishedNewborn(t *testing.T) {
	r, db, _, _ := newbornFixture(t, libvirtfake.StateRunning)
	if err := corrosion.GraduateVMOwnerEpoch(context.Background(), db, "vm1"); err != nil {
		t.Fatalf("GraduateVMOwnerEpoch: %v", err)
	}

	r.ReconcileOnce(context.Background())

	if row := newbornRow(t, db); row.State != "running" || row.OwnerEpoch != 1 {
		t.Fatalf("state=%q epoch=%d, want running at 1", row.State, row.OwnerEpoch)
	}
}

// Every "creating" row the reconciler must NOT finish. Each is held by
// something else, or has no runtime here to publish.
func TestReconciler_LeavesAHeldCreatingRowAlone(t *testing.T) {
	for _, tc := range []struct {
		name   string
		domain libvirtfake.State
		hold   string // SQL applied after the seed
	}{
		{name: "domain not running", domain: libvirtfake.StateDefined},
		{name: "create operation in flight", domain: libvirtfake.StateRunning,
			hold: `UPDATE vms SET active_operation_id = 'op-1' WHERE name = 'vm1'`},
		{name: "proof-gated action pending", domain: libvirtfake.StateRunning,
			hold: `UPDATE vms SET pending_action_id = 'proof-1' WHERE name = 'vm1'`},
		{name: "live vm_lock", domain: libvirtfake.StateRunning,
			hold: `INSERT INTO vm_locks (vm_name, holder, expires_at, updated_at)
			       VALUES ('vm1', 'node-b', '2999-01-01T00:00:00Z', '2999-01-01T00:00:00Z')`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, db, fake, dataDir := newbornFixture(t, tc.domain)
			if tc.hold != "" {
				if err := db.Execute(context.Background(), tc.hold); err != nil {
					t.Fatalf("hold: %v", err)
				}
			}

			r.ReconcileOnce(context.Background())

			row := newbornRow(t, db)
			if row.State != "creating" || row.OwnerEpoch != 0 {
				t.Errorf("state=%q epoch=%d, want creating at 0 — this row is not the reconciler's to finish",
					row.State, row.OwnerEpoch)
			}
			if _, ok, _ := fake.GetDomainOwnerEpoch("vm1"); ok {
				t.Error("a domain marker was stamped on a row the reconciler must leave alone")
			}
			if _, ok, _ := ReadVMOwnerEpochMarker(dataDir, "vm1"); ok {
				t.Error("a file marker was written on a row the reconciler must leave alone")
			}
		})
	}
}
