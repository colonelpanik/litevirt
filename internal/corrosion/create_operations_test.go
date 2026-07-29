package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func createOp(id, resourceKind, resourceID, requestHash, reservation string, ownerEpoch int64) OperationRecord {
	return OperationRecord{
		ID: id, Method: "Create" + resourceKind, Principal: "alice", Project: "p1",
		ResourceKind: resourceKind, ResourceID: resourceID,
		OperationKind: string(OpWorkloadCreate), RequestHash: requestHash,
		IdempotencyKey: id, ReservationJSON: reservation, VMOwnerEpoch: ownerEpoch,
	}
}

func TestBeginVMCreateOperationIsAtomic(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	op := createOp("op-vm", "vm", "vm1", "hash", "", 7)
	vm := VMRecord{Name: "vm1", HostName: "h1", Spec: `{"cpu":2}`, State: "creating", Project: "p1", OwnerEpoch: 7}

	applied, err := c.BeginVMCreateOperation(ctx, op, vm)
	if err != nil || !applied {
		t.Fatalf("BeginVMCreateOperation: applied=%v err=%v", applied, err)
	}
	got, err := GetVM(ctx, c, "vm1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.State != "creating" || got.ActiveOperationID != op.ID ||
		got.OwnerEpoch != 7 || got.SpecGeneration != 0 {
		t.Fatalf("provisional vm = %+v", got)
	}
	header, err := GetOperation(ctx, c, op.ID)
	if err != nil || header == nil {
		t.Fatalf("operation = %+v err=%v", header, err)
	}
	steps, err := ListOperationSteps(ctx, c, op.ID, 7)
	if err != nil {
		t.Fatal(err)
	}
	if got := stepNames(steps); !equalStrings(got, []string{OpStepDesiredPersisted, OpStepPlanned, OpStepReserved}) {
		t.Fatalf("steps = %v", got)
	}
}

func TestBeginVMCreateOperationRollsBackOnStatementFailure(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if _, err := c.db.Exec(`CREATE TRIGGER fail_vm_create BEFORE INSERT ON vms
		BEGIN SELECT RAISE(ABORT, 'injected vm insert failure'); END`); err != nil {
		t.Fatal(err)
	}
	op := createOp("op-fail", "vm", "vm-fail", "hash", "", 1)
	if applied, err := c.BeginVMCreateOperation(ctx, op, VMRecord{Name: "vm-fail", HostName: "h1", State: "creating", OwnerEpoch: 1}); err == nil || applied {
		t.Fatalf("BeginVMCreateOperation: applied=%v err=%v, want transactional failure", applied, err)
	}
	if got, _ := GetOperation(ctx, c, op.ID); got != nil {
		t.Fatalf("operation survived rollback: %+v", got)
	}
	if rows, _ := c.Query(ctx, `SELECT 1 FROM operation_steps WHERE operation_id = ?`, op.ID); len(rows) != 0 {
		t.Fatalf("steps survived rollback: %v", rows)
	}
	if got, _ := GetVM(ctx, c, "vm-fail"); got != nil {
		t.Fatalf("vm survived rollback: %+v", got)
	}
}

func TestExecuteBatchGuardedEvaluatesStructuredGuardsSequentially(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	op := createOp("op-local-guards", "vm", "vm1", "hash", "", 1)
	vm := VMRecord{Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1, SpecGeneration: 1}
	if applied, err := c.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
		t.Fatalf("begin: applied=%v err=%v", applied, err)
	}
	good, err := vmCreateMutationGuard(op.ID, 1, vm, true)
	if err != nil {
		t.Fatal(err)
	}
	bad := *good
	bad.IdentityHash = "not-the-provisional-identity"
	applied, err := c.ExecuteBatchGuarded(ctx, func(*sql.Tx) (bool, error) {
		return true, nil
	}, []Statement{
		{SQL: `UPDATE vms SET state_detail = ? WHERE name = ?`, Params: []interface{}{"must-roll-back", "vm1"}, Guard: good},
		{SQL: `UPDATE vms SET state_detail = ? WHERE name = ?`, Params: []interface{}{"must-not-apply", "vm1"}, Guard: &bad},
	})
	if err != nil || applied {
		t.Fatalf("guarded batch: applied=%v err=%v, want declined without error", applied, err)
	}
	got, err := GetVM(ctx, c, "vm1")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.StateDetail != "" {
		t.Fatalf("structured-guard decline did not roll back prior statement: %+v", got)
	}
}

func TestBeginVMCreateOperationIdempotencyAndConflicts(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	op := createOp("op-same", "vm", "vm1", "hash", "", 2)
	vm := VMRecord{Name: "vm1", HostName: "h1", State: "creating", OwnerEpoch: 2}
	if applied, err := c.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
		t.Fatalf("first begin: applied=%v err=%v", applied, err)
	}
	if applied, err := c.BeginVMCreateOperation(ctx, op, vm); err != nil || applied {
		t.Fatalf("same retry: applied=%v err=%v, want idempotent not-new", applied, err)
	}
	differentHash := op
	differentHash.RequestHash = "different"
	if _, err := c.BeginVMCreateOperation(ctx, differentHash, vm); !errors.Is(err, ErrOperationHashConflict) {
		t.Fatalf("different hash error = %v", err)
	}
	differentIdentity := op
	differentIdentity.ResourceID = "vm2"
	if _, err := c.BeginVMCreateOperation(ctx, differentIdentity, VMRecord{Name: "vm2", HostName: "h1", State: "creating", OwnerEpoch: 2}); !errors.Is(err, ErrOperationIdentityConflict) {
		t.Fatalf("different identity error = %v", err)
	}
	if got, _ := GetVM(ctx, c, "vm2"); got != nil {
		t.Fatalf("conflicting identity created vm2: %+v", got)
	}
	wrongProjectReservation, _ := (ReservationVector{
		Project: "other", ProjectCPU: 1,
	}).Encode()
	wrongProject := createOp("op-wrong-project", "vm", "vm3", "hash", wrongProjectReservation, 1)
	if _, err := c.BeginVMCreateOperation(ctx, wrongProject,
		VMRecord{Name: "vm3", HostName: "h1", Project: "p1", OwnerEpoch: 1}); !errors.Is(err, ErrOperationIdentityConflict) {
		t.Fatalf("wrong reservation project error = %v", err)
	}
	if got, _ := GetVM(ctx, c, "vm3"); got != nil {
		t.Fatalf("wrong-project reservation created vm3: %+v", got)
	}
}

func TestBeginCreateOperationRejectsReservationWorkloadBindingMismatch(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name  string
		begin func(*Client, string) (bool, error)
	}{
		{
			name: "vm target host",
			begin: func(c *Client, reservation string) (bool, error) {
				op := createOp("op-vm-target-mismatch", "vm", "vm1", "hash", reservation, 1)
				return c.BeginVMCreateOperation(ctx, op, VMRecord{
					Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1,
				})
			},
		},
		{
			name: "container target host",
			begin: func(c *Client, reservation string) (bool, error) {
				op := createOp("op-ct-target-mismatch", "container", "ct1", "hash", reservation, 1)
				return c.BeginContainerCreateOperation(ctx, op, ContainerRecord{
					HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 1,
				})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t)
			reservation, err := (ReservationVector{
				Project: "p1", ProjectCPU: 1, TargetHost: "h2", TargetCPU: 1,
			}).Encode()
			if err != nil {
				t.Fatal(err)
			}
			if applied, err := tc.begin(c, reservation); !errors.Is(err, ErrOperationIdentityConflict) || applied {
				t.Fatalf("mismatched target: applied=%v err=%v", applied, err)
			}
		})
	}
	t.Run("source host is invalid for create", func(t *testing.T) {
		c := testClient(t)
		reservation, err := (ReservationVector{
			Project: "p1", TargetHost: "h1", TargetCPU: 1, SourceHost: "old-host",
		}).Encode()
		if err != nil {
			t.Fatal(err)
		}
		op := createOp("op-vm-source-host", "vm", "vm1", "hash", reservation, 1)
		if applied, err := c.BeginVMCreateOperation(ctx, op, VMRecord{
			Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1,
		}); !errors.Is(err, ErrOperationIdentityConflict) || applied {
			t.Fatalf("source host binding: applied=%v err=%v", applied, err)
		}
	})
}

func TestBeginCreateRetryBindsCompleteProvisionalIdentity(t *testing.T) {
	ctx := context.Background()
	t.Run("vm", func(t *testing.T) {
		base := VMRecord{
			Name: "vm1", StackName: "stack1", HostName: "h1", Spec: `{"cpu":2}`,
			StateDetail: "requested", CPUActual: 2, MemActual: 1024, Project: "p1",
			IsTemplate: true, OwnerEpoch: 2, SpecGeneration: 3,
		}
		mutations := map[string]func(*VMRecord){
			"stack":      func(v *VMRecord) { v.StackName = "stack2" },
			"host":       func(v *VMRecord) { v.HostName = "h2" },
			"spec":       func(v *VMRecord) { v.Spec = `{"cpu":4}` },
			"detail":     func(v *VMRecord) { v.StateDetail = "different" },
			"cpu":        func(v *VMRecord) { v.CPUActual++ },
			"memory":     func(v *VMRecord) { v.MemActual++ },
			"template":   func(v *VMRecord) { v.IsTemplate = false },
			"generation": func(v *VMRecord) { v.SpecGeneration++ },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				c := testClient(t)
				op := createOp("op-vm-retry-"+name, "vm", "vm1", "same-hash", "", 2)
				if applied, err := c.BeginVMCreateOperation(ctx, op, base); err != nil || !applied {
					t.Fatalf("first begin: applied=%v err=%v", applied, err)
				}
				changed := base
				mutate(&changed)
				if applied, err := c.BeginVMCreateOperation(ctx, op, changed); !errors.Is(err, ErrOperationIdentityConflict) || applied {
					t.Fatalf("variant retry: applied=%v err=%v", applied, err)
				}
			})
		}
	})
	t.Run("container", func(t *testing.T) {
		base := ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "alpine", CPULimit: 2, MemMiB: 1024,
			Labels: map[string]string{"role": "web"}, RestartPolicy: `{"name":"always"}`,
			StateDetail: "requested", Project: "p1", IsTemplate: true,
			OnHostFailure: "image-recreate", CreateSpec: `{"release":"edge"}`,
			RelocateToken: "token1", OwnerEpoch: 2, SpecGeneration: 3,
		}
		mutations := map[string]func(*ContainerRecord){
			"image":      func(v *ContainerRecord) { v.Image = "debian" },
			"cpu":        func(v *ContainerRecord) { v.CPULimit++ },
			"memory":     func(v *ContainerRecord) { v.MemMiB++ },
			"labels":     func(v *ContainerRecord) { v.Labels = map[string]string{"role": "db"} },
			"restart":    func(v *ContainerRecord) { v.RestartPolicy = "never" },
			"detail":     func(v *ContainerRecord) { v.StateDetail = "different" },
			"template":   func(v *ContainerRecord) { v.IsTemplate = false },
			"on-failure": func(v *ContainerRecord) { v.OnHostFailure = "none" },
			"create-spec": func(v *ContainerRecord) {
				v.CreateSpec = `{"release":"stable"}`
			},
			"relocate":   func(v *ContainerRecord) { v.RelocateToken = "token2" },
			"generation": func(v *ContainerRecord) { v.SpecGeneration++ },
		}
		for name, mutate := range mutations {
			t.Run(name, func(t *testing.T) {
				c := testClient(t)
				op := createOp("op-ct-retry-"+name, "container", "ct1", "same-hash", "", 2)
				if applied, err := c.BeginContainerCreateOperation(ctx, op, base); err != nil || !applied {
					t.Fatalf("first begin: applied=%v err=%v", applied, err)
				}
				changed := base
				mutate(&changed)
				if applied, err := c.BeginContainerCreateOperation(ctx, op, changed); !errors.Is(err, ErrOperationIdentityConflict) || applied {
					t.Fatalf("variant retry: applied=%v err=%v", applied, err)
				}
			})
		}
	})
}

func TestBeginVMCreateOperationNeverOverwritesLiveVM(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	live := VMRecord{Name: "vm1", HostName: "old", Spec: `{"cpu":8}`, State: "running", OwnerEpoch: 9}
	if err := InsertVM(ctx, c, live, nil, nil); err != nil {
		t.Fatal(err)
	}
	applied, err := c.BeginVMCreateOperation(ctx, createOp("op-new", "vm", "vm1", "hash", "", 1),
		VMRecord{Name: "vm1", HostName: "new", State: "creating", OwnerEpoch: 1})
	if err != nil || applied {
		t.Fatalf("begin over live vm: applied=%v err=%v", applied, err)
	}
	got, _ := GetVM(ctx, c, "vm1")
	if got == nil || got.HostName != "old" || got.State != "running" {
		t.Fatalf("live vm overwritten: %+v", got)
	}
}

func TestBeginCreateOperationReusesOnlyNewerTombstonedIdentity(t *testing.T) {
	ctx := context.Background()

	t.Run("vm ordinary delete cleans stale hardware", func(t *testing.T) {
		c := testClient(t)
		oldOp := createOp("op-old-vm", "vm", "vm1", "old", "", 1)
		oldVM := VMRecord{
			Name: "vm1", HostName: "h1", Project: "p1", State: "creating",
			OwnerEpoch: 1, SpecGeneration: 1,
		}
		if applied, err := c.BeginVMCreateOperation(ctx, oldOp, oldVM); err != nil || !applied {
			t.Fatalf("old begin: applied=%v err=%v", applied, err)
		}
		if applied, err := c.CommitVMCreateOperation(ctx, oldOp.ID, 1, oldVM,
			[]InterfaceRecord{{NetworkName: "old-net", MAC: "52:54:00:00:00:01"}},
			[]DiskRecord{{DiskName: "old-disk", HostName: "h1", Path: "/old.img"}},
			[]NICRecord{{ID: "old-nic", NetworkName: "old-net", MAC: "52:54:00:00:00:01"}},
			[]PCIIntentRecord{{DeviceID: "old-pci", HostName: "h1", SelectorKind: "vendor", SelectorPayload: "1234"}},
		); err != nil || !applied {
			t.Fatalf("old commit: applied=%v err=%v", applied, err)
		}
		if err := UpsertPCIRealization(ctx, c, PCIRealizationRecord{
			VMName: "vm1", DeviceID: "old-pci", MemberID: "member-1", HostName: "h1",
		}); err != nil {
			t.Fatal(err)
		}
		if err := DeleteVM(ctx, c, "vm1"); err != nil {
			t.Fatal(err)
		}

		// Both axes are monotonic: advancing only one must not claim a tombstone.
		for _, tc := range []struct {
			id    string
			owner int64
			gen   int64
		}{
			{"same-owner", 1, 2},
			{"same-generation", 2, 1},
		} {
			op := createOp("op-"+tc.id, "vm", "vm1", tc.id, "", tc.owner)
			applied, err := c.BeginVMCreateOperation(ctx, op, VMRecord{
				Name: "vm1", HostName: "h2", Project: "p1",
				OwnerEpoch: tc.owner, SpecGeneration: tc.gen,
			})
			if err != nil || applied {
				t.Fatalf("%s begin: applied=%v err=%v, want refused", tc.id, applied, err)
			}
			if got, _ := GetOperation(ctx, c, op.ID); got != nil {
				t.Fatalf("%s left operation header: %+v", tc.id, got)
			}
		}

		newOp := createOp("op-new-vm", "vm", "vm1", "new", "", 2)
		newVM := VMRecord{
			Name: "vm1", HostName: "h2", Project: "p1", Spec: `{"new":true}`,
			OwnerEpoch: 2, SpecGeneration: 2,
		}
		if applied, err := c.BeginVMCreateOperation(ctx, newOp, newVM); err != nil || !applied {
			t.Fatalf("new begin: applied=%v err=%v", applied, err)
		}
		got, err := GetVM(ctx, c, "vm1")
		if err != nil || got == nil || got.State != "creating" ||
			got.ActiveOperationID != newOp.ID || got.OwnerEpoch != 2 ||
			got.SpecGeneration != 2 || got.HostName != "h2" {
			t.Fatalf("new provisional VM=%+v err=%v", got, err)
		}
		for _, table := range []string{
			"vm_interfaces", "vm_disks", "vm_nics", "vm_pci_intent", "vm_pci_realizations",
		} {
			rows, qerr := c.Query(ctx,
				`SELECT COUNT(*) AS n FROM `+table+` WHERE vm_name = ? AND deleted_at IS NULL`,
				"vm1")
			if qerr != nil || len(rows) != 1 || rows[0].Int("n") != 0 {
				t.Fatalf("%s live stale children=%v err=%v", table, rows, qerr)
			}
		}
	})

	t.Run("vm rollback", func(t *testing.T) {
		c := testClient(t)
		oldOp := createOp("op-old-vm-rb", "vm", "vm1", "old", "", 3)
		oldVM := VMRecord{Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 3, SpecGeneration: 4}
		if applied, err := c.BeginVMCreateOperation(ctx, oldOp, oldVM); err != nil || !applied {
			t.Fatalf("old begin: applied=%v err=%v", applied, err)
		}
		if applied, err := c.RollbackVMCreateOperation(ctx, "vm1", oldOp.ID, 3, "cleanup"); err != nil || !applied {
			t.Fatalf("rollback: applied=%v err=%v", applied, err)
		}
		newOp := createOp("op-new-vm-rb", "vm", "vm1", "new", "", 4)
		if applied, err := c.BeginVMCreateOperation(ctx, newOp,
			VMRecord{Name: "vm1", HostName: "h2", Project: "p1", OwnerEpoch: 4, SpecGeneration: 5},
		); err != nil || !applied {
			t.Fatalf("recreate after rollback: applied=%v err=%v", applied, err)
		}
		if got, _ := GetVM(ctx, c, "vm1"); got == nil || got.ActiveOperationID != newOp.ID ||
			got.OwnerEpoch != 4 || got.SpecGeneration != 5 {
			t.Fatalf("new provisional VM=%+v", got)
		}
	})

	t.Run("container ordinary delete cleans stale interfaces", func(t *testing.T) {
		c := testClient(t)
		oldOp := createOp("op-old-ct", "container", "ct1", "old", "", 1)
		oldCT := ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "old", Project: "p1",
			OwnerEpoch: 1, SpecGeneration: 1,
		}
		if applied, err := c.BeginContainerCreateOperation(ctx, oldOp, oldCT); err != nil || !applied {
			t.Fatalf("old begin: applied=%v err=%v", applied, err)
		}
		if applied, err := c.CommitContainerCreateOperation(ctx, oldOp.ID, 1, oldCT,
			[]ContainerInterfaceRecord{{NetworkName: "old-net", MAC: "52:00:00:00:00:01"}},
		); err != nil || !applied {
			t.Fatalf("old commit: applied=%v err=%v", applied, err)
		}
		// DeleteContainer intentionally does not cascade interfaces. Begin must
		// supersede them before exposing the reused identity.
		if err := DeleteContainer(ctx, c, "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			id    string
			owner int64
			gen   int64
		}{
			{"same-owner", 1, 2},
			{"same-generation", 2, 1},
		} {
			op := createOp("op-ct-"+tc.id, "container", "ct1", tc.id, "", tc.owner)
			applied, err := c.BeginContainerCreateOperation(ctx, op, ContainerRecord{
				HostName: "h1", Name: "ct1", Image: "stale", Project: "p1",
				OwnerEpoch: tc.owner, SpecGeneration: tc.gen,
			})
			if err != nil || applied {
				t.Fatalf("%s begin: applied=%v err=%v, want refused", tc.id, applied, err)
			}
			if got, _ := GetOperation(ctx, c, op.ID); got != nil {
				t.Fatalf("%s left operation header: %+v", tc.id, got)
			}
		}
		newOp := createOp("op-new-ct", "container", "ct1", "new", "", 2)
		newCT := ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "new", Project: "p1",
			OwnerEpoch: 2, SpecGeneration: 2,
		}
		if applied, err := c.BeginContainerCreateOperation(ctx, newOp, newCT); err != nil || !applied {
			t.Fatalf("new begin: applied=%v err=%v", applied, err)
		}
		got, err := GetContainer(ctx, c, "h1", "ct1")
		if err != nil || got == nil || got.State != "creating" ||
			got.ActiveOperationID != newOp.ID || got.OwnerEpoch != 2 ||
			got.SpecGeneration != 2 || got.Image != "new" {
			t.Fatalf("new provisional container=%+v err=%v", got, err)
		}
		if ifaces, err := GetContainerInterfaces(ctx, c, "h1", "ct1"); err != nil || len(ifaces) != 0 {
			t.Fatalf("stale interfaces=%+v err=%v", ifaces, err)
		}
	})

	t.Run("container rollback", func(t *testing.T) {
		c := testClient(t)
		oldOp := createOp("op-old-ct-rb", "container", "ct1", "old", "", 3)
		oldCT := ContainerRecord{HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 3, SpecGeneration: 4}
		if applied, err := c.BeginContainerCreateOperation(ctx, oldOp, oldCT); err != nil || !applied {
			t.Fatalf("old begin: applied=%v err=%v", applied, err)
		}
		if applied, err := c.RollbackContainerCreateOperation(ctx, "h1", "ct1", oldOp.ID, 3, "cleanup"); err != nil || !applied {
			t.Fatalf("rollback: applied=%v err=%v", applied, err)
		}
		newOp := createOp("op-new-ct-rb", "container", "ct1", "new", "", 4)
		if applied, err := c.BeginContainerCreateOperation(ctx, newOp,
			ContainerRecord{HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 4, SpecGeneration: 5},
		); err != nil || !applied {
			t.Fatalf("recreate after rollback: applied=%v err=%v", applied, err)
		}
		if got, _ := GetContainer(ctx, c, "h1", "ct1"); got == nil ||
			got.ActiveOperationID != newOp.ID || got.OwnerEpoch != 4 || got.SpecGeneration != 5 {
			t.Fatalf("new provisional container=%+v", got)
		}
	})
}

func TestRecreatedIdentityRejectsDelayedOldTombstoneWALAndAntiEntropy(t *testing.T) {
	ctx := context.Background()

	t.Run("vm", func(t *testing.T) {
		source := testClient(t)
		if err := InsertVM(ctx, source, VMRecord{Name: "vm1", HostName: "old", Project: "p1", State: "running"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := source.db.Exec(`UPDATE vms SET vm_owner_epoch = 1, spec_generation = 1 WHERE name = ?`, "vm1"); err != nil {
			t.Fatal(err)
		}
		if err := DeleteVM(ctx, source, "vm1"); err != nil {
			t.Fatal(err)
		}
		oldDelete := latestMutationEntry(t, source, "old-vm-delete", 1)

		receiver := testClient(t)
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		newOp := createOp("op-new-vm-replay", "vm", "vm1", "new", "", 2)
		if applied, err := receiver.BeginVMCreateOperation(ctx, newOp,
			VMRecord{Name: "vm1", HostName: "new", Project: "p1", OwnerEpoch: 2, SpecGeneration: 2},
		); err != nil || !applied {
			t.Fatalf("new begin: applied=%v err=%v", applied, err)
		}
		applyMutationEntry(t, receiver, oldDelete)
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if got, _ := GetVM(ctx, receiver, "vm1"); got == nil ||
			got.ActiveOperationID != newOp.ID || got.OwnerEpoch != 2 || got.SpecGeneration != 2 {
			t.Fatalf("old tombstone defeated recreated VM: %+v", got)
		}
	})

	t.Run("container", func(t *testing.T) {
		source := testClient(t)
		if err := UpsertContainer(ctx, source, ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "old", Project: "p1", State: "running",
			OwnerEpoch: 1, SpecGeneration: 1,
		}); err != nil {
			t.Fatal(err)
		}
		if err := DeleteContainer(ctx, source, "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		oldDelete := latestMutationEntry(t, source, "old-ct-delete", 1)

		receiver := testClient(t)
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		newOp := createOp("op-new-ct-replay", "container", "ct1", "new", "", 2)
		if applied, err := receiver.BeginContainerCreateOperation(ctx, newOp,
			ContainerRecord{HostName: "h1", Name: "ct1", Image: "new", Project: "p1", OwnerEpoch: 2, SpecGeneration: 2},
		); err != nil || !applied {
			t.Fatalf("new begin: applied=%v err=%v", applied, err)
		}
		applyMutationEntry(t, receiver, oldDelete)
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if got, _ := GetContainer(ctx, receiver, "h1", "ct1"); got == nil ||
			got.ActiveOperationID != newOp.ID || got.OwnerEpoch != 2 || got.SpecGeneration != 2 ||
			got.State != "creating" {
			t.Fatalf("old tombstone defeated recreated container: %+v", got)
		}
	})
}

func TestReplicatedBeginResurrectsTombstoneAndReplaysSafely(t *testing.T) {
	ctx := context.Background()

	t.Run("vm", func(t *testing.T) {
		source := testClient(t)
		oldOp := createOp("op-old-vm-repl", "vm", "vm1", "old", "", 1)
		oldVM := VMRecord{Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1, SpecGeneration: 1}
		if applied, err := source.BeginVMCreateOperation(ctx, oldOp, oldVM); err != nil || !applied {
			t.Fatalf("source old begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.RollbackVMCreateOperation(ctx, "vm1", oldOp.ID, 1, "cleanup"); err != nil || !applied {
			t.Fatalf("source rollback: applied=%v err=%v", applied, err)
		}
		newOp := createOp("op-new-vm-repl", "vm", "vm1", "new", "", 2)
		newVM := VMRecord{Name: "vm1", HostName: "h2", Project: "p1", OwnerEpoch: 2, SpecGeneration: 2}
		if applied, err := source.BeginVMCreateOperation(ctx, newOp, newVM); err != nil || !applied {
			t.Fatalf("source new begin: applied=%v err=%v", applied, err)
		}
		entry := latestMutationEntry(t, source, "source-new-vm", 1)

		receiver := testClient(t)
		if applied, err := receiver.BeginVMCreateOperation(ctx, oldOp, oldVM); err != nil || !applied {
			t.Fatalf("receiver old begin: applied=%v err=%v", applied, err)
		}
		if applied, err := receiver.RollbackVMCreateOperation(ctx, "vm1", oldOp.ID, 1, "cleanup"); err != nil || !applied {
			t.Fatalf("receiver rollback: applied=%v err=%v", applied, err)
		}
		if _, err := receiver.db.Exec(
			`INSERT INTO vm_interfaces
			 (vm_name, network_name, ordinal, mac, updated_at, deleted_at)
			 VALUES (?, ?, 0, ?, ?, NULL)`,
			"vm1", "stale-net", "52:54:00:00:00:01", "9000000000000-0000-stale"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, entry)
		replay := &pb.MutationEntry{
			Seq: entry.Seq, Hlc: entry.Hlc, Origin: "source-new-vm-replay", Stmts: entry.Stmts,
		}
		applyMutationEntry(t, receiver, replay)
		if got, _ := GetVM(ctx, receiver, "vm1"); got == nil ||
			got.ActiveOperationID != newOp.ID || got.OwnerEpoch != 2 || got.SpecGeneration != 2 {
			t.Fatalf("replicated/replayed begin VM=%+v", got)
		}
		if got, _ := GetOperation(ctx, receiver, newOp.ID); got == nil {
			t.Fatal("replicated begin did not install operation header")
		}
		if rows, _ := receiver.Query(ctx,
			`SELECT 1 FROM vm_interfaces WHERE vm_name = ? AND deleted_at IS NULL`, "vm1"); len(rows) != 0 {
			t.Fatalf("replicated begin inherited stale VM interfaces: %v", rows)
		}

		liveReceiver := testClient(t)
		if err := InsertVM(ctx, liveReceiver, VMRecord{
			Name: "vm1", HostName: "live", Project: "p1", State: "running",
			OwnerEpoch: 9, SpecGeneration: 9,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, liveReceiver, entry)
		if got, _ := GetVM(ctx, liveReceiver, "vm1"); got == nil || got.HostName != "live" || got.State != "running" {
			t.Fatalf("replicated begin overwrote live VM: %+v", got)
		}
		if got, _ := GetOperation(ctx, liveReceiver, newOp.ID); got != nil {
			t.Fatalf("refused replicated begin installed operation: %+v", got)
		}
	})

	t.Run("container", func(t *testing.T) {
		source := testClient(t)
		oldOp := createOp("op-old-ct-repl", "container", "ct1", "old", "", 1)
		oldCT := ContainerRecord{HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 1, SpecGeneration: 1}
		if applied, err := source.BeginContainerCreateOperation(ctx, oldOp, oldCT); err != nil || !applied {
			t.Fatalf("source old begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.RollbackContainerCreateOperation(ctx, "h1", "ct1", oldOp.ID, 1, "cleanup"); err != nil || !applied {
			t.Fatalf("source rollback: applied=%v err=%v", applied, err)
		}
		newOp := createOp("op-new-ct-repl", "container", "ct1", "new", "", 2)
		newCT := ContainerRecord{HostName: "h1", Name: "ct1", Image: "new", Project: "p1", OwnerEpoch: 2, SpecGeneration: 2}
		if applied, err := source.BeginContainerCreateOperation(ctx, newOp, newCT); err != nil || !applied {
			t.Fatalf("source new begin: applied=%v err=%v", applied, err)
		}
		entry := latestMutationEntry(t, source, "source-new-ct", 1)

		receiver := testClient(t)
		if applied, err := receiver.BeginContainerCreateOperation(ctx, oldOp, oldCT); err != nil || !applied {
			t.Fatalf("receiver old begin: applied=%v err=%v", applied, err)
		}
		if applied, err := receiver.RollbackContainerCreateOperation(ctx, "h1", "ct1", oldOp.ID, 1, "cleanup"); err != nil || !applied {
			t.Fatalf("receiver rollback: applied=%v err=%v", applied, err)
		}
		if _, err := receiver.db.Exec(
			`INSERT INTO container_interfaces
			 (host_name, ct_name, network_name, ordinal, mac, updated_at, deleted_at)
			 VALUES (?, ?, ?, 0, ?, ?, NULL)`,
			"h1", "ct1", "stale-net", "52:00:00:00:00:01", "9000000000000-0000-stale"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, entry)
		replay := &pb.MutationEntry{
			Seq: entry.Seq, Hlc: entry.Hlc, Origin: "source-new-ct-replay", Stmts: entry.Stmts,
		}
		applyMutationEntry(t, receiver, replay)
		if got, _ := GetContainer(ctx, receiver, "h1", "ct1"); got == nil ||
			got.ActiveOperationID != newOp.ID || got.OwnerEpoch != 2 || got.SpecGeneration != 2 ||
			got.Image != "new" {
			t.Fatalf("replicated/replayed begin container=%+v", got)
		}
		if got, _ := GetOperation(ctx, receiver, newOp.ID); got == nil {
			t.Fatal("replicated begin did not install operation header")
		}
		if ifaces, err := GetContainerInterfaces(ctx, receiver, "h1", "ct1"); err != nil || len(ifaces) != 0 {
			t.Fatalf("replicated begin inherited stale container interfaces=%+v err=%v", ifaces, err)
		}

		liveReceiver := testClient(t)
		if err := UpsertContainer(ctx, liveReceiver, ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "live", Project: "p1", State: "running",
			OwnerEpoch: 9, SpecGeneration: 9,
		}); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, liveReceiver, entry)
		if got, _ := GetContainer(ctx, liveReceiver, "h1", "ct1"); got == nil ||
			got.Image != "live" || got.State != "running" {
			t.Fatalf("replicated begin overwrote live container: %+v", got)
		}
		if got, _ := GetOperation(ctx, liveReceiver, newOp.ID); got != nil {
			t.Fatalf("refused replicated begin installed operation: %+v", got)
		}
	})
}

func TestCommitVMCreateOperationAtomicHardwareAndTerminalRelease(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	reservation, err := (ReservationVector{
		Project: "p1", ProjectCPU: 2, ProjectMemMiB: 1024,
		TargetHost: "h1", TargetCPU: 2, TargetMemMiB: 1024,
	}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	op := createOp("op-commit", "vm", "vm1", "hash", reservation, 4)
	vm := VMRecord{
		Name: "vm1", HostName: "h1", Spec: `{"cpu":2}`, State: "creating",
		Project: "p1", OwnerEpoch: 4, SpecGeneration: 3, CPUActual: 2, MemActual: 1024,
	}
	if applied, err := c.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
		t.Fatalf("begin: applied=%v err=%v", applied, err)
	}
	if cpu, mem, err := HostReserved(ctx, c, "h1"); err != nil || cpu != 2 || mem != 1024 {
		t.Fatalf("reservation before commit = %d/%d err=%v", cpu, mem, err)
	}
	exclusive := "0000:01:00.0"
	applied, err := c.CommitVMCreateOperation(ctx, op.ID, 4, vm,
		[]InterfaceRecord{{NetworkName: "net1", Ordinal: 0, MAC: "52:54:00:00:00:01"}},
		[]DiskRecord{{DiskName: "root", HostName: "h1", Path: "/vm1.img", DeviceKind: "disk", DeleteWithVM: true}},
		[]NICRecord{{ID: "nic1", NetworkName: "net1", MAC: "52:54:00:00:00:01"}},
		[]PCIIntentRecord{{DeviceID: "pci1", HostName: "h1", SelectorKind: "address", SelectorPayload: exclusive, ExclusiveKey: &exclusive}},
	)
	if err != nil || !applied {
		t.Fatalf("commit: applied=%v err=%v", applied, err)
	}
	got, _ := GetVM(ctx, c, "vm1")
	if got == nil || got.State != "running" || got.ActiveOperationID != "" || got.OwnerEpoch != 4 || got.SpecGeneration != 3 {
		t.Fatalf("committed VM = %+v", got)
	}
	for _, table := range []string{"vm_interfaces", "vm_disks", "vm_nics", "vm_pci_intent"} {
		rows, qerr := c.Query(ctx, `SELECT COUNT(*) AS n FROM `+table+` WHERE vm_name = ? AND deleted_at IS NULL`, "vm1")
		if qerr != nil || len(rows) != 1 || rows[0].Int("n") != 1 {
			t.Fatalf("%s rows = %v err=%v", table, rows, qerr)
		}
	}
	steps, _ := ListOperationSteps(ctx, c, op.ID, 4)
	state, faulted := ReduceOperationState(OpWorkloadCreate, stepNames(steps))
	if state != OpStepCompleted || faulted {
		t.Fatalf("terminal state = %q faulted=%v steps=%v", state, faulted, stepNames(steps))
	}
	if cpu, mem, err := HostReserved(ctx, c, "h1"); err != nil || cpu != 0 || mem != 0 {
		t.Fatalf("reservation after commit = %d/%d err=%v", cpu, mem, err)
	}
}

func TestRecreatedVMCommitRevivesTombstonedHardwareKeysLocallyAndOnReceiver(t *testing.T) {
	ctx := context.Background()
	source := testClient(t)
	oldOp := createOp("op-hw-old", "vm", "vm1", "old", "", 1)
	oldVM := VMRecord{
		Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1, SpecGeneration: 1,
	}
	if applied, err := source.BeginVMCreateOperation(ctx, oldOp, oldVM); err != nil || !applied {
		t.Fatalf("old begin: applied=%v err=%v", applied, err)
	}
	if applied, err := source.CommitVMCreateOperation(ctx, oldOp.ID, 1, oldVM,
		[]InterfaceRecord{{NetworkName: "net1", Ordinal: 0, MAC: "52:54:00:00:00:01"}},
		[]DiskRecord{{DiskName: "root", HostName: "h1", Path: "/old.img"}},
		[]NICRecord{{ID: "nic1", NetworkName: "net1"}},
		[]PCIIntentRecord{{DeviceID: "pci1", HostName: "h1", SelectorKind: "vendor", SelectorPayload: "old"}},
	); err != nil || !applied {
		t.Fatalf("old commit: applied=%v err=%v", applied, err)
	}
	if err := DeleteVM(ctx, source, "vm1"); err != nil {
		t.Fatal(err)
	}
	newOp := createOp("op-hw-new", "vm", "vm1", "new", "", 2)
	newVM := VMRecord{
		Name: "vm1", HostName: "h2", Project: "p1", OwnerEpoch: 2, SpecGeneration: 2,
	}
	if applied, err := source.BeginVMCreateOperation(ctx, newOp, newVM); err != nil || !applied {
		t.Fatalf("new begin: applied=%v err=%v", applied, err)
	}
	if applied, err := source.CommitVMCreateOperation(ctx, newOp.ID, 2, newVM,
		[]InterfaceRecord{{NetworkName: "net1", Ordinal: 0, MAC: "52:54:00:00:00:02"}},
		[]DiskRecord{{DiskName: "root", HostName: "h2", Path: "/new.img"}},
		[]NICRecord{{ID: "nic1", NetworkName: "net1", MAC: "52:54:00:00:00:02"}},
		[]PCIIntentRecord{{DeviceID: "pci1", HostName: "h2", SelectorKind: "vendor", SelectorPayload: "new"}},
	); err != nil || !applied {
		t.Fatalf("recreated commit: applied=%v err=%v", applied, err)
	}
	assertLiveHardware := func(t *testing.T, c *Client) {
		t.Helper()
		for table, wantColumn := range map[string]string{
			"vm_interfaces": "52:54:00:00:00:02",
			"vm_disks":      "/new.img",
			"vm_nics":       "52:54:00:00:00:02",
			"vm_pci_intent": "new",
		} {
			column := map[string]string{
				"vm_interfaces": "mac",
				"vm_disks":      "path",
				"vm_nics":       "mac",
				"vm_pci_intent": "selector_payload",
			}[table]
			rows, err := c.Query(ctx, `SELECT `+column+` AS value, deleted_at FROM `+table+` WHERE vm_name = ?`, "vm1")
			if err != nil || len(rows) != 1 || rows[0].String("value") != wantColumn ||
				rows[0].String("deleted_at") != "" {
				t.Fatalf("%s not revived: rows=%v err=%v", table, rows, err)
			}
		}
	}
	assertLiveHardware(t, source)

	receiver := testClient(t)
	entries, err := source.Query(ctx, `SELECT seq, hlc, stmts FROM mutation_log ORDER BY seq`)
	if err != nil || len(entries) != 5 {
		t.Fatalf("source mutation entries=%d err=%v", len(entries), err)
	}
	for _, entry := range entries {
		applyMutationEntry(t, receiver, &pb.MutationEntry{
			Seq:    entry.Int64("seq"),
			Hlc:    entry.String("hlc"),
			Origin: "source-hw-recreate",
			Stmts:  entry.String("stmts"),
		})
	}
	assertLiveHardware(t, receiver)
}

func TestRecreatedWorkloadRejectsHigherClockOldDeleteWALAndAntiEntropy(t *testing.T) {
	ctx := context.Background()
	const future = "9000000000000-0000-old-delete"

	t.Run("vm", func(t *testing.T) {
		source := testClient(t)
		oldOp := createOp("op-delete-old-vm", "vm", "vm1", "old", "", 1)
		oldVM := VMRecord{Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1, SpecGeneration: 1}
		if applied, err := source.BeginVMCreateOperation(ctx, oldOp, oldVM); err != nil || !applied {
			t.Fatalf("old begin: applied=%v err=%v", applied, err)
		}
		beginEntry := latestMutationEntry(t, source, "old-vm-source", 1)
		if applied, err := source.CommitVMCreateOperation(ctx, oldOp.ID, 1, oldVM,
			[]InterfaceRecord{{NetworkName: "old-net", MAC: "old-mac"}}, nil, nil, nil,
		); err != nil || !applied {
			t.Fatalf("old commit: applied=%v err=%v", applied, err)
		}
		commitEntry := latestMutationEntry(t, source, "old-vm-source", 2)
		if err := UpsertPCIRealization(ctx, source, PCIRealizationRecord{
			VMName: "vm1", DeviceID: "pci1", MemberID: "member1", HostName: "h1",
		}); err != nil {
			t.Fatal(err)
		}
		if err := DeleteVM(ctx, source, "vm1"); err != nil {
			t.Fatal(err)
		}
		deleteEntry := latestMutationEntry(t, source, "delayed-old-vm-delete", 1)
		var deleteStatements []Statement
		if err := json.Unmarshal([]byte(deleteEntry.Stmts), &deleteStatements); err != nil {
			t.Fatal(err)
		}
		for i := range deleteStatements {
			if len(deleteStatements[i].Params) > 1 {
				deleteStatements[i].Params[1] = future
			}
		}
		rawDelete, _ := json.Marshal(deleteStatements)
		deleteEntry.Stmts, deleteEntry.Hlc = string(rawDelete), future
		if _, err := source.db.Exec(`UPDATE vms SET updated_at = ? WHERE name = ?`, future, "vm1"); err != nil {
			t.Fatal(err)
		}
		if _, err := source.db.Exec(
			`UPDATE vm_pci_realizations SET updated_at = ? WHERE vm_name = ?`,
			future, "vm1",
		); err != nil {
			t.Fatal(err)
		}
		current := testClient(t)
		applyMutationEntry(t, current, beginEntry)
		applyMutationEntry(t, current, commitEntry)
		applyMutationEntry(t, current, deleteEntry)
		if got, _ := GetVM(ctx, current, "vm1"); got != nil {
			t.Fatalf("current-authority WAL delete did not apply: %+v", got)
		}

		recreatedReceiver := func(t *testing.T) *Client {
			t.Helper()
			receiver := testClient(t)
			applyMutationEntry(t, receiver, beginEntry)
			applyMutationEntry(t, receiver, commitEntry)
			if err := DeleteVM(ctx, receiver, "vm1"); err != nil {
				t.Fatal(err)
			}
			newOp := createOp("op-delete-new-vm", "vm", "vm1", "new", "", 2)
			newVM := VMRecord{Name: "vm1", HostName: "h2", Project: "p1", OwnerEpoch: 2, SpecGeneration: 2}
			if applied, err := receiver.BeginVMCreateOperation(ctx, newOp, newVM); err != nil || !applied {
				t.Fatalf("new begin: applied=%v err=%v", applied, err)
			}
			if applied, err := receiver.CommitVMCreateOperation(ctx, newOp.ID, 2, newVM,
				[]InterfaceRecord{{NetworkName: "new-net", MAC: "new-mac"}}, nil, nil, nil,
			); err != nil || !applied {
				t.Fatalf("new commit: applied=%v err=%v", applied, err)
			}
			if err := UpsertPCIRealization(ctx, receiver, PCIRealizationRecord{
				VMName: "vm1", DeviceID: "pci1", MemberID: "member1", HostName: "h2",
			}); err != nil {
				t.Fatal(err)
			}
			return receiver
		}
		wal := recreatedReceiver(t)
		applyMutationEntry(t, wal, deleteEntry)
		if got, _ := GetVM(ctx, wal, "vm1"); got == nil || got.OwnerEpoch != 2 {
			t.Fatalf("delayed old WAL delete killed recreated VM: %+v", got)
		}
		if rows, _ := wal.Query(ctx, `SELECT 1 FROM vm_interfaces WHERE vm_name = ? AND network_name = ? AND deleted_at IS NULL`, "vm1", "new-net"); len(rows) != 1 {
			t.Fatalf("delayed old WAL delete killed recreated interface: %v", rows)
		}
		if rows, _ := wal.Query(ctx, `SELECT 1 FROM vm_pci_realizations WHERE vm_name = ? AND host_name = ? AND deleted_at IS NULL`, "vm1", "h2"); len(rows) != 1 {
			t.Fatalf("delayed old WAL delete killed recreated PCI realization: %v", rows)
		}

		ae := recreatedReceiver(t)
		if err := ae.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if got, _ := GetVM(ctx, ae, "vm1"); got == nil || got.OwnerEpoch != 2 {
			t.Fatalf("old AE tombstone killed recreated VM: %+v", got)
		}
		if rows, _ := ae.Query(ctx, `SELECT 1 FROM vm_pci_realizations WHERE vm_name = ? AND host_name = ? AND deleted_at IS NULL`, "vm1", "h2"); len(rows) != 1 {
			t.Fatalf("old AE tombstone killed recreated PCI realization: %v", rows)
		}

		currentAE := testClient(t)
		applyMutationEntry(t, currentAE, beginEntry)
		applyMutationEntry(t, currentAE, commitEntry)
		if err := InsertInterface(ctx, currentAE, InterfaceRecord{
			VMName: "vm1", NetworkName: "receiver-only", MAC: "receiver-only",
		}); err != nil {
			t.Fatal(err)
		}
		if err := UpsertPCIRealization(ctx, currentAE, PCIRealizationRecord{
			VMName: "vm1", DeviceID: "pci1", MemberID: "member1", HostName: "h1",
		}); err != nil {
			t.Fatal(err)
		}
		if err := UpsertPCIRealization(ctx, currentAE, PCIRealizationRecord{
			VMName: "vm1", DeviceID: "pci2", MemberID: "receiver-only", HostName: "h1",
		}); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"vm_interfaces", "vm_pci_realizations"} {
			if _, err := currentAE.db.Exec(
				`UPDATE `+table+` SET updated_at = ? WHERE vm_name = ?`,
				"9500000000000-0000-newer-child", "vm1",
			); err != nil {
				t.Fatal(err)
			}
		}
		if err := currentAE.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if got, _ := GetVM(ctx, currentAE, "vm1"); got != nil {
			t.Fatalf("current-authority AE delete did not apply: %+v", got)
		}
		for _, table := range []string{"vm_interfaces", "vm_pci_realizations"} {
			if rows, _ := currentAE.Query(ctx,
				`SELECT 1 FROM `+table+` WHERE vm_name = ? AND deleted_at IS NULL`, "vm1",
			); len(rows) != 0 {
				t.Fatalf("current-authority AE delete left live %s: %v", table, rows)
			}
		}
	})

	t.Run("container", func(t *testing.T) {
		source := testClient(t)
		oldOp := createOp("op-delete-old-ct", "container", "ct1", "old", "", 1)
		oldCT := ContainerRecord{HostName: "h1", Name: "ct1", Image: "old", Project: "p1", OwnerEpoch: 1, SpecGeneration: 1}
		if applied, err := source.BeginContainerCreateOperation(ctx, oldOp, oldCT); err != nil || !applied {
			t.Fatalf("old begin: applied=%v err=%v", applied, err)
		}
		beginEntry := latestMutationEntry(t, source, "old-ct-source", 1)
		if applied, err := source.CommitContainerCreateOperation(ctx, oldOp.ID, 1, oldCT,
			[]ContainerInterfaceRecord{{NetworkName: "old-net", MAC: "old-mac"}},
		); err != nil || !applied {
			t.Fatalf("old commit: applied=%v err=%v", applied, err)
		}
		commitEntry := latestMutationEntry(t, source, "old-ct-source", 2)
		if err := DeleteContainer(ctx, source, "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		deleteEntry := latestMutationEntry(t, source, "delayed-old-ct-delete", 1)
		var deleteStatements []Statement
		if err := json.Unmarshal([]byte(deleteEntry.Stmts), &deleteStatements); err != nil {
			t.Fatal(err)
		}
		for i := range deleteStatements {
			if len(deleteStatements[i].Params) > 1 {
				deleteStatements[i].Params[1] = future
			}
		}
		rawDelete, _ := json.Marshal(deleteStatements)
		deleteEntry.Stmts, deleteEntry.Hlc = string(rawDelete), future
		if _, err := source.db.Exec(`UPDATE containers SET updated_at = ? WHERE host_name = ? AND name = ?`, future, "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		current := testClient(t)
		applyMutationEntry(t, current, beginEntry)
		applyMutationEntry(t, current, commitEntry)
		applyMutationEntry(t, current, deleteEntry)
		if got, _ := GetContainer(ctx, current, "h1", "ct1"); got != nil {
			t.Fatalf("current-authority WAL delete did not apply: %+v", got)
		}

		recreatedReceiver := func(t *testing.T) *Client {
			t.Helper()
			receiver := testClient(t)
			applyMutationEntry(t, receiver, beginEntry)
			applyMutationEntry(t, receiver, commitEntry)
			if err := DeleteContainer(ctx, receiver, "h1", "ct1"); err != nil {
				t.Fatal(err)
			}
			newOp := createOp("op-delete-new-ct", "container", "ct1", "new", "", 2)
			newCT := ContainerRecord{HostName: "h1", Name: "ct1", Image: "new", Project: "p1", OwnerEpoch: 2, SpecGeneration: 2}
			if applied, err := receiver.BeginContainerCreateOperation(ctx, newOp, newCT); err != nil || !applied {
				t.Fatalf("new begin: applied=%v err=%v", applied, err)
			}
			if applied, err := receiver.CommitContainerCreateOperation(ctx, newOp.ID, 2, newCT,
				[]ContainerInterfaceRecord{{NetworkName: "new-net", MAC: "new-mac"}},
			); err != nil || !applied {
				t.Fatalf("new commit: applied=%v err=%v", applied, err)
			}
			return receiver
		}
		wal := recreatedReceiver(t)
		applyMutationEntry(t, wal, deleteEntry)
		if got, _ := GetContainer(ctx, wal, "h1", "ct1"); got == nil || got.OwnerEpoch != 2 {
			t.Fatalf("delayed old WAL delete killed recreated container: %+v", got)
		}
		if rows, _ := wal.Query(ctx, `SELECT 1 FROM container_interfaces WHERE host_name = ? AND ct_name = ? AND network_name = ? AND deleted_at IS NULL`, "h1", "ct1", "new-net"); len(rows) != 1 {
			t.Fatalf("delayed old WAL delete killed recreated interface: %v", rows)
		}

		ae := recreatedReceiver(t)
		if err := ae.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if got, _ := GetContainer(ctx, ae, "h1", "ct1"); got == nil || got.OwnerEpoch != 2 {
			t.Fatalf("old AE tombstone killed recreated container: %+v", got)
		}

		currentAE := testClient(t)
		applyMutationEntry(t, currentAE, beginEntry)
		applyMutationEntry(t, currentAE, commitEntry)
		if err := UpsertContainerInterface(ctx, currentAE, ContainerInterfaceRecord{
			HostName: "h1", CtName: "ct1", NetworkName: "receiver-only",
			Ordinal: 99, MAC: "receiver-only",
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := currentAE.db.Exec(
			`UPDATE container_interfaces SET updated_at = ?
			 WHERE host_name = ? AND ct_name = ?`,
			"9500000000000-0000-newer-child", "h1", "ct1",
		); err != nil {
			t.Fatal(err)
		}
		if err := currentAE.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if got, _ := GetContainer(ctx, currentAE, "h1", "ct1"); got != nil {
			t.Fatalf("current-authority AE delete did not apply: %+v", got)
		}
		if rows, _ := currentAE.Query(ctx,
			`SELECT 1 FROM container_interfaces
			 WHERE host_name = ? AND ct_name = ? AND deleted_at IS NULL`,
			"h1", "ct1",
		); len(rows) != 0 {
			t.Fatalf("current-authority AE delete left live interfaces: %v", rows)
		}
	})
}

func TestLegacyWorkloadDeleteCannotCrossAuthorityBoundary(t *testing.T) {
	ctx := context.Background()
	const future = "9000000000000-0000-legacy-delete"
	entry := func(t *testing.T, origin, sqlText string, params ...interface{}) *pb.MutationEntry {
		t.Helper()
		raw, err := json.Marshal([]Statement{{SQL: sqlText, Params: params}})
		if err != nil {
			t.Fatal(err)
		}
		return &pb.MutationEntry{Seq: 1, Hlc: future, Origin: origin, Stmts: string(raw)}
	}

	t.Run("vm", func(t *testing.T) {
		legacyVMDeleteBatch := func(t *testing.T, origin string) *pb.MutationEntry {
			t.Helper()
			stmts := []Statement{
				{SQL: legacyVMDeleteSQL, Params: []interface{}{future, future, "vm1"}},
				{SQL: vmInterfacesCreateCleanupSQL, Params: []interface{}{future, future, "vm1"}},
				{SQL: vmDisksCreateCleanupSQL, Params: []interface{}{future, future, "vm1"}},
				{SQL: vmNICsCreateCleanupSQL, Params: []interface{}{future, future, "vm1"}},
				{SQL: vmPCIIntentCreateCleanupSQL, Params: []interface{}{future, future, "vm1"}},
				{SQL: vmPCIRealCreateCleanupSQL, Params: []interface{}{future, future, "vm1"}},
			}
			raw, err := json.Marshal(stmts)
			if err != nil {
				t.Fatal(err)
			}
			return &pb.MutationEntry{Seq: 1, Hlc: future, Origin: origin, Stmts: string(raw)}
		}
		recreated := testClient(t)
		if err := InsertVM(ctx, recreated, VMRecord{
			Name: "vm1", HostName: "h2", Project: "p1", State: "running",
			OwnerEpoch: 2, SpecGeneration: 2,
		}, []InterfaceRecord{{
			VMName: "vm1", NetworkName: "new-net", MAC: "new-mac",
		}}, nil); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, recreated, legacyVMDeleteBatch(t, "legacy-vm-new"))
		if got, _ := GetVM(ctx, recreated, "vm1"); got == nil ||
			got.OwnerEpoch != 2 || got.SpecGeneration != 2 {
			t.Fatalf("legacy delete crossed recreated VM authority: %+v", got)
		}
		if rows, _ := recreated.Query(ctx,
			`SELECT 1 FROM vm_interfaces
			 WHERE vm_name = ? AND network_name = ? AND deleted_at IS NULL`,
			"vm1", "new-net",
		); len(rows) != 1 {
			t.Fatalf("legacy delete batch crossed recreated VM child authority: %v", rows)
		}

		legacy := testClient(t)
		if err := InsertVM(ctx, legacy, VMRecord{
			Name: "vm1", HostName: "h1", Project: "p1", State: "running",
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, legacy, legacyVMDeleteBatch(t, "legacy-vm-old"))
		if got, _ := GetVM(ctx, legacy, "vm1"); got != nil {
			t.Fatalf("legacy delete did not apply to pre-authority VM: %+v", got)
		}
	})

	t.Run("container", func(t *testing.T) {
		recreated := testClient(t)
		if err := UpsertContainer(ctx, recreated, ContainerRecord{
			HostName: "h2", Name: "ct1", Project: "p1", State: "running",
			OwnerEpoch: 2, SpecGeneration: 2,
		}); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, recreated, entry(t, "legacy-ct-new",
			legacyContainerDeleteSQL, future, future, "h2", "ct1"))
		if got, _ := GetContainer(ctx, recreated, "h2", "ct1"); got == nil ||
			got.OwnerEpoch != 2 || got.SpecGeneration != 2 {
			t.Fatalf("legacy delete crossed recreated container authority: %+v", got)
		}

		legacy := testClient(t)
		if err := UpsertContainer(ctx, legacy, ContainerRecord{
			HostName: "h1", Name: "ct1", Project: "p1", State: "running",
		}); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, legacy, entry(t, "legacy-ct-old",
			legacyContainerDeleteSQL, future, future, "h1", "ct1"))
		if got, _ := GetContainer(ctx, legacy, "h1", "ct1"); got != nil {
			t.Fatalf("legacy delete did not apply to pre-authority container: %+v", got)
		}
	})
}

func TestCommitVMCreateOperationHardwareFailureRollsBackEverything(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	op := createOp("op-hw-fail", "vm", "vm1", "hash", "", 1)
	vm := VMRecord{Name: "vm1", HostName: "h1", State: "creating", Project: "p1", OwnerEpoch: 1}
	if applied, err := c.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
		t.Fatalf("begin: applied=%v err=%v", applied, err)
	}
	dupe := []InterfaceRecord{
		{NetworkName: "net1", Ordinal: 0, MAC: "52:54:00:00:00:01"},
		{NetworkName: "net1", Ordinal: 1, MAC: "52:54:00:00:00:02"},
	}
	if applied, err := c.CommitVMCreateOperation(ctx, op.ID, 1, vm, dupe, nil, nil, nil); err == nil || applied {
		t.Fatalf("commit with duplicate hardware: applied=%v err=%v", applied, err)
	}
	got, _ := GetVM(ctx, c, "vm1")
	if got == nil || got.State != "creating" || got.ActiveOperationID != op.ID {
		t.Fatalf("provisional row changed after rollback: %+v", got)
	}
	if rows, _ := c.Query(ctx, `SELECT 1 FROM vm_interfaces WHERE vm_name = ?`, "vm1"); len(rows) != 0 {
		t.Fatalf("partial hardware survived: %v", rows)
	}
	steps, _ := ListOperationSteps(ctx, c, op.ID, 1)
	for _, name := range stepNames(steps) {
		if name == OpStepCompleted || name == OpStepPrepared || name == OpStepRuntimeStarted || name == OpStepObserved {
			t.Fatalf("commit step %q survived rolled-back transaction", name)
		}
	}
}

func TestCommitVMCreateOperationRejectsAdmissionIdentityDrift(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func(*VMRecord)
	}{
		{"host", func(vm *VMRecord) { vm.HostName = "h2" }},
		{"project", func(vm *VMRecord) { vm.Project = "p2" }},
		{"spec", func(vm *VMRecord) { vm.Spec = `{"cpu":8}` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t)
			reservation, _ := (ReservationVector{
				Project: "p1", ProjectCPU: 2, TargetHost: "h1", TargetCPU: 2,
			}).Encode()
			op := createOp("op-drift-"+tc.name, "vm", "vm1", "hash", reservation, 3)
			vm := VMRecord{
				Name: "vm1", HostName: "h1", Project: "p1", Spec: `{"cpu":2}`,
				State: "creating", OwnerEpoch: 3, SpecGeneration: 1,
			}
			if applied, err := c.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
				t.Fatalf("begin: applied=%v err=%v", applied, err)
			}
			drifted := vm
			tc.mutate(&drifted)
			applied, err := c.CommitVMCreateOperation(ctx, op.ID, 3, drifted,
				[]InterfaceRecord{{NetworkName: "net1", MAC: "52:54:00:00:00:01"}},
				nil, nil, nil)
			if err != nil || applied {
				t.Fatalf("drifted commit: applied=%v err=%v", applied, err)
			}
			got, _ := GetVM(ctx, c, "vm1")
			if got == nil || got.HostName != "h1" || got.Project != "p1" ||
				got.Spec != `{"cpu":2}` || got.ActiveOperationID != op.ID {
				t.Fatalf("provisional VM mutated: %+v", got)
			}
			if rows, _ := c.Query(ctx, `SELECT 1 FROM vm_interfaces WHERE vm_name = ?`, "vm1"); len(rows) != 0 {
				t.Fatalf("drifted commit wrote hardware: %v", rows)
			}
			assertNoCreateTerminalSteps(t, c, op.ID, 3)
		})
	}
}

func TestVMCreateOperationStaleCommitAndRollbackAreNoOps(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	op := createOp("op-fence", "vm", "vm1", "hash", "", 5)
	vm := VMRecord{Name: "vm1", HostName: "h1", State: "creating", Project: "p1", OwnerEpoch: 5, SpecGeneration: 2}
	if applied, err := c.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
		t.Fatalf("begin: applied=%v err=%v", applied, err)
	}
	staleGeneration := vm
	staleGeneration.SpecGeneration = 1
	if applied, err := c.CommitVMCreateOperation(ctx, op.ID, 5, staleGeneration, nil, nil, nil, nil); err != nil || applied {
		t.Fatalf("stale-generation commit: applied=%v err=%v", applied, err)
	}
	if applied, err := c.CommitVMCreateOperation(ctx, "other-op", 5, vm, nil, nil, nil, nil); err != nil || applied {
		t.Fatalf("stale-operation commit: applied=%v err=%v", applied, err)
	}
	if applied, err := c.RollbackVMCreateOperation(ctx, "vm1", op.ID, 4, "stale"); err != nil || applied {
		t.Fatalf("stale-owner rollback: applied=%v err=%v", applied, err)
	}
	got, _ := GetVM(ctx, c, "vm1")
	if got == nil || got.State != "creating" || got.ActiveOperationID != op.ID {
		t.Fatalf("stale mutation changed VM: %+v", got)
	}
}

func TestRollbackVMCreateOperationTombstonesAndReleasesReservation(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	reservation, _ := (ReservationVector{Project: "p1", TargetHost: "h1", TargetCPU: 1}).Encode()
	op := createOp("op-rollback", "vm", "vm1", "hash", reservation, 3)
	vm := VMRecord{Name: "vm1", HostName: "h1", State: "creating", Project: "p1", OwnerEpoch: 3}
	if applied, err := c.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
		t.Fatalf("begin: applied=%v err=%v", applied, err)
	}
	if applied, err := c.RollbackVMCreateOperation(ctx, "vm1", op.ID, 3, "disk=/tmp/vm1"); err != nil || !applied {
		t.Fatalf("rollback: applied=%v err=%v", applied, err)
	}
	if got, _ := GetVM(ctx, c, "vm1"); got != nil {
		t.Fatalf("rolled-back provisional VM remains live: %+v", got)
	}
	rows, err := c.Query(ctx, `SELECT deleted_at FROM vms WHERE name = ?`, "vm1")
	if err != nil || len(rows) != 1 || rows[0].String("deleted_at") == "" {
		t.Fatalf("provisional tombstone = %v err=%v", rows, err)
	}
	steps, _ := ListOperationSteps(ctx, c, op.ID, 3)
	state, faulted := ReduceOperationState(OpWorkloadCreate, stepNames(steps))
	if state != OpStepFailed || faulted {
		t.Fatalf("rollback terminal = %q faulted=%v steps=%v", state, faulted, stepNames(steps))
	}
	for _, step := range steps {
		if (step.StepName == OpStepRollbackCompleted || step.StepName == OpStepFailed) &&
			step.Facts != "disk=/tmp/vm1" {
			t.Fatalf("%s facts = %q", step.StepName, step.Facts)
		}
	}
	if cpu, _, err := HostReserved(ctx, c, "h1"); err != nil || cpu != 0 {
		t.Fatalf("reservation after rollback cpu=%d err=%v", cpu, err)
	}
}

func TestContainerCreateOperationAtomicCommitAndFencing(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	op := createOp("op-ct", "container", "ct1", "hash", "", 6)
	ct := ContainerRecord{
		HostName: "h1", Name: "ct1", State: "creating", Image: "alpine",
		CPULimit: 2, MemMiB: 512, Project: "p1", OwnerEpoch: 6, SpecGeneration: 2,
		Labels: map[string]string{"app": "web"},
	}
	if applied, err := c.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
		t.Fatalf("begin container: applied=%v err=%v", applied, err)
	}
	if applied, err := c.BeginContainerCreateOperation(ctx, op, ct); err != nil || applied {
		t.Fatalf("retry container: applied=%v err=%v", applied, err)
	}
	if applied, err := c.CommitContainerCreateOperation(ctx, op.ID, 5, ct, nil); err != nil || applied {
		t.Fatalf("stale container commit: applied=%v err=%v", applied, err)
	}
	if applied, err := c.RollbackContainerCreateOperation(ctx, "h1", "ct1", op.ID, 5, "stale"); err != nil || applied {
		t.Fatalf("stale container rollback: applied=%v err=%v", applied, err)
	}
	if applied, err := c.CommitContainerCreateOperation(ctx, op.ID, 6, ct,
		[]ContainerInterfaceRecord{{NetworkName: "net1", Ordinal: 0, MAC: "52:00:00:00:00:01"}}); err != nil || !applied {
		t.Fatalf("commit container: applied=%v err=%v", applied, err)
	}
	got, _ := GetContainer(ctx, c, "h1", "ct1")
	if got == nil || got.State != "running" || got.ActiveOperationID != "" ||
		got.OwnerEpoch != 6 || got.SpecGeneration != 2 || got.Labels["app"] != "web" {
		t.Fatalf("committed container = %+v", got)
	}
	ifaces, err := GetContainerInterfaces(ctx, c, "h1", "ct1")
	if err != nil || len(ifaces) != 1 {
		t.Fatalf("container interfaces = %+v err=%v", ifaces, err)
	}
}

func TestCommitContainerCreateOperationRejectsAdmissionIdentityDrift(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		mutate func(*ContainerRecord)
	}{
		{"host", func(ct *ContainerRecord) { ct.HostName = "h2" }},
		{"project", func(ct *ContainerRecord) { ct.Project = "p2" }},
		{"create_spec", func(ct *ContainerRecord) { ct.CreateSpec = `{"template":"other"}` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t)
			reservation, _ := (ReservationVector{
				Project: "p1", ProjectCPU: 1, TargetHost: "h1", TargetCPU: 1,
			}).Encode()
			op := createOp("op-ct-drift-"+tc.name, "container", "ct1", "hash", reservation, 2)
			ct := ContainerRecord{
				HostName: "h1", Name: "ct1", Image: "alpine", Project: "p1",
				CreateSpec: `{"template":"alpine"}`, OwnerEpoch: 2, SpecGeneration: 1,
			}
			if applied, err := c.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
				t.Fatalf("begin: applied=%v err=%v", applied, err)
			}
			drifted := ct
			tc.mutate(&drifted)
			applied, err := c.CommitContainerCreateOperation(ctx, op.ID, 2, drifted,
				[]ContainerInterfaceRecord{{NetworkName: "net1"}})
			if err != nil || applied {
				t.Fatalf("drifted commit: applied=%v err=%v", applied, err)
			}
			got, _ := GetContainer(ctx, c, "h1", "ct1")
			if got == nil || got.Project != "p1" || got.CreateSpec != `{"template":"alpine"}` ||
				got.ActiveOperationID != op.ID {
				t.Fatalf("provisional container mutated: %+v", got)
			}
			if rows, _ := c.Query(ctx, `SELECT 1 FROM container_interfaces WHERE ct_name = ?`, "ct1"); len(rows) != 0 {
				t.Fatalf("drifted commit wrote interfaces: %v", rows)
			}
			assertNoCreateTerminalSteps(t, c, op.ID, 2)
		})
	}
}

func TestBeginContainerCreateOperationRetryOnDifferentHostConflicts(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	op := createOp("op-ct-host", "container", "ct1", "hash", "", 1)
	ct := ContainerRecord{HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 1}
	if applied, err := c.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
		t.Fatalf("begin: applied=%v err=%v", applied, err)
	}
	ct.HostName = "h2"
	if _, err := c.BeginContainerCreateOperation(ctx, op, ct); !errors.Is(err, ErrOperationIdentityConflict) {
		t.Fatalf("different-host retry error = %v, want identity conflict", err)
	}
	if got, _ := GetContainer(ctx, c, "h2", "ct1"); got != nil {
		t.Fatalf("different-host retry created a row: %+v", got)
	}
	ct.HostName = "h1"
	if applied, err := c.CommitContainerCreateOperation(ctx, op.ID, 1, ct, nil); err != nil || !applied {
		t.Fatalf("commit original host: applied=%v err=%v", applied, err)
	}
	ct.HostName = "h2"
	if _, err := c.BeginContainerCreateOperation(ctx, op, ct); !errors.Is(err, ErrOperationIdentityConflict) {
		t.Fatalf("different-host retry after commit error = %v, want identity conflict", err)
	}
}

func TestReplicatedVMCreateCommitIsSelfGuarded(t *testing.T) {
	ctx := context.Background()
	source := testClient(t)
	op := createOp("op-repl-vm", "vm", "vm1", "hash", "", 1)
	vm := VMRecord{
		Name: "vm1", HostName: "h1", Project: "p1", Spec: `{"cpu":2}`,
		OwnerEpoch: 1, SpecGeneration: 1,
	}
	if applied, err := source.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
		t.Fatalf("source begin: applied=%v err=%v", applied, err)
	}
	beginEntry := latestMutationEntry(t, source, "source-vm", 1)
	if applied, err := source.CommitVMCreateOperation(ctx, op.ID, 1, vm,
		[]InterfaceRecord{{NetworkName: "net1", MAC: "52:54:00:00:00:01"}},
		[]DiskRecord{{DiskName: "root", HostName: "h1", Path: "/vm1.img"}},
		[]NICRecord{{ID: "nic1", NetworkName: "net1"}},
		[]PCIIntentRecord{{DeviceID: "pci1", HostName: "h1", SelectorKind: "vendor", SelectorPayload: "1234"}},
	); err != nil || !applied {
		t.Fatalf("source commit: applied=%v err=%v", applied, err)
	}
	commitEntry := latestMutationEntry(t, source, "source-vm", 2)

	t.Run("stale receiver", func(t *testing.T) {
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		if _, err := receiver.db.Exec(
			`UPDATE vms SET state = 'running', active_operation_id = 'new-op',
			 vm_owner_epoch = 2, spec_generation = 2, updated_at = ?
			 WHERE name = ?`, "9000000000000-0000-newer", "vm1"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, commitEntry)
		got, _ := GetVM(ctx, receiver, "vm1")
		if got == nil || got.ActiveOperationID != "new-op" || got.OwnerEpoch != 2 || got.SpecGeneration != 2 {
			t.Fatalf("stale commit changed newer VM: %+v", got)
		}
		for _, table := range []string{"vm_interfaces", "vm_disks", "vm_nics", "vm_pci_intent"} {
			if rows, _ := receiver.Query(ctx, `SELECT 1 FROM `+table+` WHERE vm_name = ?`, "vm1"); len(rows) != 0 {
				t.Fatalf("stale commit wrote %s: %v", table, rows)
			}
		}
		assertNoCreateTerminalSteps(t, receiver, op.ID, 1)
	})
	t.Run("valid receiver", func(t *testing.T) {
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		applyMutationEntry(t, receiver, commitEntry)
		got, _ := GetVM(ctx, receiver, "vm1")
		if got == nil || got.State != "running" || got.ActiveOperationID != "" {
			t.Fatalf("valid commit did not apply: %+v", got)
		}
		for _, table := range []string{"vm_interfaces", "vm_disks", "vm_nics", "vm_pci_intent"} {
			if rows, _ := receiver.Query(ctx, `SELECT 1 FROM `+table+` WHERE vm_name = ?`, "vm1"); len(rows) != 1 {
				t.Fatalf("valid commit %s rows = %v", table, rows)
			}
		}
	})
	t.Run("same authority with newer local clock still transitions atomically", func(t *testing.T) {
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		if _, err := receiver.db.Exec(
			`UPDATE vms SET updated_at = ? WHERE name = ?`,
			"9000000000000-0000-newer", "vm1"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, commitEntry)
		got, _ := GetVM(ctx, receiver, "vm1")
		if got == nil || got.State != "running" || got.ActiveOperationID != "" {
			t.Fatalf("semantic commit was clock-skipped: %+v", got)
		}
		for _, table := range []string{"vm_interfaces", "vm_disks", "vm_nics", "vm_pci_intent"} {
			if rows, _ := receiver.Query(ctx, `SELECT 1 FROM `+table+` WHERE vm_name = ?`, "vm1"); len(rows) != 1 {
				t.Fatalf("atomic commit %s rows = %v", table, rows)
			}
		}
	})
}

func TestReplicatedContainerCreateCommitIsSelfGuarded(t *testing.T) {
	ctx := context.Background()
	source := testClient(t)
	op := createOp("op-repl-ct", "container", "ct1", "hash", "", 1)
	ct := ContainerRecord{
		HostName: "h1", Name: "ct1", Image: "alpine", Project: "p1",
		CreateSpec: `{"template":"alpine"}`, OwnerEpoch: 1, SpecGeneration: 1,
	}
	if applied, err := source.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
		t.Fatalf("source begin: applied=%v err=%v", applied, err)
	}
	beginEntry := latestMutationEntry(t, source, "source-ct", 1)
	if applied, err := source.CommitContainerCreateOperation(ctx, op.ID, 1, ct,
		[]ContainerInterfaceRecord{{NetworkName: "net1", MAC: "52:00:00:00:00:01"}}); err != nil || !applied {
		t.Fatalf("source commit: applied=%v err=%v", applied, err)
	}
	commitEntry := latestMutationEntry(t, source, "source-ct", 2)

	t.Run("stale receiver", func(t *testing.T) {
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		if _, err := receiver.db.Exec(
			`UPDATE containers SET state = 'running', active_operation_id = 'new-op',
			 owner_epoch = 2, spec_generation = 2, updated_at = ?
			 WHERE host_name = ? AND name = ?`,
			"9000000000000-0000-newer", "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, commitEntry)
		got, _ := GetContainer(ctx, receiver, "h1", "ct1")
		if got == nil || got.ActiveOperationID != "new-op" || got.OwnerEpoch != 2 || got.SpecGeneration != 2 {
			t.Fatalf("stale commit changed newer container: %+v", got)
		}
		if rows, _ := receiver.Query(ctx, `SELECT 1 FROM container_interfaces WHERE host_name = ? AND ct_name = ?`, "h1", "ct1"); len(rows) != 0 {
			t.Fatalf("stale commit wrote interfaces: %v", rows)
		}
		assertNoCreateTerminalSteps(t, receiver, op.ID, 1)
	})
	t.Run("valid receiver", func(t *testing.T) {
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		applyMutationEntry(t, receiver, commitEntry)
		got, _ := GetContainer(ctx, receiver, "h1", "ct1")
		if got == nil || got.State != "running" || got.ActiveOperationID != "" {
			t.Fatalf("valid commit did not apply: %+v", got)
		}
		if rows, _ := receiver.Query(ctx, `SELECT 1 FROM container_interfaces WHERE host_name = ? AND ct_name = ?`, "h1", "ct1"); len(rows) != 1 {
			t.Fatalf("valid commit interface rows = %v", rows)
		}
	})
	t.Run("same authority with newer local clock still transitions atomically", func(t *testing.T) {
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		if _, err := receiver.db.Exec(
			`UPDATE containers SET updated_at = ? WHERE host_name = ? AND name = ?`,
			"9000000000000-0000-newer", "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, commitEntry)
		got, _ := GetContainer(ctx, receiver, "h1", "ct1")
		if got == nil || got.State != "running" || got.ActiveOperationID != "" {
			t.Fatalf("semantic commit was clock-skipped: %+v", got)
		}
		if rows, _ := receiver.Query(ctx, `SELECT 1 FROM container_interfaces WHERE host_name = ? AND ct_name = ?`, "h1", "ct1"); len(rows) != 1 {
			t.Fatalf("atomic commit interface rows = %v", rows)
		}
	})
}

func TestReplicatedCreateRollbackIsSelfGuarded(t *testing.T) {
	ctx := context.Background()
	t.Run("vm", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-repl-vm-rollback", "vm", "vm1", "hash", "", 1)
		vm := VMRecord{Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1}
		if applied, err := source.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		beginEntry := latestMutationEntry(t, source, "source-vm-rollback", 1)
		if applied, err := source.RollbackVMCreateOperation(ctx, "vm1", op.ID, 1, "cleanup"); err != nil || !applied {
			t.Fatalf("source rollback: applied=%v err=%v", applied, err)
		}
		rollbackEntry := latestMutationEntry(t, source, "source-vm-rollback", 2)
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		if _, err := receiver.db.Exec(
			`UPDATE vms SET state = 'running', active_operation_id = 'new-op',
			 vm_owner_epoch = 2, updated_at = ? WHERE name = ?`,
			"9000000000000-0000-newer", "vm1"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, rollbackEntry)
		got, _ := GetVM(ctx, receiver, "vm1")
		if got == nil || got.ActiveOperationID != "new-op" || got.OwnerEpoch != 2 {
			t.Fatalf("stale rollback changed newer VM: %+v", got)
		}
		assertNoCreateTerminalSteps(t, receiver, op.ID, 1)
	})
	t.Run("container", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-repl-ct-rollback", "container", "ct1", "hash", "", 1)
		ct := ContainerRecord{HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 1}
		if applied, err := source.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		beginEntry := latestMutationEntry(t, source, "source-ct-rollback", 1)
		if applied, err := source.RollbackContainerCreateOperation(ctx, "h1", "ct1", op.ID, 1, "cleanup"); err != nil || !applied {
			t.Fatalf("source rollback: applied=%v err=%v", applied, err)
		}
		rollbackEntry := latestMutationEntry(t, source, "source-ct-rollback", 2)
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		if _, err := receiver.db.Exec(
			`UPDATE containers SET state = 'running', active_operation_id = 'new-op',
			 owner_epoch = 2, updated_at = ? WHERE host_name = ? AND name = ?`,
			"9000000000000-0000-newer", "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, rollbackEntry)
		got, _ := GetContainer(ctx, receiver, "h1", "ct1")
		if got == nil || got.ActiveOperationID != "new-op" || got.OwnerEpoch != 2 {
			t.Fatalf("stale rollback changed newer container: %+v", got)
		}
		assertNoCreateTerminalSteps(t, receiver, op.ID, 1)
	})
	t.Run("vm same authority with newer local clock", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-repl-vm-rollback-clock", "vm", "vm1", "hash", "", 1)
		vm := VMRecord{Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1}
		if applied, err := source.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		beginEntry := latestMutationEntry(t, source, "source-vm-rollback-clock", 1)
		if applied, err := source.RollbackVMCreateOperation(ctx, "vm1", op.ID, 1, "cleanup"); err != nil || !applied {
			t.Fatalf("source rollback: applied=%v err=%v", applied, err)
		}
		rollbackEntry := latestMutationEntry(t, source, "source-vm-rollback-clock", 2)
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		if _, err := receiver.db.Exec(`UPDATE vms SET updated_at = ? WHERE name = ?`,
			"9000000000000-0000-newer", "vm1"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, rollbackEntry)
		if got, _ := GetVM(ctx, receiver, "vm1"); got != nil {
			t.Fatalf("semantic rollback was clock-skipped: %+v", got)
		}
	})
	t.Run("container same authority with newer local clock", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-repl-ct-rollback-clock", "container", "ct1", "hash", "", 1)
		ct := ContainerRecord{HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 1}
		if applied, err := source.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		beginEntry := latestMutationEntry(t, source, "source-ct-rollback-clock", 1)
		if applied, err := source.RollbackContainerCreateOperation(ctx, "h1", "ct1", op.ID, 1, "cleanup"); err != nil || !applied {
			t.Fatalf("source rollback: applied=%v err=%v", applied, err)
		}
		rollbackEntry := latestMutationEntry(t, source, "source-ct-rollback-clock", 2)
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		if _, err := receiver.db.Exec(
			`UPDATE containers SET updated_at = ? WHERE host_name = ? AND name = ?`,
			"9000000000000-0000-newer", "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		applyMutationEntry(t, receiver, rollbackEntry)
		if got, _ := GetContainer(ctx, receiver, "h1", "ct1"); got != nil {
			t.Fatalf("semantic rollback was clock-skipped: %+v", got)
		}
	})
}

func TestReplicatedGuardedEntryRejectsReorderedBarrierAndMisbinding(t *testing.T) {
	ctx := context.Background()
	source := testClient(t)
	op := createOp("op-entry-validation", "vm", "vm1", "hash", "", 1)
	vm := VMRecord{
		Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1, SpecGeneration: 1,
	}
	if applied, err := source.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
		t.Fatalf("begin: applied=%v err=%v", applied, err)
	}
	beginEntry := latestMutationEntry(t, source, "entry-validation-source", 1)
	if applied, err := source.CommitVMCreateOperation(ctx, op.ID, 1, vm,
		[]InterfaceRecord{{NetworkName: "net1", MAC: "52:54:00:00:00:01"}},
		nil, nil, nil,
	); err != nil || !applied {
		t.Fatalf("commit: applied=%v err=%v", applied, err)
	}
	commitEntry := latestMutationEntry(t, source, "entry-validation-source", 2)

	t.Run("begin entry rejects unguarded tail", func(t *testing.T) {
		var stmts []Statement
		if err := json.Unmarshal([]byte(beginEntry.Stmts), &stmts); err != nil {
			t.Fatal(err)
		}
		stmts = append(stmts, operationStepInsertStatement(
			op.ID, 1, OpStepCompleted, "", nowRFC3339(), source.NowTS(), nil,
		))
		raw, _ := json.Marshal(stmts)
		bad := &pb.MutationEntry{
			Seq: 1, Hlc: beginEntry.Hlc, Origin: "malformed-begin", Stmts: string(raw),
		}
		receiver := testClient(t)
		if _, err := NewReplicator(receiver, "", RelayConfig{}).ApplyRemoteMutations(
			ctx, []*pb.MutationEntry{bad},
		); err == nil {
			t.Fatal("begin entry with unguarded tail applied")
		}
		if got, _ := GetVM(ctx, receiver, "vm1"); got != nil {
			t.Fatalf("malformed begin left provisional workload: %+v", got)
		}
	})

	mutateAndApply := func(t *testing.T, setup func(*Client), mutate func([]Statement) []Statement) *Client {
		t.Helper()
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		if setup != nil {
			setup(receiver)
		}
		var stmts []Statement
		if err := json.Unmarshal([]byte(commitEntry.Stmts), &stmts); err != nil {
			t.Fatal(err)
		}
		stmts = mutate(stmts)
		raw, _ := json.Marshal(stmts)
		bad := &pb.MutationEntry{
			Seq: commitEntry.Seq, Hlc: commitEntry.Hlc,
			Origin: "malformed-" + t.Name(), Stmts: string(raw),
		}
		if _, err := NewReplicator(receiver, "", RelayConfig{}).ApplyRemoteMutations(
			ctx, []*pb.MutationEntry{bad}); err == nil {
			t.Fatal("malformed guarded entry applied without back-pressure")
		}
		got, _ := GetVM(ctx, receiver, "vm1")
		if got == nil || got.State != "creating" || got.ActiveOperationID != op.ID {
			t.Fatalf("malformed entry changed parent: %+v", got)
		}
		if rows, _ := receiver.Query(ctx, `SELECT 1 FROM vm_interfaces WHERE vm_name = ?`, "vm1"); len(rows) != 0 {
			t.Fatalf("malformed entry wrote hardware: %v", rows)
		}
		assertNoCreateTerminalSteps(t, receiver, op.ID, 1)
		return receiver
	}
	t.Run("barrier must be last", func(t *testing.T) {
		mutateAndApply(t, nil, func(stmts []Statement) []Statement {
			last := stmts[len(stmts)-1]
			return append([]Statement{last}, stmts[:len(stmts)-1]...)
		})
	})
	t.Run("hardware identity must match guard", func(t *testing.T) {
		mutateAndApply(t, nil, func(stmts []Statement) []Statement {
			stmts[0].Params[0] = "other-vm"
			return stmts
		})
	})
	t.Run("all guards must share one identity", func(t *testing.T) {
		mutateAndApply(t, nil, func(stmts []Statement) []Statement {
			other := *stmts[0].Guard
			other.ResourceID = "other-vm"
			other.OperationID = "other-op"
			stmts[0].Guard = &other
			stmts[0].Params[0] = other.ResourceID
			return stmts
		})
	})
	t.Run("commit terminal sequence is required", func(t *testing.T) {
		mutateAndApply(t, nil, func(stmts []Statement) []Statement {
			return stmts[len(stmts)-1:]
		})
	})
	t.Run("commit guard cannot omit provisional identity", func(t *testing.T) {
		mutateAndApply(t, func(receiver *Client) {
			if _, err := receiver.db.Exec(
				`UPDATE vms SET host_name = ?, spec = ? WHERE name = ?`,
				"h2", `{"unexpected":true}`, "vm1",
			); err != nil {
				t.Fatal(err)
			}
		}, func(stmts []Statement) []Statement {
			for i := range stmts {
				weak := *stmts[i].Guard
				weak.HostName = ""
				weak.IdentityHash = ""
				weak.CheckSpecGeneration = false
				stmts[i].Guard = &weak
			}
			return stmts
		})
	})
	t.Run("unguarded statement cannot ride a guarded barrier", func(t *testing.T) {
		mutateAndApply(t, nil, func(stmts []Statement) []Statement {
			extra := stmts[0]
			extra.Guard = nil
			return append(append(stmts[:len(stmts)-1], extra), stmts[len(stmts)-1])
		})
	})
	t.Run("unrelated same-guard role cannot ride a guarded barrier", func(t *testing.T) {
		mutateAndApply(t, nil, func(stmts []Statement) []Statement {
			extra := stmts[len(stmts)-2]
			extra.Params = append([]interface{}(nil), extra.Params...)
			extra.Params[2] = OpStepPlanned
			return append(append(stmts[:len(stmts)-1], extra), stmts[len(stmts)-1])
		})
	})
	t.Run("rollback terminal sequence is required", func(t *testing.T) {
		rollbackSource := testClient(t)
		rollbackOp := createOp("op-entry-rollback", "vm", "vm-rollback", "hash", "", 1)
		rollbackVM := VMRecord{Name: "vm-rollback", HostName: "h1", Project: "p1", OwnerEpoch: 1}
		if applied, err := rollbackSource.BeginVMCreateOperation(ctx, rollbackOp, rollbackVM); err != nil || !applied {
			t.Fatalf("begin rollback source: applied=%v err=%v", applied, err)
		}
		rollbackBegin := latestMutationEntry(t, rollbackSource, "entry-rollback-source", 1)
		if applied, err := rollbackSource.RollbackVMCreateOperation(
			ctx, rollbackVM.Name, rollbackOp.ID, 1, "cleanup",
		); err != nil || !applied {
			t.Fatalf("rollback source: applied=%v err=%v", applied, err)
		}
		rollbackEntry := latestMutationEntry(t, rollbackSource, "entry-rollback-source", 2)
		var stmts []Statement
		if err := json.Unmarshal([]byte(rollbackEntry.Stmts), &stmts); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(stmts[len(stmts)-1:])
		bad := &pb.MutationEntry{
			Seq: rollbackEntry.Seq, Hlc: rollbackEntry.Hlc,
			Origin: "malformed-rollback", Stmts: string(raw),
		}

		receiver := testClient(t)
		applyMutationEntry(t, receiver, rollbackBegin)
		if _, err := NewReplicator(receiver, "", RelayConfig{}).ApplyRemoteMutations(
			ctx, []*pb.MutationEntry{bad},
		); err == nil {
			t.Fatal("rollback barrier without terminal steps applied")
		}
		if got, _ := GetVM(ctx, receiver, rollbackVM.Name); got == nil ||
			got.State != "creating" || got.ActiveOperationID != rollbackOp.ID {
			t.Fatalf("truncated rollback changed parent: %+v", got)
		}
		assertNoCreateTerminalSteps(t, receiver, rollbackOp.ID, 1)
	})
	t.Run("delete cleanup sequence is required", func(t *testing.T) {
		if err := DeleteVM(ctx, source, "vm1"); err != nil {
			t.Fatal(err)
		}
		deleteEntry := latestMutationEntry(t, source, "entry-delete-source", 3)
		var stmts []Statement
		if err := json.Unmarshal([]byte(deleteEntry.Stmts), &stmts); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(stmts[len(stmts)-1:])
		bad := &pb.MutationEntry{
			Seq: 3, Hlc: deleteEntry.Hlc, Origin: "malformed-delete", Stmts: string(raw),
		}
		receiver := testClient(t)
		applyMutationEntry(t, receiver, beginEntry)
		applyMutationEntry(t, receiver, commitEntry)
		if _, err := NewReplicator(receiver, "", RelayConfig{}).ApplyRemoteMutations(
			ctx, []*pb.MutationEntry{bad},
		); err == nil {
			t.Fatal("delete parent barrier without child cleanup applied")
		}
		if got, _ := GetVM(ctx, receiver, "vm1"); got == nil || got.State != "running" {
			t.Fatalf("truncated delete changed parent: %+v", got)
		}
		if rows, _ := receiver.Query(ctx,
			`SELECT 1 FROM vm_interfaces WHERE vm_name = ? AND deleted_at IS NULL`, "vm1",
		); len(rows) != 1 {
			t.Fatalf("truncated delete changed hardware: %v", rows)
		}

		if err := json.Unmarshal([]byte(deleteEntry.Stmts), &stmts); err != nil {
			t.Fatal(err)
		}
		stmts[0].Params[1] = "9900000000000-0000-poison"
		raw, _ = json.Marshal(stmts)
		badClock := &pb.MutationEntry{
			Seq: 3, Hlc: deleteEntry.Hlc, Origin: "malformed-delete-clock", Stmts: string(raw),
		}
		clockReceiver := testClient(t)
		applyMutationEntry(t, clockReceiver, beginEntry)
		applyMutationEntry(t, clockReceiver, commitEntry)
		if _, err := NewReplicator(clockReceiver, "", RelayConfig{}).ApplyRemoteMutations(
			ctx, []*pb.MutationEntry{badClock},
		); err == nil {
			t.Fatal("delete cleanup with a clock different from its barrier applied")
		}
		if rows, _ := clockReceiver.Query(ctx,
			`SELECT 1 FROM vm_interfaces WHERE vm_name = ? AND deleted_at IS NULL`, "vm1",
		); len(rows) != 1 {
			t.Fatalf("mismatched delete clock changed hardware: %v", rows)
		}
	})
}

func TestCreateOperationAntiEntropyFencesStaleWorkloadAuthority(t *testing.T) {
	ctx := context.Background()

	t.Run("vm commit hardware and steps", func(t *testing.T) {
		source := testClient(t)
		reservation, _ := (ReservationVector{
			Project: "p1", ProjectCPU: 2, TargetHost: "h1", TargetCPU: 2,
		}).Encode()
		op := createOp("op-ae-vm", "vm", "vm1", "hash", reservation, 1)
		vm := VMRecord{
			Name: "vm1", HostName: "h1", Project: "p1", Spec: `{"cpu":2}`,
			OwnerEpoch: 1, SpecGeneration: 1,
		}
		if applied, err := source.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		exclusive := "0000:01:00.0"
		if applied, err := source.CommitVMCreateOperation(ctx, op.ID, 1, vm,
			[]InterfaceRecord{{NetworkName: "net1", MAC: "52:54:00:00:00:01"}},
			[]DiskRecord{{DiskName: "root", HostName: "h1", Path: "/vm1.img"}},
			[]NICRecord{{ID: "nic1", NetworkName: "net1"}},
			[]PCIIntentRecord{{DeviceID: "pci1", HostName: "h1", SelectorKind: "address", SelectorPayload: exclusive, ExclusiveKey: &exclusive}},
		); err != nil || !applied {
			t.Fatalf("source commit: applied=%v err=%v", applied, err)
		}

		receiver := testClient(t)
		if err := InsertVM(ctx, receiver, VMRecord{
			Name: "vm1", HostName: "h2", Project: "p1", Spec: `{"cpu":8}`,
			State: "running", OwnerEpoch: 2, SpecGeneration: 2,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.db.Exec(`UPDATE vms SET updated_at = ? WHERE name = ?`,
			"9000000000000-0000-newer", "vm1"); err != nil {
			t.Fatal(err)
		}
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"vm_interfaces", "vm_disks", "vm_nics", "vm_pci_intent"} {
			if rows, _ := receiver.Query(ctx, `SELECT 1 FROM `+table+` WHERE vm_name = ?`, "vm1"); len(rows) != 0 {
				t.Errorf("stale anti-entropy commit wrote %s: %v", table, rows)
			}
		}
		assertNoOperationSteps(t, receiver, op.ID)
		if got, _ := GetOperation(ctx, receiver, op.ID); got == nil {
			t.Fatal("immutable operation header was not retained")
		}
		if cpu, _, err := HostReserved(ctx, receiver, "h1"); err != nil || cpu != 0 {
			t.Fatalf("stale header reserved capacity: cpu=%d err=%v", cpu, err)
		}
	})

	t.Run("container commit hardware and steps", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-ae-ct", "container", "ct1", "hash", "", 1)
		ct := ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "alpine", Project: "p1",
			CreateSpec: `{"template":"alpine"}`, OwnerEpoch: 1, SpecGeneration: 1,
		}
		if applied, err := source.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.CommitContainerCreateOperation(ctx, op.ID, 1, ct,
			[]ContainerInterfaceRecord{{NetworkName: "net1", MAC: "52:00:00:00:00:01"}}); err != nil || !applied {
			t.Fatalf("source commit: applied=%v err=%v", applied, err)
		}

		receiver := testClient(t)
		if err := UpsertContainer(ctx, receiver, ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "debian", Project: "p1",
			State: "running", OwnerEpoch: 2, SpecGeneration: 2,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := receiver.db.Exec(
			`UPDATE containers SET updated_at = ? WHERE host_name = ? AND name = ?`,
			"9000000000000-0000-newer", "h1", "ct1"); err != nil {
			t.Fatal(err)
		}
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if rows, _ := receiver.Query(ctx,
			`SELECT 1 FROM container_interfaces WHERE host_name = ? AND ct_name = ?`,
			"h1", "ct1"); len(rows) != 0 {
			t.Errorf("stale anti-entropy commit wrote container interfaces: %v", rows)
		}
		assertNoOperationSteps(t, receiver, op.ID)
	})

	for _, kind := range []string{"vm", "container"} {
		t.Run(kind+" rollback steps", func(t *testing.T) {
			source := testClient(t)
			op := createOp("op-ae-"+kind+"-rollback", kind, "workload1", "hash", "", 1)
			if kind == "vm" {
				if applied, err := source.BeginVMCreateOperation(ctx, op,
					VMRecord{Name: "workload1", HostName: "h1", Project: "p1", OwnerEpoch: 1}); err != nil || !applied {
					t.Fatalf("source begin: applied=%v err=%v", applied, err)
				}
				if applied, err := source.RollbackVMCreateOperation(ctx, "workload1", op.ID, 1, "cleanup"); err != nil || !applied {
					t.Fatalf("source rollback: applied=%v err=%v", applied, err)
				}
			} else {
				if applied, err := source.BeginContainerCreateOperation(ctx, op,
					ContainerRecord{HostName: "h1", Name: "workload1", Project: "p1", OwnerEpoch: 1}); err != nil || !applied {
					t.Fatalf("source begin: applied=%v err=%v", applied, err)
				}
				if applied, err := source.RollbackContainerCreateOperation(ctx, "h1", "workload1", op.ID, 1, "cleanup"); err != nil || !applied {
					t.Fatalf("source rollback: applied=%v err=%v", applied, err)
				}
			}

			receiver := testClient(t)
			if kind == "vm" {
				if err := InsertVM(ctx, receiver, VMRecord{
					Name: "workload1", HostName: "h2", Project: "p1", State: "running",
					OwnerEpoch: 2, SpecGeneration: 2,
				}, nil, nil); err != nil {
					t.Fatal(err)
				}
				_, _ = receiver.db.Exec(`UPDATE vms SET updated_at = ? WHERE name = ?`,
					"9000000000000-0000-newer", "workload1")
			} else {
				if err := UpsertContainer(ctx, receiver, ContainerRecord{
					HostName: "h1", Name: "workload1", Project: "p1", State: "running",
					OwnerEpoch: 2, SpecGeneration: 2,
				}); err != nil {
					t.Fatal(err)
				}
				_, _ = receiver.db.Exec(
					`UPDATE containers SET updated_at = ? WHERE host_name = ? AND name = ?`,
					"9000000000000-0000-newer", "h1", "workload1")
			}
			if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
				t.Fatal(err)
			}
			assertNoOperationSteps(t, receiver, op.ID)
		})
	}
}

func TestCreateOperationAntiEntropyCurrentAuthorityConverges(t *testing.T) {
	ctx := context.Background()
	t.Run("vm commit in reversed payload order", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-ae-valid", "vm", "vm1", "hash", "", 4)
		vm := VMRecord{
			Name: "vm1", HostName: "h1", Project: "p1", Spec: `{"cpu":2}`,
			OwnerEpoch: 4, SpecGeneration: 3,
		}
		if applied, err := source.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.CommitVMCreateOperation(ctx, op.ID, 4, vm,
			[]InterfaceRecord{{NetworkName: "net1", MAC: "52:54:00:00:00:01"}},
			[]DiskRecord{{DiskName: "root", HostName: "h1", Path: "/vm1.img"}},
			[]NICRecord{{ID: "nic1", NetworkName: "net1"}},
			[]PCIIntentRecord{{DeviceID: "pci1", HostName: "h1", SelectorKind: "vendor", SelectorPayload: "1234"}},
		); err != nil || !applied {
			t.Fatalf("source commit: applied=%v err=%v", applied, err)
		}
		receiver := testClient(t)
		payload, err := decompressPayload(source.DumpStateBytes())
		if err != nil {
			t.Fatal(err)
		}
		for left, right := 0, len(payload.Tables)-1; left < right; left, right = left+1, right-1 {
			payload.Tables[left], payload.Tables[right] = payload.Tables[right], payload.Tables[left]
		}
		if err := receiver.mergeStatePayloadLWW(payload); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"vm_interfaces", "vm_disks", "vm_nics", "vm_pci_intent"} {
			if rows, _ := receiver.Query(ctx, `SELECT 1 FROM `+table+` WHERE vm_name = ?`, "vm1"); len(rows) != 1 {
				t.Errorf("valid anti-entropy repair did not converge %s: %v", table, rows)
			}
		}
		steps, err := ListOperationSteps(ctx, receiver, op.ID, 4)
		if err != nil {
			t.Fatal(err)
		}
		if state, faulted := ReduceOperationState(OpWorkloadCreate, stepNames(steps)); state != OpStepCompleted || faulted {
			t.Fatalf("valid repaired operation state=%q faulted=%v steps=%v", state, faulted, stepNames(steps))
		}
	})

	t.Run("container commit", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-ae-valid-ct", "container", "ct1", "hash", "", 5)
		ct := ContainerRecord{
			HostName: "h1", Name: "ct1", Image: "alpine", Project: "p1",
			OwnerEpoch: 5, SpecGeneration: 2,
		}
		if applied, err := source.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.CommitContainerCreateOperation(ctx, op.ID, 5, ct,
			[]ContainerInterfaceRecord{{NetworkName: "net1"}}); err != nil || !applied {
			t.Fatalf("source commit: applied=%v err=%v", applied, err)
		}
		receiver := testClient(t)
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		if rows, _ := receiver.Query(ctx,
			`SELECT 1 FROM container_interfaces WHERE host_name = ? AND ct_name = ?`,
			"h1", "ct1"); len(rows) != 1 {
			t.Fatalf("valid container interface repair did not converge: %v", rows)
		}
		steps, err := ListOperationSteps(ctx, receiver, op.ID, 5)
		if err != nil {
			t.Fatal(err)
		}
		if state, faulted := ReduceOperationState(OpWorkloadCreate, stepNames(steps)); state != OpStepCompleted || faulted {
			t.Fatalf("valid container state=%q faulted=%v steps=%v", state, faulted, stepNames(steps))
		}
	})

	t.Run("rollback", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-ae-valid-rollback", "vm", "vm1", "hash", "", 6)
		if applied, err := source.BeginVMCreateOperation(ctx, op,
			VMRecord{Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 6}); err != nil || !applied {
			t.Fatalf("source begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.RollbackVMCreateOperation(ctx, "vm1", op.ID, 6, "cleanup"); err != nil || !applied {
			t.Fatalf("source rollback: applied=%v err=%v", applied, err)
		}
		receiver := testClient(t)
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		steps, err := ListOperationSteps(ctx, receiver, op.ID, 6)
		if err != nil {
			t.Fatal(err)
		}
		if state, faulted := ReduceOperationState(OpWorkloadCreate, stepNames(steps)); state != OpStepFailed || faulted {
			t.Fatalf("valid rollback state=%q faulted=%v steps=%v", state, faulted, stepNames(steps))
		}
	})
}

func TestCreateOperationAntiEntropyRejectsStepsFromConflictingImmutableHeader(t *testing.T) {
	ctx := context.Background()
	localReservation, _ := (ReservationVector{
		Project: "p1", ProjectCPU: 2, TargetHost: "h1", TargetCPU: 2,
	}).Encode()
	otherReservation, _ := (ReservationVector{
		Project: "p1", ProjectCPU: 9, TargetHost: "h1", TargetCPU: 9,
	}).Encode()

	tests := []struct {
		name   string
		mutate func(*OperationRecord)
	}{
		{"method", func(op *OperationRecord) { op.Method = "CreateVM-v2" }},
		{"principal", func(op *OperationRecord) { op.Principal = "bob" }},
		{"request hash", func(op *OperationRecord) { op.RequestHash = "other-hash" }},
		{"idempotency key", func(op *OperationRecord) { op.IdempotencyKey = "other-key" }},
		{"reservation", func(op *OperationRecord) { op.ReservationJSON = otherReservation }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			local := testClient(t)
			source := testClient(t)
			op := createOp("op-conflicting-header", "vm", "vm1", "hash", localReservation, 1)
			vm := VMRecord{
				Name: "vm1", HostName: "h1", Project: "p1", Spec: `{"cpu":2}`,
				OwnerEpoch: 1, SpecGeneration: 1,
			}
			if applied, err := local.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
				t.Fatalf("local begin: applied=%v err=%v", applied, err)
			}
			incoming := op
			tc.mutate(&incoming)
			if applied, err := source.BeginVMCreateOperation(ctx, incoming, vm); err != nil || !applied {
				t.Fatalf("source begin: applied=%v err=%v", applied, err)
			}
			for _, step := range []string{OpStepCompleted, OpStepRollbackCompleted, OpStepFailed} {
				if err := AppendOperationStep(ctx, source, OperationStepRecord{
					OperationID: incoming.ID, OwnerEpoch: 1, StepName: step,
				}); err != nil {
					t.Fatalf("append %s: %v", step, err)
				}
			}

			if err := local.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
				t.Fatal(err)
			}
			steps, err := ListOperationSteps(ctx, local, op.ID, 1)
			if err != nil {
				t.Fatal(err)
			}
			for _, step := range steps {
				switch step.StepName {
				case OpStepCompleted, OpStepRollbackCompleted, OpStepFailed:
					t.Errorf("terminal step %q from conflicting header was admitted", step.StepName)
				}
			}
			if cpu, _, err := HostReserved(ctx, local, "h1"); err != nil || cpu != 2 {
				t.Fatalf("local reservation after conflicting repair: cpu=%d err=%v", cpu, err)
			}
		})
	}
}

func TestWorkloadAuthorityAntiEntropyCompatibility(t *testing.T) {
	ctx := context.Background()

	t.Run("ordinary hardware still converges", func(t *testing.T) {
		source := testClient(t)
		if err := InsertVM(ctx, source, VMRecord{
			Name: "legacy-vm", HostName: "h1", Project: "p1", State: "running",
		}, []InterfaceRecord{{VMName: "legacy-vm", NetworkName: "net1"}}, []DiskRecord{{
			VMName: "legacy-vm", DiskName: "root", HostName: "h1", Path: "/legacy.img",
		}}); err != nil {
			t.Fatal(err)
		}
		receiver := testClient(t)
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"vm_interfaces", "vm_disks"} {
			if rows, _ := receiver.Query(ctx, `SELECT 1 FROM `+table+` WHERE vm_name = ?`, "legacy-vm"); len(rows) != 1 {
				t.Errorf("ordinary anti-entropy repair did not converge %s: %v", table, rows)
			}
		}
	})

	t.Run("non-create journal still converges", func(t *testing.T) {
		source := testClient(t)
		insertOp(t, source, "op-update", "hash", "2026-06-03T18:40:00Z", "")
		if err := AppendOperationStep(ctx, source, OperationStepRecord{
			OperationID: "op-update", OwnerEpoch: 1, StepName: OpStepPlanned,
		}); err != nil {
			t.Fatal(err)
		}
		receiver := testClient(t)
		if err := receiver.MergeStateBytesLWW(source.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
		steps, err := ListOperationSteps(ctx, receiver, "op-update", 1)
		if err != nil || len(steps) != 1 {
			t.Fatalf("non-create journal repair steps=%v err=%v", steps, err)
		}
	})

	t.Run("child without source authority fails closed", func(t *testing.T) {
		source := testClient(t)
		if err := InsertVM(ctx, source, VMRecord{
			Name: "vm1", HostName: "h1", Project: "p1", State: "running",
		}, []InterfaceRecord{{VMName: "vm1", NetworkName: "net1"}}, nil); err != nil {
			t.Fatal(err)
		}
		payload, err := decompressPayload(source.DumpStateBytes())
		if err != nil {
			t.Fatal(err)
		}
		filtered := payload.Tables[:0]
		for _, table := range payload.Tables {
			if table.Name != "vms" {
				filtered = append(filtered, table)
			}
		}
		payload.Tables = filtered

		receiver := testClient(t)
		if err := InsertVM(ctx, receiver, VMRecord{
			Name: "vm1", HostName: "h1", Project: "p1", State: "running",
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := receiver.mergeStatePayloadLWW(payload); err != nil {
			t.Fatal(err)
		}
		if rows, _ := receiver.Query(ctx,
			`SELECT 1 FROM vm_interfaces WHERE vm_name = ?`, "vm1"); len(rows) != 0 {
			t.Fatalf("authority-less child payload merged: %v", rows)
		}
	})

	t.Run("provisional parent cannot authorize commit hardware", func(t *testing.T) {
		source := testClient(t)
		op := createOp("op-split-snapshot", "vm", "vm1", "hash", "", 1)
		vm := VMRecord{
			Name: "vm1", HostName: "h1", Project: "p1", Spec: `{"cpu":2}`,
			OwnerEpoch: 1, SpecGeneration: 1,
		}
		if applied, err := source.BeginVMCreateOperation(ctx, op, vm); err != nil || !applied {
			t.Fatalf("begin: applied=%v err=%v", applied, err)
		}
		if applied, err := source.CommitVMCreateOperation(ctx, op.ID, 1, vm,
			[]InterfaceRecord{{NetworkName: "net1"}}, nil, nil, nil); err != nil || !applied {
			t.Fatalf("commit: applied=%v err=%v", applied, err)
		}
		payload, err := decompressPayload(source.DumpStateBytes())
		if err != nil {
			t.Fatal(err)
		}
		for tableIdx := range payload.Tables {
			table := &payload.Tables[tableIdx]
			if table.Name != "vms" {
				continue
			}
			stateIdx := indexOf(table.Columns, "state")
			activeIdx := indexOf(table.Columns, "active_operation_id")
			for rowIdx := range table.Rows {
				table.Rows[rowIdx][stateIdx] = "creating"
				table.Rows[rowIdx][activeIdx] = op.ID
			}
		}
		receiver := testClient(t)
		if err := receiver.mergeStatePayloadLWW(payload); err != nil {
			t.Fatal(err)
		}
		if rows, _ := receiver.Query(ctx,
			`SELECT 1 FROM vm_interfaces WHERE vm_name = ?`, "vm1"); len(rows) != 0 {
			t.Fatalf("provisional parent authorized commit hardware: %v", rows)
		}
	})
}

func assertNoOperationSteps(t *testing.T, c *Client, opID string) {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT step_name FROM operation_steps WHERE operation_id = ? AND deleted_at IS NULL`, opID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("stale anti-entropy steps merged: %v", rows)
	}
}

func TestBeginContainerCreateOperationRollsBackAndPreservesLiveRow(t *testing.T) {
	ctx := context.Background()
	t.Run("statement failure", func(t *testing.T) {
		c := testClient(t)
		if _, err := c.db.Exec(`CREATE TRIGGER fail_ct_begin BEFORE INSERT ON containers
			BEGIN SELECT RAISE(ABORT, 'injected container insert failure'); END`); err != nil {
			t.Fatal(err)
		}
		op := createOp("op-ct-begin-fail", "container", "ct1", "hash", "", 1)
		applied, err := c.BeginContainerCreateOperation(ctx, op,
			ContainerRecord{HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 1})
		if err == nil || applied {
			t.Fatalf("begin container: applied=%v err=%v", applied, err)
		}
		if got, _ := GetOperation(ctx, c, op.ID); got != nil {
			t.Fatalf("operation survived rollback: %+v", got)
		}
		if got, _ := GetContainer(ctx, c, "h1", "ct1"); got != nil {
			t.Fatalf("container survived rollback: %+v", got)
		}
	})
	t.Run("live row", func(t *testing.T) {
		c := testClient(t)
		if err := UpsertContainer(ctx, c, ContainerRecord{
			HostName: "h1", Name: "ct1", State: "running", Image: "existing",
		}); err != nil {
			t.Fatal(err)
		}
		op := createOp("op-ct-live", "container", "ct1", "hash", "", 1)
		applied, err := c.BeginContainerCreateOperation(ctx, op,
			ContainerRecord{HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 1})
		if err != nil || applied {
			t.Fatalf("begin over live container: applied=%v err=%v", applied, err)
		}
		got, _ := GetContainer(ctx, c, "h1", "ct1")
		if got == nil || got.State != "running" || got.Image != "existing" {
			t.Fatalf("live container overwritten: %+v", got)
		}
	})
}

func TestContainerCreateOperationStatementFailureIsAtomicAndRollbackTombstones(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	op := createOp("op-ct-fail", "container", "ct1", "hash", "", 2)
	ct := ContainerRecord{HostName: "h1", Name: "ct1", Project: "p1", OwnerEpoch: 2}
	if applied, err := c.BeginContainerCreateOperation(ctx, op, ct); err != nil || !applied {
		t.Fatalf("begin: applied=%v err=%v", applied, err)
	}
	if _, err := c.db.Exec(`CREATE TRIGGER fail_ct_hardware BEFORE INSERT ON container_interfaces
		BEGIN SELECT RAISE(ABORT, 'injected interface failure'); END`); err != nil {
		t.Fatal(err)
	}
	if applied, err := c.CommitContainerCreateOperation(ctx, op.ID, 2, ct,
		[]ContainerInterfaceRecord{{NetworkName: "net1"}}); err == nil || applied {
		t.Fatalf("commit with injected failure: applied=%v err=%v", applied, err)
	}
	got, _ := GetContainer(ctx, c, "h1", "ct1")
	if got == nil || got.State != "creating" || got.ActiveOperationID != op.ID {
		t.Fatalf("container changed after failed commit: %+v", got)
	}
	if _, err := c.db.Exec(`DROP TRIGGER fail_ct_hardware`); err != nil {
		t.Fatal(err)
	}
	if applied, err := c.RollbackContainerCreateOperation(ctx, "h1", "ct1", op.ID, 2, "cleanup"); err != nil || !applied {
		t.Fatalf("container rollback: applied=%v err=%v", applied, err)
	}
	if got, _ := GetContainer(ctx, c, "h1", "ct1"); got != nil {
		t.Fatalf("rolled-back container remains live: %+v", got)
	}
}

func TestReservationAggregationValidatesCurrentAuthority(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	if applied, err := ClaimInitialProjectAuthority(ctx, c, "p1", "authority-1"); err != nil || !applied {
		t.Fatalf("claim authority: applied=%v err=%v", applied, err)
	}
	current, _ := (ReservationVector{
		Project: "p1", ProjectCPU: 2, TargetHost: "h1", TargetCPU: 2,
	}).Encode()
	op1 := createOp("op-current", "vm", "vm1", "hash1", current, 1)
	op1.ReservationFacts = &ReservationFacts{Project: "p1", AuthorityEpoch: 1, AuthorityHost: "authority-1"}
	if applied, err := c.BeginVMCreateOperation(ctx, op1,
		VMRecord{Name: "vm1", HostName: "h1", Project: "p1", OwnerEpoch: 1}); err != nil || !applied {
		t.Fatalf("begin current reservation: applied=%v err=%v", applied, err)
	}
	if cpu, _, err := HostReserved(ctx, c, "h1"); err != nil || cpu != 2 {
		t.Fatalf("current reservation cpu=%d err=%v", cpu, err)
	}
	if _, applied, err := TakeoverProjectAuthority(ctx, c, "p1", "authority-2", "planned", "", 1); err != nil || !applied {
		t.Fatalf("takeover: applied=%v err=%v", applied, err)
	}
	if cpu, _, err := HostReserved(ctx, c, "h1"); err != nil || cpu != 0 {
		t.Fatalf("stale reservation cpu=%d err=%v", cpu, err)
	}
	current2, _ := (ReservationVector{
		Project: "p1", ProjectCPU: 3, TargetHost: "h1", TargetCPU: 3,
	}).Encode()
	op2 := createOp("op-current-2", "vm", "vm2", "hash2", current2, 1)
	op2.ReservationFacts = &ReservationFacts{Project: "p1", AuthorityEpoch: 2, AuthorityHost: "authority-2"}
	if applied, err := c.BeginVMCreateOperation(ctx, op2,
		VMRecord{Name: "vm2", HostName: "h1", Project: "p1", OwnerEpoch: 1}); err != nil || !applied {
		t.Fatalf("begin current2 reservation: applied=%v err=%v", applied, err)
	}
	if cpu, _, err := HostReserved(ctx, c, "h1"); err != nil || cpu != 3 {
		t.Fatalf("current epoch reservation cpu=%d err=%v", cpu, err)
	}
	if _, err := c.db.Exec(`UPDATE operation_steps SET facts = '{'
		WHERE operation_id = ? AND step_name = ?`, op2.ID, OpStepReserved); err != nil {
		t.Fatal(err)
	}
	if _, _, err := HostReserved(ctx, c, "h1"); err == nil || !strings.Contains(err.Error(), "malformed authority facts") {
		t.Fatalf("malformed current facts error = %v", err)
	}
}

func TestReservationAggregationWithoutAuthorityPreservesLegacyClaims(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	reservation, _ := (ReservationVector{
		Project: "p1", ProjectCPU: 1, TargetHost: "h1", TargetCPU: 1,
	}).Encode()
	op := createOp("op-legacy", "vm", "vm1", "hash", reservation, 0)
	if applied, err := c.BeginVMCreateOperation(ctx, op,
		VMRecord{Name: "vm1", HostName: "h1", Project: "p1"}); err != nil || !applied {
		t.Fatalf("begin legacy reservation: applied=%v err=%v", applied, err)
	}
	if cpu, _, err := HostReserved(ctx, c, "h1"); err != nil || cpu != 1 {
		t.Fatalf("legacy reservation cpu=%d err=%v", cpu, err)
	}
	if cpu, _, err := ProjectReserved(ctx, c, "p1"); err != nil || cpu != 1 {
		t.Fatalf("legacy project reservation cpu=%d err=%v", cpu, err)
	}
	if err := AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: op.ID, OwnerEpoch: 1, StepName: OpStepCompleted,
	}); err != nil {
		t.Fatal(err)
	}
	if cpu, _, err := HostReserved(ctx, c, "h1"); err != nil || cpu != 1 {
		t.Fatalf("stale-owner terminal released reservation: cpu=%d err=%v", cpu, err)
	}
}

func stepNames(steps []OperationStepRecord) []string {
	out := make([]string, len(steps))
	for i := range steps {
		out[i] = steps[i].StepName
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func assertNoCreateTerminalSteps(t *testing.T, c *Client, opID string, ownerEpoch int64) {
	t.Helper()
	steps, err := ListOperationSteps(context.Background(), c, opID, ownerEpoch)
	if err != nil {
		t.Fatal(err)
	}
	for _, step := range steps {
		switch step.StepName {
		case OpStepPrepared, OpStepRuntimeStarted, OpStepObserved, OpStepCompleted,
			OpStepRollbackCompleted, OpStepFailed:
			t.Fatalf("unexpected create terminal/progress step after refused mutation: %s", step.StepName)
		}
	}
}

func latestMutationEntry(t *testing.T, c *Client, origin string, seq int64) *pb.MutationEntry {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT hlc, stmts FROM mutation_log ORDER BY seq DESC LIMIT 1`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("latest mutation: rows=%v err=%v", rows, err)
	}
	return &pb.MutationEntry{
		Seq: seq, Hlc: rows[0].String("hlc"), Origin: origin, Stmts: rows[0].String("stmts"),
	}
}

func applyMutationEntry(t *testing.T, c *Client, entry *pb.MutationEntry) {
	t.Helper()
	if _, err := NewReplicator(c, "", RelayConfig{}).ApplyRemoteMutations(
		context.Background(), []*pb.MutationEntry{entry}); err != nil {
		t.Fatalf("apply mutation seq=%d: %v", entry.Seq, err)
	}
}
