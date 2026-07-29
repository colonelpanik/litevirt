package corrosion

import (
	"context"
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
	reservation, _ := (ReservationVector{TargetHost: "h1", TargetCPU: 1}).Encode()
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
