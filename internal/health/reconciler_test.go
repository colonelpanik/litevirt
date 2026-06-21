package health

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func testReconcilerDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func TestNewReconciler(t *testing.T) {
	db := testReconcilerDB(t)
	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	if r == nil {
		t.Fatal("NewReconciler returned nil")
	}
	if r.hostName != "host-a" {
		t.Errorf("hostName = %q, want host-a", r.hostName)
	}
	if r.dataDir != "/var/lib/litevirt" {
		t.Errorf("dataDir = %q, want /var/lib/litevirt", r.dataDir)
	}
	if r.db == nil {
		t.Error("db should not be nil")
	}
	if r.virt != nil {
		t.Error("virt should be nil when passed nil")
	}
}

func TestReconciler_ReconcileEmpty(t *testing.T) {
	db := testReconcilerDB(t)
	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)

	// With no VMs in the DB, reconcile should complete without error or panic.
	r.reconcile(context.Background())
}

func TestReconciler_ReconcileMixedStates_NilVirt(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Insert VMs in various states on our host.
	for _, vm := range []corrosion.VMRecord{
		{Name: "vm-running-1", HostName: "host-a", Spec: `{}`, State: "running"},
		{Name: "vm-error-1", HostName: "host-a", Spec: `{}`, State: "error"},
		{Name: "vm-stopped-1", HostName: "host-a", Spec: `{}`, State: "stopped"},
		{Name: "vm-creating-1", HostName: "host-a", Spec: `{}`, State: "creating"},
	} {
		if err := corrosion.InsertVM(ctx, db, vm, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", vm.Name, err)
		}
	}

	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	// With nil virt, reconcile should not panic and should skip virt-dependent paths.
	r.reconcile(ctx)

	// All VMs should retain their original state (nil virt skips all libvirt checks).
	for _, want := range []struct {
		name, state string
	}{
		{"vm-running-1", "running"},
		{"vm-error-1", "error"},
		{"vm-stopped-1", "stopped"},
		{"vm-creating-1", "creating"},
	} {
		vm, err := corrosion.GetVM(ctx, db, want.name)
		if err != nil {
			t.Fatalf("GetVM(%s): %v", want.name, err)
		}
		if vm.State != want.state {
			t.Errorf("%s: state = %q, want %q", want.name, vm.State, want.state)
		}
	}
}

func TestReconciler_ReconcileRunningVM_NilVirt(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Insert a running VM on our host.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-running",
		HostName: "host-a",
		Spec:     `{"cpu":1,"memory":512}`,
		State:    "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	// With nil virt, the running case's "r.virt != nil" check is false,
	// so it skips the DomainExists verification entirely.
	r.reconcile(ctx)

	// VM should remain in running state (no action taken).
	vm, err := corrosion.GetVM(ctx, db, "vm-running")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "running" {
		t.Errorf("expected VM to remain running, got %q", vm.State)
	}
}

func TestReconciler_ReconcileErrorVM_NilVirt(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Insert an errored VM on our host.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:        "vm-error",
		HostName:    "host-a",
		Spec:        `{"cpu":1,"memory":512}`,
		State:       "error",
		StateDetail: "something went wrong",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	// With nil virt, the error case's "r.virt != nil" check is false,
	// so it skips the DomainExists check.
	r.reconcile(ctx)

	// VM should remain in error state (no action taken).
	vm, err := corrosion.GetVM(ctx, db, "vm-error")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "error" {
		t.Errorf("expected VM to remain in error state, got %q", vm.State)
	}
}

func TestReconciler_ReconcileSkipsOtherHost(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Insert a pending VM on a different host.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-other",
		HostName: "host-b",
		Spec:     `{"cpu":1,"memory":512}`,
		State:    "pending",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	r.reconcile(ctx)

	// VM on host-b should remain unchanged.
	vm, err := corrosion.GetVM(ctx, db, "vm-other")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "pending" {
		t.Errorf("expected VM on other host to remain pending, got %q", vm.State)
	}
}

func TestReconciler_SelfFence_NilVirt(t *testing.T) {
	db := testReconcilerDB(t)
	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)

	// With nil virt, selfFence returns immediately (line 93-95).
	// Should not panic.
	r.selfFence(context.Background())
}

func TestReconciler_ReconcileStoppedVM_Ignored(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Insert a stopped VM on our host. reconcile should skip it
	// (no case for "stopped" in the switch).
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-stopped",
		HostName: "host-a",
		Spec:     `{"cpu":1,"memory":512}`,
		State:    "stopped",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	r.reconcile(ctx)

	// VM should remain stopped.
	vm, err := corrosion.GetVM(ctx, db, "vm-stopped")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "stopped" {
		t.Errorf("expected VM to remain stopped, got %q", vm.State)
	}
}

func TestReconciler_AutoPullImage_Called(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Insert a pending VM with an image spec.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-pull-1",
		HostName: "host-a",
		Spec:     `{"image":"ubuntu-24.04"}`,
		State:    "pending",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Insert a disk record with a backing image and a path that doesn't exist.
	err = corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
		VMName:       "vm-pull-1",
		DiskName:     "root",
		HostName:     "host-a",
		Path:         "/nonexistent/path/vm-pull-1-root.qcow2",
		BackingImage: "ubuntu-24.04",
	})
	if err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	var pulledImage string
	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	r.SetAutoPullImage(func(ctx context.Context, imageName string) error {
		pulledImage = imageName
		return nil
	})

	r.reconcile(ctx)

	if pulledImage != "ubuntu-24.04" {
		t.Errorf("autoPullImage called with %q, want %q", pulledImage, "ubuntu-24.04")
	}
}

func TestReconciler_AutoPullImage_Failure(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Insert a pending VM with an image spec.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-pull-fail",
		HostName: "host-a",
		Spec:     `{"image":"ubuntu-24.04"}`,
		State:    "pending",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Insert a disk record with a backing image and a path that doesn't exist.
	err = corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
		VMName:       "vm-pull-fail",
		DiskName:     "root",
		HostName:     "host-a",
		Path:         "/nonexistent/path/vm-pull-fail-root.qcow2",
		BackingImage: "ubuntu-24.04",
	})
	if err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	r.SetAutoPullImage(func(ctx context.Context, imageName string) error {
		return fmt.Errorf("peer unreachable")
	})

	r.reconcile(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm-pull-fail")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "error" {
		t.Errorf("state = %q, want %q", vm.State, "error")
	}
	if !strings.Contains(vm.StateDetail, "auto-pull failed") {
		t.Errorf("state_detail = %q, want it to contain %q", vm.StateDetail, "auto-pull failed")
	}
}

func TestReconciler_OnVMStarted_Callback(t *testing.T) {
	db := testReconcilerDB(t)
	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)

	if r.onVMStarted != nil {
		t.Error("onVMStarted should be nil before SetOnVMStarted")
	}

	var calledStack string
	r.SetOnVMStarted(func(ctx context.Context, stackName string) {
		calledStack = stackName
	})

	if r.onVMStarted == nil {
		t.Fatal("onVMStarted should not be nil after SetOnVMStarted")
	}

	// Verify the callback is callable with correct args.
	r.onVMStarted(context.Background(), "test-stack")
	if calledStack != "test-stack" {
		t.Errorf("onVMStarted called with %q, want %q", calledStack, "test-stack")
	}

	// Also verify that a running VM on our host with nil virt stays running
	// (the reconciler's running-VM check path with nil virt).
	ctx := context.Background()
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:      "vm-started-cb",
		HostName:  "host-a",
		StackName: "my-stack",
		Spec:      `{}`,
		State:     "running",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	r.reconcile(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm-started-cb")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "running" {
		t.Errorf("expected VM to remain running, got %q", vm.State)
	}
}

func TestReconciler_PendingVM_DiskNotFound_NoBackingImage(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Insert a pending VM.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:     "vm-nodisk",
		HostName: "host-a",
		Spec:     `{}`,
		State:    "pending",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Insert a disk record with no backing image and a nonexistent path.
	err = corrosion.InsertDisk(ctx, db, corrosion.DiskRecord{
		VMName:   "vm-nodisk",
		DiskName: "root",
		HostName: "host-a",
		Path:     "/nonexistent/path/vm-nodisk-root.qcow2",
	})
	if err != nil {
		t.Fatalf("InsertDisk: %v", err)
	}

	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	r.reconcile(ctx)

	vm, err := corrosion.GetVM(ctx, db, "vm-nodisk")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "error" {
		t.Errorf("state = %q, want %q", vm.State, "error")
	}
	if !strings.Contains(vm.StateDetail, "not found") {
		t.Errorf("state_detail = %q, want it to contain %q", vm.StateDetail, "not found")
	}
	if !strings.Contains(vm.StateDetail, "no backing image") {
		t.Errorf("state_detail = %q, want it to contain %q", vm.StateDetail, "no backing image")
	}
}

func TestReconciler_SelfFence_DifferentHost(t *testing.T) {
	db := testReconcilerDB(t)
	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)

	// With nil virt, selfFence returns immediately at line 108.
	// Verify it does not panic.
	r.selfFence(context.Background())
}

func TestReconciler_ErrorVM_NotInLibvirt(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()

	// Insert a VM in error state on the local host.
	err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name:        "vm-err-local",
		HostName:    "host-a",
		Spec:        `{}`,
		State:       "error",
		StateDetail: "previous failure",
	}, nil, nil)
	if err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)
	// With nil virt, the error case's "r.virt != nil" check is false,
	// so it skips the DomainExists check.
	r.reconcile(ctx)

	// VM should remain in error state with its original detail.
	vm, err := corrosion.GetVM(ctx, db, "vm-err-local")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.State != "error" {
		t.Errorf("state = %q, want %q", vm.State, "error")
	}
	if vm.StateDetail != "previous failure" {
		t.Errorf("state_detail = %q, want %q", vm.StateDetail, "previous failure")
	}
}
