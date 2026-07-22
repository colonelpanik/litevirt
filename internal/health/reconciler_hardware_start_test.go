package health

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The failover reconciler bypasses the gRPC Server's startVMLocked, so it invokes the
// hardware_v2 adoption gate + PCI start-preflight via the daemon-wired hook
// (SetHardwareStartPreparer). These tests use a fake hook to pin the reconciler's HANDLING
// of that hook (the gate/preflight logic itself is proven in internal/grpcapi). The hook is
// a strict no-op unless hardware_v2 is latched; when unwired the reconciler behaves exactly
// as before, which is the load-bearing dormancy property for the production fleet.

func hwStarted(fake *libvirtfake.Fake, name string) bool {
	for _, e := range fake.EventLog() {
		if e.Domain == name && e.Op == "start" {
			return true
		}
	}
	return false
}

// Latched-equivalent refusal (hook returns FailedPrecondition, as it does for a blocked VM):
// the reconciler must NOT start the domain, must terminalize non-fatally (VM → error), and
// must not panic/wedge the loop.
func TestReconciler_HardwarePreStart_Refused_NonFatal(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	var hookVM string
	r.SetHardwareStartPreparer(func(_ context.Context, vm *corrosion.VMRecord) (func(), error) {
		hookVM = vm.Name
		return func() {}, status.Errorf(codes.FailedPrecondition, "hardware adoption is blocked; repair and re-audit")
	})

	r.startPendingVM(ctx, corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"})

	if hookVM != "vm1" {
		t.Fatalf("hook must be called with the VM record, got %q", hookVM)
	}
	if hwStarted(fake, "vm1") {
		t.Fatal("reconciler must NOT start a VM the hardware pre-start refused")
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.State != "error" {
		t.Fatalf("refused (non-retryable) failover start must leave the VM in error, got %+v", vm)
	}
	if !strings.Contains(vm.StateDetail, "hardware pre-start") {
		t.Errorf("state detail should explain the hardware refusal, got %q", vm.StateDetail)
	}
}

// The proof-lifecycle classifier: a blocked adoption / unacquirable device
// (FailedPrecondition) or malformed record (InvalidArgument) is an operator-repair
// condition → non-retryable (a proof-carrying failover terminalizes + errors rather than
// looping); a transient read/DB failure → retryable (re-armed for the next tick). (With no
// proof marker, failPendingStart errors either way — the classification is load-bearing
// only for proof-carrying transfers, where the existing retryable→pending path is exercised
// by the transient-cause tests already in this package.)
func TestHwPrepareRetryable(t *testing.T) {
	nonRetryable := []codes.Code{codes.FailedPrecondition, codes.InvalidArgument}
	for _, c := range nonRetryable {
		if hwPrepareRetryable(status.Errorf(c, "x")) {
			t.Errorf("%v must be non-retryable", c)
		}
	}
	retryable := []codes.Code{codes.Internal, codes.Unavailable, codes.DeadlineExceeded}
	for _, c := range retryable {
		if !hwPrepareRetryable(status.Errorf(c, "x")) {
			t.Errorf("%v must be retryable", c)
		}
	}
}

// Success path: the hook returns a release func and no error; the domain starts and the
// release func is NOT invoked (start succeeded).
func TestReconciler_HardwarePreStart_Success_StartsNoRelease(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	released := false
	r.SetHardwareStartPreparer(func(_ context.Context, _ *corrosion.VMRecord) (func(), error) {
		return func() { released = true }, nil
	})

	r.startPendingVM(ctx, corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"})

	if !hwStarted(fake, "vm1") {
		t.Fatal("reconciler must start the VM after a successful hardware pre-start")
	}
	if released {
		t.Fatal("release func must NOT be invoked when StartDomain succeeds")
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.State != "running" {
		t.Fatalf("VM should be running after a successful failover start, got %+v", vm)
	}
}

// Release-on-start-failure: the hook succeeded (acquired devices) but StartDomain then
// fails — the reconciler must invoke the release func so a failed start leaves no VM bound
// to passthrough it never used.
func TestReconciler_HardwarePreStart_ReleaseOnStartFailure(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	fake.FailStartDomain = func(string) error { return errors.New("libvirt start failed") }
	r := NewReconciler("node-a", t.TempDir(), db, fake)
	released := false
	r.SetHardwareStartPreparer(func(_ context.Context, _ *corrosion.VMRecord) (func(), error) {
		return func() { released = true }, nil
	})

	r.startPendingVM(ctx, corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"})

	if !released {
		t.Fatal("release func MUST be invoked when StartDomain fails after a successful pre-start")
	}
}

// The VMChecker's hardware pre-start hook wrapper is nil-safe (a no-op returning a no-op
// release when unwired) and forwards to the wired hook otherwise. The health-check /
// restart-policy call sites reach StartDomain only with a non-nil concrete *libvirt.Client
// (nil in unit tests), so the wrapper is the unit-testable seam for those two sites; the
// gate/preflight logic itself is proven in internal/grpcapi and the placement mirrors the
// reconciler's (covered above).
func TestVMChecker_HwPrepareStart_Wrapper(t *testing.T) {
	db := testStartDB(t)
	v := NewVMChecker("node-a", db, nil)

	// Unwired → no-op, non-nil release, no error.
	rel, err := v.hwPrepareStart(context.Background(), &corrosion.VMRecord{Name: "vm1"})
	if err != nil || rel == nil {
		t.Fatalf("unwired wrapper must be a no-op, got nil-release=%v err=%v", rel == nil, err)
	}
	rel() // must not panic

	// Wired → forwards the record and returns the hook's result.
	var gotVM string
	sentinel := status.Errorf(codes.FailedPrecondition, "blocked")
	v.SetHardwareStartPreparer(func(_ context.Context, vm *corrosion.VMRecord) (func(), error) {
		gotVM = vm.Name
		return func() {}, sentinel
	})
	if _, err := v.hwPrepareStart(context.Background(), &corrosion.VMRecord{Name: "vm2"}); err != sentinel {
		t.Fatalf("wired wrapper must forward the hook error, got %v", err)
	}
	if gotVM != "vm2" {
		t.Fatalf("wired wrapper must forward the VM record, got %q", gotVM)
	}
}

// Dormancy / back-compat: with NO hook wired (the pre-latch fleet, and every existing
// test), the reconciler defines + starts a pending VM exactly as before.
func TestReconciler_HardwarePreStart_Unwired_Unchanged(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake := libvirtfake.New()
	r := NewReconciler("node-a", t.TempDir(), db, fake) // no SetHardwareStartPreparer

	r.startPendingVM(ctx, corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: "{}", State: "pending"})

	if !hwStarted(fake, "vm1") {
		t.Fatal("with no hook wired, the reconciler must start the VM exactly as before")
	}
	vm, _ := corrosion.GetVM(ctx, db, "vm1")
	if vm == nil || vm.State != "running" {
		t.Fatalf("VM should be running, got %+v", vm)
	}
}
