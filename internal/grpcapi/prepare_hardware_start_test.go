package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"
)

// PrepareHardwareForStart is the shared adoption-gate + PCI-start-preflight the automated
// (re)start bypass paths (failover reconciler / health auto-restart / promote / restore)
// invoke so they honor hardware_v2 exactly like the manual startVMLocked path. These tests
// pin its contract directly.

// Dormant when not latched: even a blocked VM with a reserved PCI intent must return no
// error, a no-op release, and touch NOTHING (no vfio bind, no realization) — the
// load-bearing "zero behavior change until hardware_v2 latches" property.
func TestPrepareHardwareForStart_NotLatched_NoOp(t *testing.T) {
	s := hotplugDiskServer(t) // NOT latched (no enableHardwareV2)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	seedAddressIntent(t, s, "vm1", "dev-1", "0000:41:00.0")
	const reason = "hardware audit: passthrough device incompatible on this host"
	if err := corrosion.SetHardwareAdoptionState(ctx, s.db, "vm1", "blocked", reason); err != nil {
		t.Fatalf("set adoption state: %v", err)
	}

	vm, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	release, perr := s.PrepareHardwareForStart(ctx, vm)
	if perr != nil {
		t.Fatalf("pre-latch prepare must be a no-op, got error: %v", perr)
	}
	if release == nil {
		t.Fatal("release must be non-nil (a no-op func) on success")
	}
	release() // must not panic
	if fs.binds != 0 {
		t.Fatalf("pre-latch prepare must NOT bind vfio, got %d binds", fs.binds)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) != 0 {
		t.Fatalf("pre-latch prepare must NOT write realizations, got %d", len(rs))
	}
}

// Latched + blocked: refuse, carrying the stored adoption reason, with a no-op release.
func TestPrepareHardwareForStart_Latched_Blocked_Refuses(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	const reason = "hardware audit: passthrough device incompatible on this host"
	if err := corrosion.SetHardwareAdoptionState(ctx, s.db, "vm1", "blocked", reason); err != nil {
		t.Fatalf("set adoption state: %v", err)
	}

	vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
	release, perr := s.PrepareHardwareForStart(ctx, vm)
	if status.Code(perr) != codes.FailedPrecondition {
		t.Fatalf("blocked+latched: want FailedPrecondition, got %v", perr)
	}
	if perr == nil || !strings.Contains(perr.Error(), reason) {
		t.Fatalf("error must carry the stored adoption reason %q, got %v", reason, perr)
	}
	if release == nil {
		t.Fatal("release must be non-nil even on refusal")
	}
	release() // no-op, must not panic
}

// Latched + a reserved PCI intent: acquire the lease (vfio bind), persist the realization,
// and hand back a non-nil release — the preflight the automated paths must run before start.
func TestPrepareHardwareForStart_Latched_Intent_AcquiresRealizes(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	restore := vfio.SetFS(fs)
	defer restore()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	seedAddressIntent(t, s, "vm1", "dev-1", "0000:41:00.0")

	vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
	release, perr := s.PrepareHardwareForStart(ctx, vm)
	if perr != nil {
		t.Fatalf("prepare with intent: %v", perr)
	}
	if release == nil {
		t.Fatal("release must be non-nil after acquiring devices")
	}
	if fs.binds != 1 {
		t.Fatalf("want exactly 1 vfio bind, got %d", fs.binds)
	}
	rs := liveRealizations(t, ctx, s, "vm1")
	if len(rs) != 1 || rs[0].ResolvedAddress != "0000:41:00.0" {
		t.Fatalf("want 1 realization for the device, got %+v", rs)
	}
}

// A nil record fails closed (a programming error must not silently start something).
func TestPrepareHardwareForStart_NilVM(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	release, perr := s.PrepareHardwareForStart(adminCtx(), nil)
	if status.Code(perr) != codes.InvalidArgument {
		t.Fatalf("nil vm: want InvalidArgument, got %v", perr)
	}
	if release == nil {
		t.Fatal("release must be non-nil even on error")
	}
	release()
}

// Restore-autostart wiring is DORMANT for a fresh restore: with hardware_v2 latched, a
// freshly-restored VM (a new name → no reserved PCI intents, no prior adoption row) must
// still define + start exactly as before. This is the no-regression guard for the direct
// PrepareHardwareForStart call added to autoDefineRestoredVM — it must not block a normal
// restore. (The refusal path itself is covered by TestPrepareHardwareForStart_* above:
// the RPC-level refusal can't be constructed because a "blocked" adoption row requires a
// vms row, which a restore refuses first with AlreadyExists.)
func TestRestoreLive_AutoStart_Latched_FreshRestoreStarts(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake
	setDeviceGate(s, true, true) // latch operation_protocol_v1 + hardware_v2

	data := make([]byte, 4096)
	repoDir, ts := seedLiveRepo(t, data, testSpecJSON(t, "vm1"))
	target := t.TempDir() + "/live.qcow2"

	stream, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts,
		TargetPath: target, AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	defer cancel()
	_ = stream

	var defined, started bool
	for _, e := range fake.EventLog() {
		if e.Op == "define" && e.Domain == "vm1" {
			defined = true
		}
		if e.Op == "start" && e.Domain == "vm1" {
			started = true
		}
	}
	if !defined || !started {
		t.Errorf("latched fresh restore must define+start unchanged; events=%+v", fake.EventLog())
	}
	rec, err := corrosion.GetVM(context.Background(), s.db, "vm1")
	if err != nil || rec == nil || rec.State != "running" {
		t.Fatalf("restored VM must be running, got %+v (err %v)", rec, err)
	}
	cancel()
	<-done
}
