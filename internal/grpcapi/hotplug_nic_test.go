package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// NIC hotplug tests reuse the disk suite's server/gate helpers verbatim
// (hotplugDiskServer, setDeviceGate, enableHardwareV2, mustGetVM — see
// hotplug_disk_test.go) since they are already generic, not disk-specific.

// seedNICVM inserts a VM with a minimal spec (no disks/NICs) — a NIC attach/detach
// reconcile doesn't need a pre-existing disk the way the disk suite's seedDiskVM
// gives disk attach a realistic base.
func seedNICVM(t *testing.T, s *Server, name, state string) {
	t.Helper()
	insertTestVMWithSpec(t, adminCtx(), s.db, name, "test-host", state,
		seedSpecJSON(t, &pb.VMSpec{Name: name, Cpu: 2, MemoryMib: 4096}))
}

func hasNICMac(nics []corrosion.NICRecord, mac string) bool {
	for _, n := range nics {
		if strings.EqualFold(n.MAC, mac) {
			return true
		}
	}
	return false
}

func findNIC(nics []corrosion.NICRecord, mac string) (corrosion.NICRecord, bool) {
	for _, n := range nics {
		if strings.EqualFold(n.MAC, mac) {
			return n, true
		}
	}
	return corrosion.NICRecord{}, false
}

// liveNICRows reads table ("vm_nics" or "vm_interfaces") directly (bypassing the
// MergedVMNICs overlay) and returns only the live (non-tombstoned) rows — used to
// assert exactly which table(s) a dual-write landed in.
func liveNICRows(t *testing.T, ctx context.Context, s *Server, table, vmName string) []corrosion.NICRecord {
	t.Helper()
	rows, err := corrosion.GetVMNICsRaw(ctx, s.db, table, vmName)
	if err != nil {
		t.Fatalf("GetVMNICsRaw(%s): %v", table, err)
	}
	var live []corrosion.NICRecord
	for _, r := range rows {
		if r.DeletedAt == "" {
			live = append(live, r)
		}
	}
	return live
}

// failingFWReconciler is a FirewallReconciler stub whose Reconcile always fails —
// used to exercise the fail-closed "refuse attach if the isolation drop hasn't
// applied" invariant (§12) without touching real nftables.
type failingFWReconciler struct{ err error }

func (f failingFWReconciler) Reconcile(context.Context) error { return f.err }
func (f failingFWReconciler) LastError() error                { return f.err }
func (f failingFWReconciler) LastTick() time.Time             { return time.Time{} }

// ── attach: stopped realizes (hardware_v2 latched) ───────────────────────────

func TestAttachDevice_StoppedNICRealized(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "stopped")

	out, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{
			Name: "lan", Mac: "52:54:00:aa:00:01", SecurityGroups: []string{"web", "db"},
		},
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if out == nil {
		t.Fatal("nil VM returned")
	}
	nics, _ := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	nic, ok := findNIC(nics, "52:54:00:aa:00:01")
	if !ok {
		t.Fatalf("vm_nics row for the NIC not written: %+v", nics)
	}
	if nic.NetworkName != "lan" {
		t.Fatalf("network_name = %q, want lan", nic.NetworkName)
	}
	// Security groups persisted (the known gap the brief calls out).
	var sgs []string
	if err := json.Unmarshal([]byte(nic.SecurityGroups), &sgs); err != nil {
		t.Fatalf("security_groups not valid JSON: %q (err=%v)", nic.SecurityGroups, err)
	}
	if len(sgs) != 2 || sgs[0] != "web" || sgs[1] != "db" {
		t.Fatalf("security_groups = %v, want [web db]", sgs)
	}
	// The NIC must appear in the reconciled inactive definition.
	xml := s.virt.(*libvirtfake.Fake).DefinedXML("vm1")
	if !nicMacInXML(xml, "52:54:00:aa:00:01") {
		t.Fatalf("attached nic absent from reconciled XML:\n%s", xml)
	}
}

// ── attach: running makes a live call + commits the row ───────────────────────

func TestAttachDevice_RunningNICLiveAttach(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	out, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:aa:00:02"},
	})
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	if out == nil {
		t.Fatal("nil VM returned")
	}
	if n := fake.AttachNICCount(); n != 1 {
		t.Fatalf("live AttachNIC called %d times, want 1", n)
	}
	nics, _ := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	if !hasNICMac(nics, "52:54:00:aa:00:02") {
		t.Fatalf("row not committed after running attach: %+v", nics)
	}
}

// TestAttachDevice_NICFirewallReconcileFailsClosed models the §12 invariant: a
// network provision that succeeds but whose firewall/isolation drop does NOT apply
// must fail the attach rather than silently plug into a reachable bridge. Uses an
// "sriov" network (network.Provision's sriov case is a pure PF-name lookup — no
// real system calls) so the test never touches host networking.
func TestAttachDevice_NICFirewallReconcileFailsClosed(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")

	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{
		Name: "sriovnet", Type: "sriov", Config: `{"pf":"eth-pf0"}`,
	}); err != nil {
		t.Fatalf("seed network: %v", err)
	}
	s.fwReconciler = failingFWReconciler{err: errors.New("nft apply failed")}

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "sriovnet", Mac: "52:54:00:aa:00:03"},
	})
	if err == nil {
		t.Fatal("a firewall-reconcile failure after provisioning must fail the attach")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v, want Internal", status.Code(err))
	}
	fake := s.virt.(*libvirtfake.Fake)
	if n := fake.AttachNICCount(); n != 0 {
		t.Fatalf("AttachNIC must not be called when firewall reconcile fails, got %d calls", n)
	}
	nics, _ := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	if len(nics) != 0 {
		t.Fatalf("no NIC row should exist after a firewall-reconcile failure: %+v", nics)
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after a clean pre-mutation failure: %q", vm.ActiveOperationID)
	}
}

// ── protocol prerequisite / hardware_v2 gate ──────────────────────────────────

func TestAttachDevice_NICProtocolInactiveRejected(t *testing.T) {
	s := hotplugDiskServer(t) // no gate → operation_protocol_v1 inactive
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
}

func TestAttachDevice_NICStoppedRejectedWithoutHardwareV2(t *testing.T) {
	s := hotplugDiskServer(t)
	setDeviceGate(s, true, false) // protocol active, hardware_v2 NOT latched
	ctx := adminCtx()

	seedNICVM(t, s, "stopped-vm", "stopped")
	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "stopped-vm", Nic: &pb.NetworkAttachment{Name: "lan"},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stopped attach without hardware_v2: code = %v, want FailedPrecondition", status.Code(err))
	}
	if !strings.Contains(status.Convert(err).Message(), "hardware_v2") {
		t.Fatalf("expected a hardware_v2 message, got: %v", err)
	}

	// Running still works (protocol active is enough for live hotplug).
	seedNICVM(t, s, "running-vm", "running")
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "running-vm", Nic: &pb.NetworkAttachment{Name: "lan"},
	}); err != nil {
		t.Fatalf("running attach with protocol active should succeed: %v", err)
	}
}

// ── pre-latch dual-write / latched cutover (§4.2, §8) ─────────────────────────

func TestNICPreLatchDualWrite_AttachAndDetach(t *testing.T) {
	s := hotplugDiskServer(t)
	setDeviceGate(s, true, false) // protocol active, hardware_v2 NOT latched
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")

	const mac = "52:54:00:bb:00:01"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: mac},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if legacy := liveNICRows(t, ctx, s, "vm_interfaces", "vm1"); len(legacy) != 1 {
		t.Fatalf("pre-latch attach must dual-write vm_interfaces, got %d live rows", len(legacy))
	}
	if nics := liveNICRows(t, ctx, s, "vm_nics", "vm1"); len(nics) != 1 {
		t.Fatalf("pre-latch attach must also write vm_nics, got %d live rows", len(nics))
	}

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", NicMac: mac}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if legacy := liveNICRows(t, ctx, s, "vm_interfaces", "vm1"); len(legacy) != 0 {
		t.Fatalf("pre-latch detach must tombstone vm_interfaces too, got %d live rows", len(legacy))
	}
	if nics := liveNICRows(t, ctx, s, "vm_nics", "vm1"); len(nics) != 0 {
		t.Fatalf("pre-latch detach must tombstone vm_nics, got %d live rows", len(nics))
	}
}

func TestNICLatchedSkipsLegacyWrite_AttachAndDetach(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")

	const mac = "52:54:00:bb:00:02"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: mac},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if legacy := liveNICRows(t, ctx, s, "vm_interfaces", "vm1"); len(legacy) != 0 {
		t.Fatalf("latched attach must NOT write legacy vm_interfaces, got %d live rows", len(legacy))
	}
	if nics := liveNICRows(t, ctx, s, "vm_nics", "vm1"); len(nics) != 1 {
		t.Fatalf("latched attach must write vm_nics, got %d live rows", len(nics))
	}

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", NicMac: mac}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if nics := liveNICRows(t, ctx, s, "vm_nics", "vm1"); len(nics) != 0 {
		t.Fatalf("latched detach must tombstone vm_nics, got %d live rows", len(nics))
	}
}

// ── same-network duplicate: gated on the latch ────────────────────────────────

func TestAttachDevice_NICSameNetworkDuplicateRejectedPreLatch(t *testing.T) {
	s := hotplugDiskServer(t)
	setDeviceGate(s, true, false) // NOT latched
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:cc:00:01"},
	}); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:cc:00:02"},
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("second NIC on the same network pre-latch: code = %v, want AlreadyExists", status.Code(err))
	}
}

func TestAttachDevice_NICSameNetworkDuplicateAllowedPostLatch(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s) // latched
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:cc:00:03"},
	}); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:cc:00:04"},
	}); err != nil {
		t.Fatalf("second NIC on the same network post-latch should be allowed: %v", err)
	}
	nics, _ := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	if !hasNICMac(nics, "52:54:00:cc:00:03") || !hasNICMac(nics, "52:54:00:cc:00:04") {
		t.Fatalf("both same-network NICs should be present: %+v", nics)
	}
}

func TestAttachDevice_NICDuplicateMACRejected(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:dd:00:01"},
	}); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "other-lan", Mac: "52:54:00:dd:00:01"},
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("duplicate mac (even on a different network): code = %v, want AlreadyExists", status.Code(err))
	}
}

// ── mutation error → operation failure + rollback ─────────────────────────────

func TestAttachDevice_NICMutationErrorRollsBack(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	fake.FailAttachNIC = func(_, _, _, _ string) error { return status.Error(codes.Internal, "boom") }

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:ee:00:01"},
	})
	if err == nil {
		t.Fatal("expected the live-attach failure to surface as an RPC error")
	}
	nics, _ := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	if hasNICMac(nics, "52:54:00:ee:00:01") {
		t.Fatalf("row must not survive a failed attach: %+v", nics)
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after clean rollback: %q", vm.ActiveOperationID)
	}
}

// ── DB error is surfaced, not silently logged ─────────────────────────────────

// TestAttachDevice_NICMembershipReadErrorSurfaced: a DB error on the pre-mutation
// membership read (MergedVMNICs, which reads BOTH vm_nics and vm_interfaces) must
// fail the op fail-closed BEFORE any mutation — no live attach, no row.
func TestAttachDevice_NICMembershipReadErrorSurfaced(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	if err := s.db.Execute(ctx, `DROP TABLE vm_nics`); err != nil {
		t.Fatalf("drop vm_nics: %v", err)
	}

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:ee:00:02"},
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("a membership-read error must surface as Internal, got: %v", err)
	}
	fake := s.virt.(*libvirtfake.Fake)
	if n := fake.AttachNICCount(); n != 0 {
		t.Fatalf("a pre-mutation read failure must not reach the live attach, got %d calls", n)
	}
}

// TestAttachDevice_NICRowWriteErrorRollsBackLiveAttach: the row write (UpsertNIC)
// fails AFTER the live attach has already landed — a BEFORE INSERT trigger fails
// only the write, not the membership read's SELECT, isolating this from the
// pre-mutation read-failure case above. The rollback must inverse-detach the live
// NIC exactly once and leave no row.
func TestAttachDevice_NICRowWriteErrorRollsBackLiveAttach(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	if err := s.db.Execute(ctx,
		`CREATE TRIGGER nic_insert_fail BEFORE INSERT ON vm_nics BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatalf("create failing trigger: %v", err)
	}

	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:ee:00:03"},
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("a vm_nics INSERT error must surface as Internal, got: %v", err)
	}
	fake := s.virt.(*libvirtfake.Fake)
	if n := fake.AttachNICCount(); n != 1 {
		t.Fatalf("the live attach must have run once before the write failed, got %d calls", n)
	}
	if n := fake.DetachNICCount(); n != 1 {
		t.Fatalf("rollback must inverse-detach the live NIC exactly once, got %d detach calls", n)
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after clean rollback: %q", vm.ActiveOperationID)
	}
}

// ── concurrency: same idempotency key → at-most-once ──────────────────────────

func TestAttachDevice_NICSameKeyConcurrentAtMostOnce(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	const key = "nic-fixed-key-123"
	var wg sync.WaitGroup
	var okCount int32
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
				VmName: "vm1", IdempotencyKey: key,
				Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:ff:00:01"},
			})
			if err == nil {
				atomic.AddInt32(&okCount, 1)
			}
		}()
	}
	wg.Wait()

	if n := fake.AttachNICCount(); n != 1 {
		t.Fatalf("at-most-once violated: live AttachNIC called %d times, want exactly 1", n)
	}
	nics, _ := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	count := 0
	for _, n := range nics {
		if strings.EqualFold(n.MAC, "52:54:00:ff:00:01") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("duplicate/absent row: %d matching rows, want 1", count)
	}
	if okCount < 1 {
		t.Fatal("at least one concurrent attach must succeed")
	}
}

// TestAttachDevice_NICSameKeyReplaysCompleted: a second call with the same key after
// the first completed replays the recorded result WITHOUT a second live attach.
func TestAttachDevice_NICSameKeyReplaysCompleted(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	const key = "nic-replay-key"
	req := &pb.AttachDeviceRequest{
		VmName: "vm1", IdempotencyKey: key,
		Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:ff:00:02"},
	}
	if _, err := s.AttachDevice(ctx, req); err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if _, err := s.AttachDevice(ctx, req); err != nil {
		t.Fatalf("replay attach: %v", err)
	}
	if n := fake.AttachNICCount(); n != 1 {
		t.Fatalf("replay re-executed: AttachNIC called %d times, want 1", n)
	}
}

// TestAttachNICOwner_AtMostOnce exercises the OWNER-side at-most-once claim
// directly (mirrors TestAttachDiskOwner_AtMostOnce), bypassing the entry
// idempotency layer.
func TestAttachNICOwner_AtMostOnce(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	req := &pb.AttachDeviceRequest{VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: "52:54:00:ff:00:03"}}
	opID := corrosion.DeterministicOperationID("AttachDevice", "admin@local", "_default", "vm1", "owner-key")
	reqHash := attachNICRequestHash("vm1", req.Nic)

	if _, err := s.attachNICOwner(ctx, req, "vm1", opID, reqHash, "owner-key"); err != nil {
		t.Fatalf("first owner attach: %v", err)
	}
	if _, err := s.attachNICOwner(ctx, req, "vm1", opID, reqHash, "owner-key"); err != nil {
		t.Fatalf("second owner attach (should replay completed): %v", err)
	}
	if n := fake.AttachNICCount(); n != 1 {
		t.Fatalf("owner at-most-once violated: AttachNIC called %d times, want 1", n)
	}
	// A DIFFERENT request hash on the SAME key is a conflict → InvalidArgument.
	_, err := s.attachNICOwner(ctx, req, "vm1", opID, "different-hash", "owner-key")
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("same op id + different hash: code = %v, want InvalidArgument", status.Code(err))
	}
}

// ── detach: not found, running mutation both-state verify ────────────────────

func TestDetachDevice_NICNotFound(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", NicMac: "52:54:00:00:00:99"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", status.Code(err))
	}
}

func TestAttachDevice_NICRunningVerifiesLiveAndPersistent(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	const mac = "52:54:00:ab:00:01"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: mac},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	live, err := fake.DumpXML("vm1")
	if err != nil {
		t.Fatalf("dump live: %v", err)
	}
	if !nicMacInXML(live, mac) {
		t.Fatalf("nic %s absent from the live domain:\n%s", mac, live)
	}
	inactive, err := fake.DumpXMLInactive("vm1")
	if err != nil {
		t.Fatalf("dump inactive: %v", err)
	}
	if !nicMacInXML(inactive, mac) {
		t.Fatalf("nic %s absent from the persistent definition:\n%s", mac, inactive)
	}
}

// TestAttachDevice_NICRunningConfigDivergenceRollsBack models a live-succeeded-but-
// config-not-applied divergence: the NIC lands in the live domain but never reaches
// the persistent config. The both-state verify must catch it and roll the attach
// back to a clean state.
func TestAttachDevice_NICRunningConfigDivergenceRollsBack(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	// A running domain always has a persistent definition; seed one explicitly so a
	// live-only attach is a genuine reads-succeed-but-membership-wrong divergence.
	fake.SetInactiveXML("vm1", "<domain type='kvm'><name>vm1</name><devices></devices></domain>")
	fake.SkipConfigOnNICMutation = true // live lands, persistent config does NOT

	const mac = "52:54:00:ab:00:02"
	_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: mac},
	})
	if err == nil {
		t.Fatal("a config-vs-live divergence on a running attach must fail verification, not complete")
	}
	nics, _ := corrosion.MergedVMNICs(ctx, s.db, "vm1")
	if hasNICMac(nics, mac) {
		t.Fatalf("row must not survive a rolled-back attach: %+v", nics)
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("mutation barrier not cleared after rollback: %q", vm.ActiveOperationID)
	}
}

// TestDetachDevice_NICRunningConfigDivergenceCaught models a live-succeeded-but-
// config-retained divergence on detach: the NIC leaves the live domain but lingers
// in the persistent config. The both-state verify must catch it.
func TestDetachDevice_NICRunningConfigDivergenceCaught(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)

	const mac = "52:54:00:ab:00:03"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: mac},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}

	fake.SkipConfigOnNICMutation = true // live detach lands, persistent config keeps it
	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", NicMac: mac})
	if err == nil {
		t.Fatal("a config-vs-live divergence on a running detach must fail verification, not complete")
	}
	live, _ := fake.DumpXML("vm1")
	if nicMacInXML(live, mac) {
		t.Fatalf("nic %s should be gone from the live domain: %s", mac, live)
	}
	inactive, _ := fake.DumpXMLInactive("vm1")
	if !nicMacInXML(inactive, mac) {
		t.Fatalf("test setup: persistent config should still list %s (the modeled divergence)", mac)
	}
}
