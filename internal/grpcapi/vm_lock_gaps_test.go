package grpcapi

import (
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// lockTestServer is testServerR2 plus a real (fake) libvirt backend and a
// dataDir, so the RPCs under test can run their actual bodies rather than
// nil-dereferencing on s.virt the moment they get past the lock.
func lockTestServer(t *testing.T) *Server {
	t.Helper()
	s := testServerR2(t)
	s.virt = libvirtfake.New()
	return s
}

// assertSerializedByVMLock runs call() while the per-VM lock for vmName is
// already held, and asserts the call does NOT get past the lock until it is
// released.
//
// "Did it block?" is the whole property. A destructive RPC that skips lockVM
// returns (or worse, completes its destruction) while another operation holds
// the VM, which is exactly the race these issues describe. The call's own
// error, if any, is irrelevant — only whether it waited.
func assertSerializedByVMLock(t *testing.T, s *Server, vmName string, call func()) {
	t.Helper()

	unlock := s.lockVM(vmName)

	started := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		call()
		close(done)
	}()
	<-started

	select {
	case <-done:
		t.Fatalf("the call completed while the %q lock was held — it does not take lockVM", vmName)
	case <-time.After(250 * time.Millisecond):
		// Still blocked, which is what we want.
	}

	unlock()

	select {
	case <-done:
		// Proceeded once the lock was free.
	case <-time.After(10 * time.Second):
		t.Fatalf("the call never completed after the %q lock was released", vmName)
	}
}

func seedLockableVM(t *testing.T, s *Server, name string) {
	t.Helper()
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: name, HostName: s.hostName, State: "stopped",
		Spec: `{"name":"` + name + `","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM(%s): %v", name, err)
	}
}

// TestRebuildVM_TakesTheVMLock is the #206 regression. RebuildVM destroys the
// domain, deletes every disk and wipes firmware state, and was the only
// destructive VM-lifecycle RPC in vm.go that took no lockVM — so it could run
// concurrently with a start, a resize or a migrate of the same VM.
func TestRebuildVM_TakesTheVMLock(t *testing.T) {
	s := lockTestServer(t)
	seedLockableVM(t, s, "rebuild-me")

	assertSerializedByVMLock(t, s, "rebuild-me", func() {
		_, _ = s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "rebuild-me"})
	})
}

// TestCreateSnapshot_TakesTheVMLock, TestRestoreSnapshot_TakesTheVMLock and
// TestDeleteSnapshot_TakesTheVMLock are the #208 regression. All three mutate
// the VM's disk chain, and all three ran unlocked — unlike every sibling
// mutator, including their own container twins in snapshot_container.go.
func TestCreateSnapshot_TakesTheVMLock(t *testing.T) {
	s := lockTestServer(t)
	seedLockableVM(t, s, "snap-create")

	assertSerializedByVMLock(t, s, "snap-create", func() {
		_, _ = s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "snap-create", Name: "s1"})
	})
}

func TestRestoreSnapshot_TakesTheVMLock(t *testing.T) {
	s := lockTestServer(t)
	seedLockableVM(t, s, "snap-restore")

	assertSerializedByVMLock(t, s, "snap-restore", func() {
		_, _ = s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "snap-restore", SnapshotName: "s1"})
	})
}

func TestDeleteSnapshot_TakesTheVMLock(t *testing.T) {
	s := lockTestServer(t)
	seedLockableVM(t, s, "snap-delete")

	assertSerializedByVMLock(t, s, "snap-delete", func() {
		_, _ = s.DeleteSnapshot(adminCtx(), &pb.DeleteSnapshotRequest{VmName: "snap-delete", SnapshotName: "s1"})
	})
}

// A lock on ONE VM must not serialize an operation on another — the lock is
// per-VM, and a coarser one would turn every snapshot into a cluster-wide
// bottleneck. Pins that the fix did not over-reach.
func TestSnapshotLock_DoesNotBlockADifferentVM(t *testing.T) {
	s := lockTestServer(t)
	seedLockableVM(t, s, "vm-a")
	seedLockableVM(t, s, "vm-b")

	unlock := s.lockVM("vm-a")
	defer unlock()

	done := make(chan struct{})
	go func() {
		_, _ = s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "vm-b", Name: "s1"})
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a snapshot of vm-b blocked on vm-a's lock — the lock is not per-VM")
	}
}

// TestAttachPCIDevice_TakesTheVMLock is the #210 regression. The legacy
// running-attach path (a non-address PCI selector: SR-IOV, type, vendor or
// mapping) reaches attachPCIDevice with no lock, while beginDeviceLease keys
// the durable crash anchor per-VM — so two concurrent attaches clobber the only
// record recovery has.
func TestAttachPCIDevice_TakesTheVMLock(t *testing.T) {
	s := lockTestServer(t)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "pci-vm", HostName: s.hostName, State: "running",
		Spec: `{"name":"pci-vm","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	assertSerializedByVMLock(t, s, "pci-vm", func() {
		_, _ = s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{
			VmName: "pci-vm",
			// A VENDOR selector, not a concrete address: that is what routes to
			// the legacy attachPCIDevice path rather than attachPCIEntry.
			PciDevice: &pb.DeviceSpec{Vendor: "10de"},
		})
	})
}

// The three barriers RebuildVM was missing (#206). Rebuild destroys the domain,
// deletes every disk and wipes firmware state, so each of these states means
// something else owns those disks right now. DeleteVM carries all three.

func TestRebuildVM_RefusesWhileAnOperationIsInFlight(t *testing.T) {
	s := lockTestServer(t)
	seedLockableVM(t, s, "busy")
	// InsertVM does not carry the barrier; claim it the way a real operation
	// does, so the guard is tested against a barrier the production path set.
	vm, err := corrosion.GetVM(adminCtx(), s.db, "busy")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %+v err=%v", vm, err)
	}
	applied, berr := s.db.BeginVMOperation(adminCtx(), corrosion.OperationRecord{
		ID: "op-123", Method: "RebuildVM", ResourceKind: "vm", ResourceID: "busy",
		OperationKind: "attach_disk",
	}, vm.Spec, vm.OwnerEpoch, vm.SpecGeneration)
	if berr != nil || !applied {
		t.Fatalf("BeginVMOperation: applied=%v err=%v", applied, berr)
	}
	_, rerr := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "busy"})
	if status.Code(rerr) != codes.FailedPrecondition {
		t.Fatalf("rebuild during an operation: got %v, want FailedPrecondition", rerr)
	}
	if _, ok := s.virt.(*libvirtfake.Fake); ok {
		if rec, _ := corrosion.GetVM(adminCtx(), s.db, "busy"); rec == nil {
			t.Error("the refused rebuild still removed the VM row")
		}
	}
}

func TestRebuildVM_RefusesDuringABackup(t *testing.T) {
	s := lockTestServer(t)
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "mid-backup", HostName: s.hostName, State: "backing-up",
		Spec: `{"name":"mid-backup","cpu":1,"memory_mib":512}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	_, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "mid-backup"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rebuild during a backup: got %v, want FailedPrecondition", err)
	}
}

// Rebuild has no --keep-disks, so a VM that still backs linked clones would
// take their backing file with it. DeleteVM offers an escape hatch and so may
// fail open on a read error; rebuild has none, so it fails CLOSED — a clone
// list that could not be read is not evidence there are none.
func TestRebuildVM_RefusesWhileItBacksLinkedClones(t *testing.T) {
	s := lockTestServer(t)
	// "golden" owns a disk; "clone1" is a linked-clone overlay on top of it.
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "golden", HostName: s.hostName, State: "stopped",
		Spec: `{"name":"golden","cpu":1,"memory_mib":512}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "golden", DiskName: "root", HostName: s.hostName,
		Path: "/var/lib/litevirt/golden-root.qcow2",
	}}); err != nil {
		t.Fatalf("InsertVM(golden): %v", err)
	}
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "clone1", HostName: s.hostName, State: "stopped",
		Spec: `{"name":"clone1","cpu":1,"memory_mib":512}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "clone1", DiskName: "root", HostName: s.hostName,
		Path:        "/var/lib/litevirt/clone1-root.qcow2",
		BackingDisk: "/var/lib/litevirt/golden-root.qcow2",
	}}); err != nil {
		t.Fatalf("InsertVM(clone1): %v", err)
	}

	_, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: "golden"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rebuild of a linked-clone source: got %v, want FailedPrecondition", err)
	}
	if rec, _ := corrosion.GetVM(adminCtx(), s.db, "clone1"); rec == nil {
		t.Error("the clone's row vanished")
	}
}
