package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The bug these pin, found on a real 4-node cluster and NOT by any in-process
// test: `lv detach-disk` failed with
//
//	disk detach for "e2e-vm-23" could not be verified; left recoverable:
//	disk vdb still present in the live domain after detach
//
// libvirt had done nothing wrong. Device unplug is asynchronous and requires
// guest cooperation — the API "returns success after some timeout even if the
// device was not unplugged yet" (virsh detach-device, "Quirk") — so a successful
// DetachDisk means the unplug was REQUESTED. verifyDiskDetached then read the
// live domain ONCE, immediately, and reported a guest that had not yet
// acknowledged as a detach that had failed.
//
// Every in-process test missed it because libvirtfake removed the device inside
// DetachDisk, synchronously: the fake defined away the very window the verifier
// had to wait through. libvirtfake.DeferLiveUnplug restores that window, so these
// tests fail against a verifier that does not wait. The NIC and PCI verifiers had
// the identical single-read shape — NIC unplug simply tends to win the race that
// disk unplug loses — so the NIC case is pinned here too.

const unplugDiskDomainXML = `<domain type='kvm'><devices>
  <disk type='file' device='disk'>
    <source file='/var/lib/litevirt/disks/vm1-root.qcow2'/>
    <target dev='vda' bus='virtio'/>
  </disk>
  <disk type='file' device='disk'>
    <source file='/var/lib/litevirt/disks/vm1-data.qcow2'/>
    <target dev='vdb' bus='virtio'/>
  </disk>
</devices></domain>`

const unplugNICDomainXML = `<domain type='kvm'><devices>
  <interface type='bridge'>
    <mac address='52:54:00:AA:BB:CC'/>
    <source bridge='br0'/>
  </interface>
</devices></domain>`

// fastUnplugWait shortens the poll loop so a timeout case costs milliseconds, and
// restores the package defaults afterwards.
func fastUnplugWait(t *testing.T, timeout time.Duration) {
	t.Helper()
	origTimeout, origInterval := DeviceUnplugTimeout, DeviceUnplugPollInterval
	DeviceUnplugTimeout, DeviceUnplugPollInterval = timeout, 5*time.Millisecond
	t.Cleanup(func() {
		DeviceUnplugTimeout, DeviceUnplugPollInterval = origTimeout, origInterval
	})
}

func TestVerifyDiskDetached_WaitsForGuestAcknowledgement(t *testing.T) {
	s := hotplugDiskServer(t)
	fake := hotplugFake(t, s)
	fake.DeferLiveUnplug = true
	fastUnplugWait(t, 5*time.Second)

	fake.SetDiskSource("vm1", "vda", "/var/lib/litevirt/disks/vm1-root.qcow2")
	fake.SetDiskSource("vm1", "vdb", "/var/lib/litevirt/disks/vm1-data.qcow2")
	fake.SetInactiveXML("vm1", unplugDiskDomainXML)

	if err := s.virt.DetachDisk("vm1", "vdb"); err != nil {
		t.Fatalf("DetachDisk: %v", err)
	}

	// Guard against a vacuous pass: if the fake removed the disk synchronously
	// there is no window to wait through and this test proves nothing.
	if got := fake.PendingUnplugs("vm1"); got != 1 {
		t.Fatalf("fake must hold the live removal pending, got %d — the async window is not being modeled", got)
	}
	srcs, err := s.virt.DomainDiskSources("vm1")
	if err != nil {
		t.Fatalf("DomainDiskSources: %v", err)
	}
	if _, present := srcs["vdb"]; !present {
		t.Fatal("vdb must still be in the live view before the guest acknowledges")
	}

	// The guest acknowledges shortly after verification begins.
	go func() {
		time.Sleep(40 * time.Millisecond)
		fake.AckLiveUnplug("vm1")
	}()

	if err := s.verifyDiskDetached(context.Background(), "vm1", "vdb", true); err != nil {
		t.Fatalf("verification must wait for the guest to acknowledge the unplug, got: %v", err)
	}
}

func TestVerifyDiskDetached_FailsWhenGuestNeverAcknowledges(t *testing.T) {
	s := hotplugDiskServer(t)
	fake := hotplugFake(t, s)
	fake.DeferLiveUnplug = true
	fastUnplugWait(t, 80*time.Millisecond)

	fake.SetDiskSource("vm1", "vda", "/var/lib/litevirt/disks/vm1-root.qcow2")
	fake.SetDiskSource("vm1", "vdb", "/var/lib/litevirt/disks/vm1-data.qcow2")
	fake.SetInactiveXML("vm1", unplugDiskDomainXML)

	if err := s.virt.DetachDisk("vm1", "vdb"); err != nil {
		t.Fatalf("DetachDisk: %v", err)
	}

	// Never acknowledged: a guest that refuses or stalls the unplug indefinitely
	// is still a failed detach, and the wait must not paper over it.
	err := s.verifyDiskDetached(context.Background(), "vm1", "vdb", true)
	if err == nil {
		t.Fatal("a never-acknowledged unplug must fail verification, not pass")
	}
	if !strings.Contains(err.Error(), "still present in the live domain after detach") {
		t.Fatalf("timeout must keep the operator-facing wording, got: %v", err)
	}
}

func TestVerifyDiskDetached_CancelledContextStopsTheWait(t *testing.T) {
	s := hotplugDiskServer(t)
	fake := hotplugFake(t, s)
	fake.DeferLiveUnplug = true
	fastUnplugWait(t, 30*time.Second) // long enough that only cancellation ends it

	fake.SetDiskSource("vm1", "vdb", "/var/lib/litevirt/disks/vm1-data.qcow2")
	fake.SetInactiveXML("vm1", unplugDiskDomainXML)
	if err := s.virt.DetachDisk("vm1", "vdb"); err != nil {
		t.Fatalf("DetachDisk: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	if err := s.verifyDiskDetached(ctx, "vm1", "vdb", true); err == nil {
		t.Fatal("a cancelled caller must not be reported as a verified detach")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("wait ignored cancellation, took %v", elapsed)
	}
}

func TestVerifyNICDetached_WaitsForGuestAcknowledgement(t *testing.T) {
	s := hotplugDiskServer(t)
	fake := hotplugFake(t, s)
	fake.DeferLiveUnplug = true
	fastUnplugWait(t, 5*time.Second)

	const mac = "52:54:00:aa:bb:cc"
	fake.SetActiveXML("vm1", unplugNICDomainXML)
	fake.SetInactiveXML("vm1", unplugNICDomainXML)

	if err := s.virt.DetachNIC("vm1", mac); err != nil {
		t.Fatalf("DetachNIC: %v", err)
	}
	if got := fake.PendingUnplugs("vm1"); got != 1 {
		t.Fatalf("fake must hold the live removal pending, got %d", got)
	}

	go func() {
		time.Sleep(40 * time.Millisecond)
		fake.AckLiveUnplug("vm1")
	}()

	if err := s.verifyNICDetached(context.Background(), "vm1", mac, true); err != nil {
		t.Fatalf("NIC verification must wait for the guest ack, got: %v", err)
	}
}

// A synchronous backend must not pay for the wait: the fast path costs one read.
func TestVerifyDiskDetached_SynchronousUnplugReturnsImmediately(t *testing.T) {
	s := hotplugDiskServer(t)
	fake := hotplugFake(t, s)
	fastUnplugWait(t, 30*time.Second)

	fake.SetDiskSource("vm1", "vda", "/var/lib/litevirt/disks/vm1-root.qcow2")
	fake.SetInactiveXML("vm1", unplugDiskDomainXML)
	if err := s.virt.DetachDisk("vm1", "vdb"); err != nil {
		t.Fatalf("DetachDisk: %v", err)
	}

	start := time.Now()
	if err := s.verifyDiskDetached(context.Background(), "vm1", "vdb", true); err != nil {
		t.Fatalf("already-absent disk must verify immediately: %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("synchronous unplug paid for the wait: %v", elapsed)
	}
}
