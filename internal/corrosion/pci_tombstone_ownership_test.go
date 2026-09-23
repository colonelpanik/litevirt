package corrosion

import (
	"context"
	"testing"
	"time"
)

// ownerOf reads the vm_name currently recorded for a live device row.
func ownerOf(t *testing.T, c *Client, host, addr string) string {
	t.Helper()
	devs, err := ListPCIDevices(context.Background(), c, host, "")
	if err != nil {
		t.Fatalf("ListPCIDevices: %v", err)
	}
	for _, d := range devs {
		if d.Address == addr {
			return d.VMName
		}
	}
	t.Fatalf("device %s/%s not found among %d live rows", host, addr, len(devs))
	return ""
}

func seedPCIDevice(t *testing.T, c *Client, host, addr string) {
	t.Helper()
	if err := ObservePCIDevice(context.Background(), c, PCIDeviceRecord{
		HostName: host, Address: addr, VendorID: "10de", DeviceID: "1eb8",
		VendorName: "NVIDIA", DeviceName: "T4", Type: "gpu", IOMMUGroup: 42,
	}); err != nil {
		t.Fatalf("ObservePCIDevice(%s/%s): %v", host, addr, err)
	}
}

// TestSweepStrandedPCIOwnership_FreesADeviceWhoseVMIsGone is the #218
// regression.
//
// SoftDeletePCIDevice tombstones a vanished device WITHOUT clearing vm_name,
// and ObservePCIDevice deliberately preserves vm_name when it revives the row.
// So a device that disappears and comes back is live again and still owned by
// whatever VM held it — and if that VM has since been deleted, nothing ever
// clears the assignment. ClaimPCIDevice matches only `vm_name IS NULL OR
// vm_name = ”`, so the device matches zero rows forever.
//
// The preservation itself is CORRECT and must stay: a device can vanish from a
// scan transiently (driver reload, rescan race) while the VM is still using it,
// and clearing the owner there would let a second VM claim hardware that is in
// use. The missing piece is the sweeper — the issue says so — which clears an
// assignment only once its VM genuinely no longer exists.
func TestSweepStrandedPCIOwnership_FreesADeviceWhoseVMIsGone(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	seedPCIDevice(t, c, "host-a", "0000:41:00.0")
	if ok, err := ClaimPCIDevice(ctx, c, "host-a", "0000:41:00.0", "ghost-vm"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	// ghost-vm has no vms row at all — the VM was deleted while the device was
	// tombstoned, which is exactly how the row is stranded.

	cleared, err := SweepStrandedPCIOwnership(ctx, c, "host-a", 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(cleared) != 1 || cleared[0] != "0000:41:00.0" {
		t.Fatalf("sweep cleared %v, want [0000:41:00.0]", cleared)
	}
	if got := ownerOf(t, c, "host-a", "0000:41:00.0"); got != "" {
		t.Errorf("owner = %q, want cleared", got)
	}
	if ok, err := ClaimPCIDevice(ctx, c, "host-a", "0000:41:00.0", "vm2"); err != nil || !ok {
		t.Fatalf("the swept device must be claimable again: ok=%v err=%v", ok, err)
	}
}

// A device owned by a VM that DOES exist must never be swept — that is the
// double-assignment hazard the preservation rule exists to prevent.
func TestSweepStrandedPCIOwnership_LeavesALiveVMsDevice(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedPCIDevice(t, c, "host-a", "0000:41:00.0")
	if ok, err := ClaimPCIDevice(ctx, c, "host-a", "0000:41:00.0", "vm1"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}

	cleared, err := SweepStrandedPCIOwnership(ctx, c, "host-a", 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(cleared) != 0 {
		t.Fatalf("sweep cleared %v; vm1 is alive and using that device", cleared)
	}
	if got := ownerOf(t, c, "host-a", "0000:41:00.0"); got != "vm1" {
		t.Errorf("owner = %q, want vm1", got)
	}
}

// The age guard: a freshly written assignment is never swept, so a VM row that
// has not replicated to this node yet cannot have its device taken away.
func TestSweepStrandedPCIOwnership_RespectsTheAgeGuard(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	seedPCIDevice(t, c, "host-a", "0000:41:00.0")
	if ok, err := ClaimPCIDevice(ctx, c, "host-a", "0000:41:00.0", "brand-new-vm"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}

	cleared, err := SweepStrandedPCIOwnership(ctx, c, "host-a", time.Hour)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(cleared) != 0 {
		t.Fatalf("sweep cleared %v despite a 1h age guard on a just-written row", cleared)
	}
	if got := ownerOf(t, c, "host-a", "0000:41:00.0"); got != "brand-new-vm" {
		t.Errorf("owner = %q, want brand-new-vm", got)
	}
}

// A soft-deleted VM counts as gone: its device must be recoverable.
func TestSweepStrandedPCIOwnership_TreatsATombstonedVMAsGone(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "stopped"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedPCIDevice(t, c, "host-a", "0000:41:00.0")
	if ok, err := ClaimPCIDevice(ctx, c, "host-a", "0000:41:00.0", "vm1"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if err := DeleteVM(ctx, c, "vm1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	cleared, err := SweepStrandedPCIOwnership(ctx, c, "host-a", 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(cleared) != 1 {
		t.Fatalf("sweep cleared %v, want the tombstoned VM's device", cleared)
	}
}

// The sweep is scoped to one host: another host's rows are that host's to
// sweep, and only its daemon can see whether its hardware is really there.
func TestSweepStrandedPCIOwnership_IsScopedToTheHost(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	seedPCIDevice(t, c, "host-b", "0000:41:00.0")
	if ok, err := ClaimPCIDevice(ctx, c, "host-b", "0000:41:00.0", "ghost-vm"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}

	cleared, err := SweepStrandedPCIOwnership(ctx, c, "host-a", 0)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(cleared) != 0 {
		t.Fatalf("sweeping host-a touched host-b's rows: %v", cleared)
	}
	if got := ownerOf(t, c, "host-b", "0000:41:00.0"); got != "ghost-vm" {
		t.Errorf("host-b owner = %q, want untouched", got)
	}
}

// The production combination, which nothing above exercised: a real sweep age
// AND a device that was just observed.
//
// Every other test here passes minAge=0, which disables the age guard outright.
// RescanHost passes DefaultPCIOwnershipSweepAge (15m), and it calls
// ObservePCIDevice for every scanned device immediately before the sweep — and
// that upsert's ON CONFLICT path sets `updated_at = excluded.updated_at` from
// c.NowTS(). So in production every device still physically present carries an
// `updated_at` of milliseconds old when the guard reads it, `ts.After(cutoff)`
// is true, and the row is skipped. The only rows that could be old are devices
// missing from the scan, and the loop above has just soft-deleted those, so the
// sweep's `deleted_at IS NULL` filter excludes them too.
//
// Net effect before this fix: SweepStrandedPCIOwnership could never free an
// address on the one path that calls it, and #218 was not actually closed.
//
// The age guard is still right for what it was FOR — keeping a not-yet-
// replicated VM from having its device taken — but `updated_at` answers "when
// did we last see this hardware", not "how long has this ownership been
// stranded". A tombstone answers the real question directly: the delete
// replicated here, so the VM is provably gone and no amount of waiting changes
// that.
func TestSweepStrandedPCIOwnership_FreesATombstonedVMsDeviceDespiteAFreshObservation(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	if err := InsertVM(ctx, c, VMRecord{Name: "vm1", HostName: "host-a", State: "stopped"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedPCIDevice(t, c, "host-a", "0000:41:00.0")
	if ok, err := ClaimPCIDevice(ctx, c, "host-a", "0000:41:00.0", "vm1"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}
	if err := DeleteVM(ctx, c, "vm1"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	// What RescanHost does to every present device right before sweeping.
	seedPCIDevice(t, c, "host-a", "0000:41:00.0")

	cleared, err := SweepStrandedPCIOwnership(ctx, c, "host-a", DefaultPCIOwnershipSweepAge)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(cleared) != 1 || cleared[0] != "0000:41:00.0" {
		t.Fatalf("sweep cleared %v, want [0000:41:00.0]: the rescan refreshed updated_at, so "+
			"the age guard skipped a device whose owning VM is provably deleted — the sweep "+
			"can never free anything on the path that actually calls it", cleared)
	}
	if got := ownerOf(t, c, "host-a", "0000:41:00.0"); got != "" {
		t.Errorf("owner = %q, want cleared", got)
	}
	if ok, err := ClaimPCIDevice(ctx, c, "host-a", "0000:41:00.0", "vm2"); err != nil || !ok {
		t.Fatalf("the swept device must be claimable again: ok=%v err=%v", ok, err)
	}
}

// The age guard must survive the fix: a VM with NO row at all is ambiguous —
// it may simply not have replicated here yet — so its device stays owned.
// Only a tombstone is proof of absence.
func TestSweepStrandedPCIOwnership_AnAbsentVMRowStillRespectsTheAgeGuard(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)

	seedPCIDevice(t, c, "host-a", "0000:41:00.0")
	if ok, err := ClaimPCIDevice(ctx, c, "host-a", "0000:41:00.0", "not-yet-replicated"); err != nil || !ok {
		t.Fatalf("claim: ok=%v err=%v", ok, err)
	}

	cleared, err := SweepStrandedPCIOwnership(ctx, c, "host-a", DefaultPCIOwnershipSweepAge)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if len(cleared) != 0 {
		t.Fatalf("sweep cleared %v; a VM with no row here may just not have replicated, "+
			"and taking its device is the double-assignment hazard the guard exists for", cleared)
	}
}
