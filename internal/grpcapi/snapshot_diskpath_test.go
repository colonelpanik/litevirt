package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func newDiskPathTestServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	fake := libvirtfake.New()
	return &Server{db: db, hostName: "host-a", virt: fake}, fake
}

// TestReconcileDiskPaths is the regression for the RAM-snapshot disk-divergence
// bug: a snapshot cuts the domain over to an overlay (<disk>.<snapname>), but
// the recorded vm_disks.path stayed at the canonical name, breaking
// backup/migration/restart. reconcileDiskPaths must sync the record to the live
// source by filename stem.
func TestReconcileDiskPaths(t *testing.T) {
	ctx := context.Background()
	s, fake := newDiskPathTestServer(t)

	canonical := "/var/lib/litevirt/disks/vm1-root.qcow2"
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "running"},
		nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "host-a", Path: canonical, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// Simulate a snapshot create cutting the domain onto an overlay.
	overlay := "/var/lib/litevirt/disks/vm1-root.s1"
	fake.SetDiskSource("vm1", "vda", overlay)

	s.reconcileDiskPaths(ctx, "vm1")

	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if len(disks) != 1 {
		t.Fatalf("disks = %d, want 1", len(disks))
	}
	if disks[0].Path != overlay {
		t.Errorf("recorded path = %q, want reconciled to live overlay %q", disks[0].Path, overlay)
	}

	// Idempotent: a second reconcile with the same live source is a no-op.
	s.reconcileDiskPaths(ctx, "vm1")
	disks, _ = corrosion.GetVMDisks(ctx, s.db, "vm1")
	if disks[0].Path != overlay {
		t.Errorf("second reconcile changed path to %q", disks[0].Path)
	}
}

// TestReconcileDiskPaths_IgnoresNonMatchingSource confirms an unrelated live
// source (e.g. the cloud-init cdrom, different stem) never rewrites a data disk.
func TestReconcileDiskPaths_IgnoresNonMatchingSource(t *testing.T) {
	ctx := context.Background()
	s, fake := newDiskPathTestServer(t)

	canonical := "/var/lib/litevirt/disks/vm2-root.qcow2"
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm2", HostName: "host-a", State: "running"},
		nil,
		[]corrosion.DiskRecord{{VMName: "vm2", DiskName: "root", HostName: "host-a", Path: canonical, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Only an ISO source on a different stem — must not touch the data disk.
	fake.SetDiskSource("vm2", "sda", "/var/lib/litevirt/cloudinit/vm2.iso")

	s.reconcileDiskPaths(ctx, "vm2")

	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm2")
	if disks[0].Path != canonical {
		t.Errorf("data disk path changed to %q; should stay %q", disks[0].Path, canonical)
	}
}

func TestDiskStem(t *testing.T) {
	cases := map[string]string{
		"/d/vm-root.qcow2": "/d/vm-root",
		"/d/vm-root.s1":    "/d/vm-root",
		"/d/vm-root":       "/d/vm-root",
	}
	for in, want := range cases {
		if got := diskStem(in); got != want {
			t.Errorf("diskStem(%q) = %q, want %q", in, got, want)
		}
	}
}
