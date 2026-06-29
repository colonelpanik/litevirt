package corrosion

import (
	"context"
	"testing"
)

// CountPoolsSharingResource is the teardown refcount. It must be driver/identity
// specific — not merely "same source" — so it doesn't (a) over-count an
// operator-managed NFS mount against a litevirt-derived one, nor (b) block two
// iSCSI pools that share an IQN but use different portals.
func TestCountPoolsSharingResource(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	mk := func(host, name, driver, source, target string, opts map[string]string) {
		if err := UpsertStoragePool(ctx, c, StoragePoolRecord{
			HostName: host, Name: name, Driver: driver, Source: source,
			Target: target, Options: opts, State: "active",
		}); err != nil {
			t.Fatalf("UpsertStoragePool %q: %v", name, err)
		}
	}
	count := func(rec StoragePoolRecord) int {
		n, err := CountPoolsSharingResource(ctx, c, rec)
		if err != nil {
			t.Fatalf("CountPoolsSharingResource: %v", err)
		}
		return n
	}

	// ── NFS ──────────────────────────────────────────────────────────────────
	// Two litevirt-owned (target='') NFS pools with the same source share the
	// DERIVED mountpoint → each sees the other.
	mk("h1", "nfsA", "nfs", "srv:/export", "", nil)
	mk("h1", "nfsB", "nfs", "srv:/export", "", nil)
	if got := count(StoragePoolRecord{HostName: "h1", Name: "nfsA", Driver: "nfs", Source: "srv:/export"}); got != 1 {
		t.Fatalf("NFS shared derived mount: got %d, want 1", got)
	}

	// An operator-managed pool (targetOverride set) on the same source mounts
	// ELSEWHERE — it must NOT count against the litevirt-owned unmount.
	mk("h1", "nfsOps", "nfs", "srv:/export", "/srv/shared", nil)
	if got := count(StoragePoolRecord{HostName: "h1", Name: "nfsA", Driver: "nfs", Source: "srv:/export"}); got != 1 {
		t.Fatalf("operator-managed pool must be excluded: got %d, want 1 (only nfsB)", got)
	}

	// Same source on a DIFFERENT host is unrelated (pools are host-local).
	mk("h2", "nfsC", "nfs", "srv:/export", "", nil)
	if got := count(StoragePoolRecord{HostName: "h1", Name: "nfsA", Driver: "nfs", Source: "srv:/export"}); got != 1 {
		t.Fatalf("other host must not count: got %d, want 1", got)
	}

	// ── iSCSI ────────────────────────────────────────────────────────────────
	// Same IQN + same portal = same session → counts.
	mk("h1", "iscA", "iscsi", "iqn.x:lun0", "", map[string]string{"portal": "10.0.0.1"})
	mk("h1", "iscB", "iscsi", "iqn.x:lun0", "", map[string]string{"portal": "10.0.0.1"})
	if got := count(StoragePoolRecord{HostName: "h1", Name: "iscA", Driver: "iscsi", Source: "iqn.x:lun0", Options: map[string]string{"portal": "10.0.0.1"}}); got != 1 {
		t.Fatalf("iSCSI same IQN+portal: got %d, want 1", got)
	}

	// Same IQN, DIFFERENT portal = distinct sessions → must NOT block each other.
	mk("h1", "iscC", "iscsi", "iqn.x:lun0", "", map[string]string{"portal": "10.0.0.2"})
	if got := count(StoragePoolRecord{HostName: "h1", Name: "iscC", Driver: "iscsi", Source: "iqn.x:lun0", Options: map[string]string{"portal": "10.0.0.2"}}); got != 0 {
		t.Fatalf("different portal must not count: got %d, want 0", got)
	}

	// Empty/absent portal normalizes to the driver default 127.0.0.1 on both sides.
	mk("h1", "iscD", "iscsi", "iqn.y:lun0", "", nil)
	mk("h1", "iscE", "iscsi", "iqn.y:lun0", "", map[string]string{"portal": "127.0.0.1"})
	if got := count(StoragePoolRecord{HostName: "h1", Name: "iscD", Driver: "iscsi", Source: "iqn.y:lun0"}); got != 1 {
		t.Fatalf("default portal normalization: got %d, want 1", got)
	}

	// ── no-op drivers ─────────────────────────────────────────────────────────
	mk("h1", "locA", "local", "", "/data/a", nil)
	mk("h1", "locB", "local", "", "/data/b", nil)
	if got := count(StoragePoolRecord{HostName: "h1", Name: "locA", Driver: "local"}); got != 0 {
		t.Fatalf("non-teardown driver: got %d, want 0", got)
	}
}
