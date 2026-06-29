package storage

import (
	"context"
	"errors"
	"testing"
)

// AsTeardowner returns nil for drivers that have nothing host-level to undo.
func TestAsTeardowner_NoOpDrivers(t *testing.T) {
	for _, drv := range []Driver{
		&localDriver{dataDir: t.TempDir()},
		&dirDriver{path: t.TempDir()},
		&cephDriver{pool: "rbd"},
		&zfsDriver{dataset: "tank/vm"},
		&btrfsDriver{subvolRoot: "/btr"},
		&lvmThinDriver{vg: "vg0"},
	} {
		if td := AsTeardowner(drv); td != nil {
			t.Errorf("%s: AsTeardowner should be nil (no teardown), got %T", drv.String(), td)
		}
	}
}

// NFS Teardown unmounts a litevirt-owned mountpoint when it's mounted.
func TestNFSTeardown_UnmountsWhenMounted(t *testing.T) {
	run, calls := stubRunner(func(sub string) ([]byte, error) {
		// mountpoint -q exits 0 (mounted); umount succeeds.
		return nil, nil
	})
	d := &nfsDriver{source: "srv:/export", mountBase: "/var/mnt", run: run}
	if td := AsTeardowner(d); td == nil {
		t.Fatal("nfs driver must implement Teardowner")
	}
	if err := d.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	subs := subcommands(*calls)
	if !hasSub([]string{(*calls)[0].name}, "mountpoint") {
		t.Fatalf("expected a mountpoint probe, got %+v", *calls)
	}
	// The umount call uses program name "umount" (args[0] is the path), so check names.
	var sawUmount bool
	for _, c := range *calls {
		if c.name == "umount" {
			sawUmount = true
		}
	}
	if !sawUmount {
		t.Fatalf("expected umount, calls=%+v subs=%v", *calls, subs)
	}
}

// NFS Teardown is a no-op when the path is not mounted (mountpoint -q fails).
func TestNFSTeardown_NoOpWhenNotMounted(t *testing.T) {
	run, calls := stubRunner(func(sub string) ([]byte, error) {
		return nil, errors.New("not a mountpoint") // mountpoint -q non-zero
	})
	d := &nfsDriver{source: "srv:/export", mountBase: "/var/mnt", run: run}
	if err := d.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	for _, c := range *calls {
		if c.name == "umount" {
			t.Fatalf("must NOT umount when not mounted; calls=%+v", *calls)
		}
	}
}

// NFS Teardown skips an operator-managed mount (targetOverride set) entirely —
// no mountpoint probe, no umount of a shared path we didn't create.
func TestNFSTeardown_SkipsOperatorManagedMount(t *testing.T) {
	run, calls := stubRunner(func(sub string) ([]byte, error) { return nil, nil })
	d := &nfsDriver{source: "srv:/export", targetOverride: "/srv/shared", run: run}
	if err := d.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("operator-managed mount must not be touched; calls=%+v", *calls)
	}
}

// iSCSI Teardown logs out of the target.
func TestISCSITeardown_Logout(t *testing.T) {
	run, calls := stubRunner(func(sub string) ([]byte, error) { return nil, nil })
	d := &iscsiDriver{target: "iqn.2020-01.com.example:lun0", opts: map[string]string{"portal": "10.0.0.1"}, run: run}
	if td := AsTeardowner(d); td == nil {
		t.Fatal("iscsi driver must implement Teardowner")
	}
	if err := d.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	var sawLogout bool
	for _, c := range *calls {
		if c.name != "iscsiadm" {
			continue
		}
		for _, a := range c.args {
			if a == "--logout" {
				sawLogout = true
			}
		}
	}
	if !sawLogout {
		t.Fatalf("expected iscsiadm --logout, calls=%+v", *calls)
	}
}

// iSCSI Teardown treats a "No matching sessions" logout as already-gone (idempotent).
func TestISCSITeardown_ToleratesNoSession(t *testing.T) {
	run, _ := stubRunner(func(sub string) ([]byte, error) {
		return []byte("iscsiadm: No matching sessions found"), errors.New("exit status 21")
	})
	d := &iscsiDriver{target: "iqn.x:lun0", opts: map[string]string{"portal": "10.0.0.1"}, run: run}
	if err := d.Teardown(context.Background()); err != nil {
		t.Fatalf("Teardown should tolerate no-session logout: %v", err)
	}
}
