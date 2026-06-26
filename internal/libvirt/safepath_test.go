package libvirt

import (
	"strings"
	"testing"
)

// TestSafePathBuilders verifies the Safe* path builders accept legitimate names
// and reject traversal/absolute names that the raw builders would otherwise let
// escape the data directory.
func TestSafePathBuilders(t *testing.T) {
	const dataDir = "/srv/litevirt"

	t.Run("good", func(t *testing.T) {
		if p, err := SafeDiskPath(dataDir, "web", "root"); err != nil || !strings.HasPrefix(p, dataDir+"/disks/") {
			t.Errorf("SafeDiskPath good = %q,%v", p, err)
		}
		if p, err := SafeNvramPath(dataDir, "web"); err != nil || !strings.HasPrefix(p, dataDir+"/nvram/") {
			t.Errorf("SafeNvramPath good = %q,%v", p, err)
		}
		if p, err := SafeCloudInitISOPath(dataDir, "web"); err != nil || !strings.HasPrefix(p, dataDir+"/cloudinit/") {
			t.Errorf("SafeCloudInitISOPath good = %q,%v", p, err)
		}
		if p, err := SafeVMStatePath(dataDir, "web", "snap1"); err != nil || !strings.HasPrefix(p, dataDir+"/vmstate/") {
			t.Errorf("SafeVMStatePath good = %q,%v", p, err)
		}
		if p, err := SafeImagePath(dataDir, "ubuntu-22.04"); err != nil || !strings.HasPrefix(p, dataDir+"/images/") {
			t.Errorf("SafeImagePath good = %q,%v", p, err)
		}
		if p, err := SafeSnapshotFirmwareBundlePath(dataDir, "web", "snap1"); err != nil || !strings.HasPrefix(p, dataDir+"/snapfw/") {
			t.Errorf("SafeSnapshotFirmwareBundlePath good = %q,%v", p, err)
		}
	})

	bad := "../../etc/cron.d/x"
	t.Run("reject-traversal", func(t *testing.T) {
		if _, err := SafeDiskPath(dataDir, bad, "root"); err == nil {
			t.Error("SafeDiskPath accepted traversal vm name")
		}
		if _, err := SafeDiskPath(dataDir, "web", bad); err == nil {
			t.Error("SafeDiskPath accepted traversal disk name")
		}
		if _, err := SafeNvramPath(dataDir, bad); err == nil {
			t.Error("SafeNvramPath accepted traversal")
		}
		if _, err := SafeCloudInitISOPath(dataDir, bad); err == nil {
			t.Error("SafeCloudInitISOPath accepted traversal")
		}
		if _, err := SafeVMStatePath(dataDir, "web", bad); err == nil {
			t.Error("SafeVMStatePath accepted traversal snap name")
		}
		if _, err := SafeImagePath(dataDir, bad); err == nil {
			t.Error("SafeImagePath accepted traversal")
		}
		if _, err := SafeSnapshotFirmwareBundlePath(dataDir, bad, "snap1"); err == nil {
			t.Error("SafeSnapshotFirmwareBundlePath accepted traversal")
		}
	})
}
