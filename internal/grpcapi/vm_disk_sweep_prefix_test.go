package grpcapi

import (
	"os"
	"path/filepath"
	"testing"
)

// The debris sweep for one VM name must not reach the disks of a VM whose name
// merely STARTS with that name and a dash.
//
// Disk files are flat: <vm>-<disk>.qcow2. VM "web" and VM "web-1" share a
// directory, and web-1's root disk is web-1-root.qcow2 — which the glob
// web-*.qcow2 also matches. The keep set protects only paths a live vm_disks
// row names, so a disk web-1's operator kept with `lv rm --keep-disks` (no row
// left) was deleted the moment anyone created, deleted or rebuilt "web".
func TestSweepVMDiskDebris_SparesDisksOfAVMWhoseNameExtendsThisOne(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	seed := func(vm, disk string) string {
		p := s.images.DiskPath(vm, disk)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("disk"), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ownDebris := seed("web", "root")
	kept := seed("web-1", "root") // web-1 deleted with --keep-disks: no row names it

	s.sweepVMDiskDebris(ctx, "web")

	if _, err := os.Stat(kept); err != nil {
		t.Errorf("sweeping VM %q deleted %s, a disk of VM %q the operator kept (%v)",
			"web", filepath.Base(kept), "web-1", err)
	}
	if _, err := os.Stat(ownDebris); !os.IsNotExist(err) {
		t.Errorf("web's own debris %s survived (%v); the sweep did nothing, so this test "+
			"proves nothing about what it spares", filepath.Base(ownDebris), err)
	}
}
