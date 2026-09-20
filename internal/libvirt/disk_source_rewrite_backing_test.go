package libvirt

import (
	"strings"
	"testing"
)

func domainWithSource(sourceElem string) string {
	return `<domain type='kvm'>
  <name>vm</name>
  <devices>
    <disk type='block' device='disk'>
      <driver name='qemu' type='raw'/>
      ` + sourceElem + `
      <target dev='vda' bus='virtio'/>
    </disk>
  </devices>
</domain>`
}

// TestRewriteDiskSource_BlockBackedDisk covers the gap the #195 fix opened.
//
// Before #195 every disk was emitted as <source file=…> whatever backed it, so
// a zvol or an LV happened to be rewritable by a function that only knows about
// the `file` attribute. Now a block-backed disk correctly carries
// <source dev=…>, and the rewrite refuses it outright:
//
//	disk "vda" has no file-backed <source> to rewrite
//
// It is loud rather than silent, which is the right direction — but it means
// `lv move-volume` cannot repoint a zfs, lvm-thin or iscsi disk at all. The
// rewrite has to work on the attribute the disk actually uses.
func TestRewriteDiskSource_BlockBackedDisk(t *testing.T) {
	in := domainWithSource(`<source dev='/dev/vg0/vm-root'/>`)

	out, changed, err := RewriteDiskSource(in, "vda", "/dev/vg0/vm-root", "/dev/vg1/vm-root")
	if err != nil {
		t.Fatalf("RewriteDiskSource: %v", err)
	}
	if !changed {
		t.Fatal("changed = false; the disk source was not rewritten")
	}
	if !strings.Contains(out, `dev="/dev/vg1/vm-root"`) && !strings.Contains(out, `dev='/dev/vg1/vm-root'`) {
		t.Errorf("new dev missing from output:\n%s", out)
	}
	if strings.Contains(out, "/dev/vg0/vm-root") {
		t.Errorf("old dev still present:\n%s", out)
	}
	// It must stay a block disk — only the path moved.
	if !strings.Contains(out, `type="block"`) && !strings.Contains(out, `type='block'`) {
		t.Errorf("the disk stopped being type=block:\n%s", out)
	}
}

// The same for an rbd image, whose locator lives in <source name=…>.
func TestRewriteDiskSource_NetworkBackedDisk(t *testing.T) {
	in := `<domain type='kvm'>
  <name>vm</name>
  <devices>
    <disk type='network' device='disk'>
      <driver name='qemu' type='raw'/>
      <source protocol='rbd' name='poolA/vm-root'/>
      <target dev='vda' bus='virtio'/>
    </disk>
  </devices>
</domain>`

	out, changed, err := RewriteDiskSource(in, "vda", "poolA/vm-root", "poolB/vm-root")
	if err != nil {
		t.Fatalf("RewriteDiskSource: %v", err)
	}
	if !changed {
		t.Fatal("changed = false; the rbd locator was not rewritten")
	}
	if !strings.Contains(out, "poolB/vm-root") || strings.Contains(out, "poolA/vm-root") {
		t.Errorf("rbd name not repointed:\n%s", out)
	}
}

// Idempotence has to hold per backing too: a disk already at the destination
// reports changed=false rather than erroring, or a retried move fails.
func TestRewriteDiskSource_BlockIdempotent(t *testing.T) {
	in := domainWithSource(`<source dev='/dev/vg1/vm-root'/>`)
	out, changed, err := RewriteDiskSource(in, "vda", "/dev/vg0/vm-root", "/dev/vg1/vm-root")
	if err != nil {
		t.Fatalf("RewriteDiskSource: %v", err)
	}
	if changed {
		t.Error("changed = true for a disk already at the destination")
	}
	if out != in {
		t.Error("an idempotent rewrite altered the XML")
	}
}

// A move that would change the BACKING KIND is refused. Repointing a file path
// to a block device needs the <disk type> and <driver type> to change too, and
// a source-only rewrite would produce a domain libvirt cannot start.
func TestRewriteDiskSource_RefusesACrossBackingMove(t *testing.T) {
	in := domainWithSource(`<source dev='/dev/vg0/vm-root'/>`)
	_, _, err := RewriteDiskSource(in, "vda", "/dev/vg0/vm-root", "/pool/vm-root.qcow2")
	if err == nil {
		t.Fatal("a block -> file move was accepted; the disk would keep type='block' " +
			"and driver type='raw' while pointing at a qcow2 file")
	}
}

// File-backed disks keep working exactly as before — this is an addition.
func TestRewriteDiskSource_FileBackedUnchangedBehaviour(t *testing.T) {
	in := domainWithSource(`<source file='/pool/a/vm-root.qcow2'/>`)
	out, changed, err := RewriteDiskSource(in, "vda", "/pool/a/vm-root.qcow2", "/pool/b/vm-root.qcow2")
	if err != nil {
		t.Fatalf("RewriteDiskSource: %v", err)
	}
	if !changed {
		t.Fatal("changed = false for a plain file move")
	}
	if !strings.Contains(out, "/pool/b/vm-root.qcow2") || strings.Contains(out, "/pool/a/vm-root.qcow2") {
		t.Errorf("file source not repointed:\n%s", out)
	}
}

// RewriteDiskSourceFile stays as the file-only spelling so existing callers and
// their guarantees are untouched.
func TestRewriteDiskSourceFile_StillFileOnly(t *testing.T) {
	in := domainWithSource(`<source dev='/dev/vg0/vm-root'/>`)
	if _, _, err := RewriteDiskSourceFile(in, "vda", "/dev/vg0/vm-root", "/dev/vg1/vm-root"); err == nil {
		t.Error("RewriteDiskSourceFile accepted a block disk; it is the file-only entry point")
	}
}
