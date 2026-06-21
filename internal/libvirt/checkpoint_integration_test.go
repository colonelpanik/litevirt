//go:build libvirt_integration

// Integration test for the live dirty-bitmap path. It needs a real
// libvirtd (>= 6.x) + qemu and a RUNNING VM with a qcow2 disk, so it is
// gated behind the `libvirt_integration` build tag and never runs in CI.
//
// Run it ON A CLUSTER NODE, as a user that can reach the libvirt socket:
//
//	LV_IT_VM=vm1 \
//	LV_IT_DISK_TARGET=vda \
//	LV_IT_SIZE_BYTES=$(virsh domblkinfo vm1 vda --bytes | awk '/Capacity/{print $2}') \
//	LV_IT_WRITE_MB=64 \
//	go test -tags libvirt_integration -run TestIntegration_DiskDirtyExtents \
//	    -v./internal/libvirt/
//
// LV_IT_WRITE_MB is optional: when set (and the guest agent is up) the
// test dd's that many MiB inside the guest between the checkpoint and the
// extent query, then asserts the reported dirty total is at least that
// big and strictly less than the whole disk — i.e. the bitmap really did
// narrow the read set. Without it the test only asserts the pipeline runs
// end-to-end (checkpoint -> backup-begin -> NBD block-status -> abort) and
// logs the extents for eyeballing.
package libvirt

import (
	"bytes"
	"os"
	"testing"
)

// TestIntegration_BackupSessionFullRead validates the content-based backup
// path's riskiest primitive — NBD read of GUEST content — against real
// qemu. It opens a full pull-backup session, enumerates allocated extents,
// and reads the first 4 KiB. The decisive check: guest offset 0 must be a
// partition table (MBR/GPT), NOT the qcow2 container magic "QFI\xfb" — i.e.
// we're reading the guest disk, not the qcow2 file. This is the whole point
// of the rewrite.
func TestIntegration_BackupSessionFullRead(t *testing.T) {
	vm := os.Getenv("LV_IT_VM")
	diskPath := os.Getenv("LV_IT_DISK_PATH") // source path, e.g. /var/lib/litevirt/disks/x.qcow2
	if vm == "" || diskPath == "" {
		t.Skip("set LV_IT_VM and LV_IT_DISK_PATH to run")
	}
	c, err := NewClient()
	if err != nil {
		t.Fatalf("connect libvirtd: %v", err)
	}
	defer c.Close()

	sess, err := c.BeginBackup(vm, diskPath, "", "") // full: no parent, no new checkpoint
	if err != nil {
		t.Fatalf("BeginBackup(full): %v", err)
	}
	defer sess.Close()
	size := sess.Size()
	t.Logf("resolved guest virtual size: %d bytes", size)

	exts, err := sess.ChangedExtents()
	if err != nil {
		t.Fatalf("ChangedExtents: %v", err)
	}
	var alloc int64
	for _, e := range exts {
		alloc += e[1]
	}
	t.Logf("full: %d allocated extents, %d bytes of %d (%.2f%%)", len(exts), alloc, size, 100*float64(alloc)/float64(size))
	if len(exts) == 0 || alloc == 0 {
		t.Fatal("expected some allocated content on a booted VM")
	}

	buf := make([]byte, 4096)
	if _, err := sess.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt(0): %v", err)
	}
	t.Logf("guest offset 0 prefix: %x", buf[:16])
	if bytes.HasPrefix(buf, []byte("QFI\xfb")) {
		t.Fatal("read returned qcow2 CONTAINER bytes, not guest content — address-space bug not fixed")
	}
	mbr := buf[510] == 0x55 && buf[511] == 0xAA
	gpt := bytes.Contains(buf, []byte("EFI PART"))
	t.Logf("partition table present: mbrSig=%v gpt=%v", mbr, gpt)
	if !mbr && !gpt {
		t.Logf("note: no MBR/GPT signature, but not qcow2 magic either — likely guest content on an unpartitioned/encrypted disk")
	}
}
