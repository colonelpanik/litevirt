package grpcapi

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/vmimport"
)

func qemuImg(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("qemu-img", args...).CombinedOutput(); err != nil {
		t.Fatalf("qemu-img %v: %v: %s", args, err, out)
	}
}

// End-to-end: a streamOptimized VMDK converts to a qcow2 with the right virtual
// size — the core "off VMware" disk path.
func TestConvertForeignDisk_VMDKRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "src.qcow2")
	vmdk := filepath.Join(dir, "disk-0.vmdk")
	out := filepath.Join(dir, "out.qcow2")

	qemuImg(t, "create", "-f", "qcow2", base, "16M")
	qemuImg(t, "convert", "-O", "vmdk", "-o", "subformat=streamOptimized", base, vmdk)

	if err := convertForeignDisk(context.Background(), vmdk, "vmdk", out, dir, nil); err != nil {
		t.Fatalf("convertForeignDisk: %v", err)
	}
	info, err := qcow2.Info(out)
	if err != nil {
		t.Fatalf("qcow2.Info: %v", err)
	}
	if info.VirtualSize != 16<<20 {
		t.Errorf("converted virtual size = %d, want %d", info.VirtualSize, 16<<20)
	}
}

// A disk whose backing file points outside the import dir must be rejected before
// qemu-img reads it.
func TestAssertNoExternalDiskRefs_RejectsExternalBacking(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not available")
	}
	outside := t.TempDir()
	allowed := t.TempDir()
	base := filepath.Join(outside, "base.qcow2")
	overlay := filepath.Join(allowed, "overlay.qcow2")
	qemuImg(t, "create", "-f", "qcow2", base, "16M")
	qemuImg(t, "create", "-f", "qcow2", "-b", base, "-F", "qcow2", overlay)

	if err := assertNoExternalDiskRefs(context.Background(), overlay, allowed); err == nil {
		t.Fatal("expected rejection of external backing file, got nil")
	}

	// A standalone image in the allowed dir passes.
	standalone := filepath.Join(allowed, "ok.qcow2")
	qemuImg(t, "create", "-f", "qcow2", standalone, "16M")
	if err := assertNoExternalDiskRefs(context.Background(), standalone, allowed); err != nil {
		t.Errorf("standalone image rejected: %v", err)
	}
}

func TestConvertForeignDisk_HardFailsWithoutQemuImg(t *testing.T) {
	// Simulate qemu-img absence by clearing PATH for the duration.
	t.Setenv("PATH", "")
	dir := t.TempDir()
	src := filepath.Join(dir, "x.raw")
	os.WriteFile(src, []byte("not a real disk"), 0o600)
	err := convertForeignDisk(context.Background(), src, "raw", filepath.Join(dir, "out.qcow2"), dir, nil)
	if err == nil {
		t.Fatal("expected hard failure without qemu-img, got nil")
	}
}

func TestWithinDir(t *testing.T) {
	d := "/srv/imports/x"
	cases := []struct {
		path string
		want bool
	}{
		{"/srv/imports/x/disk.qcow2", true},
		{"/srv/imports/x", true},
		{"/srv/imports/x/../y/disk.qcow2", false},
		{"/etc/passwd", false},
	}
	for _, c := range cases {
		if got := withinDir(d, filepath.Clean(c.path)); got != c.want {
			t.Errorf("withinDir(%q, %q) = %v, want %v", d, c.path, got, c.want)
		}
	}
}

func TestSniffImportFormat(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, b, 0o600)
		return p
	}
	vma := make([]byte, 16)
	copy(vma, []byte{'V', 'M', 'A', 0})
	tarb := make([]byte, 512)
	copy(tarb[257:], []byte("ustar"))
	cases := map[string]string{
		write("a.vma", vma):  "vma",
		write("a.tar", tarb): "ova",
		write("a.ovf", []byte("<?xml version='1.0'?><Envelope>")):      "ovf",
		write("a.conf", []byte("cores: 2\nscsihw: virtio-scsi-pci\n")): "proxmox",
	}
	for path, want := range cases {
		if got := sniffImportFormat(path); got != want {
			t.Errorf("sniffImportFormat(%s) = %q, want %q", filepath.Base(path), got, want)
		}
	}
}

func TestApplyImportNetworks_DupNICRejected(t *testing.T) {
	s := &Server{}
	fv := &vmimport.ForeignVM{NICs: []vmimport.ForeignNIC{{Network: "netA"}, {Network: "netB"}}}
	// Both collapse to one bridge via the wildcard → collision on vm_interfaces.
	meta := &pb.ImportVMRequest{NetMap: map[string]string{"*": "br0"}}
	if err := s.applyImportNetworks(fv, meta); err == nil {
		t.Fatal("expected dup-NIC rejection, got nil")
	}

	// Distinct bridges map cleanly + MACs are generated.
	fv2 := &vmimport.ForeignVM{NICs: []vmimport.ForeignNIC{{Network: "netA"}, {Network: "netB"}}}
	meta2 := &pb.ImportVMRequest{NetMap: map[string]string{"netA": "br0", "netB": "br1"}}
	if err := s.applyImportNetworks(fv2, meta2); err != nil {
		t.Fatalf("distinct bridges rejected: %v", err)
	}
	for i, n := range fv2.NICs {
		if n.MAC == "" {
			t.Errorf("NIC %d got no generated MAC", i)
		}
	}
}

// TestImportRecords_BuildsNICRecords covers the level ImportVM is actually
// unit-drivable at: importRecords is the pure helper that builds the rows
// ImportVM passes into corrosion.InsertVMWithHardware. A vm_nics row must be
// built alongside each legacy vm_interfaces row, carrying the foreign NIC's
// tracked model (nicModel/ForeignVM.Normalize already default it to "virtio"
// when the source declared none) and the deterministic (vmName, mac) id the
// Phase-6 backfill would derive for the same legacy NIC.
func TestImportRecords_BuildsNICRecords(t *testing.T) {
	fv := &vmimport.ForeignVM{
		NICs: []vmimport.ForeignNIC{
			{Network: "br0", Model: "e1000", MAC: "52:54:00:aa:bb:cc"},
		},
	}
	_, ifaces, nics := importRecords(fv, "vm1", "host-a")
	if len(ifaces) != 1 || ifaces[0].MAC != "52:54:00:aa:bb:cc" || ifaces[0].NetworkName != "br0" {
		t.Fatalf("ifaces = %+v", ifaces)
	}
	if len(nics) != 1 {
		t.Fatalf("nics = %+v, want 1", nics)
	}
	n := nics[0]
	if n.VMName != "vm1" || n.NetworkName != "br0" || n.Model != "e1000" ||
		n.MAC != "52:54:00:aa:bb:cc" || n.Ordinal != 0 {
		t.Errorf("nics[0] = %+v, want VMName=vm1 NetworkName=br0 Model=e1000 MAC=52:54:00:aa:bb:cc Ordinal=0", n)
	}
	wantID := corrosion.DeterministicNICID("vm1", "52:54:00:aa:bb:cc")
	if n.ID != wantID {
		t.Errorf("nics[0].ID = %q, want %q (deterministic id, converges with a later backfill pass)", n.ID, wantID)
	}
	if n.TapDevice != "" {
		t.Errorf("nics[0].TapDevice = %q, want empty at import (assigned at start, not import)", n.TapDevice)
	}
}
