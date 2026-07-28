package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
)

// fakeSysfsPF builds a fake sysfs PF directory with `numvfs` virtfn symlinks pointing
// at VF dirs, installs it via pci.SetSysDevices (restored on cleanup), and returns the
// VF BDFs.
func fakeSysfsPF(t *testing.T, pf string, totalVFs, numVFs int) []string {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(pci.SetSysDevices(root))
	dir := filepath.Join(root, pf)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	write := func(name, val string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(val+"\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	write("sriov_totalvfs", strconv.Itoa(totalVFs))
	write("sriov_numvfs", strconv.Itoa(numVFs))
	write("vendor", "0x8086")
	write("device", "0x1572")
	var vfs []string
	for i := 0; i < numVFs; i++ {
		vf := "0000:41:10." + strconv.Itoa(i)
		if err := os.MkdirAll(filepath.Join(root, vf), 0o755); err != nil {
			t.Fatalf("mkdir vf: %v", err)
		}
		if err := os.Symlink("../"+vf, filepath.Join(dir, "virtfn"+strconv.Itoa(i))); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		vfs = append(vfs, vf)
	}
	return vfs
}

func numvfsValue(t *testing.T, pf string) int {
	t.Helper()
	// The seam points sysDevices at the temp root; read numvfs back through it via a
	// fresh scan of the file path the fake wrote.
	// pci.SetSysDevices set the root; reconstruct the path is internal, so use ScanDevice.
	d, err := pci.ScanDevice(pf)
	if err != nil {
		t.Fatalf("scan %s: %v", pf, err)
	}
	// SRIOVVFsFree = total - numvfs ⇒ numvfs = total - free.
	return d.SRIOVVFsTotal - d.SRIOVVFsFree
}

func TestSetSRIOVPolicy_BDFHandling(t *testing.T) {
	s := testServer(t)
	s.SetSRIOVPolicy(true, 8, []string{"41:00.0", "garbage", "0000:42:00.0"})

	if !s.sriovManagedPFs["0000:41:00.0"] {
		t.Error("valid non-canonical BDF 41:00.0 not normalized into the allowlist")
	}
	if !s.sriovManagedPFs["0000:42:00.0"] {
		t.Error("canonical BDF missing from the allowlist")
	}
	if len(s.sriovManagedPFs) != 2 {
		t.Errorf("malformed BDF should be ignored; allowlist = %v", s.sriovManagedPFs)
	}
	if !s.sriovDegradedActive(sriovReasonPFNotFound) {
		t.Error("a malformed managed_pf should mark the host degraded (pf_not_found)")
	}
}

func TestSetSRIOVDegraded_AggregatesAcrossPFs(t *testing.T) {
	s := testServer(t)
	s.SetSRIOVPolicy(true, 8, nil)

	s.setSRIOVDegraded("0000:41:00.0", sriovReasonOverCap, true)
	s.setSRIOVDegraded("0000:42:00.0", sriovReasonOverCap, true)
	if !s.sriovDegradedActive(sriovReasonOverCap) {
		t.Fatal("over_cap should be active")
	}
	// Clearing one PF must NOT clear the aggregate while another is still degraded.
	s.setSRIOVDegraded("0000:41:00.0", sriovReasonOverCap, false)
	if !s.sriovDegradedActive(sriovReasonOverCap) {
		t.Fatal("over_cap must stay active while another PF is still over-cap")
	}
	s.setSRIOVDegraded("0000:42:00.0", sriovReasonOverCap, false)
	if s.sriovDegradedActive(sriovReasonOverCap) {
		t.Fatal("over_cap should clear once all PFs are healthy")
	}
}

func TestAllocateSRIOVVFs_ReusesFreeVF_NoNumvfsWrite(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	s.SetSRIOVPolicy(false, 8, nil) // not managed — reuse must still work

	pf := "0000:41:00.0"
	vfs := fakeSysfsPF(t, pf, 8, 2) // 2 existing VFs
	// Seed inventory: the PF + 2 unassigned VF rows.
	seedPCIDevice(t, ctx, s, pf, true)
	for _, vf := range vfs {
		seedPCIDevice(t, ctx, s, vf, false)
	}

	addrs, err := s.allocateSRIOVVFs(ctx, "vm1", &pb.DeviceSpec{Sriov: true, Type: "network", Parent: pf}, 1)
	if err != nil {
		t.Fatalf("reuse allocate: %v", err)
	}
	if len(addrs) != 1 {
		t.Fatalf("expected 1 reused VF, got %v", addrs)
	}
	// The claimed VF is now owned by vm1.
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	owned := 0
	for _, d := range devs {
		if d.VMName == "vm1" {
			owned++
		}
	}
	if owned != 1 {
		t.Errorf("expected exactly 1 VF owned by vm1, got %d", owned)
	}
	// Reuse must NOT write sriov_numvfs (still 2).
	if v := numvfsValue(t, pf); v != 2 {
		t.Errorf("reuse wrote sriov_numvfs (now %d, want 2)", v)
	}
}

func TestAllocateSRIOVVFs_OverCap_DegradedReuseOKCreateRefused(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	pf := "0000:41:00.0"
	s.SetSRIOVPolicy(true, 2, []string{pf}) // cap 2, adopted

	vfs := fakeSysfsPF(t, pf, 8, 4) // 4 live VFs → over the cap of 2
	seedPCIDevice(t, ctx, s, pf, true)
	// All 4 VFs assigned to other VMs → no free VF to reuse.
	for _, vf := range vfs {
		seedPCIDevice(t, ctx, s, vf, false)
		if err := corrosion.AssignPCIDevice(ctx, s.db, s.hostName, vf, "other"); err != nil {
			t.Fatalf("assign: %v", err)
		}
	}

	_, err := s.allocateSRIOVVFs(ctx, "vm1", &pb.DeviceSpec{Sriov: true, Type: "network", Parent: pf}, 1)
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("over-cap all-assigned: want ResourceExhausted, got %v", err)
	}
	if !s.sriovDegradedActive(sriovReasonOverCap) {
		t.Error("an over-cap PF must be marked degraded")
	}
	// Creation must be refused with no sysfs write (still 4).
	if v := numvfsValue(t, pf); v != 4 {
		t.Errorf("over-cap refused-create must not write sriov_numvfs (now %d, want 4)", v)
	}

	// Now free one VF → reuse must still succeed despite the over-cap condition.
	if err := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, vfs[0], "other"); err != nil {
		t.Fatalf("release: %v", err)
	}
	addrs, err := s.allocateSRIOVVFs(ctx, "vm1", &pb.DeviceSpec{Sriov: true, Type: "network", Parent: pf}, 1)
	if err != nil {
		t.Fatalf("reuse on over-cap PF must succeed: %v", err)
	}
	if len(addrs) != 1 {
		t.Errorf("expected 1 reused VF, got %v", addrs)
	}
}

// seedPCIDevice inserts a host_pci_devices row (unassigned) for the given address.
func seedPCIDevice(t *testing.T, ctx context.Context, s *Server, addr string, sriovCapable bool) {
	t.Helper()
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: addr, Type: "network",
		SRIOVCapable: sriovCapable, IOMMUGroup: -1,
	}); err != nil {
		t.Fatalf("seed device %s: %v", addr, err)
	}
}
