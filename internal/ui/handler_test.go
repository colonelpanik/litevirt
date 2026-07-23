package ui

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ── Cluster ──────────────────────────────────────────────────────────────────

func TestHandler_ClusterPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "host1")
}

func TestHandler_ClusterStats(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/cluster-stats"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

// ── VMs ──────────────────────────────────────────────────────────────────────

func TestHandler_VMsPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/vms"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "vm1")
}

func TestHandler_VMDetail(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/vms/vm1"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "vm1")
}

func TestHandler_VMDetail_NotFound(t *testing.T) {
	mock := newDefaultMock()
	mock.inspectVMErr = errSimulated
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/vms/nonexistent"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusNotFound)
}

// TestHandler_VMHardwareTab verifies the Hardware tab fragment renders the
// typed disk/NIC/PCI device table from ListVMHardware.
func TestHandler_VMHardwareTab(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{
		Devices: []*pb.HardwareDevice{
			{Device: &pb.HardwareDevice_Disk{Disk: &pb.HardwareDisk{
				DeviceId: "root", Target: "vdb", Bus: "virtio", SizeBytes: 10 << 30,
				StorageType: "local", State: "attached",
			}}},
			{Device: &pb.HardwareDevice_Nic{Nic: &pb.HardwareNIC{
				Mac: "52:54:00:aa:bb:cc", Network: "br0", Model: "virtio", State: "attached",
			}}},
			{Device: &pb.HardwareDevice_Pci{Pci: &pb.HardwarePCI{
				DeviceId: "gpu0", SelectorKind: "address", State: "attached",
				Members: []*pb.HardwarePCIMember{{MemberId: "m0", ResolvedAddress: "0000:41:00.0", XmlAlias: "hostdev0"}},
			}}},
		},
	}
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/tab/hardware"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "vdb")
	assertContains(t, w, "52:54:00:aa:bb:cc")
}

func TestHandler_VMHardwareTab_NotFound(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareErr = errSimulated
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/tab/hardware"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusNotFound)
}

// TestHandler_HardwareTab_BlockedBanner verifies that when a
// VM's PCI adoption is blocked, the Hardware tab must surface the reason in a
// banner and omit the attach forms (read-only) rather than let an operator
// submit a mutation the backend will independently reject.
func TestHandler_HardwareTab_BlockedBanner(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{
		HardwareAdoptionState: "blocked",
		HardwareAdoptionError: "ambiguous PCI grouping",
	}
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/tab/hardware"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "ambiguous PCI grouping")
	if strings.Contains(w.Body.String(), "attach-disk") {
		t.Error("blocked adoption state: response body contains an attach-disk form, want none")
	}
}

// TestHandler_HardwareTab_AddFormsWhenAdopted asserts the converse of the
// blocked-banner test: once adoption is resolved (or was never gated), the
// tab renders the section-header Add buttons (hx-get modal routes) and the
// per-row detach forms that mutate hardware via the existing detach handlers.
func TestHandler_HardwareTab_AddFormsWhenAdopted(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{
		HardwareAdoptionState: "adopted",
		Devices: []*pb.HardwareDevice{
			{Device: &pb.HardwareDevice_Disk{Disk: &pb.HardwareDisk{
				DeviceId: "root", Target: "vdb", Bus: "virtio", SizeBytes: 10 << 30,
				StorageType: "local", State: "attached",
			}}},
			{Device: &pb.HardwareDevice_Nic{Nic: &pb.HardwareNIC{
				Mac: "52:54:00:aa:bb:cc", Network: "br0", Model: "virtio", State: "attached",
			}}},
			{Device: &pb.HardwareDevice_Pci{Pci: &pb.HardwarePCI{
				DeviceId: "gpu0", SelectorKind: "address", State: "attached",
				Members: []*pb.HardwarePCIMember{{MemberId: "m0", ResolvedAddress: "0000:41:00.0", XmlAlias: "hostdev0"}},
			}}},
		},
	}
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/tab/hardware"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "add-disk-modal")
	assertContains(t, w, "add-nic-modal")
	assertContains(t, w, "add-pci-modal")
	assertContains(t, w, "detach-disk")
	assertContains(t, w, "detach-nic")
	assertContains(t, w, "detach-pci")
}

// TestHandler_HardwareTab_ReservedPCIDetachable verifies a reserved (0-member)
// PCI device — the reserve-at-attach state of a stopped VM — renders its
// reserved address (not a blank cell) and exactly one detach control. The bug:
// detach forms lived inside the members loop, so a 0-member device had no detach
// button and an empty address.
func TestHandler_HardwareTab_ReservedPCIDetachable(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{
		HardwareAdoptionState: "adopted",
		Devices: []*pb.HardwareDevice{
			{Device: &pb.HardwareDevice_Pci{Pci: &pb.HardwarePCI{
				DeviceId: "gpu0", SelectorKind: "address", State: "reserved",
				Desired: &pb.DeviceSpec{Address: "0000:99:00.0"},
				// No Members — reserved, not yet realized.
			}}},
		},
	}
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/tab/hardware"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "0000:99:00.0")         // reserved address shown, not "—"
	assertContains(t, w, "reserved")             // state badge / label
	assertContains(t, w, `value="0000:99:00.0"`) // detach keyed by desired address
	if n := strings.Count(w.Body.String(), `name="pci_address"`); n != 1 {
		t.Errorf("got %d detach forms, want exactly 1 for a reserved device", n)
	}
}

// TestHandler_HardwareTab_IOMMUGroupSingleDetach verifies a multi-member
// (IOMMU-group) PCI device renders exactly one detach control keyed by the
// primary/desired address — not one-per-member (a sibling address does not match
// the intent's ExclusiveKey and its detach would fail).
func TestHandler_HardwareTab_IOMMUGroupSingleDetach(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{
		HardwareAdoptionState: "adopted",
		Devices: []*pb.HardwareDevice{
			{Device: &pb.HardwareDevice_Pci{Pci: &pb.HardwarePCI{
				DeviceId: "gpu0", SelectorKind: "address", State: "attached",
				Desired: &pb.DeviceSpec{Address: "0000:41:00.0"},
				Members: []*pb.HardwarePCIMember{
					{MemberId: "m0", ResolvedAddress: "0000:41:00.0"},
					{MemberId: "m1", ResolvedAddress: "0000:41:00.1"},
				},
			}}},
		},
	}
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/tab/hardware"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if n := strings.Count(w.Body.String(), `name="pci_address"`); n != 1 {
		t.Errorf("got %d detach forms, want exactly 1 for an IOMMU group", n)
	}
	assertContains(t, w, `value="0000:41:00.0"`) // keyed by primary
	if strings.Contains(w.Body.String(), `value="0000:41:00.1"`) {
		t.Error("detach form keyed by a sibling member address (0000:41:00.1); want primary only")
	}
}

// TestHandler_HardwareTab_HeaderActionsAndRowResize verifies the redesigned
// tab layout: Add actions live in the section headers (hx-get to the modal
// routes added by a later task), disk rows carry a Resize action, and PCI
// rows carry a device-class chip. It also verifies the old inline attach-pci
// form (free-text address input) is gone now that attach is modal-driven.
func TestHandler_HardwareTab_HeaderActionsAndRowResize(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{
		HardwareAdoptionState: "adopted",
		Devices: []*pb.HardwareDevice{
			{Device: &pb.HardwareDevice_Disk{Disk: &pb.HardwareDisk{DeviceId: "vda", Target: "vda", Bus: "virtio", SizeBytes: 32212254720, StorageType: "local", State: "attached"}}},
			{Device: &pb.HardwareDevice_Pci{Pci: &pb.HardwarePCI{DeviceId: "gpu0", SelectorKind: "address", State: "attached",
				Desired: &pb.DeviceSpec{Type: "gpu"}, Members: []*pb.HardwarePCIMember{{ResolvedAddress: "0000:41:00.0", XmlAlias: "ua-gpu-0"}}}}},
		},
	}
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm-a/tab/hardware"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	// Add actions live in the section headers, hx-get the modal routes.
	for _, want := range []string{
		`hx-get="/ui/vms/vm-a/add-disk-modal"`,
		`hx-get="/ui/vms/vm-a/add-nic-modal"`,
		`hx-get="/ui/vms/vm-a/add-pci-modal"`,
		`+ Add disk`, `+ Add NIC`, `+ Add PCI device`,
		`resize-disk-modal?disk=vda`, // disk row Resize action
		`dev-chip dev-gpu`,           // PCI row device-class chip
	} {
		if !strings.Contains(body, want) {
			t.Errorf("hardware tab missing %q", want)
		}
	}
	// The old inline add-forms are gone.
	if strings.Contains(body, `hx-post="/ui/vms/vm-a/attach-pci"`) && strings.Contains(body, `placeholder="0000:41:00.0"`) {
		t.Error("old inline PCI attach form should be removed (now a modal)")
	}
}

// TestHandler_HardwareTab_EmptyPCIShowsEmptyState verifies an empty PCI
// section renders the shared .empty-state invitation (with its own Add
// button), not a flat catch-all sentence.
func TestHandler_HardwareTab_EmptyPCIShowsEmptyState(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{HardwareAdoptionState: "adopted"} // no devices
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm-a/tab/hardware"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, "empty-state") || !strings.Contains(body, "No passthrough devices attached") {
		t.Error("empty PCI section must render the .empty-state invitation, not a flat sentence")
	}
	if strings.Contains(body, "No hardware devices recorded") {
		t.Error("the old catch-all empty block should be removed")
	}
}

// TestDevChip verifies the devChip funcMap helper maps each known PCI
// DeviceSpec.type value to its chip class + label, with an "other" fallback
// for anything unrecognized (including the empty string).
func TestDevChip(t *testing.T) {
	cases := map[string]string{"gpu": "dev-gpu\">GPU", "network": "dev-nic\">NIC", "nvme": "dev-nvme\">NVMe", "": "dev-other\">PCI"}
	for in, want := range cases {
		if got := string(devChip(in)); !strings.Contains(got, want) {
			t.Errorf("devChip(%q)=%q, want substring %q", in, got, want)
		}
	}
}

// TestHandler_VMDetail_TabHardware covers the ?tab=hardware full-page load —
// the Hardware body must server-render, not only be reachable via htmx.
func TestHandler_VMDetail_TabHardware(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{
		Devices: []*pb.HardwareDevice{
			{Device: &pb.HardwareDevice_Disk{Disk: &pb.HardwareDisk{Target: "vdb", Bus: "virtio"}}},
		},
	}
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/vms/vm1?tab=hardware"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "vdb")
}

// TestHandler_HardwareTab_RendersWithoutNetworksFetch verifies fix (2): with
// the dead .Networks threading removed (hardwareTabData no longer takes a
// nets param, and neither tab-render call site fetches ListNetworks), both
// the htmx fragment route and the ?tab=hardware full-page route still render
// the Hardware tab's devices correctly.
func TestHandler_HardwareTab_RendersWithoutNetworksFetch(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{Devices: []*pb.HardwareDevice{
		{Device: &pb.HardwareDevice_Disk{Disk: &pb.HardwareDisk{Target: "vdb", Bus: "virtio"}}},
	}}
	s := newTestUIServer(t, mock)

	if body := doGET(t, s, "/ui/vms/vm1/tab/hardware"); !strings.Contains(body, "vdb") {
		t.Error("hardware fragment route must still render devices with Networks gone")
	}
	if body := doGET(t, s, "/vms/vm1?tab=hardware"); !strings.Contains(body, "vdb") {
		t.Error("?tab=hardware full-page route must still render devices with Networks gone")
	}
}

func TestHandler_VMsTable(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms-table"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_NewVMModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms/new-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_CreateVM(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("name=test-vm&image=ubuntu&cpu=2&memory=2048")
	r, _ := http.NewRequest("POST", "/ui/vms", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/vms")
	if mock.lastCreateVMReq == nil {
		t.Fatal("CreateVM was not called")
	}
	if mock.lastCreateVMReq.Spec.Name != "test-vm" {
		t.Errorf("VM name = %q, want test-vm", mock.lastCreateVMReq.Spec.Name)
	}
}

func TestHandler_CreateVM_WithResourceTuning(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("name=gpu-vm&image=ubuntu&cpu=4&memory=8192&hugepages=true&io_threads=2&numa_strict=true&cpu_pinning=0%2C1%2C2%2C3")
	r, _ := http.NewRequest("POST", "/ui/vms", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	assertHXRedirect(t, w, "/vms")
	if mock.lastCreateVMReq == nil {
		t.Fatal("CreateVM was not called")
	}
	spec := mock.lastCreateVMReq.Spec
	if spec.Resources == nil {
		t.Fatal("Resources is nil")
	}
	if !spec.Resources.Hugepages {
		t.Error("Hugepages should be true")
	}
	if spec.Resources.IoThreads != 2 {
		t.Errorf("IoThreads = %d, want 2", spec.Resources.IoThreads)
	}
	if spec.Resources.NumaPolicy == nil {
		t.Fatal("NumaPolicy is nil")
	}
	if !spec.Resources.NumaPolicy.Strict {
		t.Error("NumaPolicy.Strict should be true")
	}
	if len(spec.Resources.CpuPinning) != 4 {
		t.Fatalf("CpuPinning len = %d, want 4", len(spec.Resources.CpuPinning))
	}
	if spec.Resources.CpuPinning[3] != 3 {
		t.Errorf("CpuPinning[3] = %d, want 3", spec.Resources.CpuPinning[3])
	}
}

func TestHandler_CreateVM_WithPCIDevices(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("name=pci-vm&image=ubuntu&cpu=2&memory=4096&dev_type%5B%5D=gpu&dev_address%5B%5D=0000%3A41%3A00.0&dev_type%5B%5D=nvme&dev_address%5B%5D=")
	r, _ := http.NewRequest("POST", "/ui/vms", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastCreateVMReq == nil {
		t.Fatal("CreateVM was not called")
	}
	spec := mock.lastCreateVMReq.Spec
	if len(spec.Devices) != 2 {
		t.Fatalf("Devices len = %d, want 2", len(spec.Devices))
	}
	if spec.Devices[0].Type != "gpu" {
		t.Errorf("Device[0].Type = %q, want gpu", spec.Devices[0].Type)
	}
	if spec.Devices[0].Address != "0000:41:00.0" {
		t.Errorf("Device[0].Address = %q, want 0000:41:00.0", spec.Devices[0].Address)
	}
	if spec.Devices[1].Type != "nvme" {
		t.Errorf("Device[1].Type = %q, want nvme", spec.Devices[1].Type)
	}
	if spec.Devices[1].Address != "" {
		t.Errorf("Device[1].Address = %q, want empty (auto)", spec.Devices[1].Address)
	}
}

func TestHandler_CreateVM_NoTuning(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("name=plain-vm&image=ubuntu&cpu=2&memory=4096")
	r, _ := http.NewRequest("POST", "/ui/vms", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	serveRequest(s, r)

	if mock.lastCreateVMReq == nil {
		t.Fatal("CreateVM was not called")
	}
	if mock.lastCreateVMReq.Spec.Resources != nil {
		t.Error("Resources should be nil when no tuning knobs are set")
	}
	if len(mock.lastCreateVMReq.Spec.Devices) != 0 {
		t.Errorf("Devices len = %d, want 0", len(mock.lastCreateVMReq.Spec.Devices))
	}
}

func TestHandler_StatsHistory_Empty(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms/nonexistent/stats-history"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if w.Body.String() != "[]\n" && w.Body.String() != "[]" {
		t.Errorf("body = %q, want empty JSON array", w.Body.String())
	}
}

func TestHandler_StartVM(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/ui/vms/vm1/start"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if mock.lastStartVMName != "vm1" {
		t.Errorf("StartVM name = %q, want vm1", mock.lastStartVMName)
	}
}

func TestHandler_StopVM(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/ui/vms/vm1/stop"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if mock.lastStopVMName != "vm1" {
		t.Errorf("StopVM name = %q, want vm1", mock.lastStopVMName)
	}
}

func TestHandler_RestartVM(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/ui/vms/vm1/restart"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if mock.lastRestartVMName != "vm1" {
		t.Errorf("RestartVM name = %q, want vm1", mock.lastRestartVMName)
	}
}

func TestHandler_DeleteVM(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "DELETE", "/ui/vms/vm1"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if !mock.deleteVMCalled {
		t.Error("DeleteVM was not called")
	}
	if mock.lastDeleteVMName != "vm1" {
		t.Errorf("DeleteVM name = %q, want vm1", mock.lastDeleteVMName)
	}
}

func TestHandler_VMStatsPartial(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/stats"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_VMStatsPartial_Error(t *testing.T) {
	mock := newDefaultMock()
	mock.vmStatsErr = errSimulated
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/stats"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "unavailable")
}

func TestHandler_SnapshotModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/snapshot-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_CreateSnapshot(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("snapshot_name=snap1")
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/snapshot", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastCreateSnapshotReq == nil {
		t.Fatal("CreateSnapshot was not called")
	}
	if mock.lastCreateSnapshotReq.Name != "snap1" {
		t.Errorf("snapshot name = %q, want snap1", mock.lastCreateSnapshotReq.Name)
	}
}

func TestHandler_RestoreSnapshot(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/ui/vms/vm1/snapshot/snap1/restore"))
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastRestoreSnapshotReq == nil {
		t.Fatal("RestoreSnapshot was not called")
	}
}

func TestHandler_DeleteSnapshot(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "DELETE", "/ui/vms/vm1/snapshot/snap1"))
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastDeleteSnapshotReq == nil {
		t.Fatal("DeleteSnapshot was not called")
	}
}

func TestHandler_MigrateModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/migrate-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

// TestHandler_EditVMModal verifies the retirement of the edit-modal device
// panes: the Hardware tab is now the sole surface for
// disks/NICs/PCI devices, so the modal must no longer render those panes and
// must instead point operators at the tab.
func TestHandler_EditVMModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/edit-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	for _, removed := range []string{"vmTab(this,'disks')", `data-pane="disks"`, `data-pane="devices"`} {
		if strings.Contains(body, removed) {
			t.Errorf("edit modal still contains retired device-pane markup %q, want it removed (Hardware tab is now the sole hardware surface)", removed)
		}
	}
	assertContains(t, w, "Manage hardware")
	assertContains(t, w, "/vms/vm1?tab=hardware")
}

func TestHandler_UpdateVMSpec(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("cpu=4&memory_mib=4096")
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/update-spec", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastUpdateVMReq == nil {
		t.Fatal("UpdateVM was not called")
	}
	if mock.lastUpdateVMReq.Cpu != 4 {
		t.Errorf("CPU = %d, want 4", mock.lastUpdateVMReq.Cpu)
	}
}

func TestHandler_AttachDisk(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("name=data&size_gib=10&bus=virtio")
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/attach-disk", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastAttachDeviceReq == nil {
		t.Fatal("AttachDevice was not called")
	}
}

// TestHandler_AddDiskModal_PrefillsNextName verifies the Add-disk modal
// (opened via the Hardware tab's "+ Add disk" header action) prefills the
// name field with the next free dataN slot, derived from the VM's existing
// disks, and renders inside the shared form-modal shell with a primary
// submit button.
func TestHandler_AddDiskModal_PrefillsNextName(t *testing.T) {
	mock := newDefaultMock()
	mock.listVMHardwareResp = &pb.ListVMHardwareResponse{Devices: []*pb.HardwareDevice{
		{Device: &pb.HardwareDevice_Disk{Disk: &pb.HardwareDisk{DeviceId: "data0"}}},
	}}
	s := newTestUIServer(t, mock)
	s.SetCorrosionDB(newCorrosionForUITest(t))
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm-a/add-disk-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	if !strings.Contains(body, `value="data1"`) {
		t.Error("Add-disk modal must prefill the next free dataN name (data1)")
	}
	if !strings.Contains(body, "fm-foot") || !strings.Contains(body, "btn-primary") {
		t.Error("modal must use the form-modal shell with a primary submit")
	}
}

// TestHandler_AddDiskModal_NilDB_NoPanic verifies handleAddDiskModal guards
// s.db before resolving the VM's host via corrosion.GetVM — corrosion.Client.Query
// panics on a nil receiver, so a server with no Corrosion DB wired in (s.db ==
// nil) must still render the modal instead of crashing the request.
func TestHandler_AddDiskModal_NilDB_NoPanic(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock) // no SetCorrosionDB call — s.db stays nil
	body := doGET(t, s, "/ui/vms/vm-a/add-disk-modal")
	if !strings.Contains(body, "add-disk-modal") {
		t.Error("Add-disk modal must render even without a corrosion DB wired in")
	}
}

// TestHandler_AttachDisk_PassesStoragePool verifies the operator's chosen
// storage pool (from the Add-disk modal's pool dropdown) reaches the
// AttachDevice RPC's DiskSpec, alongside the existing name/size/bus fields.
func TestHandler_AttachDisk_PassesStoragePool(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	form := url.Values{"name": {"data1"}, "size_gib": {"20"}, "bus": {"virtio"}, "storage": {"fast-nvme"}}
	doPOSTForm(t, s, "/ui/vms/vm-a/attach-disk", form)
	if mock.lastAttachDeviceReq.GetDisk().GetStorage() != "fast-nvme" {
		t.Errorf("Storage = %q, want fast-nvme", mock.lastAttachDeviceReq.GetDisk().GetStorage())
	}
	if mock.lastAttachDeviceReq.GetDisk().GetSize() != "20G" {
		t.Errorf("Size = %q, want 20G", mock.lastAttachDeviceReq.GetDisk().GetSize())
	}
}

// TestNextDiskName verifies the dataN name-generation helper: it fills the
// lowest unused slot (not just appends), ignores non-dataN disk names
// (e.g. "root"), and starts at data0 for a VM with no disks yet.
func TestNextDiskName(t *testing.T) {
	if got := nextDiskName([]string{"data0", "data2"}); got != "data1" {
		t.Errorf("nextDiskName gap = %q, want data1", got)
	}
	if got := nextDiskName([]string{"root", "data0", "data1"}); got != "data2" {
		t.Errorf("nextDiskName = %q, want data2", got)
	}
	if got := nextDiskName(nil); got != "data0" {
		t.Errorf("nextDiskName empty = %q, want data0", got)
	}
}

func TestHandler_DetachDisk(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("disk_name=data")
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/detach-disk", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastDetachDeviceReq == nil {
		t.Fatal("DetachDevice was not called")
	}
}

func TestHandler_ResizeDisk(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("disk_name=root&size_gib=20")
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/resize-disk", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastResizeDiskReq == nil {
		t.Fatal("ResizeDisk was not called")
	}
}

func TestHandler_AttachNIC(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("bridge=br0&model=virtio")
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/attach-nic", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastAttachDeviceReq == nil {
		t.Fatal("AttachDevice (NIC) was not called")
	}
}

// newHardwareTestServer creates a UI test server with a corrosion test DB
// wired in and two security groups seeded ("web", "ssh"), for the Add-NIC
// modal tests below — the SG multiselect renders nothing without a DB.
func newHardwareTestServer(t *testing.T) (*Server, *mockGRPC) {
	t.Helper()
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	db := newCorrosionForUITest(t)
	s.SetCorrosionDB(db)
	for _, name := range []string{"web", "ssh"} {
		if err := corrosion.InsertSecurityGroup(context.Background(), db, corrosion.SecurityGroup{ID: name, Name: name}); err != nil {
			t.Fatalf("InsertSecurityGroup(%s): %v", name, err)
		}
	}
	return s, mock
}

// seedVM inserts a minimal VM row into the test corrosion DB so
// corrosion.GetVM(ctx, s.db, name) resolves a HostName for handlers (like the
// Add-PCI modal) that need to scope a host-local lookup to the VM's host.
func seedVM(t *testing.T, db *corrosion.Client, name, host string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name: name, HostName: host, Spec: "{}", State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("seedVM(%s, %s): %v", name, host, err)
	}
}

// TestHandler_AddNICModal_RelabelsNetwork verifies the Add-NIC modal offers a
// managed-network / custom-bridge toggle, labels the managed field "Network"
// (never "Bridge" — the field can point at any managed network, not just an
// L2 bridge), lists the security groups available to attach, and populates
// the network dropdown from ListNetworks.
func TestHandler_AddNICModal_RelabelsNetwork(t *testing.T) {
	s, m := newHardwareTestServer(t)
	m.listNetworksResp = &pb.ListNetworksResponse{Networks: []*pb.NetworkInfo{{Name: "lab-net", Type: "bridge", Subnet: "10.20.0.0/24", Dhcp: true}}}
	body := doGET(t, s, "/ui/vms/vm-a/add-nic-modal")
	for _, want := range []string{"Network", "Custom bridge", "Security groups", `name="mode"`, "lab-net"} {
		if !strings.Contains(body, want) {
			t.Errorf("Add-NIC modal missing %q", want)
		}
	}
	if strings.Contains(body, ">Bridge<") {
		t.Error(`the managed-network field must be labeled "Network", not "Bridge"`)
	}
}

// TestHandler_AttachNIC_CustomBridgeAndSGs verifies the custom-bridge mode
// (bridge_custom overrides the managed "bridge" field) and the security
// groups / static IP / gateway fields all reach the AttachDevice RPC's
// NetworkAttachment.
func TestHandler_AttachNIC_CustomBridgeAndSGs(t *testing.T) {
	s, m := newHardwareTestServer(t)
	form := url.Values{"mode": {"custom"}, "bridge_custom": {"br0"}, "model": {"virtio"},
		"security_groups": {"web", "ssh"}, "ip": {"10.20.0.5"}, "gateway": {"10.20.0.1"}}
	doPOSTForm(t, s, "/ui/vms/vm-a/attach-nic", form)
	nic := m.lastAttachDeviceReq.GetNic()
	if nic.GetName() != "br0" {
		t.Errorf("Name = %q, want br0 (custom bridge)", nic.GetName())
	}
	if strings.Join(nic.GetSecurityGroups(), ",") != "web,ssh" {
		t.Errorf("SecurityGroups = %v, want [web ssh]", nic.GetSecurityGroups())
	}
	if nic.GetIp() != "10.20.0.5" || nic.GetGateway() != "10.20.0.1" {
		t.Errorf("static IP/gw not passed: ip=%q gw=%q", nic.GetIp(), nic.GetGateway())
	}
}

func TestHandler_DetachNIC(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("nic_mac=52:54:00:aa:bb:cc")
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/detach-nic", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastDetachDeviceReq == nil {
		t.Fatal("DetachDevice (NIC) was not called")
	}
}

func TestHandler_AttachPCI(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("type=gpu&address=0000:03:00.0")
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/attach-pci", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastAttachDeviceReq == nil {
		t.Fatal("AttachDevice (PCI) was not called")
	}
}

func TestHandler_DetachPCI(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("pci_address=0000:03:00.0")
	r, _ := http.NewRequest("POST", "/ui/vms/vm1/detach-pci", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastDetachDeviceReq == nil {
		t.Fatal("DetachDevice (PCI) was not called")
	}
}

// TestHandler_AddPCIModal_GroupsUnownedByType verifies the Add-PCI modal scans
// the VM's host (resolved via corrosion.GetVM) for host devices, groups the
// UNASSIGNED ones by class (GPU/NIC/NVMe/Other) into optgroups, and excludes
// any device already assigned to another VM from the picker entirely.
func TestHandler_AddPCIModal_GroupsUnownedByType(t *testing.T) {
	s, m := newHardwareTestServer(t)
	seedVM(t, s.db, "vm-a", "host-1") // insert a VM row so GetVM(host)="host-1"
	m.listHostDevicesResp = &pb.ListHostDevicesResponse{Devices: []*pb.PCIDevice{
		{Address: "0000:41:00.0", Type: "gpu", VendorName: "NVIDIA", DeviceName: "L40S", IommuGroup: 34, VmName: ""},
		{Address: "0000:31:00.1", Type: "network", VendorName: "Intel", DeviceName: "E810", IommuGroup: 18, VmName: "vm-b"}, // owned → excluded
	}}
	body := doGET(t, s, "/ui/vms/vm-a/add-pci-modal")
	if !strings.Contains(body, "0000:41:00.0") || !strings.Contains(body, "NVIDIA") {
		t.Error("scanned unowned GPU must be listed")
	}
	if strings.Contains(body, "0000:31:00.1") {
		t.Error("a device owned by another VM must be excluded from the picker")
	}
	if !strings.Contains(body, "<optgroup label=\"GPU\"") {
		t.Error("devices must be grouped by class")
	}
}

// TestHandler_AddPCIModal_NoDevices_EmptyState verifies that when a host has
// no unassigned passthrough devices in any of the four ByType groups (GPU/
// NIC/NVMe/Other), the scanned block renders explanatory copy instead of an
// empty <select> the operator could submit with nothing chosen (spec §5).
func TestHandler_AddPCIModal_NoDevices_EmptyState(t *testing.T) {
	s, m := newHardwareTestServer(t)
	seedVM(t, s.db, "vm-a", "host-1")
	m.listHostDevicesResp = &pb.ListHostDevicesResponse{} // no scanned devices at all
	body := doGET(t, s, "/ui/vms/vm-a/add-pci-modal")
	if !strings.Contains(body, "No unassigned passthrough devices on this host.") {
		t.Error("empty scanned devices must render the no-devices copy, not an empty select")
	}
}

// TestHandler_AddPCIModal_NoMappings_RadioDisabled verifies that when no
// cluster-wide resource mappings exist, the "Resource mapping" radio is
// disabled so an operator can't select an option with nothing behind it
// (spec §5: shown/enabled only when mappings exist; scanned stays default).
func TestHandler_AddPCIModal_NoMappings_RadioDisabled(t *testing.T) {
	s, _ := newHardwareTestServer(t)
	seedVM(t, s.db, "vm-a", "host-1") // ListResourceMappings mock default is empty
	body := doGET(t, s, "/ui/vms/vm-a/add-pci-modal")
	if !strings.Contains(body, `value="mapping" onclick="pciMode()" disabled`) {
		t.Error(`the "Resource mapping" radio must be disabled when no mappings exist`)
	}
}

// TestHandler_AttachPCI_MappingMode verifies mode=mapping sends the chosen
// resource-mapping name via DeviceSpec.Mapping and leaves Address empty,
// distinct from the scanned/custom address-based modes.
func TestHandler_AttachPCI_MappingMode(t *testing.T) {
	s, m := newHardwareTestServer(t)
	form := url.Values{"mode": {"mapping"}, "mapping": {"gpu-pool"}}
	doPOSTForm(t, s, "/ui/vms/vm-a/attach-pci", form)
	pci := m.lastAttachDeviceReq.GetPciDevice()
	if pci.GetMapping() != "gpu-pool" {
		t.Errorf("Mapping = %q, want gpu-pool", pci.GetMapping())
	}
	if pci.GetAddress() != "" {
		t.Errorf("Address must be empty in mapping mode, got %q", pci.GetAddress())
	}
}

// ── Hosts ────────────────────────────────────────────────────────────────────

func TestHandler_HostsPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/hosts"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "host1")
}

func TestHandler_HostDetail(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/hosts/host1"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "host1")
}

func TestHandler_HostDetail_NotFound(t *testing.T) {
	mock := newDefaultMock()
	mock.inspectHostErr = errSimulated
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/hosts/nonexistent"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusNotFound)
}

func TestHandler_DrainHost(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/ui/hosts/host1/drain"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if mock.lastDrainHostName != "host1" {
		t.Errorf("DrainHost name = %q, want host1", mock.lastDrainHostName)
	}
}

func TestHandler_UndrainHost(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/ui/hosts/host1/undrain"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if mock.lastUndrainHostName != "host1" {
		t.Errorf("UndrainHost name = %q, want host1", mock.lastUndrainHostName)
	}
}

func TestHandler_FenceHost(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/ui/hosts/host1/fence"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if mock.lastFenceHostReq == nil || mock.lastFenceHostReq.Name != "host1" {
		t.Error("FenceHost was not called correctly")
	}
}

func TestHandler_RemoveHost(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "DELETE", "/ui/hosts/host1"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if !mock.removeHostCalled {
		t.Error("RemoveHost was not called")
	}
}

func TestHandler_HostLabelsUpdate(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("label=env%3Dprod")
	r, _ := http.NewRequest("POST", "/ui/hosts/host1/labels", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastSetLabelsReq == nil {
		t.Fatal("SetHostLabels was not called")
	}
}

func TestHandler_ConfigureHost(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("fence_strategy=ipmi&ipmi_address=10.0.0.1")
	r, _ := http.NewRequest("POST", "/ui/hosts/host1/config", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastConfigureHostReq == nil {
		t.Fatal("ConfigureHost was not called")
	}
}

func TestHandler_HostStatsPartial(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/hosts/host1/stats"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_HostStatsPartial_Error(t *testing.T) {
	mock := newDefaultMock()
	mock.hostStatsErr = errSimulated
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/ui/hosts/host1/stats"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "unavailable")
}

// ── Stacks ───────────────────────────────────────────────────────────────────

func TestHandler_StacksPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/stacks"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "mystack")
}

func TestHandler_StackDetail(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/stacks/mystack"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "mystack")
}

func TestHandler_StackDetail_NotFound(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/stacks/nosuchstack"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusNotFound)
}

func TestHandler_DeployStackModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/stacks/deploy-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_PlanPreview(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("compose_yaml=name: test\nvms:\n  web:\n    image: ubuntu")
	r, _ := http.NewRequest("POST", "/ui/stacks/plan", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_PlanPreview_EmptyYAML(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	body := strings.NewReader("compose_yaml=")
	r, _ := http.NewRequest("POST", "/ui/stacks/plan", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ── Images ───────────────────────────────────────────────────────────────────

func TestHandler_ImagesPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/images"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "ubuntu")
}

func TestHandler_ImagesTable(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/images-table"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_PullImageModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/images/pull-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_DeleteImage(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "DELETE", "/ui/images/ubuntu"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if !mock.deleteImageCalled {
		t.Error("DeleteImage was not called")
	}
	if mock.lastDeleteImageName != "ubuntu" {
		t.Errorf("DeleteImage name = %q, want ubuntu", mock.lastDeleteImageName)
	}
}

// ── Networks ─────────────────────────────────────────────────────────────────

func TestHandler_NetworksPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/networks"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "br0")
}

func TestHandler_CreateNetworkModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/networks/create-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_CreateNetwork(t *testing.T) {
	mock := newDefaultMock()
	mock.createNetworkResp = &pb.NetworkInfo{Name: "vxlan0"}
	s := newTestUIServer(t, mock)
	body := strings.NewReader("name=vxlan0&type=vxlan&subnet=10.0.0.0/24")
	r, _ := http.NewRequest("POST", "/ui/networks", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastCreateNetworkReq == nil {
		t.Fatal("CreateNetwork was not called")
	}
	if mock.lastCreateNetworkReq.Name != "vxlan0" {
		t.Errorf("network name = %q, want vxlan0", mock.lastCreateNetworkReq.Name)
	}
}

func TestHandler_DeleteNetwork(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "DELETE", "/ui/networks/br0"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if !mock.deleteNetworkCalled {
		t.Error("DeleteNetwork was not called")
	}
}

// ── Load Balancers ───────────────────────────────────────────────────────────

func TestHandler_LBPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/lb"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "lb1")
}

func TestHandler_LBDetail(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/lb/lb1"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "lb1")
}

func TestHandler_LBDetail_NotFound(t *testing.T) {
	mock := newDefaultMock()
	mock.inspectLBErr = errSimulated
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "GET", "/lb/nosuchlb"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusNotFound)
}

func TestHandler_LBDelete(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "POST", "/lb/lb1/delete"))
	w := serveRequest(s, r)
	// LBDelete now responds htmx-style: 200 + HX-Redirect (so the themed
	// hx-confirm dialog drives it instead of a native confirm + 303).
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Redirect"); got != "/lb" {
		t.Errorf("HX-Redirect = %q, want /lb", got)
	}
	if !mock.deleteLBCalled {
		t.Error("DeleteLoadBalancer was not called")
	}
}

func TestHandler_LBDrain(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("backend=web-1")
	r, _ := http.NewRequest("POST", "/lb/lb1/drain", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if got := w.Header().Get("HX-Redirect"); got != "/lb/lb1" {
		t.Errorf("HX-Redirect = %q, want /lb/lb1", got)
	}
	if mock.lastDrainReq == nil {
		t.Fatal("DrainBackend was not called")
	}
}

func TestHandler_LBDrain_MissingBackend(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "POST", "/lb/lb1/drain"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusBadRequest)
}

// ── Events / Audit ───────────────────────────────────────────────────────────

func TestHandler_EventsPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/events"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

func TestHandler_AuditPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/audit"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

// ── PCI ──────────────────────────────────────────────────────────────────────

func TestHandler_PCIPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/pci"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
}

// ── Users ────────────────────────────────────────────────────────────────────

func TestHandler_UsersPage(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/users"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "admin")
}

func TestHandler_CreateUser(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("username=newuser&password=pass123&role=viewer")
	r, _ := http.NewRequest("POST", "/ui/users", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)

	assertStatus(t, w, http.StatusOK)
	if mock.lastCreateUserReq == nil {
		t.Fatal("CreateUser was not called")
	}
	if mock.lastCreateUserReq.Username != "newuser" {
		t.Errorf("username = %q, want newuser", mock.lastCreateUserReq.Username)
	}
}

func TestHandler_DeleteUser(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "DELETE", "/ui/users/olduser"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if !mock.deleteUserCalled {
		t.Error("DeleteUser was not called")
	}
}

func TestHandler_CreateToken(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	body := strings.NewReader("username=admin&label=ci-token")
	r, _ := http.NewRequest("POST", "/ui/users/admin/token", body)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = withAuth(r)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if mock.lastCreateTokenReq == nil {
		t.Fatal("CreateToken was not called")
	}
}

func TestHandler_RevokeToken(t *testing.T) {
	mock := newDefaultMock()
	s := newTestUIServer(t, mock)
	r := withAuth(mustReq(t, "DELETE", "/ui/tokens/tok-123"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
	if !mock.revokeTokenCalled {
		t.Error("RevokeToken was not called")
	}
	if mock.lastRevokeTokenID != "tok-123" {
		t.Errorf("RevokeToken ID = %q, want tok-123", mock.lastRevokeTokenID)
	}
}

// ── Template helper functions ────────────────────────────────────────────────

func TestVmStateBadge(t *testing.T) {
	tests := []struct {
		state pb.VMState
		want  string
	}{
		{pb.VMState_VM_RUNNING, "running"},
		{pb.VMState_VM_STOPPED, "stopped"},
		{pb.VMState_VM_ERROR, "error"},
		{pb.VMState_VM_MIGRATING, "migrating"},
	}
	for _, tt := range tests {
		badge := vmStateBadge(tt.state)
		if !strings.Contains(string(badge), tt.want) {
			t.Errorf("vmStateBadge(%v) = %q, want to contain %q", tt.state, badge, tt.want)
		}
	}
}

func TestHostStateBadge(t *testing.T) {
	tests := []struct {
		state pb.HostState
		want  string
	}{
		{pb.HostState_HOST_ACTIVE, "active"},
		{pb.HostState_HOST_DRAINING, "draining"},
		{pb.HostState_HOST_SUSPECT, "suspect"},
	}
	for _, tt := range tests {
		badge := hostStateBadge(tt.state)
		if !strings.Contains(string(badge), tt.want) {
			t.Errorf("hostStateBadge(%v) = %q, want to contain %q", tt.state, badge, tt.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0B"},
		{500, "500B"},
		{1024, "1.0KiB"},
		{1048576, "1.0MiB"},
		{1073741824, "1.0GiB"},
	}
	for _, tt := range tests {
		got := formatBytes(tt.input)
		if got != tt.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFirstIP(t *testing.T) {
	if got := firstIP(nil); got != "—" {
		t.Errorf("firstIP(nil) = %q, want —", got)
	}
	ifaces := []*pb.VMInterface{
		{Ip: ""},
		{Ip: "10.0.0.5"},
		{Ip: "10.0.0.6"},
	}
	if got := firstIP(ifaces); got != "10.0.0.5" {
		t.Errorf("firstIP = %q, want 10.0.0.5", got)
	}
}

func TestClusterStats(t *testing.T) {
	const giB = int64(1024 * 1024 * 1024)
	hosts := []*pb.Host{
		{State: pb.HostState_HOST_ACTIVE, CpuTotal: 16, CpuUsed: 8, MemTotalMib: 32768, MemUsedMib: 16384,
			// Allocated (DiskUsedGib) is intentionally large to prove the
			// aggregate uses actual statfs usage, not allocation.
			DiskUsedGib: 9999,
			StoragePools: []*pb.StoragePool{
				{Target: "/data", UsedBytes: 100 * giB, TotalBytes: 400 * giB},
			}},
		{State: pb.HostState_HOST_DRAINING, CpuTotal: 8, CpuUsed: 0, MemTotalMib: 16384, MemUsedMib: 0},
	}
	vms := []*pb.VM{
		{State: pb.VMState_VM_RUNNING},
		{State: pb.VMState_VM_RUNNING},
		{State: pb.VMState_VM_STOPPED},
		{State: pb.VMState_VM_ERROR},
	}
	s := clusterStats(hosts, vms)
	if s.TotalHosts != 2 {
		t.Errorf("TotalHosts = %d, want 2", s.TotalHosts)
	}
	if s.ActiveHosts != 1 {
		t.Errorf("ActiveHosts = %d, want 1", s.ActiveHosts)
	}
	if s.RunningVMs != 2 {
		t.Errorf("RunningVMs = %d, want 2", s.RunningVMs)
	}
	if s.StoppedVMs != 1 {
		t.Errorf("StoppedVMs = %d, want 1", s.StoppedVMs)
	}
	if s.ErrorVMs != 1 {
		t.Errorf("ErrorVMs = %d, want 1", s.ErrorVMs)
	}
	if s.CPUPct == 0 {
		t.Error("CPUPct should be non-zero")
	}
	// Disk aggregate must be actual statfs usage (100/400 GiB), not the 9999
	// GiB allocated figure.
	if s.DiskUsedGiB != 100 {
		t.Errorf("DiskUsedGiB = %d, want 100 (actual/statfs, not allocated)", s.DiskUsedGiB)
	}
	if s.DiskTotalGiB != 400 {
		t.Errorf("DiskTotalGiB = %d, want 400", s.DiskTotalGiB)
	}
	if s.DiskPct != 25 {
		t.Errorf("DiskPct = %v, want 25", s.DiskPct)
	}
}

func TestTruncateHelper(t *testing.T) {
	if got := truncateHelper("hello", 10); got != "hello" {
		t.Errorf("truncateHelper short = %q", got)
	}
	if got := truncateHelper("hello world", 5); got != "hello..." {
		t.Errorf("truncateHelper long = %q", got)
	}
}

func TestVmActions(t *testing.T) {
	// Running VM should have stop + restart buttons.
	html := vmActions("vm1", pb.VMState_VM_RUNNING)
	if !strings.Contains(string(html), "stop") {
		t.Error("running VM should have stop button")
	}
	if !strings.Contains(string(html), "restart") {
		t.Error("running VM should have restart button")
	}

	// Stopped VM should have start button.
	html = vmActions("vm1", pb.VMState_VM_STOPPED)
	if !strings.Contains(string(html), "start") {
		t.Error("stopped VM should have start button")
	}
}

func TestSendToast(t *testing.T) {
	w := &fakeResponseWriter{headers: http.Header{}}
	sendToast(w, "test message", "success")
	trigger := w.headers.Get("HX-Trigger")
	if !strings.Contains(trigger, "test message") {
		t.Errorf("HX-Trigger = %q, want to contain 'test message'", trigger)
	}
}

// fakeResponseWriter captures headers for toast testing.
type fakeResponseWriter struct {
	headers http.Header
}

func (f *fakeResponseWriter) Header() http.Header         { return f.headers }
func (f *fakeResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (f *fakeResponseWriter) WriteHeader(int)             {}

// Silence unused import warning.
var _ = template.HTML("")
