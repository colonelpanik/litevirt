package ui

import (
	"html/template"
	"net/http"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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

func TestHandler_EditVMModal(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(mustReq(t, "GET", "/ui/vms/vm1/edit-modal"))
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)
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
