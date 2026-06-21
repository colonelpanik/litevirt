package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// mockWithVMDisk returns a mock whose vm1 (on host1) has one disk on pool "local",
// plus the given pools, so the replicate/move modals have something to render.
func mockWithVMDisk(pools ...*pb.StoragePool) *mockGRPC {
	m := newDefaultMock()
	m.inspectVMResp = &pb.VM{
		Name: "vm1", State: pb.VMState_VM_RUNNING, HostName: "host1",
		Disks: []*pb.VMDisk{{Name: "disk0", StorageVolume: "local", SizeBytes: 1 << 30}},
	}
	m.listStoragePoolsResp = &pb.ListStoragePoolsResponse{Pools: pools}
	return m
}

// ── handleReplicateVolumeModal ────────────────────────────────────────────────

func TestReplicateModal_ListsOtherPools(t *testing.T) {
	mock := mockWithVMDisk(
		&pb.StoragePool{Name: "local", Host: "host1"},   // current — excluded
		&pb.StoragePool{Name: "nvme-2t", Host: "host1"}, // candidate
		&pb.StoragePool{Name: "other", Host: "host2"},   // wrong host — excluded
	)
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/vm1/replicate-volume-modal?disk=disk0")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Replicate disk to another pool")
	assertContains(t, w, "nvme-2t")
	body := w.Body.String()
	if bodyHas(body, ">other<") {
		t.Error("pool on a different host should not be offered")
	}
}

func TestReplicateModal_NoOtherPools(t *testing.T) {
	mock := mockWithVMDisk(&pb.StoragePool{Name: "local", Host: "host1"}) // only the current pool
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/vm1/replicate-volume-modal?disk=disk0")))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "No other file-based pools")
}

// ── handleReplicateVolume ─────────────────────────────────────────────────────

func TestReplicateVolume_Happy(t *testing.T) {
	mock := mockWithVMDisk()
	mock.replicateFrames = []*pb.ReplicateVolumeProgress{
		{Phase: pb.ReplicateVolumeProgress_COPY, Status: "copying", CopyPct: 50},
		{Phase: pb.ReplicateVolumeProgress_DONE, Status: "done", TargetPath: "/pools/nvme-2t/vm1-disk0.qcow2"},
	}
	s := newTestUIServer(t, mock)
	form := url.Values{"disk": {"disk0"}, "target_pool": {"nvme-2t"}, "target_path": {"/pools/nvme-2t/vm1-disk0.qcow2"}}
	w := serveRequest(s, formPost(t, "/ui/vms/vm1/replicate-volume", form))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Disk replicated")
	assertContains(t, w, "/pools/nvme-2t/vm1-disk0.qcow2")
	req := mock.lastReplicateReq
	if req == nil || req.VmName != "vm1" || req.DiskName != "disk0" || req.TargetPool != "nvme-2t" || req.TargetPath != "/pools/nvme-2t/vm1-disk0.qcow2" {
		t.Errorf("ReplicateVolume req = %+v", req)
	}
}

func TestReplicateVolume_OptionalTargetPathOmitted(t *testing.T) {
	mock := mockWithVMDisk()
	s := newTestUIServer(t, mock)
	form := url.Values{"disk": {"disk0"}, "target_pool": {"nvme-2t"}}
	w := serveRequest(s, formPost(t, "/ui/vms/vm1/replicate-volume", form))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Disk replicated") // empty stream → still success
	if mock.lastReplicateReq.TargetPath != "" {
		t.Errorf("TargetPath = %q, want empty", mock.lastReplicateReq.TargetPath)
	}
}

func TestReplicateVolume_MissingFieldsRejected(t *testing.T) {
	for _, tc := range []struct {
		name string
		form url.Values
	}{
		{"no disk", url.Values{"target_pool": {"nvme-2t"}}},
		{"no pool", url.Values{"disk": {"disk0"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mock := mockWithVMDisk()
			s := newTestUIServer(t, mock)
			w := serveRequest(s, formPost(t, "/ui/vms/vm1/replicate-volume", tc.form))
			assertStatus(t, w, http.StatusBadRequest)
			assertToast(t, w, "required")
			if mock.lastReplicateReq != nil {
				t.Error("ReplicateVolume should not be called")
			}
		})
	}
}

func TestReplicateVolume_StreamStartErrorReported(t *testing.T) {
	mock := mockWithVMDisk()
	mock.replicateErr = errSimulated
	s := newTestUIServer(t, mock)
	form := url.Values{"disk": {"disk0"}, "target_pool": {"nvme-2t"}}
	w := serveRequest(s, formPost(t, "/ui/vms/vm1/replicate-volume", form))
	assertStatus(t, w, http.StatusOK) // result fragment carries the error
	assertContains(t, w, "Replication failed")
}

func TestReplicateVolume_ErrorFrameReported(t *testing.T) {
	mock := mockWithVMDisk()
	mock.replicateFrames = []*pb.ReplicateVolumeProgress{{Error: "qemu-img convert failed"}}
	s := newTestUIServer(t, mock)
	form := url.Values{"disk": {"disk0"}, "target_pool": {"nvme-2t"}}
	w := serveRequest(s, formPost(t, "/ui/vms/vm1/replicate-volume", form))
	assertStatus(t, w, http.StatusOK)
	assertContains(t, w, "Replication failed")
	assertContains(t, w, "qemu-img convert failed")
}

// bodyHas is a tiny substring helper (assertContains fails the test; this returns bool).
func bodyHas(s, sub string) bool {
	return strings.Contains(s, sub)
}
