package ui

import (
	"net/http"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestISOBrowser(t *testing.T) {
	mock := newDefaultMock()
	mock.listStoragePoolsResp = &pb.ListStoragePoolsResponse{Pools: []*pb.StoragePool{
		{Name: "local", Driver: "local", Host: "host1"},
		{Name: "fast", Driver: "ceph", Host: "host1"}, // block — must be filtered out
	}}
	mock.poolContentsResp = &pb.ListStoragePoolContentsResponse{Contents: []*pb.StoragePoolContent{
		{Name: "debian-12.iso", Path: "/var/lib/litevirt/disks/debian-12.iso", SizeBytes: 700 << 20, IsIso: true},
	}}
	s := newTestUIServer(t, mock)

	t.Run("modal lists only file-based pools", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/storage/iso-browser?field=iso")))
		assertStatus(t, w, http.StatusOK)
		body := w.Body.String()
		mustContain(t, body, "Browse storage", "host1::local", "pickStorageFile")
		if strings.Contains(body, "::fast") {
			t.Error("block-backed pool should be filtered from the browser")
		}
	})

	t.Run("contents lists files with picker path", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/storage/contents?poolref=host1::local&field=iso")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "debian-12.iso", `data-path="/var/lib/litevirt/disks/debian-12.iso"`)
		if mock.lastPoolContentsReq.Host != "host1" || mock.lastPoolContentsReq.PoolName != "local" {
			t.Errorf("forwarded req = %+v, want host1/local", mock.lastPoolContentsReq)
		}
	})

	t.Run("create modal has Browse button", func(t *testing.T) {
		w := serveRequest(s, withAuth(mustReq(t, "GET", "/ui/vms/new-modal")))
		assertStatus(t, w, http.StatusOK)
		mustContain(t, w.Body.String(), "/ui/storage/iso-browser?field=iso")
	})
}
