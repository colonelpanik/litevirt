package ui

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func TestUploadStorageContent(t *testing.T) {
	mock := newDefaultMock()
	mock.uploadStream = &fakeUploadStream{}
	// after upload the handler re-renders the pool listing
	mock.poolContentsResp = &pb.ListStoragePoolContentsResponse{Contents: []*pb.StoragePoolContent{
		{Name: "alpine.iso", Path: "/pool/alpine.iso", IsIso: true},
	}}
	s := newTestUIServer(t, mock)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	// hidden fields first (so the handler knows host/pool before the file part)
	_ = mw.WriteField("host", "host1")
	_ = mw.WriteField("pool", "local")
	_ = mw.WriteField("field", "iso")
	fw, _ := mw.CreateFormFile("file", "alpine.iso")
	fw.Write([]byte("ISO-CONTENTS-HERE"))
	mw.Close()

	r, _ := http.NewRequest("POST", "/ui/storage/upload", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r = withAuth(r)
	w := serveRequest(s, r)
	assertStatus(t, w, http.StatusOK)

	if mock.uploadStream.first == nil || mock.uploadStream.first.Filename != "alpine.iso" {
		t.Fatalf("upload first msg = %+v, want filename alpine.iso", mock.uploadStream.first)
	}
	if mock.uploadStream.first.PoolName != "local" || mock.uploadStream.first.Host != "host1" {
		t.Errorf("upload target = %s/%s, want host1/local", mock.uploadStream.first.Host, mock.uploadStream.first.PoolName)
	}
	got := bytes.Join(mock.uploadStream.chunks, nil)
	if string(got) != "ISO-CONTENTS-HERE" {
		t.Errorf("streamed bytes = %q, want ISO-CONTENTS-HERE", got)
	}
	// re-renders the pool's files
	mustContain(t, w.Body.String(), "alpine.iso")
}
