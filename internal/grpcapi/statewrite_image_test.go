package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/image"
)

// TestPersistImageRecord_WriteFailureSurfaces reproduces the fail-open image bug:
// when the image_host "ready" write fails, the pre-fix code discards the error and
// reports success, leaving an image on disk that placement/failover cannot see. A
// dropped image_hosts table forces the write to fail.
//
// Correct behavior: persistImageRecord returns an error so the caller can mark the
// image_host status "error" instead of silently claiming ready. This fails against
// the pre-fix (void / ignored-error) code and passes once the write is checked.
func TestPersistImageRecord_WriteFailureSurfaces(t *testing.T) {
	s := testServer(t)
	s.images = image.NewStore(t.TempDir())
	ctx := context.Background()

	if err := s.db.Execute(ctx, `DROP TABLE image_hosts`); err != nil {
		t.Fatalf("drop image_hosts: %v", err)
	}

	err := s.persistImageRecord(&pb.PullImageRequest{Name: "img1", Format: "qcow2"})
	if err == nil {
		t.Error("persistImageRecord returned nil; want an error when the image_host write fails")
	}
}
