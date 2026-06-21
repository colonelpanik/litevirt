package grpcapi

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestListImages_Empty(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	resp, err := s.ListImages(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(resp.Images) != 0 {
		t.Errorf("expected 0 images, got %d", len(resp.Images))
	}
}

func TestListImages_WithImages(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name:      "ubuntu-22.04",
		Format:    "qcow2",
		SizeBytes: 1024 * 1024 * 500,
	})

	resp, err := s.ListImages(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(resp.Images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(resp.Images))
	}
	if resp.Images[0].Name != "ubuntu-22.04" {
		t.Errorf("Name = %q, want ubuntu-22.04", resp.Images[0].Name)
	}
}

func TestDeleteImage(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name: "to-delete",
	})

	_, err := s.DeleteImage(ctx, &pb.DeleteImageRequest{Name: "to-delete"})
	if err != nil {
		t.Fatalf("DeleteImage: %v", err)
	}
}

func TestBuildImage_EmptyFields(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.BuildImage(ctx, &pb.BuildImageRequest{})
	if c := status.Code(err); c != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", c)
	}
}

func TestBuildImage_VMNotFound(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	_, err := s.BuildImage(ctx, &pb.BuildImageRequest{VmName: "ghost", ImageName: "img"})
	if c := status.Code(err); c != codes.NotFound {
		t.Errorf("code = %v, want NotFound", c)
	}
}

func TestBuildImage_WrongHost(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	insertTestVM(t, ctx, s.db, "remote-vm", "other-host", "running")

	_, err := s.BuildImage(ctx, &pb.BuildImageRequest{VmName: "remote-vm", ImageName: "img"})
	c := status.Code(err)
	if c != codes.Unavailable && c != codes.FailedPrecondition {
		t.Errorf("code = %v, want Unavailable or FailedPrecondition", c)
	}
}
