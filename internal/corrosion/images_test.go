package corrosion

import (
	"context"
	"testing"
)

func TestInsertAndGetImage(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	img := ImageRecord{
		Name:      "ubuntu-22.04",
		Format:    "qcow2",
		SourceURL: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
		Checksum:  "sha256:abc123",
		SizeBytes: 1073741824,
	}
	if err := InsertImage(ctx, c, img); err != nil {
		t.Fatalf("InsertImage: %v", err)
	}

	got, err := GetImage(ctx, c, "ubuntu-22.04")
	if err != nil {
		t.Fatalf("GetImage: %v", err)
	}
	if got == nil {
		t.Fatal("GetImage returned nil")
	}
	if got.Name != "ubuntu-22.04" {
		t.Errorf("Name = %q, want ubuntu-22.04", got.Name)
	}
	if got.Format != "qcow2" {
		t.Errorf("Format = %q, want qcow2", got.Format)
	}
	if got.SourceURL != img.SourceURL {
		t.Errorf("SourceURL = %q, want %q", got.SourceURL, img.SourceURL)
	}
	if got.Checksum != "sha256:abc123" {
		t.Errorf("Checksum = %q, want sha256:abc123", got.Checksum)
	}
	if got.SizeBytes != 1073741824 {
		t.Errorf("SizeBytes = %d, want 1073741824", got.SizeBytes)
	}
	if got.CreatedAt == "" {
		t.Error("CreatedAt should be set")
	}
	if got.UpdatedAt == "" {
		t.Error("UpdatedAt should be set")
	}
}

func TestGetImage_NotFound(t *testing.T) {
	c := testClient(t)

	got, err := GetImage(context.Background(), c, "nonexistent")
	if err != nil {
		t.Fatalf("GetImage error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for missing image, got %+v", got)
	}
}

func TestListImages(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	for _, img := range []ImageRecord{
		{Name: "ubuntu-22.04", Format: "qcow2", SourceURL: "https://example.com/ubuntu.img", SizeBytes: 1000},
		{Name: "debian-12", Format: "qcow2", SourceURL: "https://example.com/debian.img", SizeBytes: 2000},
		{Name: "alpine-3.18", Format: "raw", SourceURL: "https://example.com/alpine.img", SizeBytes: 500},
	} {
		if err := InsertImage(ctx, c, img); err != nil {
			t.Fatalf("InsertImage %s: %v", img.Name, err)
		}
	}

	images, err := ListImages(ctx, c)
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(images) != 3 {
		t.Fatalf("expected 3 images, got %d", len(images))
	}
}

func TestListImages_Empty(t *testing.T) {
	c := testClient(t)

	images, err := ListImages(context.Background(), c)
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	if len(images) != 0 {
		t.Errorf("expected 0 images, got %d", len(images))
	}
}

func TestInsertImage_Upsert(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	img := ImageRecord{Name: "ubuntu", Format: "qcow2", SizeBytes: 1000}
	if err := InsertImage(ctx, c, img); err != nil {
		t.Fatalf("InsertImage: %v", err)
	}

	// Insert again with updated size (INSERT OR REPLACE)
	img.SizeBytes = 2000
	img.Format = "raw"
	if err := InsertImage(ctx, c, img); err != nil {
		t.Fatalf("InsertImage upsert: %v", err)
	}

	got, _ := GetImage(ctx, c, "ubuntu")
	if got.SizeBytes != 2000 {
		t.Errorf("SizeBytes = %d after upsert, want 2000", got.SizeBytes)
	}
	if got.Format != "raw" {
		t.Errorf("Format = %q after upsert, want raw", got.Format)
	}
}

func TestInsertImageHost(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Create an image first
	if err := InsertImage(ctx, c, ImageRecord{Name: "ubuntu", Format: "qcow2"}); err != nil {
		t.Fatalf("InsertImage: %v", err)
	}

	ih := ImageHostRecord{
		ImageName: "ubuntu",
		HostName:  "node1",
		Path:      "/var/lib/litevirt/images/ubuntu.qcow2",
		Status:    "ready",
		PulledAt:  "2024-01-01T00:00:00Z",
	}
	if err := InsertImageHost(ctx, c, ih); err != nil {
		t.Fatalf("InsertImageHost: %v", err)
	}

	hosts, err := GetImageHosts(ctx, c, "ubuntu")
	if err != nil {
		t.Fatalf("GetImageHosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].HostName != "node1" {
		t.Errorf("HostName = %q, want node1", hosts[0].HostName)
	}
	if hosts[0].Path != "/var/lib/litevirt/images/ubuntu.qcow2" {
		t.Errorf("Path = %q", hosts[0].Path)
	}
	if hosts[0].Status != "ready" {
		t.Errorf("Status = %q, want ready", hosts[0].Status)
	}
}

func TestGetImageHosts_MultipleHosts(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertImage(ctx, c, ImageRecord{Name: "ubuntu", Format: "qcow2"})

	for _, h := range []ImageHostRecord{
		{ImageName: "ubuntu", HostName: "node1", Path: "/images/ubuntu.qcow2", Status: "ready", PulledAt: "2024-01-01T00:00:00Z"},
		{ImageName: "ubuntu", HostName: "node2", Path: "/images/ubuntu.qcow2", Status: "ready", PulledAt: "2024-01-01T00:00:00Z"},
		{ImageName: "ubuntu", HostName: "node3", Path: "/images/ubuntu.qcow2", Status: "pulling", PulledAt: ""},
	} {
		if err := InsertImageHost(ctx, c, h); err != nil {
			t.Fatalf("InsertImageHost %s: %v", h.HostName, err)
		}
	}

	hosts, err := GetImageHosts(ctx, c, "ubuntu")
	if err != nil {
		t.Fatalf("GetImageHosts: %v", err)
	}
	// All statuses are returned (ready + pulling).
	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(hosts))
	}
	// Verify pulling host is included with correct status.
	var pullingCount int
	for _, h := range hosts {
		if h.Status == "pulling" {
			pullingCount++
		}
	}
	if pullingCount != 1 {
		t.Fatalf("expected 1 pulling host, got %d", pullingCount)
	}
}

func TestGetImageHosts_Empty(t *testing.T) {
	c := testClient(t)

	hosts, err := GetImageHosts(context.Background(), c, "nonexistent")
	if err != nil {
		t.Fatalf("GetImageHosts: %v", err)
	}
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts, got %d", len(hosts))
	}
}

func TestDeleteImage(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertImage(ctx, c, ImageRecord{Name: "ubuntu", Format: "qcow2"})
	InsertImageHost(ctx, c, ImageHostRecord{
		ImageName: "ubuntu", HostName: "node1",
		Path: "/images/ubuntu.qcow2", Status: "ready",
	})

	if err := DeleteImage(ctx, c, "ubuntu"); err != nil {
		t.Fatalf("DeleteImage: %v", err)
	}

	// Image should no longer appear in GetImage
	got, _ := GetImage(ctx, c, "ubuntu")
	if got != nil {
		t.Error("expected nil after delete, got image record")
	}

	// Image should no longer appear in ListImages
	images, _ := ListImages(ctx, c)
	if len(images) != 0 {
		t.Errorf("expected 0 images after delete, got %d", len(images))
	}

	// Image hosts should also be tombstoned
	hosts, _ := GetImageHosts(ctx, c, "ubuntu")
	if len(hosts) != 0 {
		t.Errorf("expected 0 hosts after delete, got %d", len(hosts))
	}
}

func TestDeleteImage_PreservesOtherImages(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	InsertImage(ctx, c, ImageRecord{Name: "ubuntu", Format: "qcow2"})
	InsertImage(ctx, c, ImageRecord{Name: "debian", Format: "qcow2"})

	if err := DeleteImage(ctx, c, "ubuntu"); err != nil {
		t.Fatalf("DeleteImage: %v", err)
	}

	images, _ := ListImages(ctx, c)
	if len(images) != 1 {
		t.Fatalf("expected 1 image after delete, got %d", len(images))
	}
	if images[0].Name != "debian" {
		t.Errorf("remaining image = %q, want debian", images[0].Name)
	}
}
