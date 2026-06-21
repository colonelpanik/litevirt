package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestPruneReplicas(t *testing.T) {
	dir := t.TempDir()
	// Five timestamped replicas of vm1/root, plus an unrelated file.
	names := []string{
		"vm1-root-20260101-000000.qcow2",
		"vm1-root-20260102-000000.qcow2",
		"vm1-root-20260103-000000.qcow2",
		"vm1-root-20260104-000000.qcow2",
		"vm1-root-20260105-000000.qcow2",
	}
	for _, n := range names {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644)
	}
	os.WriteFile(filepath.Join(dir, "other-vm-root-20260105-000000.qcow2"), []byte("x"), 0o644)

	// Keep newest 2 → delete the 3 oldest.
	if got := pruneReplicas(dir, "vm1", "root", 2); got != 3 {
		t.Fatalf("pruned %d, want 3", got)
	}
	// The two newest survive; the unrelated file is untouched.
	for _, keep := range []string{"vm1-root-20260104-000000.qcow2", "vm1-root-20260105-000000.qcow2", "other-vm-root-20260105-000000.qcow2"} {
		if _, err := os.Stat(filepath.Join(dir, keep)); err != nil {
			t.Errorf("expected %s to survive: %v", keep, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "vm1-root-20260101-000000.qcow2")); !os.IsNotExist(err) {
		t.Errorf("oldest replica should have been pruned")
	}
	// keepN=0 keeps all.
	if got := pruneReplicas(dir, "vm1", "root", 0); got != 0 {
		t.Errorf("keepN=0 should prune nothing, got %d", got)
	}
}

func TestIsSharedDriver(t *testing.T) {
	for _, d := range []string{"nfs", "ceph", "iscsi"} {
		if !isSharedDriver(d) {
			t.Errorf("%s should be shared", d)
		}
	}
	for _, d := range []string{"local", "dir", "btrfs", ""} {
		if isSharedDriver(d) {
			t.Errorf("%s should not be shared", d)
		}
	}
}

// fakeReplClient implements just the two RPCs pruneReplicasRemote uses.
type fakeReplClient struct {
	pb.LiteVirtClient
	contents []*pb.StoragePoolContent
	deleted  []string
}

func (f *fakeReplClient) ListStoragePoolContents(_ context.Context, _ *pb.ListStoragePoolContentsRequest, _ ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	return &pb.ListStoragePoolContentsResponse{Contents: f.contents}, nil
}
func (f *fakeReplClient) DeleteStoragePoolContent(_ context.Context, in *pb.DeleteStoragePoolContentRequest, _ ...grpc.CallOption) (*emptypb.Empty, error) {
	f.deleted = append(f.deleted, in.Filename)
	return &emptypb.Empty{}, nil
}

func TestPruneReplicasRemote(t *testing.T) {
	c := &fakeReplClient{contents: []*pb.StoragePoolContent{
		{Name: "vm1-root-20260101-000000.qcow2"},
		{Name: "vm1-root-20260102-000000.qcow2"},
		{Name: "vm1-root-20260103-000000.qcow2"},
		{Name: "other-root-20260103-000000.qcow2"}, // different VM — must be ignored
	}}
	n := pruneReplicasRemote(context.Background(), c, "dr", "host-b", "vm1", "root", 1)
	if n != 2 {
		t.Fatalf("pruned %d, want 2", n)
	}
	want := map[string]bool{"vm1-root-20260101-000000.qcow2": true, "vm1-root-20260102-000000.qcow2": true}
	for _, d := range c.deleted {
		if !want[d] {
			t.Errorf("deleted unexpected %q (should keep newest + other VM)", d)
		}
	}
}
