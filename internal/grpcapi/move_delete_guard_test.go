package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestDeleteSourceIfUnreferenced verifies the post-move source delete only
// removes the old file when no other disk still references it.
func TestDeleteSourceIfUnreferenced(t *testing.T) {
	ctx := context.Background()

	setup := func(t *testing.T) (*Server, *corrosion.VMRecord, *corrosion.DiskRecord, string) {
		t.Helper()
		s := testServer(t)
		path := filepath.Join(t.TempDir(), "vm1-data.qcow2")
		if err := os.WriteFile(path, []byte("disk-bytes"), 0o644); err != nil {
			t.Fatal(err)
		}
		vm := &corrosion.VMRecord{Name: "vm1", HostName: "test-host"}
		src := &corrosion.DiskRecord{VMName: "vm1", DiskName: "data", Path: path, StorageType: "dir"}
		return s, vm, src, path
	}

	collect := func() (func(*pb.MoveVolumeProgress) error, *[]string) {
		var msgs []string
		return func(p *pb.MoveVolumeProgress) error { msgs = append(msgs, p.Status); return nil }, &msgs
	}
	contains := func(t *testing.T, msgs []string, sub string) {
		t.Helper()
		for _, m := range msgs {
			if strings.Contains(m, sub) {
				return
			}
		}
		t.Fatalf("expected a status containing %q; got %v", sub, msgs)
	}

	t.Run("unreferenced is deleted", func(t *testing.T) {
		s, vm, src, path := setup(t)
		// The moved disk's record now points at the new pool (post-repoint).
		corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
			VMName: "vm1", DiskName: "data", HostName: "test-host",
			Path: "/new/pool/vm1-data.qcow2", StorageType: "dir"})
		send, msgs := collect()
		s.deleteSourceIfUnreferenced(ctx, vm, src, send)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("source should have been deleted; stat err=%v", err)
		}
		contains(t, *msgs, "source removed")
	})

	t.Run("own record still at src path does not block delete", func(t *testing.T) {
		s, vm, src, path := setup(t)
		corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
			VMName: "vm1", DiskName: "data", HostName: "test-host",
			Path: path, StorageType: "dir"})
		send, _ := collect()
		s.deleteSourceIfUnreferenced(ctx, vm, src, send)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("the moved disk's own record must not block its cleanup; stat err=%v", err)
		}
	})

	t.Run("shared by another VM is kept", func(t *testing.T) {
		s, vm, src, path := setup(t)
		corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
			VMName: "vm2", DiskName: "root", HostName: "test-host",
			Path: path, StorageType: "dir"})
		send, msgs := collect()
		s.deleteSourceIfUnreferenced(ctx, vm, src, send)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("a shared source must be kept; stat err=%v", err)
		}
		contains(t, *msgs, "NOT deleted")
	})

	t.Run("used as a backing image is kept", func(t *testing.T) {
		s, vm, src, path := setup(t)
		corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
			VMName: "vm3", DiskName: "root", HostName: "test-host",
			Path: "/elsewhere/vm3-root.qcow2", BackingImage: path, StorageType: "dir"})
		send, msgs := collect()
		s.deleteSourceIfUnreferenced(ctx, vm, src, send)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("a source used as a backing image must be kept; stat err=%v", err)
		}
		contains(t, *msgs, "backing image")
	})

	// bug-sweep #3: a linked clone references its source via backing_disk, which
	// DisksReferencingPath does NOT check — the old guard missed it and deleted
	// the clone's backing chain.
	t.Run("backing a linked clone is kept", func(t *testing.T) {
		s, vm, src, path := setup(t)
		corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
			VMName: "clone1", DiskName: "root", HostName: "test-host",
			Path: "/pool/clone1-root.qcow2", BackingDisk: path, StorageType: "dir"})
		send, msgs := collect()
		s.deleteSourceIfUnreferenced(ctx, vm, src, send)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("a source backing a linked clone must be kept; stat err=%v", err)
		}
		contains(t, *msgs, "linked clone")
	})
}
