package daemon

import (
	"context"
	"syscall"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const poolTestGiB = uint64(1024 * 1024 * 1024)

type fakeFS struct {
	fsid int32 // 0 = the filesystem reports no identity
	gib  uint64
}

// fakeStatfs replaces statfsFn for the test with a path → filesystem table, so
// paths can sit on distinct filesystems (or share one) at will.
func fakeStatfs(t *testing.T, fs map[string]fakeFS) {
	t.Helper()
	orig := statfsFn
	statfsFn = func(path string, st *syscall.Statfs_t) error {
		f, ok := fs[path]
		if !ok {
			return syscall.ENOENT
		}
		*st = syscall.Statfs_t{}
		st.Bsize = 4096
		st.Blocks = f.gib * poolTestGiB / 4096
		st.Fsid.X__val[0] = f.fsid // Linux field name; hence the _linux file
		return nil
	}
	t.Cleanup(func() { statfsFn = orig })
}

func upsertPool(t *testing.T, db *corrosion.Client, host, name, driver, target string) {
	t.Helper()
	if err := corrosion.UpsertStoragePool(context.Background(), db, corrosion.StoragePoolRecord{
		HostName: host, Name: name, Driver: driver, Target: target, State: "active",
	}); err != nil {
		t.Fatalf("UpsertStoragePool(%s): %v", name, err)
	}
}

// TestSumPoolDiskTotal_IncludesAPIPoolsOncePerFilesystem pins the second defect
// of colonelpanik/litevirt#142. The host's recorded disk total walked only
// cfg.StoragePools, so a ~7 TiB pool created through the API (it lives in the
// replicated storage_pools table, never in config.yaml) was left out and the
// host reported its 438 GiB root filesystem as its whole capacity.
//
// The total is now config pools plus this host's file-based storage_pools
// rows, each FILESYSTEM counted once: the config pool's own row, and a second
// pool on a different path of the same filesystem, must not add its capacity
// again. Another host's pools, and pools of drivers that are not a local
// path, are not this host's capacity.
func TestSumPoolDiskTotal_IncludesAPIPoolsOncePerFilesystem(t *testing.T) {
	ctx := context.Background()
	db := newPoolTotalTestDB(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	fakeStatfs(t, map[string]fakeFS{
		"/var/lib/litevirt/disks":  {fsid: 1, gib: 438},
		"/var/lib/litevirt/images": {fsid: 1, gib: 438}, // same filesystem, other path
		"/srv/bulk":                {fsid: 2, gib: 7000},
		"/srv/other-host":          {fsid: 3, gib: 900},
		"/mnt/rbd":                 {fsid: 4, gib: 500},
	})
	upsertPool(t, db, "node-1", "default", "local", "/var/lib/litevirt/disks") // config pool's own row
	upsertPool(t, db, "node-1", "images", "dir", "/var/lib/litevirt/images")
	upsertPool(t, db, "node-1", "bulk", "local", "/srv/bulk") // created through the API
	upsertPool(t, db, "node-1", "rbd", "ceph", "/mnt/rbd")    // not a local path
	upsertPool(t, db, "node-2", "bulk", "local", "/srv/other-host")

	d := &Daemon{db: db, cfg: &Config{
		HostName: "node-1",
		DataDir:  "/var/lib/litevirt",
		StoragePools: []StoragePoolConfig{
			{Name: "default", Driver: "local", Target: "/var/lib/litevirt/disks"},
		},
	}}
	if got := d.sumPoolDiskTotalGiB(ctx); got != 7438 {
		t.Errorf("sumPoolDiskTotalGiB = %d, want 7438: the config pool's 438 plus the API pool's 7000, "+
			"each filesystem once (438 alone is the bug; 7876 or more counts one filesystem twice)", got)
	}
}

// A filesystem that reports no fsid must not collapse every such path into
// one: without an identity the path is the only key, so distinct paths count
// separately and only a repeated path is deduplicated.
func TestSumPoolDiskTotal_NoFsidFallsBackToPath(t *testing.T) {
	ctx := context.Background()
	db := newPoolTotalTestDB(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	fakeStatfs(t, map[string]fakeFS{
		"/a": {gib: 100},
		"/b": {gib: 200},
	})
	upsertPool(t, db, "node-1", "a", "local", "/a")
	upsertPool(t, db, "node-1", "a-again", "local", "/a/")
	upsertPool(t, db, "node-1", "b", "nfs", "/b")

	d := &Daemon{db: db, cfg: &Config{
		HostName:     "node-1",
		StoragePools: []StoragePoolConfig{{Name: "a", Driver: "local", Target: "/a"}},
	}}
	if got := d.sumPoolDiskTotalGiB(ctx); got != 300 {
		t.Errorf("sumPoolDiskTotalGiB = %d, want 300 (/a once, /b once)", got)
	}
}

// With no config pools and no pool rows (first boot), the data directory's
// filesystem is the total, as before.
func TestSumPoolDiskTotal_NoPoolsFallsBackToDataDir(t *testing.T) {
	ctx := context.Background()
	db := newPoolTotalTestDB(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	fakeStatfs(t, map[string]fakeFS{"/var/lib/litevirt": {fsid: 1, gib: 438}})

	d := &Daemon{db: db, cfg: &Config{HostName: "node-1", DataDir: "/var/lib/litevirt"}}
	if got := d.sumPoolDiskTotalGiB(ctx); got != 438 {
		t.Errorf("sumPoolDiskTotalGiB = %d, want the data dir's 438", got)
	}
}

// newPoolTotalTestDB opens a test database and closes it when the test ends.
func newPoolTotalTestDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
