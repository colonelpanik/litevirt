// Package storage implements per-driver disk provisioning for litevirt.
//
// split: each backend lives in its own file (local.go, nfs.go,
// ceph.go, iscsi.go, zfs.go, btrfs.go, lvmthin.go, dir.go). This file
// holds only the cross-driver types and the New() dispatcher.
//
// Backends fall into two structural camps:
//
//	File-based  (local, nfs, dir): hand back a path to a qcow2 file.
//	Object-/block-based (ceph, iscsi, zfs, btrfs, lvm-thin): hand back
//	                    an opaque identifier libvirt knows how to attach.
//
// All paths returned by CreateDisk are passed verbatim into libvirt XML
// generation, so the format must match what go-libvirt's
// `<disk source>` expects for that backend.
package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// DiskOptions holds parameters for a single disk operation. Driver-specific
// knobs live in Config.Options; everything universal lives here.
type DiskOptions struct {
	// VMName derives the image name when DiskName is unset and is recorded
	// in driver-specific metadata for visibility.
	VMName string
	// DiskName is the logical name (e.g. "root", "data") and forms the
	// file/image suffix.
	DiskName string
	// SizeBytes is the requested disk size. Drivers round up to their
	// native granularity (sector, extent, RBD MiB).
	SizeBytes int64
	// Format is "qcow2" (file-based default) or "raw" (required for ceph,
	// iscsi, lvm-thin block devices). Empty defers to the driver default.
	Format string
	// SourceImage is an optional backing file or snapshot to clone from.
	SourceImage string
	// ClusterSize overrides the qcow2 cluster size (e.g. "64K", "2M").
	// Empty = qcow2 package default of 64K. Ignored for raw/block formats.
	ClusterSize string
	// RefcountBits overrides the qcow2 refcount width (1–64). Zero = 16.
	// Ignored for raw/block formats.
	RefcountBits int
}

// Driver abstracts disk lifecycle operations across storage backends.
//
// Drivers are constructed once per pool config and reused across many
// CreateDisk/DeleteDisk calls; Prepare runs once at startup or pool
// attach to verify reachability and mount/login as needed.
type Driver interface {
	// Prepare ensures the backend is accessible: mount NFS, log into
	// iSCSI, verify rbd ls, etc. Returning nil means subsequent
	// CreateDisk calls may run.
	Prepare(ctx context.Context) error
	// CreateDisk allocates a new disk and returns the path / identifier
	// to put in libvirt's <disk source> element.
	CreateDisk(ctx context.Context, opts DiskOptions) (string, error)
	// DeleteDisk releases a disk previously returned from CreateDisk.
	// Implementations are tolerant of missing-disk errors.
	DeleteDisk(ctx context.Context, path string) error
	// String returns the driver's stable short name ("local", "nfs", …)
	// — used in logs and metrics labels.
	String() string
}

// Config is the parsed VolumeDef from a compose file or host pool config.
// Each pool produces one Driver via New().
type Config struct {
	Driver  string            // see SupportedDrivers
	Source  string            // driver-specific (NFS server:/path, Ceph pool, ZFS dataset, …)
	Target  string            // local mount/path override; empty = derive
	Options map[string]string // driver-specific key/value options
}

// SupportedDrivers lists every storage driver known to New(). Update this
// list when a new backend lands so config validation can produce a useful
// "did you mean?" error.
var SupportedDrivers = []string{
	"local", "nfs", "iscsi", "ceph",
	"zfs", "btrfs", "lvm-thin", "dir",
}

// New returns the Driver for the given config. Driver names are
// lowercased and matched exactly. An empty driver string defaults to
// "local" — consistent with the legacy compose schema.
func New(dataDir string, cfg Config) (Driver, error) {
	switch strings.ToLower(cfg.Driver) {
	case "", "local":
		diskDir := filepath.Join(dataDir, "disks")
		if cfg.Target != "" {
			diskDir = cfg.Target
		}
		return &localDriver{dataDir: diskDir}, nil
	case "dir":
		// Like local, but Target is mandatory — used to attach an
		// arbitrary directory that may live on a different filesystem
		// (e.g. a hand-mounted SAN LUN). Behaves identically to local
		// once Prepare has confirmed the path exists.
		if cfg.Target == "" {
			return nil, fmt.Errorf("dir driver requires Target")
		}
		return &dirDriver{path: cfg.Target}, nil
	case "nfs":
		mountBase := filepath.Join(dataDir, "mounts")
		if cfg.Target != "" {
			mountBase = ""
		}
		return &nfsDriver{
			source:         cfg.Source,
			mountBase:      mountBase,
			targetOverride: cfg.Target,
			opts:           cfg.Options,
			run:            realCmd,
		}, nil
	case "ceph":
		return &cephDriver{pool: cfg.Source, opts: cfg.Options}, nil
	case "iscsi":
		return &iscsiDriver{target: cfg.Source, opts: cfg.Options, run: realCmd}, nil
	case "zfs":
		return &zfsDriver{dataset: cfg.Source, opts: cfg.Options}, nil
	case "btrfs":
		return &btrfsDriver{subvolRoot: cfg.Source, opts: cfg.Options}, nil
	case "lvm-thin", "lvmthin":
		return &lvmThinDriver{vg: cfg.Source, opts: cfg.Options}, nil
	default:
		return nil, fmt.Errorf("unknown storage driver %q (supported: %v)", cfg.Driver, SupportedDrivers)
	}
}

// qcow2Opts builds a *qcow2.Options from DiskOptions, falling back to
// volume-level options when per-disk values are not set. Returns nil
// when no overrides are present so the qcow2 package uses its defaults.
func qcow2Opts(opts DiskOptions) *qcow2.Options {
	var o qcow2.Options

	if opts.ClusterSize != "" {
		if sz, err := qcow2.ParseSize(opts.ClusterSize); err == nil {
			for bits := uint32(9); bits <= 21; bits++ {
				if uint64(1)<<bits == sz {
					o.ClusterBits = bits
					break
				}
			}
		}
	}

	if opts.RefcountBits > 0 {
		for order := uint32(0); order <= 6; order++ {
			if 1<<order == uint32(opts.RefcountBits) {
				o.RefcountOrder = order
				break
			}
		}
	}

	if o.ClusterBits == 0 && o.RefcountOrder == 0 {
		return nil
	}
	return &o
}
