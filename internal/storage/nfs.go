package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// nfsDriver mounts an NFS export and stores qcow2/raw files inside the
// mountpoint. The export is mounted lazily by Prepare() and survives
// across daemon restarts (we re-bind-mount on start; no umount on shutdown
// to avoid disturbing co-tenants).
type nfsDriver struct {
	source         string            // "server:/export"
	mountBase      string            // local base directory for mounts (empty if targetOverride set)
	targetOverride string            // explicit mount point from pool config
	opts           map[string]string // mount options et al.
	mountDir       string            // resolved by Prepare()
	run            cmdRunner         // mountpoint/umount seam (Teardown); tests inject a fake
}

func (d *nfsDriver) String() string { return "nfs" }

// Teardown unmounts a litevirt-OWNED NFS mount on pool delete. It does NOT touch a
// mount the operator manages (targetOverride set) — that's a shared path we didn't
// create. Idempotent: a no-op when the path isn't mounted. Derives the mountpoint
// the same way Prepare does, so it's safe to call without a prior Prepare. The
// caller is responsible for the cross-pool refcount (don't tear down an export
// another pool still uses).
func (d *nfsDriver) Teardown(ctx context.Context) error {
	if d.targetOverride != "" {
		slog.Info("NFS teardown skipped: operator-managed mount", "source", d.source, "target", d.targetOverride)
		return nil
	}
	run := d.run
	if run == nil {
		run = realCmd
	}
	safe := strings.NewReplacer("/", "_", ":", "_").Replace(d.source)
	mountDir := filepath.Join(d.mountBase, safe)
	if _, err := run(ctx, "mountpoint", "-q", mountDir); err != nil {
		return nil // not mounted → nothing to undo
	}
	if out, err := run(ctx, "umount", mountDir); err != nil {
		return fmt.Errorf("umount nfs %s: %w: %s", mountDir, err, out)
	}
	slog.Info("NFS unmounted", "source", d.source, "mountpoint", mountDir)
	return nil
}

func (d *nfsDriver) Prepare(ctx context.Context) error {
	if d.targetOverride != "" {
		d.mountDir = d.targetOverride
	} else {
		safe := strings.NewReplacer("/", "_", ":", "_").Replace(d.source)
		d.mountDir = filepath.Join(d.mountBase, safe)
	}

	if err := os.MkdirAll(d.mountDir, 0755); err != nil {
		return fmt.Errorf("create mount dir: %w", err)
	}

	// `mountpoint -q` reports the result ONLY via exit code (0 = already a
	// mountpoint) — it prints nothing — so the old `string(out) == ""` test was
	// always true and re-ran `mount` on every Prepare (every CreateVM / restart),
	// which fails on already-mounted configs or stacks mounts (bug-sweep #8).
	// Skip the mount when it's already mounted, keyed on the exit code.
	alreadyMounted := exec.CommandContext(ctx, "mountpoint", "-q", d.mountDir).Run() == nil
	if !alreadyMounted {
		mountOpts := "vers=4,hard,intr"
		if extra, ok := d.opts["options"]; ok {
			mountOpts = extra
		}
		cmd := exec.CommandContext(ctx, "mount", "-t", "nfs", "-o", mountOpts, d.source, d.mountDir)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("mount nfs %s: %w: %s", d.source, err, out)
		}
		slog.Info("NFS mounted", "source", d.source, "mountpoint", d.mountDir)
	}
	return nil
}

func (d *nfsDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	if d.mountDir == "" {
		return "", fmt.Errorf("NFS not prepared; call Prepare first")
	}
	path := filepath.Join(d.mountDir, fmt.Sprintf("%s-%s.qcow2", opts.VMName, opts.DiskName))
	format := opts.Format
	if format == "" {
		format = "qcow2"
	}

	if format == "qcow2" {
		qOpts := qcow2Opts(opts)
		if opts.SourceImage != "" {
			if err := qcow2.CreateWithBacking(path, opts.SourceImage, uint64(opts.SizeBytes), qOpts); err != nil {
				return "", fmt.Errorf("create overlay disk on NFS: %w", err)
			}
		} else {
			if err := qcow2.Create(path, uint64(opts.SizeBytes), qOpts); err != nil {
				return "", fmt.Errorf("create disk on NFS: %w", err)
			}
		}
	} else {
		f, err := os.Create(path)
		if err != nil {
			return "", fmt.Errorf("create raw disk on NFS: %w", err)
		}
		if err := f.Truncate(opts.SizeBytes); err != nil {
			f.Close()
			return "", fmt.Errorf("truncate raw disk on NFS: %w", err)
		}
		// fsync to flush the new file to the NFS server before reporting
		// success — a crash mid-write must not leave a partial disk (F7).
		if err := f.Sync(); err != nil {
			f.Close()
			return "", fmt.Errorf("sync raw disk on NFS: %w", err)
		}
		f.Close()
	}

	slog.Info("NFS disk created", "path", path)
	return path, nil
}

func (d *nfsDriver) DeleteDisk(_ context.Context, path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove NFS disk %s: %w", path, err)
	}
	return nil
}
