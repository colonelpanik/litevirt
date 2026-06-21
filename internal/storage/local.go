package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/qcow2"
)

// localDriver stores qcow2 (or raw) files in a directory on the local
// filesystem under dataDir. It is the default and the simplest backend.
type localDriver struct {
	dataDir string
}

func (d *localDriver) String() string { return "local" }

func (d *localDriver) Prepare(_ context.Context) error {
	return os.MkdirAll(d.dataDir, 0755)
}

func (d *localDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	path := filepath.Join(d.dataDir, fmt.Sprintf("%s-%s.qcow2", opts.VMName, opts.DiskName))
	format := opts.Format
	if format == "" {
		format = "qcow2"
	}

	if format == "qcow2" {
		qOpts := qcow2Opts(opts)
		if opts.SourceImage != "" {
			if err := qcow2.CreateWithBacking(path, opts.SourceImage, uint64(opts.SizeBytes), qOpts); err != nil {
				return "", fmt.Errorf("create overlay disk: %w", err)
			}
		} else {
			if err := qcow2.Create(path, uint64(opts.SizeBytes), qOpts); err != nil {
				return "", fmt.Errorf("create disk: %w", err)
			}
		}
	} else {
		f, err := os.Create(path)
		if err != nil {
			return "", fmt.Errorf("create raw disk: %w", err)
		}
		if err := f.Truncate(opts.SizeBytes); err != nil {
			f.Close()
			return "", fmt.Errorf("truncate raw disk: %w", err)
		}
		// fsync so a crash/power-loss right after create can't leave a
		// zero/partial file that's reported as a usable disk (F7).
		if err := f.Sync(); err != nil {
			f.Close()
			return "", fmt.Errorf("sync raw disk: %w", err)
		}
		f.Close()
	}

	slog.Info("local disk created", "path", path, "size", opts.SizeBytes)
	return path, nil
}

func (d *localDriver) DeleteDisk(_ context.Context, path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove disk %s: %w", path, err)
	}
	return nil
}

// dirDriver is a thin variant of localDriver where Target is required and
// fixed. Useful for hand-mounted directories (e.g. an external block
// device formatted with ext4 and mounted at /srv/litevirt/disks).
type dirDriver struct {
	path string
}

func (d *dirDriver) String() string { return "dir" }

func (d *dirDriver) Prepare(_ context.Context) error {
	st, err := os.Stat(d.path)
	if err != nil {
		return fmt.Errorf("dir storage: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("dir storage target %q is not a directory", d.path)
	}
	return nil
}

func (d *dirDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	inner := &localDriver{dataDir: d.path}
	return inner.CreateDisk(ctx, opts)
}

func (d *dirDriver) DeleteDisk(ctx context.Context, path string) error {
	return (&localDriver{dataDir: d.path}).DeleteDisk(ctx, path)
}
