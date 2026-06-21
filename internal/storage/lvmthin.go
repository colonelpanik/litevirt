package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// lvmThinDriver allocates thin-provisioned logical volumes from a
// pre-existing thin pool inside a volume group. Snapshots are atomic
// at the LVM layer — useful for fast backups without quiescing qemu.
//
// Pool config:
//   driver:  lvm-thin
//   source:  <volume-group>             # e.g. "vg0"
//   options:
//     thinpool: pool0                   # required; name of the LVM thin pool
//     filesystem: ""                    # leave blank — we hand the raw LV to qemu
type lvmThinDriver struct {
	vg   string
	opts map[string]string
}

func (d *lvmThinDriver) String() string { return "lvm-thin" }

func (d *lvmThinDriver) Prepare(ctx context.Context) error {
	if d.vg == "" {
		return fmt.Errorf("lvm-thin: volume group (Source) required")
	}
	if d.opts["thinpool"] == "" {
		return fmt.Errorf("lvm-thin: options.thinpool required")
	}
	out, err := exec.CommandContext(ctx, "lvs", "--noheadings", "-o", "lv_name",
		d.vg+"/"+d.opts["thinpool"]).CombinedOutput()
	if err != nil {
		return fmt.Errorf("lvs %s/%s: %w: %s", d.vg, d.opts["thinpool"], err, out)
	}
	return nil
}

func (d *lvmThinDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	lvName := fmt.Sprintf("%s-%s", opts.VMName, opts.DiskName)
	args := []string{
		"--type", "thin",
		"--virtualsize", fmt.Sprintf("%dB", opts.SizeBytes),
		"--thinpool", d.opts["thinpool"],
		"--name", lvName,
		d.vg,
	}
	if out, err := exec.CommandContext(ctx, "lvcreate", args...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("lvcreate %s/%s: %w: %s", d.vg, lvName, err, out)
	}
	path := fmt.Sprintf("/dev/%s/%s", d.vg, lvName)
	slog.Info("thin LV created", "lv", path, "size", opts.SizeBytes)
	return path, nil
}

func (d *lvmThinDriver) DeleteDisk(ctx context.Context, path string) error {
	// path is /dev/<vg>/<lv>
	parts := strings.Split(strings.TrimPrefix(path, "/dev/"), "/")
	if len(parts) != 2 {
		return fmt.Errorf("lvm-thin: cannot derive vg/lv from %q", path)
	}
	vg, lv := parts[0], parts[1]
	if out, err := exec.CommandContext(ctx, "lvremove", "-f", vg+"/"+lv).CombinedOutput(); err != nil {
		return fmt.Errorf("lvremove %s/%s: %w: %s", vg, lv, err, out)
	}
	return nil
}
