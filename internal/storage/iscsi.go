package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// iscsiDriver attaches a pre-provisioned iSCSI LUN. litevirt does not
// allocate LUNs on the SAN — the operator does that out-of-band; we
// only handle iscsiadm discovery / login and surface the resulting
// /dev/disk/by-path device to libvirt.
type iscsiDriver struct {
	target string
	opts   map[string]string
	run    cmdRunner // iscsiadm seam (Teardown); tests inject a fake
}

func (d *iscsiDriver) String() string { return "iscsi" }

// Teardown logs the host out of the iSCSI target on pool delete. Idempotent: a
// "no matching"/"not found" logout is treated as already-gone. The caller is
// responsible for the cross-pool refcount (don't log out a target another pool's
// LUN still uses). Safe to call without a prior Prepare.
func (d *iscsiDriver) Teardown(ctx context.Context) error {
	portal := d.opts["portal"]
	if portal == "" {
		portal = "127.0.0.1"
	}
	run := d.run
	if run == nil {
		run = realCmd
	}
	out, err := run(ctx, "iscsiadm", "-m", "node", "-T", d.target, "-p", portal, "--logout")
	if err != nil && !strings.Contains(string(out), "No matching") && !strings.Contains(string(out), "not found") {
		return fmt.Errorf("iscsi logout %s: %w: %s", d.target, err, out)
	}
	slog.Info("iSCSI logged out", "target", d.target)
	return nil
}

func (d *iscsiDriver) Prepare(ctx context.Context) error {
	portal := d.opts["portal"]
	if portal == "" {
		portal = "127.0.0.1"
	}

	out, err := exec.CommandContext(ctx, "iscsiadm",
		"-m", "discovery", "-t", "st", "-p", portal).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iscsi discovery %s: %w: %s", portal, err, out)
	}

	out, err = exec.CommandContext(ctx, "iscsiadm",
		"-m", "node", "-T", d.target, "-p", portal, "--login").CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already") {
		return fmt.Errorf("iscsi login %s: %w: %s", d.target, err, out)
	}
	slog.Info("iSCSI target connected", "target", d.target)
	return nil
}

func (d *iscsiDriver) CreateDisk(_ context.Context, opts DiskOptions) (string, error) {
	lun := d.opts["lun"]
	if lun == "" {
		lun = "0"
	}
	path := fmt.Sprintf("/dev/disk/by-path/ip-%s-iscsi-%s-lun-%s",
		d.opts["portal"], d.target, lun)
	slog.Info("iSCSI disk path", "vm", opts.VMName, "disk", opts.DiskName, "path", path)
	return path, nil
}

func (d *iscsiDriver) DeleteDisk(_ context.Context, path string) error {
	slog.Info("iSCSI DeleteDisk: LUN management is external", "path", path)
	return nil
}
