package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// cephDriver provisions Ceph RBD images via the rbd CLI. We deliberately
// shell out instead of vendoring go-ceph (CGO) so the default litevirtd
// binary stays CGO-free; a separate -tags ceph build will replace this
// with native bindings if needed.
type cephDriver struct {
	pool string
	opts map[string]string // keyring, conf, id, …
	run  cmdRunner         // nil → realCmd; overridable in tests
}

func (d *cephDriver) String() string { return "ceph" }

// rbd runs an rbd subcommand through the driver's runner (real exec by default).
func (d *cephDriver) rbd(ctx context.Context, args ...string) ([]byte, error) {
	run := d.run
	if run == nil {
		run = realCmd
	}
	return run(ctx, "rbd", args...)
}

func (d *cephDriver) Prepare(ctx context.Context) error {
	args := d.rbdArgs("ls", d.pool)
	if out, err := exec.CommandContext(ctx, "rbd", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("ceph pool %q not accessible: %w: %s", d.pool, err, out)
	}
	return nil
}

func (d *cephDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	imageName := fmt.Sprintf("%s-%s", opts.VMName, opts.DiskName)
	sizeMiB := opts.SizeBytes / (1024 * 1024)
	if sizeMiB == 0 {
		sizeMiB = 1024
	}

	args := d.rbdArgs("create",
		"--size", fmt.Sprintf("%d", sizeMiB),
		"--image-feature", "layering",
		fmt.Sprintf("%s/%s", d.pool, imageName),
	)
	if out, err := d.rbd(ctx, args...); err != nil {
		return "", fmt.Errorf("rbd create %s: %w: %s", imageName, err, out)
	}

	if opts.SourceImage != "" {
		if err := d.cloneFromImage(ctx, opts.SourceImage, imageName); err != nil {
			// A blank-but-"successful" disk would silently boot the wrong OS, so
			// roll back the empty image and surface the failure to the caller.
			rmArgs := d.rbdArgs("rm", fmt.Sprintf("%s/%s", d.pool, imageName))
			if rmOut, rmErr := d.rbd(ctx, rmArgs...); rmErr != nil {
				slog.Error("ceph: rollback of un-cloned image failed; manual cleanup needed",
					"image", imageName, "error", rmErr, "output", string(rmOut))
			}
			return "", fmt.Errorf("ceph clone %s from %s failed (rolled back empty image): %w",
				imageName, opts.SourceImage, err)
		}
	}

	path := fmt.Sprintf("rbd:%s/%s", d.pool, imageName)
	if conf := d.opts["conf"]; conf != "" {
		path += ":conf=" + conf
	}
	if keyring := d.opts["keyring"]; keyring != "" {
		path += ":keyring=" + keyring
	}
	slog.Info("Ceph RBD disk created", "image", imageName, "pool", d.pool)
	return path, nil
}

func (d *cephDriver) DeleteDisk(ctx context.Context, path string) error {
	imageName := cephImageName(path)
	if imageName == "" {
		return fmt.Errorf("cannot parse Ceph image name from %q", path)
	}
	args := d.rbdArgs("rm", fmt.Sprintf("%s/%s", d.pool, imageName))
	if out, err := exec.CommandContext(ctx, "rbd", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("rbd rm %s: %w: %s", imageName, err, out)
	}
	return nil
}

func (d *cephDriver) cloneFromImage(ctx context.Context, sourceImage, destImage string) error {
	args := d.rbdArgs("clone", sourceImage, fmt.Sprintf("%s/%s", d.pool, destImage))
	out, err := d.rbd(ctx, args...)
	if err != nil {
		return fmt.Errorf("rbd clone: %w: %s", err, out)
	}
	return nil
}

// rbdArgs prepends authentication options to rbd command args.
func (d *cephDriver) rbdArgs(subArgs ...string) []string {
	args := []string{}
	if id := d.opts["id"]; id != "" {
		args = append(args, "--id", id)
	}
	if conf := d.opts["conf"]; conf != "" {
		args = append(args, "--conf", conf)
	}
	if keyring := d.opts["keyring"]; keyring != "" {
		args = append(args, "--keyring", keyring)
	}
	return append(args, subArgs...)
}

// Replicate implements native Ceph send/recv via
// `rbd export-diff | rbd import-diff`. SrcRef is "<pool>/<image>"
// (or "<pool>/<image>@<snap>"); DstRef is "<pool>/<image>" on the
// destination cluster. Cross-cluster replication uses SSHTarget,
// matching ZFS.
func (d *cephDriver) Replicate(ctx context.Context, opts ReplicateOptions) error {
	if opts.SrcRef == "" || opts.DstRef == "" {
		return fmt.Errorf("ceph replicate: src and dst refs required")
	}
	snap := opts.SnapshotName
	if snap == "" {
		snap = "litevirt-" + nowSnapTag()
	}
	srcSnapSpec := opts.SrcRef + "@" + snap
	if out, err := exec.CommandContext(ctx, "rbd", d.rbdArgs("snap", "create", srcSnapSpec)...).CombinedOutput(); err != nil {
		return fmt.Errorf("rbd snap create %s: %w: %s", srcSnapSpec, err, out)
	}

	sendArgs := []string{"export-diff"}
	if opts.Incremental {
		sendArgs = append(sendArgs, "--from-snap", "litevirt-replicate-prev")
	}
	sendArgs = append(sendArgs, srcSnapSpec, "-")
	recvArgs := []string{"import-diff", "-", opts.DstRef}

	if _, err := pipeCmds(ctx, opts.SSHTarget, "rbd", sendArgs, "rbd", recvArgs); err != nil {
		return fmt.Errorf("ceph replicate %s → %s: %w", opts.SrcRef, opts.DstRef, err)
	}
	return nil
}

// CreateRBDSnapshot creates and protects a snapshot of an RBD image.
// Exposed as a package-level helper because snapshot handlers manage
// lifetime independently of any Driver instance.
func CreateRBDSnapshot(ctx context.Context, pool, imageName, snapName string, opts map[string]string) error {
	d := &cephDriver{pool: pool, opts: opts}
	spec := fmt.Sprintf("%s/%s@%s", pool, imageName, snapName)
	args := d.rbdArgs("snap", "create", spec)
	out, err := exec.CommandContext(ctx, "rbd", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rbd snap create %s: %w: %s", spec, err, out)
	}
	protectArgs := d.rbdArgs("snap", "protect", spec)
	out, err = exec.CommandContext(ctx, "rbd", protectArgs...).CombinedOutput()
	if err != nil && !strings.Contains(string(out), "already protected") {
		return fmt.Errorf("rbd snap protect %s: %w: %s", spec, err, out)
	}
	slog.Info("RBD snapshot created", "pool", pool, "image", imageName, "snap", snapName)
	return nil
}

// CloneRBDSnapshot clones a protected snapshot into a new RBD image.
func CloneRBDSnapshot(ctx context.Context, pool, srcImage, snapName, destImage string, opts map[string]string) error {
	d := &cephDriver{pool: pool, opts: opts}
	src := fmt.Sprintf("%s/%s@%s", pool, srcImage, snapName)
	dst := fmt.Sprintf("%s/%s", pool, destImage)
	args := d.rbdArgs("clone", "--image-feature", "layering", src, dst)
	out, err := exec.CommandContext(ctx, "rbd", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rbd clone %s → %s: %w: %s", src, dst, err, out)
	}
	slog.Info("RBD snapshot cloned", "src", src, "dest", dst)
	return nil
}

// DeleteRBDSnapshot unprotects (best-effort) and removes an RBD snapshot.
func DeleteRBDSnapshot(ctx context.Context, pool, imageName, snapName string, opts map[string]string) error {
	d := &cephDriver{pool: pool, opts: opts}
	spec := fmt.Sprintf("%s/%s@%s", pool, imageName, snapName)
	unprotectArgs := d.rbdArgs("snap", "unprotect", spec)
	exec.CommandContext(ctx, "rbd", unprotectArgs...).CombinedOutput()
	args := d.rbdArgs("snap", "rm", spec)
	out, err := exec.CommandContext(ctx, "rbd", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("rbd snap rm %s: %w: %s", spec, err, out)
	}
	slog.Info("RBD snapshot deleted", "pool", pool, "image", imageName, "snap", snapName)
	return nil
}

// CephImageName extracts the image name from an "rbd:" path.
//
//	"rbd:litevirt/vm1-root:conf=/etc/ceph/ceph.conf" → "vm1-root"
func CephImageName(path string) string { return cephImageName(path) }

// CephPoolName extracts the pool name from an "rbd:" path.
func CephPoolName(path string) string {
	s := strings.TrimPrefix(path, "rbd:")
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	return parts[0]
}

func cephImageName(path string) string {
	s := strings.TrimPrefix(path, "rbd:")
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 {
		return ""
	}
	imgParts := strings.SplitN(parts[1], ":", 2)
	return imgParts[0]
}
