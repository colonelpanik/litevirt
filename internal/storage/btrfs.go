package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// btrfsDriver creates a subvolume per VM disk under a parent path on a
// BTRFS filesystem, then stores a qcow2 file inside the subvolume. The
// subvolume gives us atomic snapshots via `btrfs subvolume snapshot` and
// efficient send/receive replication.
//
// Pool config:
//
//	driver:  btrfs
//	source:  /mnt/btrfs/litevirt        # absolute path; must be on btrfs
type btrfsDriver struct {
	subvolRoot string
	opts       map[string]string
}

func (d *btrfsDriver) String() string { return "btrfs" }

func (d *btrfsDriver) Prepare(ctx context.Context) error {
	if d.subvolRoot == "" {
		return fmt.Errorf("btrfs: subvolume root (Source) required")
	}
	if err := os.MkdirAll(d.subvolRoot, 0755); err != nil {
		return fmt.Errorf("btrfs: create subvol root: %w", err)
	}
	// `btrfs filesystem show <path>` confirms the path lives on btrfs.
	out, err := exec.CommandContext(ctx, "btrfs", "filesystem", "show", d.subvolRoot).CombinedOutput()
	if err != nil {
		return fmt.Errorf("btrfs filesystem show %s: %w: %s", d.subvolRoot, err, out)
	}
	return nil
}

func (d *btrfsDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	subvol := filepath.Join(d.subvolRoot, fmt.Sprintf("%s-%s", opts.VMName, opts.DiskName))
	if out, err := exec.CommandContext(ctx, "btrfs", "subvolume", "create", subvol).CombinedOutput(); err != nil {
		return "", fmt.Errorf("btrfs subvolume create %s: %w: %s", subvol, err, out)
	}
	// Reuse the local qcow2 path inside the subvolume. CoW conflicts
	// with qcow2 random writes on some workloads — operators who need
	// raw can override Format=raw.
	inner := &localDriver{dataDir: subvol}
	if err := inner.Prepare(ctx); err != nil {
		return "", err
	}
	return inner.CreateDisk(ctx, opts)
}

// Replicate implements via `btrfs send | btrfs receive`.
// SrcRef is the absolute path of a btrfs subvolume; DstRef is the
// parent directory on the destination side that `btrfs receive`
// extracts into (it creates a subvolume named after the source).
//
// Same-host = local pipe; cross-host wraps the receive in SSH.
func (d *btrfsDriver) Replicate(ctx context.Context, opts ReplicateOptions) error {
	if opts.SrcRef == "" || opts.DstRef == "" {
		return fmt.Errorf("btrfs replicate: src and dst refs required")
	}
	// btrfs send requires a read-only snapshot of the source. We
	// snapshot, send, then leave the snapshot in place so the next
	// run can do an incremental `-p`.
	tag := opts.SnapshotName
	if tag == "" {
		tag = "litevirt-" + nowSnapTag()
	}
	snapPath := opts.SrcRef + "-" + tag
	if out, err := exec.CommandContext(ctx,
		"btrfs", "subvolume", "snapshot", "-r", opts.SrcRef, snapPath,
	).CombinedOutput(); err != nil {
		return fmt.Errorf("btrfs snapshot %s: %w: %s", snapPath, err, out)
	}

	sendArgs := []string{"send"}
	prev := opts.SrcRef + "-litevirt-replicate-prev"
	if opts.Incremental && pathExists(prev) {
		sendArgs = append(sendArgs, "-p", prev)
	}
	sendArgs = append(sendArgs, snapPath)

	recvArgs := []string{"receive", opts.DstRef}
	if _, err := pipeCmds(ctx, opts.SSHTarget, "btrfs", sendArgs, "btrfs", recvArgs); err != nil {
		return fmt.Errorf("btrfs replicate: %w", err)
	}
	return nil
}

func (d *btrfsDriver) DeleteDisk(ctx context.Context, path string) error {
	// Always remove the qcow2 file. Whether to also reap a wrapping
	// subvolume depends on how the file was created: only CreateDisk
	// puts each disk in its own subvolume; storage-motion / replication
	// drop files directly under subvolRoot.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove btrfs qcow2 %s: %w", path, err)
	}
	subvol := filepath.Dir(path)
	// Refuse to delete if the parent is the pool root, the filesystem
	// root, or anything outside subvolRoot — otherwise a misconfigured
	// path could nuke the pool. A bug here in earlier versions would
	// have called `btrfs subvolume delete <subvolRoot>`.
	cleanRoot := filepath.Clean(d.subvolRoot)
	cleanParent := filepath.Clean(subvol)
	if cleanParent == cleanRoot || cleanParent == "/" || cleanParent == "." {
		return nil
	}
	rel, err := filepath.Rel(cleanRoot, cleanParent)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil
	}
	if out, err := exec.CommandContext(ctx, "btrfs", "subvolume", "delete", cleanParent).CombinedOutput(); err != nil {
		// Non-fatal: caller may have created the file directly without
		// a wrapping subvolume.
		slog.Warn("btrfs subvolume delete failed", "subvol", cleanParent, "error", err, "output", string(out))
		return nil
	}
	slog.Info("btrfs subvolume deleted", "subvol", cleanParent)
	return nil
}
