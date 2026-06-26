package libvirt

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Firmware-state travel (G1). A VM's portable firmware state is its name-keyed
// UEFI vars file (NvramPath) plus its UUID-keyed swtpm tree (LibvirtSwtpmDir).
// These helpers bundle / restore / wipe that state as ONE unit so backup,
// migration, and snapshot carry it identically — vtpmstate.go is the single
// owner; no lifecycle handler hand-rolls firmware-state copy/wipe.

// libvirtSwtpmBase is libvirt's swtpm state root. A var (not const) so tests can
// redirect it away from the root-owned /var/lib/libvirt.
var libvirtSwtpmBase = "/var/lib/libvirt/swtpm"

const (
	fwBundleNvram = "nvram"  // tar entry: the UEFI vars file
	fwBundleSwtpm = "swtpm/" // tar entry prefix: the swtpm state tree
)

// LibvirtSwtpmDir is libvirt's default per-domain swtpm state directory, keyed by
// the (stable) domain UUID — the AppArmor-permitted location.
func LibvirtSwtpmDir(uuid string) string {
	return filepath.Join(libvirtSwtpmBase, uuid)
}

// SnapshotFirmwareBundlePath is the sidecar tar holding a snapshot's captured
// firmware state. Derived from (dataDir, vm, snap) — no DB column; nested
// <vm>/<snap> avoids flat-name collisions (G1). filepath.Base on both components
// is defense-in-depth against an unvalidated name escaping dataDir/snapfw
// (callers must still validate names — this just guarantees containment).
func SnapshotFirmwareBundlePath(dataDir, vmName, snapName string) string {
	return filepath.Join(dataDir, "snapfw", filepath.Base(vmName), filepath.Base(snapName)+".tar")
}

// HasTPMState reports whether the (UUID-keyed) swtpm state exists.
func HasTPMState(uuid string) bool {
	if uuid == "" {
		return false
	}
	ents, err := os.ReadDir(LibvirtSwtpmDir(uuid))
	return err == nil && len(ents) > 0
}

// WriteFirmwareBundle writes a tar of the VM's firmware state (nvram + swtpm) to
// w. Returns false (no error) when the VM has no firmware state to carry.
func WriteFirmwareBundle(dataDir, vmName, uuid string, w io.Writer) (bool, error) {
	hasNvram := HasNvram(dataDir, vmName)
	hasTPM := HasTPMState(uuid)
	if !hasNvram && !hasTPM {
		return false, nil
	}
	tw := tar.NewWriter(w)
	if hasNvram {
		if err := tarFile(tw, NvramPath(dataDir, vmName), fwBundleNvram); err != nil {
			return false, err
		}
	}
	if hasTPM {
		if err := tarTree(tw, LibvirtSwtpmDir(uuid), fwBundleSwtpm); err != nil {
			return false, err
		}
	}
	if err := tw.Close(); err != nil {
		return false, err
	}
	return true, nil
}

// ReadFirmwareBundle restores a bundle from WriteFirmwareBundle: the nvram entry
// → NvramPath(dataDir,vmName); swtpm/* → LibvirtSwtpmDir(uuid). It is ATOMIC — the
// bundle is staged in full (swtpm into a sibling temp dir, nvram into memory),
// then each destination is swapped into place as a unit, so a partial/aborted
// restore never leaves mixed old/new firmware state (the BitLocker failure mode).
// Slip-safe: rejects ../absolute paths and symlink/hardlink/device members (a
// backup-repo bundle is untrusted); restored modes are clamped (files 0600, dirs
// 0700), never trusting tar header modes.
func ReadFirmwareBundle(r io.Reader, dataDir, vmName, uuid string) error {
	swtpmRoot := LibvirtSwtpmDir(uuid)
	var (
		nvramBytes []byte
		haveNvram  bool
		swtpmStage string // sibling temp dir holding the staged swtpm tree
	)
	defer func() {
		if swtpmStage != "" {
			_ = os.RemoveAll(swtpmStage)
		}
	}()

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read firmware bundle: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA && hdr.Typeflag != tar.TypeDir {
			return fmt.Errorf("firmware bundle: disallowed member type %d for %q", hdr.Typeflag, hdr.Name)
		}
		// Reject (don't silently re-root) absolute paths and any member that
		// escapes the tree — a backup-repo bundle is untrusted. `../nvram` and
		// `/nvram` must be rejected, not normalized to `nvram`.
		if filepath.IsAbs(hdr.Name) {
			return fmt.Errorf("firmware bundle: rejected absolute member path %q", hdr.Name)
		}
		name := filepath.Clean(hdr.Name)
		if name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("firmware bundle: rejected path-escaping member %q", hdr.Name)
		}
		switch {
		case name == fwBundleNvram:
			if hdr.Size > 64<<20 {
				return fmt.Errorf("firmware bundle nvram member implausibly large (%d bytes)", hdr.Size)
			}
			b, err := io.ReadAll(io.LimitReader(tr, 64<<20))
			if err != nil {
				return fmt.Errorf("read nvram member: %w", err)
			}
			nvramBytes, haveNvram = b, true
		case strings.HasPrefix(name, fwBundleSwtpm):
			if uuid == "" {
				return fmt.Errorf("firmware bundle carries swtpm state but no target uuid was given")
			}
			if swtpmStage == "" {
				// The swtpm base dir must be world-traversable (libvirt uses 0711)
				// so the dropped-privilege swtpm user can reach per-UUID state.
				base := filepath.Dir(swtpmRoot)
				if err := os.MkdirAll(base, 0o711); err != nil {
					return err
				}
				_ = os.Chmod(base, 0o711) // MkdirAll won't fix an existing 0700
				swtpmStage, err = os.MkdirTemp(base, ".swtpm-restore-*")
				if err != nil {
					return err
				}
			}
			rel := strings.TrimPrefix(name, fwBundleSwtpm)
			if rel == "" {
				continue
			}
			dst := filepath.Join(swtpmStage, rel)
			if !withinDir(swtpmStage, dst) {
				return fmt.Errorf("firmware bundle entry %q escapes the swtpm dir", hdr.Name)
			}
			if hdr.Typeflag == tar.TypeDir {
				if err := os.MkdirAll(dst, 0o700); err != nil {
					return err
				}
				continue
			}
			if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
				return err
			}
			if err := writeFileFromTar(tr, dst); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected firmware bundle entry %q", hdr.Name)
		}
	}

	// Install NVRAM + swtpm as a UNIT with rollback: back up the existing files,
	// install the staged ones, and on ANY failure restore the backups — so we
	// never leave new NVRAM with stale/missing TPM (or vice-versa).
	nvramDst := NvramPath(dataDir, vmName)
	var nvramBak, swtpmBak string
	rollback := func() {
		if nvramBak != "" {
			_ = os.Remove(nvramDst)
			_ = os.Rename(nvramBak, nvramDst)
		}
		if swtpmBak != "" {
			_ = os.RemoveAll(swtpmRoot)
			_ = os.Rename(swtpmBak, swtpmRoot)
		}
	}

	if haveNvram {
		if err := os.MkdirAll(filepath.Dir(nvramDst), 0o755); err != nil {
			return err
		}
		staged := nvramDst + ".staged"
		if err := os.WriteFile(staged, nvramBytes, 0o600); err != nil {
			return err
		}
		if err := fsyncPath(staged); err != nil {
			_ = os.Remove(staged)
			return err
		}
		if _, e := os.Stat(nvramDst); e == nil {
			nvramBak = nvramDst + ".bak"
			if err := os.Rename(nvramDst, nvramBak); err != nil {
				_ = os.Remove(staged)
				return err
			}
		}
		if err := os.Rename(staged, nvramDst); err != nil {
			_ = os.Remove(staged)
			rollback()
			return err
		}
	}
	if swtpmStage != "" {
		if _, e := os.Stat(swtpmRoot); e == nil {
			swtpmBak = swtpmRoot + ".bak"
			_ = os.RemoveAll(swtpmBak)
			if err := os.Rename(swtpmRoot, swtpmBak); err != nil {
				rollback()
				return err
			}
		}
		if err := os.Rename(swtpmStage, swtpmRoot); err != nil {
			rollback()
			return fmt.Errorf("swap swtpm state into place: %w", err)
		}
		swtpmStage = "" // consumed — don't let the defer remove it
		// libvirt runs swtpm as a dropped-privilege user (qemu.conf swtpm_user)
		// and relabels the tpm2/ contents on domain start, but it does NOT chmod
		// the per-UUID parent dir — so it must be world-traversable (0711, the mode
		// libvirt itself uses) or swtpm can't reach its state ("Could not open
		// lockfile: Permission denied" → CMD_INIT fails). os.Rename carries the
		// staging dir's 0700, so fix it explicitly here (G1; caught by a live drill).
		if err := os.Chmod(swtpmRoot, 0o711); err != nil {
			rollback()
			return fmt.Errorf("set swtpm dir traversable: %w", err)
		}
	}
	// Success — drop the backups.
	if nvramBak != "" {
		_ = os.Remove(nvramBak)
	}
	if swtpmBak != "" {
		_ = os.RemoveAll(swtpmBak)
	}
	return nil
}

// WipeFirmwareState removes a VM's firmware state (true delete). Best-effort.
func WipeFirmwareState(dataDir, vmName, uuid string) {
	_ = os.Remove(NvramPath(dataDir, vmName))
	_ = os.Remove(retainedMarkerPath(dataDir, vmName))
	if uuid != "" {
		_ = os.RemoveAll(LibvirtSwtpmDir(uuid))
	}
}

// Retained-firmware marker (G1): `delete --keep-disks` keeps the firmware state
// but the DB row is gone, so the UUID-keyed swtpm tree would be unlocatable.
// Record name→uuid in a marker under dataDir so an explicit restore/adopt can
// find it. (The name-keyed NVRAM guard already blocks accidental same-name reuse.)
func retainedMarkerPath(dataDir, vmName string) string {
	return filepath.Join(dataDir, "nvram", vmName+".kept-uuid")
}

func WriteRetainedFirmwareMarker(dataDir, vmName, uuid string) error {
	p := retainedMarkerPath(dataDir, vmName)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(uuid), 0o600)
}

// ReadRetainedFirmwareMarker returns the retained swtpm UUID for a name, if any.
func ReadRetainedFirmwareMarker(dataDir, vmName string) (string, bool) {
	b, err := os.ReadFile(retainedMarkerPath(dataDir, vmName))
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

// ── tar helpers ──

func tarFile(tw *tar.Writer, srcPath, name string) error {
	fi, err := os.Stat(srcPath)
	if err != nil {
		return err
	}
	if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: fi.Size(), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	f, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(tw, f)
	return err
}

func tarTree(tw *tar.Writer, srcDir, prefix string) error {
	return filepath.WalkDir(srcDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.Name() == ".lock" {
			// swtpm's runtime lock file — recreated on start; carrying it is at best
			// noise and at worst confuses a restored instance. Skip it (G1).
			return nil
		}
		if !d.Type().IsRegular() && !d.IsDir() {
			// swtpm state is plain files + dirs; anything else means a malformed or
			// tampered tree — fail rather than produce an incomplete bundle.
			return fmt.Errorf("unexpected swtpm state entry %q (type %v)", p, d.Type())
		}
		name := prefix + filepath.ToSlash(rel)
		if d.IsDir() {
			return tw.WriteHeader(&tar.Header{Name: name + "/", Mode: 0o700, Typeflag: tar.TypeDir})
		}
		return tarFile(tw, p, name)
	})
}

// writeFileFromTar writes a tar entry to dst, clamping the mode to 0600 (never
// trusting the header mode) and fsyncing before close.
func writeFileFromTar(tr io.Reader, dst string) error {
	f, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, tr); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// fsyncPath fsyncs a file at path (used after staging the nvram temp file).
func fsyncPath(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func withinDir(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}
