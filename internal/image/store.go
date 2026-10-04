package image

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
)

// Store manages local image storage.
type Store struct {
	imageDir string
	diskDir  string
}

// NewStore creates an image store rooted at the given data directory.
func NewStore(dataDir string) *Store {
	return &Store{
		imageDir: filepath.Join(dataDir, "images"),
		diskDir:  filepath.Join(dataDir, "disks"),
	}
}

// Init creates required directories.
func (s *Store) Init() error {
	for _, d := range []string{s.imageDir, s.diskDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return fmt.Errorf("create dir %s: %w", d, err)
		}
	}
	return nil
}

// ImagePath returns the path to a base image.
func (s *Store) ImagePath(imageName string) string {
	return filepath.Join(s.imageDir, imageName+".qcow2")
}

// SafeImagePath is ImagePath with the image name validated, so a name like
// "../../x" can't escape the image dir. Use this on write/import paths.
func (s *Store) SafeImagePath(imageName string) (string, error) {
	if err := safename.ValidateImageName(imageName); err != nil {
		return "", err
	}
	return s.ImagePath(imageName), nil
}

// ImageExists checks if a base image exists locally.
func (s *Store) ImageExists(imageName string) bool {
	_, err := os.Stat(s.ImagePath(imageName))
	return err == nil
}

// DiskDir returns the directory for a VM's disks.
// DiskDir returns the directory containing VM disks (flat — all VMs share the same dir).
func (s *Store) DiskDir(vmName string) string {
	return s.diskDir
}

// DiskPath returns the path to a specific VM disk.
// Uses flat naming ({vmName}-{diskName}.qcow2) so all disks live directly
// in the pool target directory, which libvirt requires for storage migration.
func (s *Store) DiskPath(vmName, diskName string) string {
	return filepath.Join(s.diskDir, vmName+"-"+diskName+".qcow2")
}

// SafeDiskPath is DiskPath with the name components validated, so a name like
// "../../x" can't escape the disk dir. Use on write paths (clone/restore).
func (s *Store) SafeDiskPath(vmName, diskName string) (string, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return "", err
	}
	if err := safename.ValidateDiskName(diskName); err != nil {
		return "", err
	}
	return s.DiskPath(vmName, diskName), nil
}

// CreateOverlayDisk creates a qcow2 disk backed by a base image (COW).
func (s *Store) CreateOverlayDisk(vmName, diskName, backingImage, size string) (string, error) {
	// Validate names at the write layer so neither an operator-supplied nor a
	// peer-replicated name can place the disk (or read a backing file) outside
	// the pool directory.
	if err := safename.ValidateVMName(vmName); err != nil {
		return "", err
	}
	if err := safename.ValidateDiskName(diskName); err != nil {
		return "", err
	}
	if err := safename.ValidateImageName(backingImage); err != nil {
		return "", err
	}
	diskDir := s.DiskDir(vmName)
	if err := os.MkdirAll(diskDir, 0755); err != nil {
		return "", fmt.Errorf("create disk dir: %w", err)
	}

	diskPath := s.DiskPath(vmName, diskName)
	backingPath := s.ImagePath(backingImage)

	var sizeBytes uint64
	if size != "" {
		var err error
		sizeBytes, err = qcow2.ParseSize(size)
		if err != nil {
			return "", fmt.Errorf("parse size %q: %w", size, err)
		}
	}
	if err := qcow2.CreateWithBacking(diskPath, backingPath, sizeBytes, nil); err != nil {
		return "", fmt.Errorf("create overlay disk: %w", err)
	}

	return diskPath, nil
}

// CreateEmptyDisk creates an empty qcow2 disk.
func (s *Store) CreateEmptyDisk(vmName, diskName, size string) (string, error) {
	if err := safename.ValidateVMName(vmName); err != nil {
		return "", err
	}
	if err := safename.ValidateDiskName(diskName); err != nil {
		return "", err
	}
	diskDir := s.DiskDir(vmName)
	if err := os.MkdirAll(diskDir, 0755); err != nil {
		return "", fmt.Errorf("create disk dir: %w", err)
	}

	diskPath := s.DiskPath(vmName, diskName)
	sizeBytes, err := qcow2.ParseSize(size)
	if err != nil {
		return "", fmt.Errorf("parse size %q: %w", size, err)
	}
	if err := qcow2.Create(diskPath, sizeBytes, nil); err != nil {
		return "", fmt.Errorf("create empty disk: %w", err)
	}

	return diskPath, nil
}

// DeleteVMDisks removes all disks for a VM using the flat naming convention,
// skipping any path in keep.
//
// keep is required rather than optional because the glob is indiscriminate: it
// matches every <vm>-*.qcow2 in the shared disk dir whether or not something
// else still depends on it. A linked clone's base is exactly that case — the
// overlay names it in backing_disk, the file is swept anyway, and every chain
// built on it is destroyed. Callers pass the set of paths still referenced;
// nil means "nothing is referenced", which the caller has to mean.
// VMDiskCandidates returns exactly the files DeleteVMDisks would consider for
// this VM name. Both go through it so the set a caller PROTECTS and the set that
// gets DELETED cannot drift apart — a guard computed against a different list
// than the glob walks is a guard with a hole in it.
func (s *Store) VMDiskCandidates(vmName string) ([]string, error) {
	globbed, err := filepath.Glob(filepath.Join(s.diskDir, vmName+"-*.qcow2"))
	if err != nil {
		return nil, err
	}
	// Only names this VM can be the ONLY owner of. The glob also matches every
	// disk of a VM whose name extends this one with a dash: web-*.qcow2 matches
	// web-1-root.qcow2, which is VM "web-1"'s root disk. The keep set protects
	// only paths a live row names, so a disk web-1's operator kept with
	// --keep-disks (no row left) was swept whenever "web" was created, deleted
	// or rebuilt.
	//
	// The flat name cannot say which split is meant — disk names may contain a
	// dash too, so web-1-root is equally "web" + "1-root". Every file of
	// another VM that this glob can match has a dash after "web-", and a file
	// with none can belong to no other VM, so the rule is: a remainder with a
	// dash is ambiguous and is NOT a candidate. The cost is that this VM's own
	// dashed-name debris is left on disk; a recorded disk of that shape is still
	// freed by its row (deleteRecordedVMDiskVolumes), and leaking a file is
	// recoverable where deleting someone else's is not.
	matches := make([]string, 0, len(globbed))
	for _, m := range globbed {
		rest := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), vmName+"-"), ".qcow2")
		if strings.Contains(rest, "-") {
			continue
		}
		matches = append(matches, m)
	}
	// The LEGACY per-VM subdirectory's contents too, because DeleteVMDisksIn
	// used to remove that whole tree with os.RemoveAll — a recursive delete no
	// candidate list contained and no reference check ever saw, sitting behind a
	// comment promising one listing drove everything. Listing its files here is
	// what makes that promise true: they go through the same keep set as the
	// flat ones, so a legacy disk another VM still references is protected.
	legacyDir := filepath.Join(s.diskDir, vmName)
	// LSTAT, and a real directory only. os.ReadDir FOLLOWS a symlink, so a
	// legacy directory an operator symlinked onto another volume would have its
	// contents enumerated as candidates and unlinked one by one — while the
	// os.RemoveAll this replaced removed only the link and left the target
	// intact. Enlarging the blast radius across a symlink is the opposite of
	// what listing these files is for.
	li, lerr := os.Lstat(legacyDir)
	if lerr != nil || !li.Mode().IsDir() {
		// Absent, a symlink, or not a directory at all: nothing this sweep owns.
		// ENOTDIR matters in particular — a plain FILE at that path used to
		// sweep normally, and returning an error here would disable the sweep
		// for that VM name on every attempt, including createVM's pre-create
		// debris pass.
		return matches, nil
	}
	entries, err := os.ReadDir(legacyDir)
	if err != nil {
		if os.IsNotExist(err) {
			return matches, nil
		}
		// Reported, not swallowed: a directory that exists but cannot be read is
		// not evidence it is empty, and the caller refuses to sweep at all on
		// this error rather than deleting the flat files and guessing about
		// these.
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			matches = append(matches, filepath.Join(legacyDir, e.Name()))
		}
	}
	return matches, nil
}

// DeleteVMDisksIn deletes from a candidate list the caller already holds,
// instead of listing again.
//
// This is the form a protected sweep has to use. DeleteVMDisks re-lists, so the
// set it deletes is not the set the caller computed protection against: a file
// created after the keep set was built is in no keep set and gets removed with
// no reference check ever run against it, and a listing that succeeds for the
// caller but fails here turns "protect nothing" into "delete everything". One
// listing, passed down, removes both — the guarantee stops depending on two
// calls agreeing.
func (s *Store) DeleteVMDisksIn(vmName string, candidates []string, keep map[string]bool) error {
	// REFUSED before any path is built. Every path below is derived from this
	// name, so a name carrying a separator or a parent reference would aim the
	// delete outside the disk directory. Callers validate VM names, but this
	// function's whole contract is about what it is allowed to remove, and it
	// should not depend on someone else having checked.
	if vmName == "" || strings.ContainsAny(vmName, `/\`) || vmName == ".." || strings.Contains(vmName, "..") {
		return fmt.Errorf("refusing to delete disks for an unsafe VM name %q", vmName)
	}
	legacyDir := filepath.Join(s.diskDir, vmName)
	var errs []error
	for _, m := range candidates {
		if keep[m] {
			continue
		}
		// EVERY path checked, not just the one built here. The name guard above
		// only constrains legacyDir; the paths actually removed come from a
		// caller-supplied slice, and sweepVMDiskDebrisIn is a package-internal
		// seam any future caller can hand an arbitrary list. A function whose
		// whole doc is "what it is allowed to remove" must enforce it.
		if d := filepath.Dir(m); d != s.diskDir && d != legacyDir {
			errs = append(errs, fmt.Errorf("refusing to delete %s: outside %s", m, s.diskDir))
			continue
		}
		// COLLECTED, not discarded. These were dropped entirely, so a sweep that
		// removed nothing — a read-only directory, a busy file — was reported to
		// the caller as a successful sweep and logged as one. The caller then
		// believes the debris is gone.
		if err := os.Remove(m); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("remove %s: %w", m, err))
		}
	}
	// The legacy directory itself, only once it is EMPTY. os.Remove refuses a
	// non-empty one, which is the point: anything still inside was either kept
	// by the keep set or is a subdirectory this sweep does not own, and the
	// os.RemoveAll that used to be here destroyed both without ever consulting a
	// reference check.
	if info, err := os.Lstat(legacyDir); err == nil && info.Mode().IsDir() {
		// Not an error when it fails: a non-empty directory is the EXPECTED
		// outcome whenever the keep set spared something inside it.
		_ = os.Remove(legacyDir)
	}
	return errors.Join(errs...)
}

// DiskInfo returns size info for a disk file.
func (s *Store) DiskInfo(path string) (virtualSize int64, actualSize int64, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	actualSize = info.Size()

	// Get virtual size from qcow2 header.
	qInfo, qErr := qcow2.Info(path)
	if qErr == nil && qInfo.VirtualSize > 0 {
		virtualSize = int64(qInfo.VirtualSize)
		return virtualSize, actualSize, nil
	}

	// Fallback: use actual size if not a valid qcow2 file.
	virtualSize = actualSize
	return virtualSize, actualSize, nil
}
