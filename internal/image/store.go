package image

import (
	"fmt"
	"os"
	"path/filepath"

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

// DeleteVMDisks removes all disks for a VM using the flat naming convention.
func (s *Store) DeleteVMDisks(vmName string) error {
	pattern := filepath.Join(s.diskDir, vmName+"-*.qcow2")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return err
	}
	for _, m := range matches {
		os.Remove(m)
	}
	// Also clean up legacy VM subdirectory if it exists.
	legacyDir := filepath.Join(s.diskDir, vmName)
	if info, err := os.Stat(legacyDir); err == nil && info.IsDir() {
		os.RemoveAll(legacyDir)
	}
	return nil
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
