package grpcapi

import (
	"fmt"
	"io"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// BackupReader is one open guest-content backup session: random-access
// reads of a VM disk's guest-visible bytes plus the set of regions that
// matter (allocated for a full backup, dirty for an incremental).
type BackupReader interface {
	io.ReaderAt
	Size() int64
	Incremental() bool
	ChangedExtents() ([][2]int64, error)
	Close() error
}

// backupCauser is implemented by a BackupReader that can say, best effort,
// why its backup failed. A read that fails mid-backup surfaces as a broken NBD
// pipe; the cause of the export's death lives in qemu's backup job.
type backupCauser interface {
	FailureCause() string
}

// readRecorder wraps a BackupReader and records the first error its ReadAt
// returned, so a failed push can tell a failed read of the VM's disk from a
// failure on the backup repository's side.
type readRecorder struct {
	BackupReader
	err error
}

func (r *readRecorder) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.BackupReader.ReadAt(p, off)
	if err != nil && err != io.EOF && r.err == nil {
		r.err = err
	}
	return n, err
}

// backupPushError is the error of a failed guest-content push. When the read
// of the VM's disk failed it names the disk and the cause of the failure when
// libvirt can give one; any other failure (the repository full, a chunk or
// manifest write) is a plain `push: <err>`, which says nothing about the disk.
func backupPushError(vm string, disk *corrosion.DiskRecord, rec *readRecorder, err error) error {
	if rec == nil || rec.err == nil {
		return status.Errorf(codes.Internal, "push: %v", err)
	}
	cause := ""
	if c, ok := rec.BackupReader.(backupCauser); ok {
		cause = c.FailureCause()
	}
	return status.Error(codes.Internal, formatBackupPushError(vm, disk, err, cause))
}

// formatBackupPushError composes the message: the disk (VM, name, path,
// storage), the original error's text, and the cause, or a plain statement
// that none was available. An empty cause does not mean qemu saw no error.
func formatBackupPushError(vm string, disk *corrosion.DiskRecord, err error, cause string) string {
	where := fmt.Sprintf("disk %q of %q (%s", disk.DiskName, vm, disk.Path)
	if disk.StorageType != "" {
		where += ", storage " + disk.StorageType
		if disk.StorageVolume != "" {
			where += " " + disk.StorageVolume
		}
	}
	where += ")"
	msg := fmt.Sprintf("push: reading %s: %v", where, err)
	if cause != "" {
		return msg + "; cause: " + cause
	}
	return msg + "; no cause was available from libvirt (the disk's storage may have returned an I/O error to qemu; check the host's kernel log and the storage)"
}

// BackupSource opens guest-content backup sessions and prunes the libvirt
// checkpoints that back incrementals. Implemented by *libvirt.Client (via
// LibvirtBackupSource); a fake stands in for tests.
type BackupSource interface {
	// BeginBackup starts a pull-mode backup of the disk whose source is
	// diskPath. The target dev + guest-visible size are resolved from the
	// live domain. parentCheckpoint != "" makes it incremental (dirty
	// bitmap since that checkpoint); newCheckpoint is created atomically so
	// the NEXT backup can diff against it.
	BeginBackup(domain, diskPath, parentCheckpoint, newCheckpoint string) (BackupReader, error)
	// GCCheckpoints deletes this disk's litevirt-owned checkpoints whose
	// names are not in keep.
	GCCheckpoints(domain, diskName string, keep []string) error
	// DeleteCheckpoint removes one checkpoint by name. Incremental replication
	// uses it to prune its own previous chain anchor without touching the
	// disk's backup checkpoints (which GCCheckpoints would). A missing
	// checkpoint is not an error.
	DeleteCheckpoint(domain, name string) error
}

// SetBackupSource wires the guest-content backup engine. When nil,
// BackupSnapshot falls back to the legacy qcow2-container full backup.
func (s *Server) SetBackupSource(b BackupSource) { s.backupSource = b }

// LibvirtBackupSource adapts *libvirt.Client to BackupSource.
type LibvirtBackupSource struct{ c *libvirt.Client }

func NewLibvirtBackupSource(c *libvirt.Client) *LibvirtBackupSource {
	return &LibvirtBackupSource{c: c}
}

func (s *LibvirtBackupSource) BeginBackup(domain, diskPath, parentCheckpoint, newCheckpoint string) (BackupReader, error) {
	sess, err := s.c.BeginBackup(domain, diskPath, parentCheckpoint, newCheckpoint)
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *LibvirtBackupSource) DeleteCheckpoint(domain, name string) error {
	if name == "" {
		return nil
	}
	return s.c.DeleteCheckpoint(domain, name, false)
}

func (s *LibvirtBackupSource) GCCheckpoints(domain, diskName string, keep []string) error {
	infos, err := s.c.ListCheckpoints(domain)
	if err != nil {
		return err
	}
	keepSet := make(map[string]struct{}, len(keep))
	for _, k := range keep {
		if k != "" {
			keepSet[k] = struct{}{}
		}
	}
	prefix := "lv-" + sanitizeName(diskName) + "-"
	var firstErr error
	for _, info := range infos {
		if !strings.HasPrefix(info.Name, prefix) {
			continue
		}
		if _, ok := keepSet[info.Name]; ok {
			continue
		}
		if err := s.c.DeleteCheckpoint(domain, info.Name, false); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

var _ BackupSource = (*LibvirtBackupSource)(nil)
