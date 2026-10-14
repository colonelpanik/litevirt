// (content-based rewrite) — a BackupSession is an open
// pull-mode backup: a point-in-time NBD export of a VM disk's GUEST-VISIBLE
// content, plus a meta-context describing which regions matter
// (base:allocation for a full backup, the merged dirty bitmap for an
// incremental). The backup layer enumerates the regions it needs
// (ChangedExtents) and reads their bytes (ReadAt) — all in guest-virtual
// address space, so the dirty bitmap and the data are consistent.
//
// This supersedes the earlier qcow2-container backup: reading the guest
// disk (not the qcow2 file) is what makes incremental dirty-bitmap backups
// correct, and makes restores format-portable.
package libvirt

import (
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// domainDisksXML is the minimal view of a domain's <devices><disk> list we
// need to map a disk's source file to its libvirt target dev.
type domainDisksXML struct {
	Disks []struct {
		Source struct {
			File string `xml:"file,attr"`
			Dev  string `xml:"dev,attr"`
		} `xml:"source"`
		Target struct {
			Dev string `xml:"dev,attr"`
		} `xml:"target"`
	} `xml:"devices>disk"`
}

// diskTargetForSource returns the <target dev> of the disk whose source
// (file or block dev) matches sourcePath, or "" if none.
func diskTargetForSource(domXML, sourcePath string) string {
	var d domainDisksXML
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return ""
	}
	for _, disk := range d.Disks {
		if disk.Source.File == sourcePath || disk.Source.Dev == sourcePath {
			return disk.Target.Dev
		}
	}
	return ""
}

const (
	// Scratch + socket live under /var/lib (traversable by the
	// unprivileged libvirt-qemu user) and the dirs are chmod 0777 so qemu
	// can create the fleecing image + bind the NBD socket. Learned from
	// live testing on libvirt 10 (AppArmor-confined, qemu unprivileged).
	sessScratchDir = "/var/lib/litevirt/backup-scratch"
	sessSocketDir  = "/var/lib/litevirt/backup-sock"
)

// BackupSession holds an in-flight pull-mode backup. Close() ends it.
type BackupSession struct {
	c           *Client
	dom         golibvirt.Domain
	nbd         *nbdConn
	size        int64
	ctxID       uint32
	incremental bool
	export      string
	scratch     string
	socket      string
}

// BeginBackup starts a pull-mode backup of diskTarget (e.g. "vda") whose
// guest-visible content is `size` bytes. If parentCheckpoint != "" the
// export carries the dirty bitmap merged since that checkpoint
// (incremental); otherwise it carries base:allocation (full). newCheckpoint,
// if non-empty, is created atomically as the backup begins so the NEXT
// backup can diff against it.
//
// On any error the transient job + scratch are cleaned up. Requires a
// running domain and libvirt ≥ 6.x.
func (c *Client) BeginBackup(domain, diskPath, parentCheckpoint, newCheckpoint string) (*BackupSession, error) {
	dom, err := c.virt.DomainLookupByName(domain)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	// Resolve the libvirt target dev + the guest-visible (virtual) size
	// from the live domain — never trust caller-supplied values, which can
	// be stale/empty (e.g. vm_disks.target_dev is unset for VMs created via
	// CreateVM). This is what makes the backup cover the whole disk.
	domXML, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return nil, fmt.Errorf("dump domain xml: %w", err)
	}
	diskTarget := diskTargetForSource(domXML, diskPath)
	if diskTarget == "" {
		return nil, fmt.Errorf("no disk with source %q in domain %s", diskPath, domain)
	}
	_, capacity, _, err := c.virt.DomainGetBlockInfo(dom, diskPath, 0)
	if err != nil {
		return nil, fmt.Errorf("get block info for %s: %w", diskPath, err)
	}
	size := int64(capacity)

	for _, d := range []string{sessScratchDir, sessSocketDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", d, err)
		}
		if err := os.Chmod(d, 0o777); err != nil {
			return nil, fmt.Errorf("chmod %s: %w", d, err)
		}
	}
	tag := fmt.Sprintf("%s-%s", domain, diskTarget)
	scratch := filepath.Join(sessScratchDir, tag+".scratch")
	socket := filepath.Join(sessSocketDir, tag+".sock")
	// qemu creates these itself; clear stale leftovers from a crashed run.
	_ = os.Remove(scratch)
	_ = os.Remove(socket)

	backupDoc, err := buildBackupXML(diskTarget, parentCheckpoint, socket, scratch)
	if err != nil {
		return nil, err
	}
	var cpXML golibvirt.OptString
	if newCheckpoint != "" {
		doc, derr := buildCheckpointXML(newCheckpoint, []string{diskTarget})
		if derr != nil {
			return nil, derr
		}
		cpXML = golibvirt.OptString{doc}
	}
	if err := c.virt.DomainBackupBegin(dom, backupDoc, cpXML, 0); err != nil {
		_ = os.Remove(scratch)
		return nil, fmt.Errorf("begin pull backup: %w", err)
	}

	s := &BackupSession{
		c: c, dom: dom, size: size, incremental: parentCheckpoint != "",
		export: diskTarget, scratch: scratch, socket: socket,
	}

	conn, err := net.DialTimeout("unix", socket, 15*time.Second)
	if err != nil {
		s.abort()
		return nil, fmt.Errorf("dial nbd %s: %w", socket, err)
	}
	n := &nbdConn{c: conn}
	if err := n.handshake(); err != nil {
		conn.Close()
		s.abort()
		return nil, fmt.Errorf("nbd handshake: %w", err)
	}
	if err := n.negotiateStructuredReply(); err != nil {
		conn.Close()
		s.abort()
		return nil, err
	}
	ctxName := "base:allocation"
	if s.incremental {
		ctxName = "qemu:dirty-bitmap:" + exportBitmapName
	}
	ctxID, err := n.setMetaContext(diskTarget, ctxName)
	if err != nil {
		conn.Close()
		s.abort()
		return nil, err
	}
	if err := n.optGo(diskTarget); err != nil {
		conn.Close()
		s.abort()
		return nil, err
	}
	s.nbd = n
	s.ctxID = ctxID
	return s, nil
}

// Size is the guest-visible disk size in bytes.
func (s *BackupSession) Size() int64 { return s.size }

// Incremental reports whether this session diffs against a parent
// checkpoint (true) or reads allocation (false).
func (s *BackupSession) Incremental() bool { return s.incremental }

// ChangedExtents returns the (offset,length) regions the backup must read:
// dirty regions for an incremental, allocated non-zero regions for a full.
// Holes / known-zero regions are excluded so a sparse guest disk is cheap
// to back up.
func (s *BackupSession) ChangedExtents() ([][2]int64, error) {
	s.nbd.c.SetDeadline(time.Now().Add(5 * time.Minute))
	exts, err := s.nbd.queryExtents(s.ctxID, s.size)
	if err != nil {
		return nil, fmt.Errorf("query extents: %w", err)
	}
	var out [][2]int64
	for _, e := range exts {
		var want bool
		if s.incremental {
			want = e.flags&nbdStateDirty != 0
		} else {
			// Full: read everything not a hole and not known-zero.
			want = e.flags&(nbdStateHole|nbdStateZero) == 0
		}
		if want && e.length > 0 {
			out = append(out, [2]int64{e.off, e.length})
		}
	}
	return out, nil
}

// ReadAt fills p with guest-visible bytes at offset (holes read as zero).
func (s *BackupSession) ReadAt(p []byte, offset int64) (int, error) {
	s.nbd.c.SetDeadline(time.Now().Add(5 * time.Minute))
	if err := s.nbd.readAt(p, offset); err != nil {
		return 0, err
	}
	return len(p), nil
}

// FailureCause says, best effort, why this session's backup failed, for a
// caller whose read just failed with a bare broken NBD pipe. It reads the
// backup job's own completion error (the job's `errmsg` in the completed job
// stats, which is where a qemu block-layer failure such as an EIO on the disk
// surfaces) and, failing that, the disks libvirt reports paused on an I/O
// error. Empty when neither source has anything: libvirt then holds no cause.
func (s *BackupSession) FailureCause() string {
	if _, params, err := s.c.virt.DomainGetJobStats(s.dom, golibvirt.DomainJobStatsCompleted); err == nil {
		if msg := backupJobErrmsg(params); msg != "" {
			return "the backup job failed: " + msg
		}
	}
	if errs, n, err := s.c.virt.DomainGetDiskErrors(s.dom, 64, 0); err == nil {
		return diskErrorsCause(errs, n)
	}
	return ""
}

// backupJobErrmsg is the error message of the completed job when that job was
// a backup: the completed stats are the domain's last completed job of any
// kind, and a migration's or a save's error is not this backup's cause.
func backupJobErrmsg(params []golibvirt.TypedParam) string {
	for _, p := range params {
		if p.Field != golibvirt.DomainJobOperationStr {
			continue
		}
		op, ok := p.Value.I.(int32)
		if !ok || golibvirt.DomainJobOperation(op) != golibvirt.DomainJobOperationStrBackup {
			return ""
		}
		return jobErrmsg(params)
	}
	return ""
}

// jobErrmsg is the job's error message among its stats parameters.
func jobErrmsg(params []golibvirt.TypedParam) string {
	for _, p := range params {
		if p.Field != golibvirt.DomainJobErrmsg {
			continue
		}
		if msg, ok := p.Value.I.(string); ok {
			return strings.TrimSpace(msg)
		}
	}
	return ""
}

// diskErrorsCause names the disks libvirt reports an I/O error on. Only a disk
// qemu paused on an error appears here, so an empty result says nothing.
func diskErrorsCause(errs []golibvirt.DomainDiskError, n int32) string {
	if n <= 0 || len(errs) == 0 {
		return ""
	}
	disks := make([]string, 0, len(errs))
	for _, e := range errs {
		disks = append(disks, e.Disk)
	}
	return "libvirt reports an I/O error on disk " + strings.Join(disks, ", ")
}

// Close ends the NBD connection and the qemu backup job and removes the
// scratch file. Safe to call once.
func (s *BackupSession) Close() error {
	if s.nbd != nil {
		s.nbd.disconnect()
		s.nbd = nil
	}
	s.abort()
	return nil
}

func (s *BackupSession) abort() {
	_ = s.c.virt.DomainAbortJob(s.dom)
	_ = os.Remove(s.scratch)
}
