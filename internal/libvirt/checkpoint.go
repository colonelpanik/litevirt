// (real driver) — wrappers around the go-libvirt domain
// checkpoint + pull-mode backup API so the backup layer can drive
// QEMU persistent dirty bitmaps for incremental backup.
//
// The model: each successful backup creates a checkpoint, which begins a
// persistent dirty bitmap that tracks every write from that point on. The
// NEXT incremental backup asks libvirt (via a pull-mode DomainBackupBegin
// referencing the parent checkpoint) for the set of blocks dirtied since
// then, reads only those blocks, and inherits the rest from the parent
// manifest's chunk refs.
package libvirt

import (
	"encoding/xml"
	"fmt"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// exportBitmapName is the deterministic name we give the merged dirty
// bitmap that a pull-mode backup exposes, so the NBD meta-context query is
// version-independent ("qemu:dirty-bitmap:<exportBitmapName>").
const exportBitmapName = "lvdirty"

// CheckpointInfo is a typed view of one libvirt domain checkpoint.
// Parent/CreationTime are populated only by callers that need them
// (ListCheckpoints leaves them empty to avoid a GetXMLDesc per row).
type CheckpointInfo struct {
	Name         string
	Parent       string
	CreationTime string
}

// checkpointXML is the minimal <domaincheckpoint> document libvirt
// accepts. Each disk gets a persistent bitmap named after the checkpoint.
type checkpointXML struct {
	XMLName xml.Name            `xml:"domaincheckpoint"`
	Name    string              `xml:"name"`
	Disks   []checkpointXMLDisk `xml:"disks>disk"`
}

type checkpointXMLDisk struct {
	Name       string `xml:"name,attr"`
	Checkpoint string `xml:"checkpoint,attr"`
}

// buildCheckpointXML renders the create document for a checkpoint that
// begins a bitmap on each of diskTargets (e.g. "vda", "vdb").
func buildCheckpointXML(name string, diskTargets []string) (string, error) {
	doc := checkpointXML{Name: name}
	for _, t := range diskTargets {
		doc.Disks = append(doc.Disks, checkpointXMLDisk{Name: t, Checkpoint: "bitmap"})
	}
	b, err := xml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal checkpoint xml: %w", err)
	}
	return string(b), nil
}

// ListCheckpoints returns the checkpoints currently defined on a domain.
// Only Name is populated (cheap single RPC); use DomainCheckpointGetXMLDesc
// if you need parent/creation-time.
func (c *Client) ListCheckpoints(domain string) ([]CheckpointInfo, error) {
	dom, err := c.virt.DomainLookupByName(domain)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	cps, _, err := c.virt.DomainListAllCheckpoints(dom, 1, 0)
	if err != nil {
		return nil, fmt.Errorf("list checkpoints: %w", err)
	}
	out := make([]CheckpointInfo, 0, len(cps))
	for _, cp := range cps {
		out = append(out, CheckpointInfo{Name: cp.Name})
	}
	return out, nil
}

// DeleteCheckpoint removes a checkpoint. With withChildren=false libvirt
// merges the deleted checkpoint's bitmap into its child so the chain
// remains diffable; with withChildren=true the whole subtree is dropped.
func (c *Client) DeleteCheckpoint(domain, checkpointName string, withChildren bool) error {
	dom, err := c.virt.DomainLookupByName(domain)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domain, err)
	}
	cp, err := c.virt.DomainCheckpointLookupByName(dom, checkpointName, 0)
	if err != nil {
		if isNotFound(err) {
			return nil // already gone — idempotent
		}
		return fmt.Errorf("lookup checkpoint %s: %w", checkpointName, err)
	}
	var flags golibvirt.DomainCheckpointDeleteFlags
	if withChildren {
		flags = golibvirt.DomainCheckpointDeleteChildren
	}
	if err := c.virt.DomainCheckpointDelete(cp, flags); err != nil {
		return fmt.Errorf("delete checkpoint %s: %w", checkpointName, err)
	}
	return nil
}

// backupXML is the minimal pull-mode <domainbackup> document. We pin the
// export name and bitmap name so the NBD query is deterministic.
type backupXML struct {
	XMLName     xml.Name        `xml:"domainbackup"`
	Mode        string          `xml:"mode,attr"`
	Incremental string          `xml:"incremental,omitempty"`
	Server      backupXMLServer `xml:"server"`
	Disks       []backupXMLDisk `xml:"disks>disk"`
}

type backupXMLServer struct {
	Transport string `xml:"transport,attr"`
	Socket    string `xml:"socket,attr"`
}

type backupXMLDisk struct {
	Name         string            `xml:"name,attr"`
	Backup       string            `xml:"backup,attr"`
	Type         string            `xml:"type,attr"`
	ExportName   string            `xml:"exportname,attr"`
	ExportBitmap string            `xml:"exportbitmap,attr,omitempty"`
	Scratch      *backupXMLScratch `xml:"scratch,omitempty"`
}

type backupXMLScratch struct {
	File string `xml:"file,attr"`
}

func buildBackupXML(diskTarget, parentCheckpoint, socket, scratch string) (string, error) {
	disk := backupXMLDisk{
		Name:       diskTarget,
		Backup:     "yes",
		Type:       "file",
		ExportName: diskTarget,
		Scratch:    &backupXMLScratch{File: scratch},
	}
	// exportbitmap only applies to an incremental backup (there's a merged
	// dirty bitmap to export); a full backup carries base:allocation only.
	if parentCheckpoint != "" {
		disk.ExportBitmap = exportBitmapName
	}
	doc := backupXML{
		Mode:        "pull",
		Incremental: parentCheckpoint,
		Server:      backupXMLServer{Transport: "unix", Socket: socket},
		Disks:       []backupXMLDisk{disk},
	}
	b, err := xml.Marshal(doc)
	if err != nil {
		return "", fmt.Errorf("marshal backup xml: %w", err)
	}
	return string(b), nil
}

// isNotFound classifies a libvirt error as "object does not exist" so
// existence probes don't conflate a missing checkpoint with a real fault.
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	if e, ok := err.(golibvirt.Error); ok {
		switch e.Code {
		case uint32(golibvirt.ErrNoDomainCheckpoint),
			uint32(golibvirt.ErrNoDomain),
			uint32(golibvirt.ErrNoDomainSnapshot):
			return true
		}
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found") ||
		strings.Contains(msg, "no domain checkpoint") ||
		strings.Contains(msg, "cannot find")
}
