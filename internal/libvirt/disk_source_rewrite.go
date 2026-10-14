package libvirt

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
)

// RewriteDiskSourceFile rewrites exactly one disk's <source file=...> in a libvirt
// domain XML from oldFile to newFile and returns the new XML. It is the authoritative
// cutover used by MoveVolume to repoint a domain's persistent config after a disk
// moves between pools — so it is deliberately strict and precise rather than a blunt
// string replace (which can hit the path outside the <source> attribute or mishandle
// XML-escaped attribute values).
//
// Matching:
//   - targetDev != "": the disk with <target dev=targetDev> is the subject. Its current
//     <source file> must equal oldFile (→ rewrite, changed=true) or newFile (→ already
//     cut over, changed=false); anything else, a missing such disk, or a subject disk
//     that has no file-backed <source> (cdrom/block/network) is an error.
//   - targetDev == "" (legacy rows with no recorded dev): exactly one disk whose
//     <source file> equals oldFile → rewrite; else exactly one equal to newFile →
//     idempotent (changed=false); zero or multiple matches → error.
//
// Other disks — including source-less devices (empty cdrom) and block/network disks
// (<source dev=…>/<source protocol=…>, no file attr) — are parsed but never modified.
//
// The result is semantically equivalent, not byte-identical: it is produced via the
// encoding/xml tokenizer (lossless at the element/attribute level and escaping-safe),
// and libvirt re-canonicalizes on DomainDefineXML anyway, so formatting/comments need
// not be preserved. Domains carrying XML namespaces (e.g. the qemu:/ passthrough
// extension) are refused rather than risk a mangling round-trip — litevirt-managed
// domains are namespace-free, so this only blocks externally-customized ones, where
// failing the cutover safely beats corrupting the definition.
// RewriteDiskSource repoints one disk's source, whichever attribute that disk
// actually uses: <source file=> for a file, <source dev=> for a block device,
// <source name=> for an rbd image.
//
// RewriteDiskSourceFile knows only about `file`, which was enough while every
// generated disk was emitted as type="file" regardless of what backed it. A
// zvol or an LV was therefore rewritable by accident. Now that a block-backed
// disk correctly carries <source dev=>, the file-only rewrite refuses it and
// `lv move-volume` cannot repoint a zfs, lvm-thin or iscsi disk at all.
//
// A move that would change the BACKING KIND is refused: repointing a block
// device at a qcow2 file needs the <disk type> and <driver type> to change too,
// and a source-only rewrite would leave a domain libvirt cannot start. That is
// a different operation, not a path edit.
func RewriteDiskSource(domXML, targetDev, oldSource, newSource string) (out string, changed bool, err error) {
	return rewriteDiskSourceLocator(domXML, targetDev, oldSource, newSource, anySourceAttr)
}

// sourceAttrKind names the <source> attribute a disk uses to locate itself. The
// three are mutually exclusive and are selected by the enclosing <disk type=>.
type sourceAttrKind string

const (
	sourceAttrFile sourceAttrKind = "file" // type="file"
	sourceAttrDev  sourceAttrKind = "dev"  // type="block"
	sourceAttrName sourceAttrKind = "name" // type="network" (rbd et al)
	// anySourceAttr means "whichever one this disk carries".
	anySourceAttr sourceAttrKind = ""
)

// sourceAttrKinds is the search order when a disk's kind is not pinned. A disk
// carries exactly one of these, so the order only decides which is reported
// first for a malformed domain that carries several.
var sourceAttrKinds = []sourceAttrKind{sourceAttrFile, sourceAttrDev, sourceAttrName}

func RewriteDiskSourceFile(domXML, targetDev, oldFile, newFile string) (out string, changed bool, err error) {
	return rewriteDiskSourceLocator(domXML, targetDev, oldFile, newFile, sourceAttrFile)
}

// rewriteDiskSource is the shared body. `want` pins which source attribute is
// eligible; anySourceAttr accepts whichever the disk carries.
func rewriteDiskSourceLocator(domXML, targetDev, oldSource, newSource string, want sourceAttrKind) (string, bool, error) {
	if hasXMLNamespace(domXML) {
		return "", false, fmt.Errorf("domain xml uses XML namespaces; refusing automated disk-source rewrite")
	}
	matchIndex, kind, idempotent, err := matchDiskToRewrite(domXML, targetDev, oldSource, newSource, want)
	if err != nil {
		return "", false, err
	}
	if idempotent {
		return domXML, false, nil
	}
	// Refuse a move that changes the backing KIND. Repointing a block device at
	// a qcow2 file (or the reverse) needs the <disk type> and the <driver type>
	// to change with it; editing only the locator leaves a domain that claims to
	// be one thing and points at another, and libvirt will not start it. That is
	// a different operation, not a path edit.
	if !sourceSuitsKind(kind, newSource) {
		return "", false, fmt.Errorf(
			"cannot repoint a %s to %q: that is a %s. Changing a disk's backing needs "+
				"the disk type and driver type to change too, which this rewrite does not do",
			sourceAttrDescription(kind), newSource, sourceAttrDescription(kindOfSource(newSource)))
	}
	rewritten, err := rewriteNthDiskSource(domXML, matchIndex, kind, oldSource, newSource)
	if err != nil {
		return "", false, err
	}
	return rewritten, true, nil
}

// hasXMLNamespace reports whether the domain XML actually declares or uses an XML
// namespace (e.g. the qemu:/ passthrough extension), detected via the tokenizer —
// a namespaced element name or an xmlns/xmlns:prefix declaration. This is precise,
// unlike a substring scan for "xmlns" which false-positives on path/attribute values.
// On a parse error it returns false and lets the main rewrite surface the error.
func hasXMLNamespace(domXML string) bool {
	dec := xml.NewDecoder(strings.NewReader(domXML))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		if se.Name.Space != "" {
			return true // a namespaced element (e.g. qemu:commandline)
		}
		for _, a := range se.Attr {
			// xmlns="…" → {Space:"", Local:"xmlns"}; xmlns:p="…" → {Space:"xmlns", …}.
			if a.Name.Local == "xmlns" || a.Name.Space == "xmlns" {
				return true
			}
		}
	}
}

// diskSourceInfo is one disk's identity for matching: its target dev and its
// file-backed source (empty when the disk has no <source file>).
type diskSourceInfo struct {
	dev string // <target dev=…>, the disk's stable name
	// Exactly one of these is non-empty for a well-formed disk; all three are
	// empty for a source-less device such as an ejected cdrom.
	src map[sourceAttrKind]string
}

// source returns the disk's locator under `want`, plus which attribute it came
// from. With anySourceAttr it reports whichever one the disk carries.
func (d diskSourceInfo) source(want sourceAttrKind) (string, sourceAttrKind) {
	if want != anySourceAttr {
		return d.src[want], want
	}
	for _, k := range sourceAttrKinds {
		if v := d.src[k]; v != "" {
			return v, k
		}
	}
	return "", anySourceAttr
}

// parseDiskSourceInfos returns every devices/disk in document order with its target
// dev and <source file>. Document order matches the token stream in
// rewriteNthDiskSource, so a disk's index is a stable handle between the two passes.
func parseDiskSourceInfos(domXML string) ([]diskSourceInfo, error) {
	var domain struct {
		Devices struct {
			Disks []struct {
				Source struct {
					File string `xml:"file,attr"`
					Dev  string `xml:"dev,attr"`
					Name string `xml:"name,attr"`
				} `xml:"source"`
				Target struct {
					Dev string `xml:"dev,attr"`
				} `xml:"target"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &domain); err != nil {
		return nil, fmt.Errorf("parse domain xml: %w", err)
	}
	out := make([]diskSourceInfo, 0, len(domain.Devices.Disks))
	for _, d := range domain.Devices.Disks {
		out = append(out, diskSourceInfo{
			dev: d.Target.Dev,
			src: map[sourceAttrKind]string{
				sourceAttrFile: d.Source.File,
				sourceAttrDev:  d.Source.Dev,
				sourceAttrName: d.Source.Name,
			},
		})
	}
	return out, nil
}

// matchDiskToRewrite resolves which devices/disk (by document-order index) must have
// its source rewritten, enforcing the locked matching rules. idempotent=true means
// the subject disk already points at newFile and no rewrite is needed.
func matchDiskToRewrite(domXML, targetDev, oldSource, newSource string, want sourceAttrKind) (matchIndex int, kind sourceAttrKind, idempotent bool, err error) {
	disks, err := parseDiskSourceInfos(domXML)
	if err != nil {
		return -1, anySourceAttr, false, err
	}
	if targetDev != "" {
		idx := -1
		for i, d := range disks {
			if d.dev == targetDev {
				if idx >= 0 {
					return -1, anySourceAttr, false, fmt.Errorf("multiple disks with target dev %q", targetDev)
				}
				idx = i
			}
		}
		if idx < 0 {
			return -1, anySourceAttr, false, fmt.Errorf("no disk with target dev %q", targetDev)
		}
		cur, k := disks[idx].source(want)
		switch {
		case cur == newSource:
			return idx, k, true, nil // already cut over
		case cur == oldSource:
			return idx, k, false, nil
		case cur == "":
			return -1, anySourceAttr, false, fmt.Errorf(
				"disk %q has no %s to rewrite", targetDev, sourceAttrDescription(want))
		default:
			return -1, anySourceAttr, false, fmt.Errorf(
				"disk %q source is %q, expected %q", targetDev, cur, oldSource)
		}
	}
	// targetDev == "": match by source across every disk that has one.
	var oldIdxs, newIdxs []int
	var oldKind sourceAttrKind
	for i, d := range disks {
		cur, k := d.source(want)
		switch cur {
		case "":
			// source-less device (an ejected cdrom) — never a rewrite subject.
		case oldSource:
			oldIdxs = append(oldIdxs, i)
			oldKind = k
		case newSource:
			newIdxs = append(newIdxs, i)
			oldKind = k
		}
	}
	switch {
	case len(oldIdxs) == 1:
		return oldIdxs[0], oldKind, false, nil
	case len(oldIdxs) > 1:
		return -1, anySourceAttr, false, fmt.Errorf("multiple disks with source %q", oldSource)
	case len(newIdxs) == 1:
		return newIdxs[0], oldKind, true, nil // idempotent
	case len(newIdxs) > 1:
		return -1, anySourceAttr, false, fmt.Errorf("multiple disks with source %q", newSource)
	default:
		return -1, anySourceAttr, false, fmt.Errorf("no disk with source %q", oldSource)
	}
}

// kindOfSource infers which <source> attribute a bare locator belongs in.
//
// It reads the locator's SHAPE, not a URI scheme, because inside the domain XML
// the scheme is already gone: an rbd disk stores "pool/image" under
// <source name=>, not "rbd:pool/image". A device node is absolute under /dev,
// a file is any other absolute path, and anything relative is a network name.
func kindOfSource(s string) sourceAttrKind {
	switch {
	case strings.HasPrefix(s, "/dev/"):
		return sourceAttrDev
	case strings.HasPrefix(s, "/"):
		return sourceAttrFile
	default:
		return sourceAttrName
	}
}

// sourceSuitsKind reports whether newSource can live under the attribute the
// disk already uses.
func sourceSuitsKind(kind sourceAttrKind, newSource string) bool {
	return kindOfSource(newSource) == kind
}

// sourceAttrDescription renders a kind for an operator-facing error.
func sourceAttrDescription(k sourceAttrKind) string {
	switch k {
	case sourceAttrFile:
		return "file-backed <source>"
	case sourceAttrDev:
		return "block-backed <source>"
	case sourceAttrName:
		return "network <source>"
	default:
		return "<source> locator"
	}
}

// rewriteNthDiskSource streams the domain XML through the tokenizer and rewrites the
// file attribute of the <source> that is a direct child of the matchIndex-th
// devices/disk, from oldFile to newFile, re-emitting every other token verbatim.
func rewriteNthDiskSource(domXML string, matchIndex int, kind sourceAttrKind, oldSource, newSource string) (string, error) {
	dec := xml.NewDecoder(strings.NewReader(domXML))
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	var stack []string     // open ancestor element names (parent is the last entry)
	diskIndex := -1        // index among devices/disk
	matchedDiskDepth := -1 // stack depth at the matched <disk> start; -1 ⇒ not inside it
	rewrote := false

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("decode domain xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			parent := ""
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			if t.Name.Local == "disk" && parent == "devices" {
				diskIndex++
				if diskIndex == matchIndex {
					matchedDiskDepth = len(stack)
				}
			}
			emit := t
			if matchedDiskDepth >= 0 && t.Name.Local == "source" && parent == "disk" {
				emit = rewriteSourceAttr(t, kind, oldSource, newSource, &rewrote)
			}
			stack = append(stack, t.Name.Local)
			if err := enc.EncodeToken(emit); err != nil {
				return "", err
			}
		case xml.EndElement:
			if err := enc.EncodeToken(t); err != nil {
				return "", err
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if matchedDiskDepth >= 0 && len(stack) == matchedDiskDepth {
				matchedDiskDepth = -1 // closed the matched <disk>
			}
		default:
			if err := enc.EncodeToken(tok); err != nil {
				return "", err
			}
		}
	}
	if err := enc.Flush(); err != nil {
		return "", err
	}
	if !rewrote {
		return "", fmt.Errorf("internal: matched disk %d had no rewritable <source %s=%q>", matchIndex, kind, oldSource)
	}
	return buf.String(), nil
}

// rewriteSourceFileAttr returns a copy of a <source> start element with its file
// attribute changed oldFile→newFile (and flags rewrote). It copies first so the
// decoder's internal attribute buffer is never mutated.
func rewriteSourceAttr(se xml.StartElement, kind sourceAttrKind, oldSource, newSource string, rewrote *bool) xml.StartElement {
	se = se.Copy()
	for i := range se.Attr {
		if se.Attr[i].Name.Local == string(kind) && se.Attr[i].Value == oldSource {
			se.Attr[i].Value = newSource
			*rewrote = true
		}
	}
	return se
}
