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
func RewriteDiskSourceFile(domXML, targetDev, oldFile, newFile string) (out string, changed bool, err error) {
	if hasXMLNamespace(domXML) {
		return "", false, fmt.Errorf("domain xml uses XML namespaces; refusing automated disk-source rewrite")
	}
	matchIndex, idempotent, err := matchDiskToRewrite(domXML, targetDev, oldFile, newFile)
	if err != nil {
		return "", false, err
	}
	if idempotent {
		return domXML, false, nil
	}
	rewritten, err := rewriteNthDiskSource(domXML, matchIndex, oldFile, newFile)
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
	dev  string
	file string
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
		out = append(out, diskSourceInfo{dev: d.Target.Dev, file: d.Source.File})
	}
	return out, nil
}

// matchDiskToRewrite resolves which devices/disk (by document-order index) must have
// its source rewritten, enforcing the locked matching rules. idempotent=true means
// the subject disk already points at newFile and no rewrite is needed.
func matchDiskToRewrite(domXML, targetDev, oldFile, newFile string) (matchIndex int, idempotent bool, err error) {
	disks, err := parseDiskSourceInfos(domXML)
	if err != nil {
		return -1, false, err
	}
	if targetDev != "" {
		idx := -1
		for i, d := range disks {
			if d.dev == targetDev {
				if idx >= 0 {
					return -1, false, fmt.Errorf("multiple disks with target dev %q", targetDev)
				}
				idx = i
			}
		}
		if idx < 0 {
			return -1, false, fmt.Errorf("no disk with target dev %q", targetDev)
		}
		switch d := disks[idx]; {
		case d.file == newFile:
			return idx, true, nil // already cut over
		case d.file == oldFile:
			return idx, false, nil
		case d.file == "":
			return -1, false, fmt.Errorf("disk %q has no file-backed <source> to rewrite", targetDev)
		default:
			return -1, false, fmt.Errorf("disk %q source is %q, expected %q", targetDev, d.file, oldFile)
		}
	}
	// targetDev == "": match by source file across all file-backed disks.
	var oldIdxs, newIdxs []int
	for i, d := range disks {
		switch d.file {
		case "":
			// source-less / block / network disk — never a file rewrite subject.
		case oldFile:
			oldIdxs = append(oldIdxs, i)
		case newFile:
			newIdxs = append(newIdxs, i)
		}
	}
	switch {
	case len(oldIdxs) == 1:
		return oldIdxs[0], false, nil
	case len(oldIdxs) > 1:
		return -1, false, fmt.Errorf("multiple disks with source %q", oldFile)
	case len(newIdxs) == 1:
		return newIdxs[0], true, nil // idempotent
	case len(newIdxs) > 1:
		return -1, false, fmt.Errorf("multiple disks with source %q", newFile)
	default:
		return -1, false, fmt.Errorf("no disk with source %q", oldFile)
	}
}

// rewriteNthDiskSource streams the domain XML through the tokenizer and rewrites the
// file attribute of the <source> that is a direct child of the matchIndex-th
// devices/disk, from oldFile to newFile, re-emitting every other token verbatim.
func rewriteNthDiskSource(domXML string, matchIndex int, oldFile, newFile string) (string, error) {
	dec := xml.NewDecoder(strings.NewReader(domXML))
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)

	var stack []string    // open ancestor element names (parent is the last entry)
	diskIndex := -1       // index among devices/disk
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
				emit = rewriteSourceFileAttr(t, oldFile, newFile, &rewrote)
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
		return "", fmt.Errorf("internal: matched disk %d had no rewritable <source file=%q>", matchIndex, oldFile)
	}
	return buf.String(), nil
}

// rewriteSourceFileAttr returns a copy of a <source> start element with its file
// attribute changed oldFile→newFile (and flags rewrote). It copies first so the
// decoder's internal attribute buffer is never mutated.
func rewriteSourceFileAttr(se xml.StartElement, oldFile, newFile string, rewrote *bool) xml.StartElement {
	se = se.Copy()
	for i := range se.Attr {
		if se.Attr[i].Name.Local == "file" && se.Attr[i].Value == oldFile {
			se.Attr[i].Value = newFile
			*rewrote = true
		}
	}
	return se
}
