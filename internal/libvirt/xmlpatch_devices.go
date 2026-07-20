package libvirt

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
)

// ErrDeviceCardinality is returned when a hostdev alias referenced in the desired
// device set matches more than one existing <hostdev> in the inactive XML (an
// ambiguous mapping the patcher refuses to guess through), or when the desired
// set itself names the same hostdev alias twice.
var ErrDeviceCardinality = errors.New("libvirt: hostdev alias maps to an ambiguous number of devices")

// WantDisk is a desired disk in the reconciled device set. TargetDev is the
// stable match key (libvirt target dev, e.g. "vda"); Path is the backing file.
// Bus/Cache are used only when ADDING a new disk — a matched disk has only its
// <source> rewritten, leaving bus/cache/topology untouched.
type WantDisk struct {
	TargetDev string
	Bus       string
	Path      string
	Cache     string
	// ControllerModel is reserved for Task 3.3 (disk-controller selection); the
	// patcher does not read or emit it yet — matched disks mutate only <source>
	// and the add path does not render a controller model.
	ControllerModel string
}

// WantNIC is a desired network interface. MAC is the stable match key. Bridge or
// Direct name the desired <source>; Model is used only when adding a new NIC.
type WantNIC struct {
	MAC    string
	Bridge string
	Direct string
	Model  string
}

// WantHostdev is a desired PCI passthrough device. Alias (the "ua-<device>-<member>"
// user alias) is the stable match key; Address is the host BDF ("0000:41:00.0")
// that becomes the <source> address. A matched hostdev keeps its guest <address>
// and <alias> — only the host BDF in <source> is re-resolved.
type WantHostdev struct {
	Alias   string
	Address string
}

// WantDevices is the desired device set the reconcile primitive realizes.
type WantDevices struct {
	Disks    []WantDisk
	NICs     []WantNIC
	Hostdevs []WantHostdev
}

// PatchInactiveDevices reconciles the disk/interface/hostdev set of a libvirt
// INACTIVE domain XML toward want, preserving guest-visible topology: matched
// devices keep their libvirt-assigned <address> and <alias> byte-for-byte (only
// their <source> — disk path / NIC bridge / hostdev host BDF — is rewritten),
// devices absent from want are removed, and new devices are appended WITHOUT an
// <address> so libvirt assigns a fresh slot. Controllers, serial, memballoon,
// TPM, and every element outside the three reconciled device kinds are left
// verbatim. This exists so a device-set change to a STOPPED VM doesn't reshuffle
// the PCI slots / aliases of untouched devices (which a full regenerate from the
// spec would, breaking Windows licensing / bootability).
//
// It operates by byte-span surgery on the serialized document rather than a
// whole-domain unmarshal/remarshal: a remarshal through typed structs would
// silently drop any element the structs don't model (disk <serial>, interface
// <driver>, <seclabel>, <metadata>, per-device <alias>/<address>, ...). Surgery
// touches only the three device kinds and preserves everything else exactly.
func PatchInactiveDevices(inactiveXML string, want WantDevices) (string, error) {
	elems, devicesCloseOff, err := scanDeviceElements(inactiveXML)
	if err != nil {
		return "", err
	}

	// Index desired sets by their stable keys.
	wantDisk := make(map[string]WantDisk, len(want.Disks))
	for _, d := range want.Disks {
		wantDisk[d.TargetDev] = d
	}
	wantNIC := make(map[string]WantNIC, len(want.NICs))
	for _, n := range want.NICs {
		wantNIC[normalizeMAC(n.MAC)] = n
	}
	wantHostdev := make(map[string]WantHostdev, len(want.Hostdevs))
	for _, h := range want.Hostdevs {
		if h.Alias == "" {
			continue
		}
		if _, dup := wantHostdev[h.Alias]; dup {
			return "", fmt.Errorf("%w: alias %q appears twice in the desired set", ErrDeviceCardinality, h.Alias)
		}
		wantHostdev[h.Alias] = h
	}

	// Count existing hostdevs per alias to detect an ambiguous mapping before
	// mutating anything.
	hostdevAliasCount := make(map[string]int)
	for _, e := range elems {
		if e.kind == "hostdev" {
			if a := e.key; a != "" {
				hostdevAliasCount[a]++
			}
		}
	}
	for alias := range wantHostdev {
		if hostdevAliasCount[alias] > 1 {
			return "", fmt.Errorf("%w: alias %q matches %d existing hostdevs", ErrDeviceCardinality, alias, hostdevAliasCount[alias])
		}
	}

	// Track which desired entries were matched to an existing element so the
	// remainder can be appended as new devices.
	seenDisk := make(map[string]bool)
	seenNIC := make(map[string]bool)
	seenHostdev := make(map[string]bool)

	var edits []spanEdit
	for _, e := range elems {
		switch e.kind {
		case "disk":
			d, ok := wantDisk[e.key]
			if !ok {
				edits = append(edits, deleteEdit(inactiveXML, e))
				continue
			}
			seenDisk[e.key] = true
			if patched := rewriteDiskSource(e.raw, d.Path); patched != e.raw {
				edits = append(edits, spanEdit{e.start, e.end, patched})
			}
		case "interface":
			n, ok := wantNIC[e.key]
			if !ok {
				edits = append(edits, deleteEdit(inactiveXML, e))
				continue
			}
			seenNIC[e.key] = true
			if patched := rewriteNICSource(e.raw, n); patched != e.raw {
				edits = append(edits, spanEdit{e.start, e.end, patched})
			}
		case "hostdev":
			h, ok := wantHostdev[e.key]
			if !ok {
				edits = append(edits, deleteEdit(inactiveXML, e))
				continue
			}
			seenHostdev[e.key] = true
			if patched := rewriteHostdevSource(e.raw, h.Address); patched != e.raw {
				edits = append(edits, spanEdit{e.start, e.end, patched})
			}
		}
	}

	// Assemble fragments for the desired devices with no existing match. These
	// are emitted WITHOUT an <address> so libvirt assigns a fresh guest slot.
	closeIndent, childIndent := devicesIndent(inactiveXML, devicesCloseOff)
	var additions strings.Builder
	appendFrag := func(frag string, err error) error {
		if err != nil {
			return err
		}
		additions.WriteString("\n")
		additions.WriteString(frag)
		return nil
	}
	for _, d := range want.Disks {
		if seenDisk[d.TargetDev] {
			continue
		}
		if err := appendFrag(marshalNewDisk(childIndent, d)); err != nil {
			return "", err
		}
	}
	for _, n := range want.NICs {
		if seenNIC[normalizeMAC(n.MAC)] {
			continue
		}
		if err := appendFrag(marshalNewNIC(childIndent, n)); err != nil {
			return "", err
		}
	}
	for _, h := range want.Hostdevs {
		if h.Alias == "" || seenHostdev[h.Alias] {
			continue
		}
		if err := appendFrag(marshalNewHostdev(childIndent, h)); err != nil {
			return "", err
		}
	}

	if additions.Len() > 0 {
		if devicesCloseOff < 0 {
			return "", errors.New("libvirt: cannot add devices — no <devices> element in inactive XML")
		}
		insertOff := insertBeforeClose(inactiveXML, devicesCloseOff, closeIndent)
		edits = append(edits, spanEdit{insertOff, insertOff, additions.String()})
	}

	return applyEdits(inactiveXML, edits)
}

// deviceElement is a top-level <disk>/<interface>/<hostdev> child of <devices>,
// with its stable match key and exact byte span in the source document.
type deviceElement struct {
	kind  string // "disk" | "interface" | "hostdev"
	key   string // target dev | MAC | alias name
	start int
	end   int
	raw   string
}

// qname is a namespace-aware element name tracked on the ancestor stack. Space
// is the resolved XML namespace URI (or the literal prefix for an undeclared
// prefix), and "" for the default/no-namespace libvirt elements.
type qname struct {
	local string
	space string
}

// scanDeviceElements tokenizes the domain XML and returns the disk/interface/
// hostdev elements that are direct children of the real <devices> container, in
// document order, plus the byte offset of the "<" in "</devices>" (-1 if absent).
//
// Device detection is PATH-ANCHORED and NAMESPACE-AWARE: a candidate counts as a
// reconciled device ONLY when its enclosing <devices> is a direct child of the
// root <domain> (the ancestor stack is exactly ["domain","devices"]) AND both
// those ancestors and the candidate itself are in the default (no-namespace)
// libvirt namespace. This is load-bearing: without it, a <devices><disk>…</disk>
// subtree — or a namespaced <lv:devices><lv:disk/></lv:devices> — nested inside
// <metadata> would be scanned as a real device and deleted, violating the
// "<metadata> (and all unmodeled elements) survive verbatim" guarantee.
func scanDeviceElements(doc string) ([]deviceElement, int, error) {
	dec := xml.NewDecoder(strings.NewReader(doc))
	var stack []qname
	var elems []deviceElement
	devicesCloseOff := -1

	// atDevicesPath reports whether the current ancestor stack is exactly
	// domain > devices, both in the default (no-namespace) libvirt namespace.
	atDevicesPath := func() bool {
		return len(stack) == 2 &&
			stack[0].local == "domain" && stack[0].space == "" &&
			stack[1].local == "devices" && stack[1].space == ""
	}

	for {
		startOff := int(dec.InputOffset())
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, fmt.Errorf("PatchInactiveDevices: parse inactive XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			if atDevicesPath() && t.Name.Space == "" &&
				(name == "disk" || name == "interface" || name == "hostdev") {
				// startOff sits at (or just before) the "<"; skip any leading
				// whitespace the decoder reported as separate CharData.
				lt := skipWSForward(doc, startOff)
				if err := dec.Skip(); err != nil {
					return nil, 0, fmt.Errorf("PatchInactiveDevices: parse inactive XML: %w", err)
				}
				endOff := int(dec.InputOffset())
				raw := doc[lt:endOff]
				elems = append(elems, deviceElement{
					kind:  name,
					key:   deviceKey(name, raw),
					start: lt,
					end:   endOff,
					raw:   raw,
				})
				// Fully consumed by Skip — do not push onto the stack.
				continue
			}
			stack = append(stack, qname{local: name, space: t.Name.Space})
		case xml.EndElement:
			// Record the close offset of the real domain>devices only — never a
			// <devices> nested inside <metadata> or a foreign-namespace one.
			if t.Name.Local == "devices" && t.Name.Space == "" && atDevicesPath() {
				devicesCloseOff = skipWSForward(doc, startOff)
			}
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	return elems, devicesCloseOff, nil
}

var (
	reDiskTargetDev = regexp.MustCompile(`<target\b[^>]*\bdev=(['"])([^'"]*)['"]`)
	reIfaceMAC      = regexp.MustCompile(`<mac\b[^>]*\baddress=(['"])([^'"]*)['"]`)
	reHostdevAlias  = regexp.MustCompile(`<alias\b[^>]*\bname=(['"])([^'"]*)['"]`)
)

// deviceKey extracts the stable match key from a device element's raw XML.
//
// Key/source extraction here (and in rewriteDiskSource et al.) is comment-blind:
// a key-like fragment inside an XML comment (e.g. <!-- dev='x' -->) would drive
// matching. This is a deliberate non-issue — libvirt's serializer never emits
// comments inside device elements — so device raw XML is assumed comment-free
// rather than paying for a full comment-stripping pass.
func deviceKey(kind, raw string) string {
	switch kind {
	case "disk":
		if m := reDiskTargetDev.FindStringSubmatch(raw); m != nil {
			return m[2]
		}
	case "interface":
		if m := reIfaceMAC.FindStringSubmatch(raw); m != nil {
			return normalizeMAC(m[2])
		}
	case "hostdev":
		if m := reHostdevAlias.FindStringSubmatch(raw); m != nil {
			return m[2]
		}
	}
	return ""
}

func normalizeMAC(mac string) string { return strings.ToLower(strings.TrimSpace(mac)) }

// ── source rewriting (matched devices: touch only <source>) ──

var reDiskSourceFile = regexp.MustCompile(`(<source\b[^>]*\bfile=)(['"])[^'"]*(['"])`)

// rewriteDiskSource replaces the disk's <source file='...'> value with newPath,
// leaving target/driver/<address>/<alias> untouched. A disk with no file-backed
// source (e.g. a block <source dev=...>) is left unchanged.
func rewriteDiskSource(raw, newPath string) string {
	if newPath == "" {
		return raw
	}
	return reDiskSourceFile.ReplaceAllStringFunc(raw, func(m string) string {
		s := reDiskSourceFile.FindStringSubmatch(m)
		return s[1] + s[2] + newPath + s[3]
	})
}

var reIfaceSourceElem = regexp.MustCompile(`<source\b[^>]*?/?>`)

// rewriteNICSource updates the interface's <source> bridge/dev to match want,
// only when the corresponding attribute already exists (it does not flip the
// interface type). MAC/model/<address>/<alias>/<target> are left untouched.
func rewriteNICSource(raw string, n WantNIC) string {
	return reIfaceSourceElem.ReplaceAllStringFunc(raw, func(src string) string {
		if n.Bridge != "" {
			src = replaceAttrIfPresent(src, "bridge", n.Bridge)
		}
		if n.Direct != "" {
			src = replaceAttrIfPresent(src, "dev", n.Direct)
		}
		return src
	})
}

var reHostdevSourceBlock = regexp.MustCompile(`(?s)<source\b[^>]*>.*?</source>`)

// rewriteHostdevSource re-resolves the host BDF inside <source><address .../>,
// leaving the guest <address> (a sibling of <source>) and the <alias> intact.
// This is the topology-preserving re-resolve: the passthrough device can move to
// a different host PCI address without changing the guest-visible slot.
func rewriteHostdevSource(raw, bdf string) string {
	if bdf == "" {
		return raw
	}
	p := ParsePCIAddress(bdf)
	return reHostdevSourceBlock.ReplaceAllStringFunc(raw, func(src string) string {
		src = replaceAttrIfPresent(src, "domain", p.Domain)
		src = replaceAttrIfPresent(src, "bus", p.Bus)
		src = replaceAttrIfPresent(src, "slot", p.Slot)
		src = replaceAttrIfPresent(src, "function", p.Function)
		return src
	})
}

// replaceAttrIfPresent rewrites attr="val" (either quote style) everywhere it
// appears in s, preserving the original quoting; s is returned unchanged if the
// attribute is absent.
func replaceAttrIfPresent(s, attr, val string) string {
	re := attrRegex(attr)
	return re.ReplaceAllStringFunc(s, func(m string) string {
		sub := re.FindStringSubmatch(m)
		return sub[1] + sub[2] + val + sub[3]
	})
}

var attrRegexCache = map[string]*regexp.Regexp{}

func attrRegex(attr string) *regexp.Regexp {
	if re, ok := attrRegexCache[attr]; ok {
		return re
	}
	re := regexp.MustCompile(`(\b` + regexp.QuoteMeta(attr) + `=)(['"])[^'"]*(['"])`)
	attrRegexCache[attr] = re
	return re
}

// ── new-device fragment generation (added devices carry NO <address>) ──

func marshalNewDisk(childIndent string, d WantDisk) (string, error) {
	disk := diskDevice{
		Type:   "file",
		Device: "disk",
		Driver: diskDriver{Name: "qemu", Type: "qcow2", Cache: d.Cache},
		Source: diskSource{File: d.Path},
		Target: diskTarget{Dev: d.TargetDev, Bus: d.Bus},
	}
	return marshalFragment(childIndent, disk)
}

func marshalNewNIC(childIndent string, n WantNIC) (string, error) {
	model := n.Model
	if model == "" {
		model = "virtio"
	}
	var iface interfaceDevice
	if n.Direct != "" {
		iface = interfaceDevice{
			Type:   "direct",
			MAC:    ifaceMAC{Address: n.MAC},
			Source: ifaceSource{Dev: n.Direct, Mode: "bridge"},
			Model:  ifaceModel{Type: model},
		}
	} else {
		iface = interfaceDevice{
			Type:   "bridge",
			MAC:    ifaceMAC{Address: n.MAC},
			Source: ifaceSource{Bridge: n.Bridge},
			Model:  ifaceModel{Type: model},
		}
	}
	return marshalFragment(childIndent, iface)
}

func marshalNewHostdev(childIndent string, h WantHostdev) (string, error) {
	p := ParsePCIAddress(h.Address)
	hd := hostdevDevice{
		Mode:    "subsystem",
		Type:    "pci",
		Managed: "yes",
		Source: hostdevSource{
			Address: hostdevAddress{Domain: p.Domain, Bus: p.Bus, Slot: p.Slot, Function: p.Function},
		},
	}
	if h.Alias != "" {
		hd.Alias = &hostdevAlias{Name: h.Alias}
	}
	return marshalFragment(childIndent, hd)
}

// marshalFragment renders a device struct indented as a child of <devices>. The
// first line carries childIndent; callers prepend the leading newline.
func marshalFragment(childIndent string, v any) (string, error) {
	b, err := xml.MarshalIndent(v, childIndent, "  ")
	if err != nil {
		return "", fmt.Errorf("PatchInactiveDevices: marshal new device: %w", err)
	}
	return string(b), nil
}

// ── byte-span editing ──

type spanEdit struct {
	start int
	end   int
	repl  string
}

// deleteEdit removes an element, consuming the indentation and single newline
// that precede it so no blank line is left behind.
func deleteEdit(doc string, e deviceElement) spanEdit {
	start := e.start
	for start > 0 && (doc[start-1] == ' ' || doc[start-1] == '\t') {
		start--
	}
	if start > 0 && doc[start-1] == '\n' {
		start--
		if start > 0 && doc[start-1] == '\r' {
			start--
		}
	}
	return spanEdit{start, e.end, ""}
}

// devicesIndent returns the indentation of </devices> and the derived child
// indentation for inserted device fragments.
func devicesIndent(doc string, devicesCloseOff int) (closeIndent, childIndent string) {
	if devicesCloseOff < 0 {
		return "", "  "
	}
	i := devicesCloseOff
	for i > 0 && (doc[i-1] == ' ' || doc[i-1] == '\t') {
		i--
	}
	closeIndent = doc[i:devicesCloseOff]
	return closeIndent, closeIndent + "  "
}

// insertBeforeClose returns the offset at which new device fragments should be
// spliced: just after the last existing child, before the newline that indents
// </devices>.
func insertBeforeClose(doc string, devicesCloseOff int, closeIndent string) int {
	i := devicesCloseOff - len(closeIndent)
	if i > 0 && doc[i-1] == '\n' {
		i--
		if i > 0 && doc[i-1] == '\r' {
			i--
		}
	}
	if i < 0 {
		i = devicesCloseOff
	}
	return i
}

// applyEdits applies non-overlapping span replacements left to right.
func applyEdits(doc string, edits []spanEdit) (string, error) {
	sort.SliceStable(edits, func(i, j int) bool {
		if edits[i].start != edits[j].start {
			return edits[i].start < edits[j].start
		}
		return edits[i].end < edits[j].end
	})
	var b strings.Builder
	cursor := 0
	for _, e := range edits {
		if e.start < cursor {
			return "", fmt.Errorf("PatchInactiveDevices: overlapping edits (start %d < cursor %d)", e.start, cursor)
		}
		b.WriteString(doc[cursor:e.start])
		b.WriteString(e.repl)
		cursor = e.end
	}
	b.WriteString(doc[cursor:])
	return b.String(), nil
}

// skipWSForward advances i over any leading whitespace so it lands on the "<" of
// the next tag (the decoder may report inter-element whitespace as its own token,
// leaving InputOffset a few bytes ahead of the tag).
func skipWSForward(doc string, i int) int {
	for i < len(doc) && (doc[i] == ' ' || doc[i] == '\t' || doc[i] == '\n' || doc[i] == '\r') {
		i++
	}
	return i
}
