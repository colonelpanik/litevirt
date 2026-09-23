package libvirt

import (
	"encoding/xml"
	"fmt"
	"regexp"
	"strings"
)

// These operate on libvirt's OWN serialized (inactive) domain XML — single-quoted
// attributes, compact element bodies — not on GenerateDomainXML's output. They
// target only the top-level <vcpu>/<memory>/<currentMemory> elements: `\b` after
// the tag name and a required numeric body avoid matching <vcpus>, <vcpupin>, or
// nested memory-tuning nodes.
var (
	reVCPUBody          = regexp.MustCompile(`(<vcpu\b[^>]*>)\d+(</vcpu>)`)
	reMemoryBody        = regexp.MustCompile(`(<memory\b[^>]*>)\d+(</memory>)`)
	reMemoryElement     = regexp.MustCompile(`(<memory\b[^>]*>\d+</memory>)`)
	reCurrentMemoryBody = regexp.MustCompile(`(<currentMemory\b[^>]*>)\d+(</currentMemory>)`)
	reCurrentMemoryElem = regexp.MustCompile(`[ \t]*<currentMemory\b[^>]*>\d+</currentMemory>\n?`)
	// reVCPUClose locates the insertion point for a <cpu> element the inactive
	// XML does not have yet (see PatchInactiveCPUMode).
	reVCPUClose = regexp.MustCompile(`</vcpu>`)
)

// PatchInactiveResources returns domainXML with ONLY its <vcpu>, <memory>, and
// <currentMemory> values updated to reflect cpu/memMiB/maxMemMiB; every other node
// is preserved verbatim. It patches libvirt's serialized INACTIVE domain XML so a
// CPU/memory-only redefine of a STOPPED VM keeps libvirt-assigned details (PCI slot
// addresses, controller models, disk ordering) that a full regeneration from the
// spec would reshuffle — the invariant is semantic equality OUTSIDE the targeted
// nodes, not byte-identity of the whole document.
//
// <memory> is set to the ceiling max(memMiB, maxMemMiB) in KiB. <currentMemory> is
// set to memMiB in KiB when a ceiling is present (created right after <memory> if
// absent), and removed when there is no ceiling (maxMemMiB <= memMiB).
func PatchInactiveResources(domainXML string, cpu, memMiB, maxMemMiB int) (string, error) {
	if cpu <= 0 || memMiB <= 0 {
		return "", fmt.Errorf("PatchInactiveResources: cpu (%d) and memMiB (%d) must be positive", cpu, memMiB)
	}
	ceilingMiB := memMiB
	if maxMemMiB > ceilingMiB {
		ceilingMiB = maxMemMiB
	}

	if !reVCPUBody.MatchString(domainXML) {
		return "", fmt.Errorf("PatchInactiveResources: no <vcpu> element found")
	}
	out := reVCPUBody.ReplaceAllString(domainXML, fmt.Sprintf("${1}%d${2}", cpu))

	if !reMemoryBody.MatchString(out) {
		return "", fmt.Errorf("PatchInactiveResources: no <memory> element found")
	}
	out = reMemoryBody.ReplaceAllString(out, fmt.Sprintf("${1}%d${2}", ceilingMiB*1024))

	if ceilingMiB > memMiB {
		// Balloon ceiling set: <currentMemory> is the boot allocation.
		if reCurrentMemoryBody.MatchString(out) {
			out = reCurrentMemoryBody.ReplaceAllString(out, fmt.Sprintf("${1}%d${2}", memMiB*1024))
		} else {
			// Insert immediately after </memory> (libvirt's canonical ordering).
			out = reMemoryElement.ReplaceAllString(out,
				fmt.Sprintf("${1}\n  <currentMemory unit='KiB'>%d</currentMemory>", memMiB*1024))
		}
	} else {
		// No ballooning: drop any stale <currentMemory> so <memory> is authoritative.
		out = reCurrentMemoryElem.ReplaceAllString(out, "")
	}
	return out, nil
}

// PatchInactiveCPUMode returns domainXML with its top-level <cpu> element set to
// mode/model, every other node preserved verbatim.
//
// It exists so retrofitting a CPU mode onto an EXISTING VM is an in-place edit
// of libvirt's own serialized XML rather than a regeneration from the spec. That
// matters because GenerateDomainXML emits no guest-side PCI addresses, so a
// regeneration hands libvirt a device list with no addressing and lets it
// re-derive every slot. With an unchanged device set it usually lands the same
// layout, but "usually" is not a property a Windows guest keying its licensing
// off stable hardware addresses can rely on. Patching keeps the addresses that
// are already there.
//
// An EMPTY mode is a deliberate no-op, not a removal: "" means the caller is
// changing something else (cpu count, memory) on a VM that never named a CPU
// mode. Inserting or deleting a <cpu> element there would change the guest's CPU
// as a side effect of an unrelated edit, which is precisely the surprise this
// whole path exists to avoid.
//
// Returns an error rather than guessing when the element is absent and there is
// no safe place to put it; the caller falls back to full regeneration.
func PatchInactiveCPUMode(domainXML, mode, model string) (string, error) {
	if err := ValidateCPUMode(mode, model); err != nil {
		return "", fmt.Errorf("PatchInactiveCPUMode: %w", err)
	}
	if mode == "" {
		return domainXML, nil
	}

	replacement, err := renderCPUElement(mode, model)
	if err != nil {
		return "", err
	}

	// Replace an existing top-level <cpu>, matched by exact bytes so nothing else
	// in the document can be touched.
	if existing, ok := extractRootChild(domainXML, "cpu"); ok {
		return strings.Replace(domainXML, existing, replacement, 1), nil
	}

	// Absent: insert after </vcpu>, which PatchInactiveResources has already
	// required to exist. libvirt looks top-level children up by name rather than
	// reading them in order, and re-canonicalizes on dump, so the position only
	// has to be inside <domain> — this one also matches where GenerateDomainXML
	// puts it, keeping patched and generated XML consistent.
	if loc := reVCPUClose.FindStringIndex(domainXML); loc != nil {
		return domainXML[:loc[1]] + "\n  " + replacement + domainXML[loc[1]:], nil
	}
	return "", fmt.Errorf("PatchInactiveCPUMode: no <cpu> element to replace and no </vcpu> to insert after")
}

// renderCPUElement serializes the <cpu> element for a validated mode/model pair,
// using encoding/xml so a model name can never break out of the document.
func renderCPUElement(mode, model string) (string, error) {
	cd := &cpuDef{Mode: mode}
	if mode == CPUModeCustom {
		cd.Match = "exact"
		cd.Model = &cpuModel{Fallback: "allow", Name: model}
	}
	out, err := xml.Marshal(cd)
	if err != nil {
		return "", fmt.Errorf("PatchInactiveCPUMode: render cpu element: %w", err)
	}
	return string(out), nil
}
