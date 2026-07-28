package libvirt

import (
	"fmt"
	"regexp"
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
