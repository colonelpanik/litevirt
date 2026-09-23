package libvirt

import (
	"encoding/xml"
	"fmt"
	"strings"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// CPUCompare is the verdict of comparing a guest CPU requirement against a
// host. It mirrors virConnectCompareCPU, minus the error code (returned as a
// Go error instead).
type CPUCompare int

const (
	// CPUCompareIncompatible: the host cannot run a guest needing this CPU.
	CPUCompareIncompatible CPUCompare = 0
	// CPUCompareIdentical: the host CPU matches the requirement exactly.
	CPUCompareIdentical CPUCompare = 1
	// CPUCompareSuperset: the host is richer than required — the guest runs.
	CPUCompareSuperset CPUCompare = 2
)

func (c CPUCompare) String() string {
	switch c {
	case CPUCompareIncompatible:
		return "incompatible"
	case CPUCompareIdentical:
		return "identical"
	case CPUCompareSuperset:
		return "superset"
	default:
		return fmt.Sprintf("unknown(%d)", int(c))
	}
}

// Runnable reports whether a guest requiring the compared CPU can run here.
func (c CPUCompare) Runnable() bool {
	return c == CPUCompareIdentical || c == CPUCompareSuperset
}

// CompareCPU asks the LOCAL hypervisor whether it can satisfy the guest CPU
// described by cpuXML (a standalone <cpu>…</cpu> element). This is the
// destination side of a migration CPU preflight.
func (c *Client) CompareCPU(cpuXML string) (CPUCompare, error) {
	if strings.TrimSpace(cpuXML) == "" {
		return CPUCompareIncompatible, fmt.Errorf("compare cpu: empty cpu xml")
	}
	res, err := c.virt.ConnectCompareCPU(cpuXML, 0)
	if err != nil {
		return CPUCompareIncompatible, fmt.Errorf("compare cpu: %w", err)
	}
	if golibvirt.CPUCompareResult(res) == golibvirt.CPUCompareError {
		return CPUCompareIncompatible, fmt.Errorf("compare cpu: hypervisor returned an error result")
	}
	return CPUCompare(res), nil
}

// HostCPUXML returns this host's own CPU as a comparable <cpu> element, read
// from the hypervisor capabilities. It is what a host-passthrough guest
// effectively requires, so it is the requirement a migration of such a guest
// must compare against the destination.
func (c *Client) HostCPUXML() (string, error) {
	caps, err := c.virt.ConnectGetCapabilities()
	if err != nil {
		return "", fmt.Errorf("host capabilities: %w", err)
	}
	cpu, err := hostCPUFromCapabilities(caps)
	if err != nil {
		return "", err
	}
	return cpu, nil
}

// extractRootChild returns the named element VERBATIM when it appears as a
// DIRECT child of doc's root element, plus whether it was found.
//
// The depth scoping is the point: a plain document-wide search for "cpu" in a
// domain XML could match something nested under <metadata> or a future schema
// addition, and patching the wrong element would rewrite the guest's CPU from a
// node that has nothing to do with it.
func extractRootChild(doc, name string) (string, bool) {
	dec := xml.NewDecoder(strings.NewReader(doc))
	var startOff int64
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		switch se := tok.(type) {
		case xml.StartElement:
			depth++
			if depth == 2 && se.Name.Local == name {
				if serr := dec.Skip(); serr != nil {
					return "", false
				}
				return strings.TrimSpace(doc[startOff:dec.InputOffset()]), true
			}
			if depth >= 2 {
				// Not the element we want: skip its whole subtree so nothing
				// inside it can be mistaken for a root child.
				if serr := dec.Skip(); serr != nil {
					return "", false
				}
				depth--
			}
		case xml.EndElement:
			depth--
		}
		startOff = dec.InputOffset()
	}
}

// extractElement returns the named element from doc VERBATIM — attributes,
// children and all — plus whether it was found.
//
// Verbatim matters: virConnectCompareCPU parses a <cpu> element in one of two
// native forms, the host form from capabilities (which carries <arch> and no
// mode/match) or the guest form from a domain (which carries mode/match and no
// <arch>). Rebuilding the element by hand produces a hybrid that is neither, so
// the bytes are passed through untouched.
//
// Byte offsets are exact because the decoder accounts for every byte: the
// offset after the previous token is the offset at which this token begins.
func extractElement(doc, name string) (string, bool) {
	dec := xml.NewDecoder(strings.NewReader(doc))
	var startOff int64
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		if se, ok := tok.(xml.StartElement); ok && se.Name.Local == name {
			if err := dec.Skip(); err != nil {
				return "", false
			}
			return strings.TrimSpace(doc[startOff:dec.InputOffset()]), true
		}
		startOff = dec.InputOffset()
	}
}

// hostCPUFromCapabilities lifts <capabilities><host><cpu> out verbatim, as the
// host-form <cpu> element virConnectCompareCPU expects. This is the same
// description `virsh cpu-compare` is fed to answer "can this host run a guest
// that was running on that one".
func hostCPUFromCapabilities(caps string) (string, error) {
	// Scope to <host> first: <guest> blocks further down also contain CPU
	// material, and the host's own CPU is the one a passthrough guest requires.
	host, ok := extractElement(caps, "host")
	if !ok {
		return "", fmt.Errorf("host capabilities carry no <host> element")
	}
	cpu, ok := extractElement(host, "cpu")
	if !ok {
		return "", fmt.Errorf("host capabilities carry no <host><cpu> element")
	}
	return cpu, nil
}

// DomainCPURequirement extracts, from a domain XML, the guest CPU requirement
// to compare against a migration destination — and reports whether one could be
// derived at all.
//
// For a RUNNING domain libvirt has already expanded mode='host-model' into a
// concrete model plus feature list in the live XML, so the live element IS the
// exact requirement and is returned verbatim. A domain with no <cpu> element
// (the qemu64 case) or an unexpanded mode='host-passthrough' yields ok=false:
// neither names a model, so neither is a comparable requirement, and the caller
// resolves passthrough via the source's HostCPUXML instead.
func DomainCPURequirement(domainXML string) (cpuXML string, ok bool) {
	cpu, found := extractElement(domainXML, "cpu")
	if !found {
		return "", false
	}
	var probe struct {
		Model string `xml:"model"`
	}
	if err := xml.Unmarshal([]byte(cpu), &probe); err != nil {
		return "", false
	}
	if strings.TrimSpace(probe.Model) == "" {
		return "", false
	}
	return cpu, true
}

// DomainCPUMode returns the mode attribute of a domain XML's <cpu> element
// ("" when it has none).
func DomainCPUMode(domainXML string) string {
	cpu, ok := extractElement(domainXML, "cpu")
	if !ok {
		return ""
	}
	var probe struct {
		Mode string `xml:"mode,attr"`
	}
	if err := xml.Unmarshal([]byte(cpu), &probe); err != nil {
		return ""
	}
	return probe.Mode
}
