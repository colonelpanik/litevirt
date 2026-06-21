package libvirtfake

import "strings"

// domainNameFromXML extracts <name>foo</name> from a libvirt domain
// XML blob. The full Go xml decoder is overkill — the produced XML
// from internal/libvirt/xmlgen always puts <name> near the top.
//
// Returns "" if not found; the caller treats that as a malformed
// XML.
func domainNameFromXML(xml string) string {
	const (
		open  = "<name>"
		close = "</name>"
	)
	i := strings.Index(xml, open)
	if i < 0 {
		return ""
	}
	j := strings.Index(xml[i+len(open):], close)
	if j < 0 {
		return ""
	}
	return xml[i+len(open) : i+len(open)+j]
}
