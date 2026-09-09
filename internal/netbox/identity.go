package netbox

import "strings"

// IdentityField is the NetBox custom field carrying litevirt's identity. It is
// a STRUCTURED field, not a prose description, because the orphan sweeper must
// be able to reclaim an object with no surviving local row.
const IdentityField = "litevirt_identity"

// Identity builds the incarnation-unique identity for one NIC.
//
// All three components are load-bearing:
//   - clusterFingerprint distinguishes two litevirt clusters sharing one NetBox.
//   - vmUUID is minted fresh per VM, so a REUSED name cannot adopt a previous
//     incarnation's object.
//   - mac distinguishes NICs within one VM.
func Identity(clusterFingerprint, vmUUID, mac string) string {
	return strings.Join([]string{"lv", clusterFingerprint, vmUUID, mac}, ":")
}

// IdentityVMUUID is the incarnation uuid inside an identity, or "" when the
// string is not one this cluster's own builder produced.
//
// ONE SPELLING, exported, because the mirror's withholding gate has to ask about
// the INCARNATION an action targets and the only thing the action carries is the
// identity. A caller splitting the string by hand would be a second parser to
// drift from Identity's own layout — and the direction it would drift in is a
// gate reading the wrong field and proving nothing.
//
// SplitN with a limit of four, not Split: a MAC contains colons and is the last
// component, so an unbounded split would shred it and shift nothing about the
// uuid — but a limit is what makes that a property of the code rather than of
// the field order. The uuid itself never contains a colon.
func IdentityVMUUID(identity string) string {
	parts := strings.SplitN(identity, ":", 4)
	if len(parts) < 4 || parts[0] != "lv" {
		return ""
	}
	return parts[2]
}
