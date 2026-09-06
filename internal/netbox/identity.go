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
