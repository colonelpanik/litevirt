package hostnet

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// SelfCutoffRisk decides whether a plan could disconnect this node from its
// cluster. clusterIface is the interface currently carrying advertiseIP (the
// daemon resolves it from live state at apply time); either may be empty when
// undetectable, in which case only the address-rehoming check can fire.
//
// It reports the FIRST risk found, as a reason a refusal can print verbatim.
// The rules, from the design's safety invariant ("no mutation may touch the
// interface carrying the cluster LAN unless explicitly forced"):
//
//  1. an intent row NAMED after the cluster interface reconfigures the carrier;
//  2. an intent that ENSLAVES the carrier into a bond or bridge re-homes its
//     address as a side effect (the kernel strips addresses from enslaved
//     ports) — this is the classic "made my uplink a bridge port and vanished";
//  3. an intent on any OTHER interface that claims the advertise address
//     creates a duplicate/moved cluster identity.
//
// A VLAN whose link is the carrier is deliberately NOT a risk: adding a tagged
// subinterface leaves the underlying address in place.
func SelfCutoffRisk(plan []corrosion.HostNetworkRecord, clusterIface, advertiseIP string) (string, bool) {
	for _, r := range plan {
		if clusterIface != "" && r.Name == clusterIface {
			return fmt.Sprintf("intent %q reconfigures the interface carrying the cluster LAN (%s, %s)",
				r.Name, clusterIface, advertiseIP), true
		}
		if clusterIface != "" {
			for _, m := range r.Members {
				if m == clusterIface {
					return fmt.Sprintf("intent %q enslaves the cluster-LAN interface %s as a %s member — "+
						"enslaving strips its address (%s) and disconnects this node",
						r.Name, clusterIface, r.Kind, advertiseIP), true
				}
			}
		}
		if advertiseIP != "" && r.Name != clusterIface && addressingClaims(r.Addressing, advertiseIP) {
			return fmt.Sprintf("intent %q claims the advertise address %s away from %s",
				r.Name, advertiseIP, clusterIface), true
		}
	}
	return "", false
}

// addressingClaims reports whether an addressing blob assigns exactly ip
// (compared as parsed IPs, so ::ffff:-mapped and zero-padded spellings match).
func addressingClaims(addressing, ip string) bool {
	if addressing == "" {
		return false
	}
	want := net.ParseIP(ip)
	if want == nil {
		return false
	}
	var a corrosion.HostNetworkAddressing
	if json.Unmarshal([]byte(addressing), &a) != nil {
		return false
	}
	for _, cidr := range a.Addresses {
		host := cidr
		if i := strings.IndexByte(cidr, '/'); i >= 0 {
			host = cidr[:i]
		}
		if got := net.ParseIP(host); got != nil && got.Equal(want) {
			return true
		}
	}
	return false
}

// ForeignConflicts reports plan interfaces that are already defined by a
// netplan file litevirt does not own. foreign maps path → file content for
// every /etc/netplan/*.y(a)ml EXCEPT ManagedFile (the caller globs; this stays
// pure). litevirt never edits an operator's file, so a conflict is a refusal
// naming the file — the operator decides which side owns the interface.
//
// Parsing is strict YAML: a file that fails to parse is reported as a conflict
// for EVERY planned interface, because "we could not prove the interface is
// free" must fail closed, same as every other guard in this tree.
func ForeignConflicts(plan []corrosion.HostNetworkRecord, foreign map[string]string) map[string]string {
	conflicts := map[string]string{}
	names := make([]string, 0, len(plan))
	for _, r := range plan {
		names = append(names, r.Name)
	}
	paths := make([]string, 0, len(foreign))
	for p := range foreign {
		paths = append(paths, p)
	}
	sort.Strings(paths) // deterministic attribution when several files define one name
	for _, path := range paths {
		if filepath.Clean(path) == ManagedFile {
			continue // defensive: the caller should already have excluded it
		}
		defined, err := netplanInterfaceNames(foreign[path])
		for _, n := range names {
			if _, taken := conflicts[n]; taken {
				continue
			}
			if err != nil {
				conflicts[n] = fmt.Sprintf("%s (unparseable: %v)", path, err)
				continue
			}
			if defined[n] {
				conflicts[n] = path
			}
		}
	}
	return conflicts
}

// netplanInterfaceNames extracts every interface name a netplan document
// defines, across all section types (ethernets, bonds, bridges, vlans, and
// anything else keyed the same way — wifis, tunnels — since a definition there
// conflicts just the same).
//
// BOTH the stanza key and any `set-name` value count: netplan lets a stanza be
// keyed by an arbitrary id with match+set-name choosing the real device
// (`clusternet: {match: …, set-name: net1}` — exactly how the lab's cluster
// NIC is defined, which is how this gap was found: a plan for net1 slipped
// past the key-only check and produced two definitions racing on one device).
func netplanInterfaceNames(content string) (map[string]bool, error) {
	var doc struct {
		Network map[string]yaml.Node `yaml:"network"`
	}
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for section, node := range doc.Network {
		if section == "version" || section == "renderer" || node.Kind != yaml.MappingNode {
			continue
		}
		// A mapping node's content alternates key, value.
		for i := 0; i+1 < len(node.Content); i += 2 {
			k, v := node.Content[i], node.Content[i+1]
			if k != nil && k.Value != "" {
				names[k.Value] = true
			}
			if v == nil || v.Kind != yaml.MappingNode {
				continue
			}
			for j := 0; j+1 < len(v.Content); j += 2 {
				if v.Content[j] != nil && v.Content[j].Value == "set-name" &&
					v.Content[j+1] != nil && v.Content[j+1].Value != "" {
					names[v.Content[j+1].Value] = true
				}
			}
		}
	}
	return names, nil
}
