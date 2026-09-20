// Package hostnet renders and guards declarative host network intent
// (host_networks rows) as the single litevirt-owned netplan file. The apply
// protocol around it (journal, netplan try, snapshot/confirm) lives with the
// daemon; everything in this package is pure — inputs in, YAML/decisions out —
// so the safety-critical pieces are directly testable.
package hostnet

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// ManagedFile is the one netplan file litevirt owns. It never edits or deletes
// any other file — see ForeignConflicts.
const ManagedFile = "/etc/netplan/90-litevirt.yaml"

// header marks the rendered file as machine-owned. Kept stable: the foreign-
// conflict detector uses it to recognize litevirt's own file.
const header = "# Managed by litevirt (lv host network) — DO NOT EDIT.\n# Rendered from replicated host_networks intent; manual edits are overwritten.\n"

// Render produces the full desired netplan file for one host's live intent
// rows. Deterministic: same rows (any order) → byte-identical output, so the
// apply protocol's "empty diff = no-op" check and the golden tests are stable.
// An empty intent set renders an empty network stanza — applying it removes
// every litevirt-managed interface, which is the deliberate meaning of
// deleting every row.
func Render(recs []corrosion.HostNetworkRecord) (string, error) {
	byKind := map[string][]corrosion.HostNetworkRecord{}
	for _, r := range recs {
		switch r.Kind {
		case "ethernet", "bond", "bridge", "vlan":
		default:
			// Refuse rather than skip: a silently dropped intent would render a
			// file that REMOVES the interface while the row claims it exists.
			return "", fmt.Errorf("unknown host network kind %q for %q", r.Kind, r.Name)
		}
		byKind[r.Kind] = append(byKind[r.Kind], r)
	}
	var b strings.Builder
	b.WriteString(header)
	b.WriteString("network:\n  version: 2\n")
	for _, section := range []struct{ kind, stanza string }{
		// netplan section order fixed for determinism; ethernets first because
		// members must exist before the bond/bridge that enslaves them.
		{"ethernet", "ethernets"},
		{"bond", "bonds"},
		{"bridge", "bridges"},
		{"vlan", "vlans"},
	} {
		rs := byKind[section.kind]
		if len(rs) == 0 {
			continue
		}
		sort.Slice(rs, func(i, j int) bool { return rs[i].Name < rs[j].Name })
		fmt.Fprintf(&b, "  %s:\n", section.stanza)
		for _, r := range rs {
			if err := renderInterface(&b, r); err != nil {
				return "", err
			}
		}
	}
	return b.String(), nil
}

func renderInterface(b *strings.Builder, r corrosion.HostNetworkRecord) error {
	if err := validName(r.Name); err != nil {
		return err
	}
	fmt.Fprintf(b, "    %s:\n", r.Name)
	switch r.Kind {
	case "bond":
		if len(r.Members) == 0 {
			return fmt.Errorf("bond %q has no member interfaces", r.Name)
		}
		if err := renderMembers(b, r.Members); err != nil {
			return err
		}
		mode := r.BondMode
		if mode == "" {
			mode = "active-backup" // the safe default: works with any switch
		}
		if err := validEnum("bond mode", mode, bondModes); err != nil {
			return fmt.Errorf("bond %q: %w", r.Name, err)
		}
		fmt.Fprintf(b, "      parameters:\n        mode: %s\n", yamlScalar(mode))
		if r.LACPRate != "" {
			if err := validEnum("lacp-rate", r.LACPRate, lacpRates); err != nil {
				return fmt.Errorf("bond %q: %w", r.Name, err)
			}
			fmt.Fprintf(b, "        lacp-rate: %s\n", yamlScalar(r.LACPRate))
		}
		if r.HashPolicy != "" {
			if err := validEnum("transmit-hash-policy", r.HashPolicy, hashPolicies); err != nil {
				return fmt.Errorf("bond %q: %w", r.Name, err)
			}
			fmt.Fprintf(b, "        transmit-hash-policy: %s\n", yamlScalar(r.HashPolicy))
		}
	case "bridge":
		// A bridge with no members is valid (VM-only bridge, like a default
		// libvirt bridge without uplink).
		if len(r.Members) > 0 {
			if err := renderMembers(b, r.Members); err != nil {
				return err
			}
		}
	case "vlan":
		if r.VLANID < 1 || r.VLANID > 4094 || r.VLANLink == "" {
			return fmt.Errorf("vlan %q needs link and id in 1..4094", r.Name)
		}
		if err := validName(r.VLANLink); err != nil {
			return fmt.Errorf("vlan %q link: %w", r.Name, err)
		}
		fmt.Fprintf(b, "      id: %d\n      link: %s\n", r.VLANID, r.VLANLink)
	case "ethernet":
		// addressing/MTU only; nothing structural.
	default:
		return fmt.Errorf("unknown host network kind %q for %q", r.Kind, r.Name)
	}
	if r.MTU > 0 {
		fmt.Fprintf(b, "      mtu: %d\n", r.MTU)
	}
	return renderAddressing(b, r)
}

func renderMembers(b *strings.Builder, members []string) error {
	ms := append([]string(nil), members...)
	sort.Strings(ms)
	for _, m := range ms {
		if err := validName(m); err != nil {
			return err
		}
	}
	fmt.Fprintf(b, "      interfaces: [%s]\n", strings.Join(ms, ", "))
	return nil
}

func renderAddressing(b *strings.Builder, r corrosion.HostNetworkRecord) error {
	if r.Addressing == "" {
		return nil
	}
	var a corrosion.HostNetworkAddressing
	if err := json.Unmarshal([]byte(r.Addressing), &a); err != nil {
		return fmt.Errorf("addressing for %q: %w", r.Name, err)
	}
	if a.DHCP4 {
		b.WriteString("      dhcp4: true\n")
	}
	if a.DHCP6 {
		b.WriteString("      dhcp6: true\n")
	}
	if len(a.Addresses) > 0 {
		quoted := make([]string, len(a.Addresses))
		for i, addr := range a.Addresses {
			if err := validScalar(addr); err != nil {
				return fmt.Errorf("address on %q: %w", r.Name, err)
			}
			quoted[i] = yamlScalar(addr)
		}
		fmt.Fprintf(b, "      addresses: [%s]\n", strings.Join(quoted, ", "))
	}
	if a.Gateway != "" || a.Gateway6 != "" {
		b.WriteString("      routes:\n")
		if a.Gateway != "" {
			if err := validScalar(a.Gateway); err != nil {
				return fmt.Errorf("gateway on %q: %w", r.Name, err)
			}
			fmt.Fprintf(b, "        - to: default\n          via: %s\n", yamlScalar(a.Gateway))
		}
		if a.Gateway6 != "" {
			if err := validScalar(a.Gateway6); err != nil {
				return fmt.Errorf("gateway6 on %q: %w", r.Name, err)
			}
			fmt.Fprintf(b, "        - to: \"::/0\"\n          via: %s\n", yamlScalar(a.Gateway6))
		}
	}
	if len(a.Nameservers) > 0 {
		quoted := make([]string, len(a.Nameservers))
		for i, ns := range a.Nameservers {
			if err := validScalar(ns); err != nil {
				return fmt.Errorf("nameserver on %q: %w", r.Name, err)
			}
			quoted[i] = yamlScalar(ns)
		}
		fmt.Fprintf(b, "      nameservers:\n        addresses: [%s]\n", strings.Join(quoted, ", "))
	}
	return nil
}

// validName enforces Linux interface-name rules (IFNAMSIZ, no separators) so a
// row can never inject YAML structure or shell into the rendered file. The DB
// row is replicated — every peer applies these strings — so this is a security
// boundary, not a convenience check.
func validName(name string) error {
	if name == "" || len(name) > 15 {
		return fmt.Errorf("interface name %q: must be 1..15 characters", name)
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.':
		default:
			return fmt.Errorf("interface name %q: allowed [A-Za-z0-9._-]", name)
		}
	}
	if name == "." || name == ".." {
		return fmt.Errorf("interface name %q is reserved", name)
	}
	return nil
}

// validScalar rejects anything that could escape a YAML scalar context
// (newlines, quotes). Addresses and gateways are IPs/CIDRs; nothing legitimate
// contains these.
func validScalar(s string) error {
	if s == "" || strings.ContainsAny(s, "\n\r\"'\\#{}[]") {
		return fmt.Errorf("invalid value %q", s)
	}
	return nil
}

// yamlScalar double-quotes a pre-validated scalar so YAML type sniffing can't
// reinterpret it (e.g. a bare `no` or `3.10`).
// yamlScalar renders s as a YAML double-quoted scalar.
//
// It used to wrap the value in quotes and escape nothing, which is not quoting
// at all: a value containing a double quote closed the scalar, and a newline
// then opened whatever YAML followed. That reached a netplan file written as
// root and handed to `netplan apply`, via bond parameters no validator was
// looking at.
//
// Double-quoted style is the one YAML flavour that can carry every byte, using
// C-style escapes. Callers should still validate — see bondMode et al — but
// this function has to be safe on its own, because the next caller will not
// know that it wasn't.
func yamlScalar(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)
				continue
			}
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// The bond parameters netplan accepts. They are enumerations, not free text,
// so an allow-list is both the tightest and the most honest validation: it
// rejects an injection payload and a typo alike, at the point the value would
// otherwise be written to disk.
//
// UpsertHostNetwork says "The renderer is the deep validator (names, injection,
// kind invariants)" — so this is where it belongs. Neither downstream guard
// would catch it: SelfCutoffRisk inspects only name, members and addressing,
// and ForeignConflicts only compares against OTHER files.
var (
	bondModes = map[string]bool{
		"balance-rr": true, "active-backup": true, "balance-xor": true,
		"broadcast": true, "802.3ad": true, "balance-tlb": true, "balance-alb": true,
	}
	lacpRates    = map[string]bool{"slow": true, "fast": true}
	hashPolicies = map[string]bool{
		"layer2": true, "layer2+3": true, "layer3+4": true,
		"encap2+3": true, "encap3+4": true, "vlan+srcmac": true,
	}
)

// validEnum checks value against an allow-list, naming the field so the
// operator sees which one they got wrong.
func validEnum(field, value string, allowed map[string]bool) error {
	if !allowed[value] {
		return fmt.Errorf("%s %q is not one of %s", field, value, sortedKeys(allowed))
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
