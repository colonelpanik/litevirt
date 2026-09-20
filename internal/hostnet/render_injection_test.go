package hostnet

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"gopkg.in/yaml.v3"
)

func bondRec(mode, lacp, hash string) corrosion.HostNetworkRecord {
	return corrosion.HostNetworkRecord{
		Name: "bond0", Kind: "bond", Members: []string{"eno1", "eno2"},
		Addressing: `{"dhcp4":true}`, BondMode: mode, LACPRate: lacp, HashPolicy: hash,
	}
}

// TestRender_BondParametersCannotInjectYAML is the #191 regression.
//
// yamlScalar wrapped its argument in double quotes and escaped nothing, and
// Render ran validScalar only on addresses, gateways and nameservers. A
// bond_mode carrying a quote and a newline therefore closed its own scalar and
// opened whatever YAML it liked — in a file that is written as root and handed
// to `netplan apply`.
//
// UpsertHostNetwork states "The renderer is the deep validator (names,
// injection, kind invariants)", so nothing upstream was checking either.
// Neither guard catches it: SelfCutoffRisk inspects only name, members and
// addressing, and ForeignConflicts only compares against OTHER files.
func TestRender_BondParametersCannotInjectYAML(t *testing.T) {
	// Closes the quoted scalar, ends the bond stanza, and opens a top-level
	// vlans: block that no row describes.
	payload := "active-backup\"\n  vlans:\n    vlan666:\n      id: 666\n      link: eno1\n#"

	for _, tc := range []struct {
		field string
		rec   corrosion.HostNetworkRecord
	}{
		{"bond_mode", bondRec(payload, "", "")},
		{"lacp_rate", bondRec("802.3ad", payload, "")},
		{"hash_policy", bondRec("802.3ad", "fast", payload)},
	} {
		t.Run(tc.field, func(t *testing.T) {
			out, err := Render([]corrosion.HostNetworkRecord{tc.rec})
			if err != nil {
				return // refused outright: the value never reaches the file
			}
			if strings.Contains(out, "vlan666") {
				t.Fatalf("%s injected a vlans: stanza into a root-applied netplan "+
					"file:\n%s", tc.field, out)
			}
			// Even without that exact marker the document must still describe
			// only what the rows asked for.
			var doc struct {
				Network struct {
					Vlans     map[string]any `yaml:"vlans"`
					Ethernets map[string]any `yaml:"ethernets"`
					Bonds     map[string]any `yaml:"bonds"`
				} `yaml:"network"`
			}
			if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
				t.Fatalf("%s produced YAML that does not parse: %v\n%s", tc.field, err, out)
			}
			if len(doc.Network.Vlans) != 0 {
				t.Errorf("%s produced %d vlan(s) that no row describes:\n%s",
					tc.field, len(doc.Network.Vlans), out)
			}
			if len(doc.Network.Bonds) != 1 {
				t.Errorf("%s produced %d bonds, want 1:\n%s", tc.field, len(doc.Network.Bonds), out)
			}
		})
	}
}

// The legitimate values must all still render — an allow-list that rejects
// 802.3ad or layer2+3 would break every LACP bond in the fleet.
func TestRender_AcceptsEveryRealBondParameter(t *testing.T) {
	modes := []string{
		"balance-rr", "active-backup", "balance-xor", "broadcast",
		"802.3ad", "balance-tlb", "balance-alb",
	}
	for _, m := range modes {
		if _, err := Render([]corrosion.HostNetworkRecord{bondRec(m, "", "")}); err != nil {
			t.Errorf("Render rejected bond mode %q: %v", m, err)
		}
	}
	for _, r := range []string{"slow", "fast"} {
		if _, err := Render([]corrosion.HostNetworkRecord{bondRec("802.3ad", r, "")}); err != nil {
			t.Errorf("Render rejected lacp-rate %q: %v", r, err)
		}
	}
	for _, h := range []string{"layer2", "layer2+3", "layer3+4", "encap2+3", "encap3+4"} {
		if _, err := Render([]corrosion.HostNetworkRecord{bondRec("802.3ad", "fast", h)}); err != nil {
			t.Errorf("Render rejected transmit-hash-policy %q: %v", h, err)
		}
	}
}

// yamlScalar is the function that made the injection possible. It is called
// from places an allow-list does not cover, so it has to be safe on its own.
func TestYamlScalar_EscapesWhatItQuotes(t *testing.T) {
	for _, in := range []string{
		`plain`,
		`has "quotes"`,
		"has\nnewline",
		`back\slash`,
		"tab\there",
	} {
		got := yamlScalar(in)
		var round string
		if err := yaml.Unmarshal([]byte("v: "+got), &struct{ V *string }{&round}); err != nil {
			t.Errorf("yamlScalar(%q) = %s, which does not parse as a YAML scalar: %v", in, got, err)
			continue
		}
		if round != in {
			t.Errorf("yamlScalar(%q) round-tripped to %q via %s", in, round, got)
		}
	}
}
