package hostnet

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Golden render per kind. Byte-exact on purpose: the apply protocol's
// "empty diff = no-op" and the file's stability across daemon restarts both
// depend on deterministic output.
func TestRenderGolden(t *testing.T) {
	recs := []corrosion.HostNetworkRecord{
		// deliberately out of order — Render must sort
		{HostName: "h1", Name: "vmbr0", Kind: "bridge", Members: []string{"eth1"},
			Addressing: `{"addresses":["10.0.10.2/24"],"gateway":"10.0.10.1","nameservers":["10.0.10.1"]}`},
		{HostName: "h1", Name: "bond0", Kind: "bond", Members: []string{"eth3", "eth2"},
			BondMode: "802.3ad", LACPRate: "fast", HashPolicy: "layer3+4", MTU: 9000},
		{HostName: "h1", Name: "vlan40", Kind: "vlan", VLANID: 40, VLANLink: "bond0",
			Addressing: `{"dhcp4":true}`},
		{HostName: "h1", Name: "eth9", Kind: "ethernet", MTU: 1500,
			Addressing: `{"addresses":["fd77::19/64"],"gateway6":"fd77::1"}`},
	}
	got, err := Render(recs)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	want := header + `network:
  version: 2
  ethernets:
    eth9:
      mtu: 1500
      addresses: ["fd77::19/64"]
      routes:
        - to: "::/0"
          via: "fd77::1"
  bonds:
    bond0:
      interfaces: [eth2, eth3]
      parameters:
        mode: "802.3ad"
        lacp-rate: "fast"
        transmit-hash-policy: "layer3+4"
      mtu: 9000
  bridges:
    vmbr0:
      interfaces: [eth1]
      addresses: ["10.0.10.2/24"]
      routes:
        - to: default
          via: "10.0.10.1"
      nameservers:
        addresses: ["10.0.10.1"]
  vlans:
    vlan40:
      id: 40
      link: bond0
      dhcp4: true
`
	if got != want {
		t.Fatalf("golden mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// Determinism: shuffled input renders the identical bytes.
	shuffled := []corrosion.HostNetworkRecord{recs[2], recs[0], recs[3], recs[1]}
	again, err := Render(shuffled)
	if err != nil || again != got {
		t.Fatalf("render is order-sensitive (err=%v)", err)
	}
}

func TestRenderRefusesInjection(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  corrosion.HostNetworkRecord
	}{
		{"newline in name", corrosion.HostNetworkRecord{Name: "e\nth0", Kind: "ethernet"}},
		{"yaml structure in name", corrosion.HostNetworkRecord{Name: "eth0: {a", Kind: "ethernet"}},
		{"overlong name", corrosion.HostNetworkRecord{Name: "abcdefghijklmnopq", Kind: "ethernet"}},
		{"injection via member", corrosion.HostNetworkRecord{Name: "br0", Kind: "bridge", Members: []string{"e]\n  x:"}}},
		{"injection via address", corrosion.HostNetworkRecord{Name: "eth0", Kind: "ethernet",
			Addressing: `{"addresses":["10.0.0.1/24\"], evil: [\""]}`}},
		{"injection via gateway", corrosion.HostNetworkRecord{Name: "eth0", Kind: "ethernet",
			Addressing: `{"gateway":"10.0.0.1\n  routes-evil: x"}`}},
		{"bond without members", corrosion.HostNetworkRecord{Name: "bond0", Kind: "bond"}},
		{"vlan without link", corrosion.HostNetworkRecord{Name: "v", Kind: "vlan", VLANID: 4}},
		{"unknown kind", corrosion.HostNetworkRecord{Name: "x", Kind: "gre"}},
	} {
		if _, err := Render([]corrosion.HostNetworkRecord{tc.rec}); err == nil {
			t.Errorf("%s: rendered instead of refusing", tc.name)
		}
	}
}

// An empty intent set renders a valid, empty file — the "remove everything
// litevirt manages" plan, not an error.
func TestRenderEmpty(t *testing.T) {
	got, err := Render(nil)
	if err != nil {
		t.Fatalf("Render(nil): %v", err)
	}
	if !strings.Contains(got, "network:\n  version: 2\n") {
		t.Fatalf("empty render: %q", got)
	}
}

func TestSelfCutoffRisk(t *testing.T) {
	adv := "10.77.0.11"
	for _, tc := range []struct {
		name string
		plan corrosion.HostNetworkRecord
		want bool
	}{
		{"reconfigures the carrier", corrosion.HostNetworkRecord{Name: "net1", Kind: "ethernet"}, true},
		{"enslaves the carrier into a bridge", corrosion.HostNetworkRecord{
			Name: "vmbr0", Kind: "bridge", Members: []string{"net1"}}, true},
		{"enslaves the carrier into a bond", corrosion.HostNetworkRecord{
			Name: "bond0", Kind: "bond", Members: []string{"eth5", "net1"}}, true},
		{"re-homes the advertise address", corrosion.HostNetworkRecord{
			Name: "vmbr1", Kind: "bridge", Addressing: `{"addresses":["10.77.0.11/24"]}`}, true},
		{"unrelated bridge is fine", corrosion.HostNetworkRecord{
			Name: "vmbr1", Kind: "bridge", Members: []string{"eth5"},
			Addressing: `{"addresses":["10.0.99.1/24"]}`}, false},
		{"vlan ON the carrier is fine", corrosion.HostNetworkRecord{
			Name: "vlan40", Kind: "vlan", VLANID: 40, VLANLink: "net1"}, false},
	} {
		reason, risky := SelfCutoffRisk([]corrosion.HostNetworkRecord{tc.plan}, "net1", adv)
		if risky != tc.want {
			t.Errorf("%s: risky=%v (reason=%q), want %v", tc.name, risky, reason, tc.want)
		}
	}

	// Unknown carrier: only the address check can fire — and it must.
	_, risky := SelfCutoffRisk([]corrosion.HostNetworkRecord{{
		Name: "vmbr1", Kind: "bridge", Addressing: `{"addresses":["10.77.0.11/24"]}`,
	}}, "", adv)
	if !risky {
		t.Error("address re-homing must be caught even when the carrier interface is unknown")
	}
}

func TestForeignConflicts(t *testing.T) {
	plan := []corrosion.HostNetworkRecord{
		{Name: "vmbr0", Kind: "bridge"},
		{Name: "eth2", Kind: "ethernet"},
	}
	foreign := map[string]string{
		"/etc/netplan/50-cloud-init.yaml": `
network:
  version: 2
  ethernets:
    eth0: {dhcp4: true}
    eth2: {mtu: 1500}
`,
	}
	got := ForeignConflicts(plan, foreign)
	if got["eth2"] != "/etc/netplan/50-cloud-init.yaml" {
		t.Fatalf("eth2 conflict not attributed: %v", got)
	}
	if _, bad := got["vmbr0"]; bad {
		t.Fatalf("vmbr0 wrongly flagged: %v", got)
	}

	// An unparseable foreign file fails closed for every planned interface.
	got = ForeignConflicts(plan, map[string]string{"/etc/netplan/99-broken.yaml": "{{{not yaml"})
	if len(got) != 2 {
		t.Fatalf("unparseable foreign file must conflict everything, got %v", got)
	}

	// Regression, lab 2026-08-02: a stanza may be keyed by an ARBITRARY id and
	// claim the real interface via match+set-name — here the key is
	// "clusternet" and the device is net1 — so the original key-only scan
	// never saw "net1" and let a plan for it through, producing two netplan
	// definitions racing on one device. The fixture is the offending lab file
	// VERBATIM (it is only test input to a pure function — nothing reads
	// /etc/netplan here): sanitizing the input that defeated a guard is how a
	// regression test quietly stops reproducing the trigger. The MAC and
	// address play no role in the property; only key ≠ set-name does.
	got = ForeignConflicts(
		[]corrosion.HostNetworkRecord{{Name: "net1", Kind: "ethernet"}},
		map[string]string{"/etc/netplan/60-cluster.yaml": `
network:
  version: 2
  ethernets:
    clusternet:
      match:
        macaddress: "52:54:00:77:01:03"
      set-name: net1
      addresses: [10.77.0.13/24]
`})
	if got["net1"] != "/etc/netplan/60-cluster.yaml" {
		t.Fatalf("a set-name definition must conflict: %v", got)
	}
}
