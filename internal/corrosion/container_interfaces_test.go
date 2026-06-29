package corrosion

import (
	"regexp"
	"testing"
)

func TestContainerVethName_StableAndBounded(t *testing.T) {
	if ContainerVethName("web", 0) != ContainerVethName("web", 0) {
		t.Fatal("veth name must be deterministic")
	}
	if got := ContainerVethName("a-fairly-long-container-name", 7); len(got) > 15 {
		t.Fatalf("veth %q exceeds IFNAMSIZ (15)", got)
	}
	if ContainerVethName("web", 0) == ContainerVethName("web", 1) {
		t.Fatal("ordinal must vary the veth name")
	}
	// Wide (48-bit) name space: 12 hex digits after the "lvc" prefix.
	if got := ContainerVethName("web", 0); !regexp.MustCompile(`^lvc[0-9a-f]{12}$`).MatchString(got) {
		t.Fatalf("veth %q not lvc + 12 hex (48 bits)", got)
	}
}

// TestContainerMAC_LAAWideAndHostScoped: the MAC is a valid locally-administered
// unicast address with a 40-bit (5-octet) hash suffix, deterministic, and the HOST
// distinguishes two same-named containers (so they don't collide on a shared L2).
func TestContainerMAC_LAAWideAndHostScoped(t *testing.T) {
	m := ContainerMAC("host-a", "web", 0)
	if m != ContainerMAC("host-a", "web", 0) {
		t.Fatal("MAC must be deterministic")
	}
	if !regexp.MustCompile(`^52(:[0-9a-f]{2}){5}$`).MatchString(m) {
		t.Fatalf("MAC %q not 52: + 5 hex octets (40-bit suffix)", m)
	}
	// 0x52 is locally-administered (0x02 set) and unicast (0x01 clear).
	if first := byte(0x52); first&0x02 == 0 || first&0x01 != 0 {
		t.Fatal("first octet must be locally-administered + unicast")
	}
	// Same name + ordinal, DIFFERENT host ⇒ different MAC (no shared-L2 collision).
	if ContainerMAC("host-a", "web", 0) == ContainerMAC("host-b", "web", 0) {
		t.Fatal("same-named containers on different hosts must not derive the same MAC")
	}
	// Ordinal varies the MAC too.
	if ContainerMAC("host-a", "web", 0) == ContainerMAC("host-a", "web", 1) {
		t.Fatal("ordinal must vary the MAC")
	}
}

// BuildContainerInterfacesFromSpec rebuilds only the MANAGED NICs (those naming a
// network), recomputes the deterministic veth, and carries the static-IP intent.
func TestBuildContainerInterfacesFromSpec_ManagedOnly(t *testing.T) {
	spec := ContainerCreateSpec{Networks: []ContainerNetwork{
		{Name: "eth0", NetworkName: "net1", MAC: "52:54:00:ab:cd:ef", IP: "10.0.0.5", SecurityGroups: []string{"web"}},
		{Name: "eth1", Bridge: "br-raw"}, // legacy/unmanaged → no row
	}}
	ifs := BuildContainerInterfacesFromSpec("h1", "web", spec)
	if len(ifs) != 1 {
		t.Fatalf("expected 1 managed interface (legacy NIC skipped), got %d", len(ifs))
	}
	got := ifs[0]
	if got.HostName != "h1" || got.CtName != "web" || got.NetworkName != "net1" ||
		got.IP != "10.0.0.5" || got.MAC != "52:54:00:ab:cd:ef" ||
		got.VethDevice != ContainerVethName("web", 0) || len(got.SecurityGroups) != 1 {
		t.Fatalf("unexpected rebuilt interface: %+v", got)
	}
}
