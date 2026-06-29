package corrosion

import "testing"

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
}

// BuildContainerInterfacesFromSpec rebuilds only the MANAGED NICs (those naming a
// network), recomputes the deterministic veth, and carries the static-IP intent.
func TestBuildContainerInterfacesFromSpec_ManagedOnly(t *testing.T) {
	spec := ContainerCreateSpec{Networks: []ContainerNetwork{
		{Name: "eth0", NetworkName: "net1", MAC: "52:54:00:ab:cd:ef", IP: "10.0.0.5", SecurityGroups: []string{"web"}},
		{Name: "eth1", Bridge: "br-raw"}, // legacy/unmanaged → no row
	}}
	ifs, leases := BuildContainerInterfacesFromSpec("h1", "web", spec)
	if len(ifs) != 1 {
		t.Fatalf("expected 1 managed interface, got %d", len(ifs))
	}
	got := ifs[0]
	if got.HostName != "h1" || got.CtName != "web" || got.NetworkName != "net1" ||
		got.IP != "10.0.0.5" || got.MAC != "52:54:00:ab:cd:ef" ||
		got.VethDevice != ContainerVethName("web", 0) || len(got.SecurityGroups) != 1 {
		t.Fatalf("unexpected rebuilt interface: %+v", got)
	}
	// The static-IP NIC yields a transferable lease; the legacy NIC does not.
	if len(leases) != 1 || leases[0].IP != "10.0.0.5" || leases[0].OwnerKind != "ct" || leases[0].OwnerHost != "h1" {
		t.Fatalf("expected one CT lease for the static-IP NIC, got %+v", leases)
	}
}
