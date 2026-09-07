package network

import (
	"os"
	"path/filepath"
	"testing"
)

// BridgeHasUplink is what separates the operator's remedy from the symptom, so
// it is driven against a modelled sysfs tree rather than the test machine's own
// interfaces.
//
// The two bridges it has to tell apart:
//
//   - an infrastructure bridge with a VLAN sub-interface, a bond or a NIC
//     enslaved: a guest reaches the router that owns the subnet, which is the
//     configuration a bound network is documented to need;
//   - a bridge litevirt created for a placement: guest taps only, so the guest
//     has no gateway and its NetBox address routes nowhere.
func fakeSysfs(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	old := sysfsNet
	sysfsNet = root
	t.Cleanup(func() { sysfsNet = old })
	return root
}

// iface creates an interface directory with the given sysfs markers under it
// ("device", "bonding", "bridge") plus any lower links.
func iface(t *testing.T, root, name string, markers []string, lowers []string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	for _, m := range markers {
		if err := os.MkdirAll(filepath.Join(dir, m), 0o755); err != nil {
			t.Fatalf("mkdir %s/%s: %v", name, m, err)
		}
	}
	for _, l := range lowers {
		if err := os.MkdirAll(filepath.Join(dir, "lower_"+l), 0o755); err != nil {
			t.Fatalf("mkdir %s/lower_%s: %v", name, l, err)
		}
	}
}

// enslave records members under <bridge>/brif/, which is how the kernel reports
// what a bridge carries.
func enslave(t *testing.T, root, bridge string, members ...string) {
	t.Helper()
	iface(t, root, bridge, []string{"bridge"}, nil)
	for _, m := range members {
		p := filepath.Join(root, bridge, "brif", m)
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatalf("enslave %s to %s: %v", m, bridge, err)
		}
	}
}

func TestBridgeHasUplink(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(t *testing.T, root string)
		want bool
	}{{
		name: "a bridge litevirt created for a placement carries only guest taps",
		set: func(t *testing.T, root string) {
			iface(t, root, "vnet0", nil, nil)
			iface(t, root, "vnet1", nil, nil)
			enslave(t, root, "br-auto", "vnet0", "vnet1")
		},
		want: false,
	}, {
		name: "an empty bridge, before any guest lands on it",
		set:  func(t *testing.T, root string) { enslave(t, root, "br-auto") },
		want: false,
	}, {
		name: "an infrastructure bridge with a physical NIC",
		set: func(t *testing.T, root string) {
			iface(t, root, "eth0", []string{"device"}, nil)
			enslave(t, root, "br0", "eth0", "vnet0")
		},
		want: true,
	}, {
		name: "an infrastructure bridge with a bond",
		set: func(t *testing.T, root string) {
			iface(t, root, "bond0", []string{"bonding"}, nil)
			enslave(t, root, "br0", "bond0")
		},
		want: true,
	}, {
		name: "an infrastructure bridge on a tagged VLAN sub-interface",
		set: func(t *testing.T, root string) {
			iface(t, root, "bond0.100", nil, []string{"bond0"})
			enslave(t, root, "br0", "bond0.100", "vnet3")
		},
		want: true,
	}, {
		name: "a bridge stacked on another bridge",
		set: func(t *testing.T, root string) {
			iface(t, root, "br-under", []string{"bridge"}, nil)
			enslave(t, root, "br0", "br-under")
		},
		want: true,
	}, {
		// Fail closed. "We could not read the topology" is not "there is an
		// uplink" — answering true would resolve the finding on no evidence,
		// which is the self-clearing behaviour this exists to stop.
		name: "an interface that does not exist at all",
		set:  func(t *testing.T, root string) {},
		want: false,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			root := fakeSysfs(t)
			tc.set(t, root)
			bridge := "br0"
			if _, err := os.Stat(filepath.Join(root, "br-auto")); err == nil {
				bridge = "br-auto"
			}
			if got := BridgeHasUplink(bridge); got != tc.want {
				t.Fatalf("BridgeHasUplink(%q) = %v, want %v", bridge, got, tc.want)
			}
		})
	}
}
