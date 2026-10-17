package network

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv network rm` of a bridge network litevirt created (`--type bridge` with no
// --interface, or a compose network) tore down its dnsmasq, gateway address
// and NAT, and left the Linux bridge itself on the host that served the
// delete: Deprovision skipped the delete for every bridge, because it could
// not tell its own bridge from an operator's infrastructure bridge.
//
// EnsureBridge now records the bridges it created, and Deprovision removes a
// bridge only when that record says litevirt made it, nothing is plugged into
// it, it carries no address, no live network still names it, and no VM or
// container on this host has a NIC on it. An operator's bridge — one litevirt
// found already there — is never removed.
func TestDeprovision_RemovesOnlyTheBridgeLitevirtCreated(t *testing.T) {
	type env struct {
		db      *corrosion.Client
		deleted func() []string
		sys     string
	}
	setup := func(t *testing.T, ipLinkAddOut string) env {
		t.Helper()
		sys := t.TempDir()
		origSys, origDir, origAddrs := sysClassNet, createdBridgeDir, interfaceAddrs
		sysClassNet = sys
		createdBridgeDir = filepath.Join(t.TempDir(), "bridges")
		interfaceAddrs = func(string) ([]net.Addr, error) { return nil, nil }
		var dels []string
		ifindex := 6
		execCommand = func(name string, args ...string) ([]byte, error) {
			if name == "ip" && len(args) >= 3 && args[0] == "link" && args[1] == "add" {
				if ipLinkAddOut != "" {
					return []byte(ipLinkAddOut), errors.New("exit status 2")
				}
				// The kernel makes the bridge: it appears in sysfs with a
				// fresh ifindex, as on a real host.
				ifindex++
				writeSysBridge(t, sys, args[2], ifindex)
			}
			if name == "ip" && len(args) == 3 && args[0] == "link" && args[1] == "del" {
				dels = append(dels, args[2])
			}
			return nil, nil
		}
		t.Cleanup(func() {
			sysClassNet, createdBridgeDir, interfaceAddrs = origSys, origDir, origAddrs
			execCommand = defaultExec
		})
		db, err := corrosion.NewTestClient()
		if err != nil {
			t.Fatalf("NewTestClient: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if err := corrosion.InitSchema(context.Background(), db); err != nil {
			t.Fatalf("InitSchema: %v", err)
		}
		return env{db: db, deleted: func() []string { return dels }, sys: sys}
	}
	// The bridge as sysfs shows it: created by the stubbed `ip link add`, or
	// already there (an operator's), plus any ports.
	mkBridge := func(t *testing.T, e env, name string, ports ...string) {
		t.Helper()
		if _, err := os.Stat(filepath.Join(e.sys, name)); errors.Is(err, os.ErrNotExist) {
			writeSysBridge(t, e.sys, name, 100)
		}
		for _, p := range ports {
			if err := os.WriteFile(filepath.Join(e.sys, name, "brif", p), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A name no test host carries, so EnsureBridge takes its create path.
	const br = "lvtnetrm0"
	def := compose.NetworkDef{Type: "bridge", Interface: br, Subnet: "10.66.0.0/24"}
	ctx := context.Background()

	t.Run("created by litevirt and unused: removed", func(t *testing.T) {
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := strings.Join(e.deleted(), ","); got != br {
			t.Fatalf("ip link del issued for %q, want %q: the bridge litevirt created outlives its network", got, br)
		}
		if _, err := os.Stat(filepath.Join(createdBridgeDir, br)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the created-bridge record for %s survived the bridge's removal (stat err %v)", br, err)
		}
	})

	t.Run("an operator's bridge litevirt found already there: kept", func(t *testing.T) {
		e := setup(t, "RTNETLINK answers: File exists")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v: a bridge litevirt did not create was removed", got)
		}
	})

	t.Run("a port still on it: kept, and still removable later", func(t *testing.T) {
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br, "vnet0")
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v while a port is on the bridge", got)
		}
		if _, err := os.Stat(filepath.Join(createdBridgeDir, br)); err != nil {
			t.Errorf("the created-bridge record was dropped while the bridge stayed: %v", err)
		}
	})

	t.Run("a live network still names it: kept", func(t *testing.T) {
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
		if err := corrosion.UpsertNetwork(ctx, e.db, corrosion.NetworkRecord{
			Name: "sibling", Type: "bridge", Config: `{"interface":"` + br + `"}`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v while live network sibling uses the bridge", got)
		}
	})

	t.Run("the deleted network's own row may still be live: removed", func(t *testing.T) {
		// DeleteNetwork deprovisions BEFORE it soft-deletes the row, so the
		// network being torn down still reads as live; it must not count.
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
		if err := corrosion.UpsertNetwork(ctx, e.db, corrosion.NetworkRecord{
			Name: "nr", Type: "bridge", Config: `{"interface":"` + br + `","subnet":"10.66.0.0/24"}`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := strings.Join(e.deleted(), ","); got != br {
			t.Fatalf("ip link del issued for %q, want %q", got, br)
		}
	})

	// A workload on this host whose NIC attaches to the bridge keeps it, even
	// with no port on it: a stopped VM has no tap, and a VM start does not
	// re-create its bridge, so removing it would leave the VM unable to start.
	seedVM := func(t *testing.T, e env, vm, host, netName string) {
		t.Helper()
		if err := corrosion.InsertVM(ctx, e.db, corrosion.VMRecord{Name: vm, HostName: host, State: "stopped", Spec: "{}"},
			[]corrosion.InterfaceRecord{{VMName: vm, NetworkName: netName, Ordinal: 0, MAC: "52:54:00:00:00:01"}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	seedCT := func(t *testing.T, e env, ct, spec string) {
		t.Helper()
		if err := corrosion.UpsertContainer(ctx, e.db, corrosion.ContainerRecord{
			HostName: "h", Name: ct, State: "stopped", CreateSpec: spec,
		}); err != nil {
			t.Fatal(err)
		}
	}
	created := func(t *testing.T, e env) {
		t.Helper()
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
	}
	kept := func(t *testing.T, e env, why string) {
		t.Helper()
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v while %s", got, why)
		}
		if _, err := os.Stat(filepath.Join(createdBridgeDir, br)); err != nil {
			t.Errorf("the created-bridge record was dropped while the bridge stayed: %v", err)
		}
	}
	removed := func(t *testing.T, e env, why string) {
		t.Helper()
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := strings.Join(e.deleted(), ","); got != br {
			t.Fatalf("ip link del issued for %q, want %q: %s", got, br, why)
		}
	}

	t.Run("a stopped VM on this host on the deleted network (rm --force): kept", func(t *testing.T) {
		e := setup(t, "")
		created(t, e)
		seedVM(t, e, "vm1", "h", "nr")
		kept(t, e, "a stopped VM on this host is on the network")
	})

	t.Run("a stopped VM on this host whose NIC names the bridge itself: kept", func(t *testing.T) {
		// `lv create --network <bridge>`: the NIC row names the bridge, not
		// the network, and the VM's domain keeps that bridge.
		e := setup(t, "")
		created(t, e)
		seedVM(t, e, "vm1", "h", br)
		kept(t, e, "a stopped VM on this host names the bridge")
	})

	t.Run("a VM whose typed NIC (vm_nics) names the bridge: kept", func(t *testing.T) {
		e := setup(t, "")
		created(t, e)
		if err := corrosion.InsertVM(ctx, e.db, corrosion.VMRecord{Name: "vm1", HostName: "h", State: "stopped", Spec: "{}"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := e.db.Execute(ctx,
			`INSERT INTO vm_nics (vm_name, id, network_name, mac, ordinal, updated_at)
			 VALUES ('vm1', 'n0', ?, '52:54:00:00:00:02', 0, '2026-01-01T00:00:00Z')`, br); err != nil {
			t.Fatal(err)
		}
		kept(t, e, "a VM on this host has a typed NIC on the bridge")
	})

	t.Run("a VM on another deleted network whose device is the bridge: kept", func(t *testing.T) {
		// Network "old" (also on the bridge) was deleted with --force; its VM
		// is still defined against the bridge.
		e := setup(t, "")
		created(t, e)
		if err := corrosion.UpsertNetwork(ctx, e.db, corrosion.NetworkRecord{
			Name: "old", Type: "bridge", Config: `{"interface":"` + br + `"}`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteNetwork(ctx, e.db, "old"); err != nil {
			t.Fatal(err)
		}
		seedVM(t, e, "vm1", "h", "old")
		kept(t, e, "a VM on this host is on a deleted network on the same bridge")
	})

	t.Run("a container on this host with an interface row on the network: kept", func(t *testing.T) {
		e := setup(t, "")
		created(t, e)
		seedCT(t, e, "ct1", "")
		if err := corrosion.UpsertContainerInterface(ctx, e.db, corrosion.ContainerInterfaceRecord{
			HostName: "h", CtName: "ct1", NetworkName: "nr", Ordinal: 0, MAC: "52:54:00:00:00:03",
		}); err != nil {
			t.Fatal(err)
		}
		kept(t, e, "a container on this host is on the network")
	})

	t.Run("a stopped container on this host with a raw bridge NIC on it: kept", func(t *testing.T) {
		// A raw `bridge=` NIC has no interface row; only the create spec has it.
		e := setup(t, "")
		created(t, e)
		seedCT(t, e, "ct1", `{"networks":[{"name":"eth0","bridge":"`+br+`"}]}`)
		kept(t, e, "a container on this host has a raw bridge NIC on it")
	})

	t.Run("a container whose create spec cannot be read: kept", func(t *testing.T) {
		e := setup(t, "")
		created(t, e)
		seedCT(t, e, "ct1", `{"networks":[`)
		kept(t, e, "this host's container NICs could not be read")
	})

	t.Run("a VM on a network whose config cannot be read: kept", func(t *testing.T) {
		e := setup(t, "")
		created(t, e)
		if err := corrosion.UpsertNetwork(ctx, e.db, corrosion.NetworkRecord{
			Name: "odd", Type: "bridge", Config: `{"interface":`,
		}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteNetwork(ctx, e.db, "odd"); err != nil {
			t.Fatal(err)
		}
		seedVM(t, e, "vm1", "h", "odd")
		kept(t, e, "the device of a network a VM here is on could not be read")
	})

	t.Run("the workload tables cannot be read: kept", func(t *testing.T) {
		e := setup(t, "")
		created(t, e)
		if err := e.db.Execute(ctx, `DROP TABLE container_interfaces`); err != nil {
			t.Fatal(err)
		}
		kept(t, e, "this host's workload NICs could not be read")
	})

	t.Run("a VM on another host on the network: removed here", func(t *testing.T) {
		e := setup(t, "")
		created(t, e)
		seedVM(t, e, "vm1", "other", "nr")
		removed(t, e, "a VM on another host kept this host's bridge")
	})

	t.Run("a deleted VM on this host, and an unrelated container: removed", func(t *testing.T) {
		e := setup(t, "")
		created(t, e)
		seedVM(t, e, "vm1", "h", br)
		if err := corrosion.DeleteVM(ctx, e.db, "vm1"); err != nil {
			t.Fatal(err)
		}
		seedCT(t, e, "ct1", `{"networks":[{"name":"eth0","bridge":"lvtother0"}]}`)
		removed(t, e, "a deleted VM or a container on another bridge kept it")
	})

	recordGone := func(t *testing.T) {
		t.Helper()
		if _, err := os.Stat(filepath.Join(createdBridgeDir, br)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the created-bridge record for %s is still there (stat err %v)", br, err)
		}
	}

	t.Run("a recorded bridge carrying an address: kept, record kept", func(t *testing.T) {
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		mkBridge(t, e, br)
		interfaceAddrs = func(string) ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10").To4(), Mask: net.CIDRMask(24, 32)}}, nil
		}
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v while the bridge carries an address", got)
		}
		if _, err := os.Stat(filepath.Join(createdBridgeDir, br)); err != nil {
			t.Errorf("the record was dropped while the bridge stayed: %v", err)
		}
	})

	t.Run("the bridge is already gone: its record goes", func(t *testing.T) {
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(e.sys, br)); err != nil {
			t.Fatal(err)
		}
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v for a bridge that is gone", got)
		}
		recordGone(t)
	})

	t.Run("a bridge recreated under a recorded name: kept, stale record dropped", func(t *testing.T) {
		// litevirt made it; someone deleted it and made their own of the
		// same name (a new ifindex). The record no longer describes it.
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(e.sys, br)); err != nil {
			t.Fatal(err)
		}
		writeSysBridge(t, e.sys, br, 4242)
		if err := Deprovision(ctx, e.db, "nr", def, "h"); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}
		if got := e.deleted(); len(got) != 0 {
			t.Fatalf("ip link del issued for %v: a bridge litevirt did not create (new ifindex) was removed", got)
		}
		recordGone(t)
	})

	t.Run("RemoveBridgeIfUnused drops the record too", func(t *testing.T) {
		e := setup(t, "")
		if err := EnsureBridge(br); err != nil {
			t.Fatal(err)
		}
		removed, err := RemoveBridgeIfUnused(br)
		if err != nil || !removed {
			t.Fatalf("RemoveBridgeIfUnused = %v, %v; want removed", removed, err)
		}
		_ = e
		recordGone(t)
	})
}

// writeSysBridge makes name a bridge in the fake sysfs tree, with ifindex.
func writeSysBridge(t *testing.T, sys, name string, ifindex int) {
	t.Helper()
	for _, d := range []string{"bridge", "brif"} {
		if err := os.MkdirAll(filepath.Join(sys, name, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(sys, name, "ifindex"), []byte(strconv.Itoa(ifindex)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
