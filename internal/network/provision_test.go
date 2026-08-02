package network

import (
	"context"
	"net"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func testLoopbackInterface(t *testing.T) string {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list network interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			return iface.Name
		}
	}
	t.Fatal("no loopback network interface found")
	return ""
}

func TestProvision_Bridge(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:      "bridge",
		Interface: "lv-test-br99",
	}
	bridge, err := Provision(ctx, db, "test-net", def,"10.0.0.1", "host1")
	if err != nil {
		t.Fatalf("Provision bridge: %v", err)
	}
	if bridge != "lv-test-br99" {
		t.Errorf("expected lv-test-br99, got %s", bridge)
	}
	// EnsureBridge creates and brings up the bridge (2 calls), then
	// RemoveHostIsolation runs as convergent cleanup (2 calls: flush + delete).
	if len(calls) < 2 {
		t.Fatalf("expected at least 2 exec commands, got %d: %v", len(calls), calls)
	}
	if calls[0][len(calls[0])-1] != "bridge" {
		t.Errorf("expected 'ip link add ... type bridge', got %v", calls[0])
	}
	if calls[1][len(calls[1])-1] != "up" {
		t.Errorf("expected 'ip link set ... up', got %v", calls[1])
	}
}

// TestProvision_Bridge_PreExistingNAT_NoDHCP reproduces the upgrade cutover gap:
// a managed NAT network with DHCP off, re-provisioned onto a bridge that already
// exists (every litevirt bridge "pre-exists" on a re-provision / daemon restart),
// must still record its masquerade intent so the consolidated renderer migrates
// the network off the pre-consolidation iptables rule. Before the fix the NAT
// intent was gated behind (!bridgePreExisted || def.DHCP), so this shape recorded
// nothing and the old iptables MASQUERADE was stranded.
func TestProvision_Bridge_PreExistingNAT_NoDHCP(t *testing.T) {
	execCommand = func(name string, args ...string) ([]byte, error) { return nil, nil }
	defer func() { execCommand = defaultExec }()
	dhcpStarted := false
	startDHCPFunc = func(bridge, gw, rangeStart, rangeEnd, mask, pidFile string) error {
		dhcpStarted = true
		return nil
	}
	defer func() { startDHCPFunc = StartDHCP }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Use the host loopback so BridgeExists is true → bridgePreExisted, exactly
	// like a litevirt bridge on a re-provision. NAT default (nil→true), DHCP off.
	loopback := testLoopbackInterface(t)
	def := compose.NetworkDef{
		Type:      "bridge",
		Interface: loopback,
		Subnet:    "10.77.0.0/24",
		DHCP:      false,
	}
	if _, err := Provision(ctx, db, "reprov-net", def, "10.0.0.1", "host1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	intents, err := corrosion.ListHostFWIntent(ctx, db, "host1")
	if err != nil {
		t.Fatalf("ListHostFWIntent: %v", err)
	}
	var got *corrosion.HostFWIntent
	for i := range intents {
		if intents[i].ScopeKey == "net:reprov-net" {
			got = &intents[i]
		}
	}
	if got == nil {
		t.Fatalf("expected a host_fw_intent row for net:reprov-net (masquerade), got none: %v", intents)
	}
	if got.MasqueradeSubnet != "10.77.0.0/24" {
		t.Errorf("expected MasqueradeSubnet=10.77.0.0/24, got %q", got.MasqueradeSubnet)
	}
	// DHCP must still NOT start on a pre-existing bridge with DHCP off — only the
	// NAT intent is decoupled from that gate.
	if dhcpStarted {
		t.Error("DHCP must not start on a pre-existing bridge with DHCP disabled")
	}
}

func TestProvision_VXLAN(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:      "vxlan",
		Interface: "overlay0",
		VNI:       500,
		Underlay:  "eth0",
	}
	bridge, err := Provision(ctx, db, "test-net", def,"10.1.0.1", "host1")
	if err != nil {
		t.Fatalf("Provision vxlan: %v", err)
	}
	if bridge != "br-vni500" {
		t.Errorf("expected br-vni500, got %s", bridge)
	}

	// Verify VTEP was upserted under the logical network name
	vteps, err := GetVTEPs(ctx, db, "test-net")
	if err != nil {
		t.Fatalf("GetVTEPs: %v", err)
	}
	if len(vteps) != 1 {
		t.Fatalf("expected 1 VTEP, got %d", len(vteps))
	}
	if vteps[0].VTEPAddr != "10.1.0.1" {
		t.Errorf("expected vtep 10.1.0.1, got %s", vteps[0].VTEPAddr)
	}
}

func TestProvision_WithSubnet(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()
	startDHCPFunc = func(bridge, gw, rangeStart, rangeEnd, mask, pidFile string) error {
		return nil
	}
	defer func() { startDHCPFunc = StartDHCP }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:      "vxlan",
		Interface: "overlay1",
		VNI:       600,
		Underlay:  "eth0",
		Subnet:    "10.200.0.0/24",
	}
	_, err = Provision(ctx, db, "test-net", def,"10.1.0.2", "host1")
	if err != nil {
		t.Fatalf("Provision with subnet: %v", err)
	}

	// Should have called ip addr add for IRB
	foundIRB := false
	for _, call := range calls {
		if len(call) > 3 && call[0] == "ip" && call[2] == "add" && call[3] == "10.200.0.1/24" {
			foundIRB = true
		}
	}
	if !foundIRB {
		t.Errorf("expected IRB ip addr add 10.200.0.1/24; calls: %v", calls)
	}
}

func TestProvision_SRIOV(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type: "sriov",
		PF:   "ens3f0",
	}
	pf, err := Provision(ctx, db, "test-net", def,"10.0.0.1", "host1")
	if err != nil {
		t.Fatalf("Provision sriov: %v", err)
	}
	if pf != "ens3f0" {
		t.Errorf("expected ens3f0, got %s", pf)
	}
}

func TestProvision_Direct(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	loopback := testLoopbackInterface(t)
	def := compose.NetworkDef{
		Type:      "direct",
		Interface: loopback,
	}
	result, err := Provision(ctx, db, "test-direct", def, "10.0.0.1", "host1")
	if err != nil {
		t.Fatalf("Provision direct: %v", err)
	}
	if want := "direct:" + loopback; result != want {
		t.Errorf("expected %s, got %s", want, result)
	}
}

func TestProvision_Direct_MissingInterface(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type:      "direct",
		Interface: "nonexistent-iface-xyz",
	}
	_, err = Provision(ctx, db, "test-direct", def, "10.0.0.1", "host1")
	if err == nil {
		t.Fatal("expected error for non-existent interface, got nil")
	}
}

func TestProvision_Direct_NoInterface(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	def := compose.NetworkDef{
		Type: "direct",
		// Interface intentionally empty
	}
	_, err = Provision(ctx, db, "test-direct", def, "10.0.0.1", "host1")
	if err == nil {
		t.Fatal("expected error for empty interface, got nil")
	}
}

func TestDeprovision_Direct(t *testing.T) {
	def := compose.NetworkDef{
		Type:      "direct",
		Interface: "bond0.206",
	}
	err := Deprovision(context.Background(), nil, "test-direct", def, "test-host")
	if err != nil {
		t.Fatalf("Deprovision direct: %v", err)
	}
}

func TestUpsertAndGetVTEPs(t *testing.T) {
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	if err := UpsertVTEP(ctx, db, "net1", "host1", "10.0.0.1", 100); err != nil {
		t.Fatalf("UpsertVTEP host1: %v", err)
	}
	if err := UpsertVTEP(ctx, db, "net1", "host2", "10.0.0.2", 100); err != nil {
		t.Fatalf("UpsertVTEP host2: %v", err)
	}

	vteps, err := GetVTEPs(ctx, db, "net1")
	if err != nil {
		t.Fatalf("GetVTEPs: %v", err)
	}
	if len(vteps) != 2 {
		t.Fatalf("expected 2 VTEPs, got %d", len(vteps))
	}

	// Upsert again to verify idempotent
	if err := UpsertVTEP(ctx, db, "net1", "host1", "10.0.0.100", 100); err != nil {
		t.Fatalf("UpsertVTEP upsert: %v", err)
	}
	vteps, err = GetVTEPs(ctx, db, "net1")
	if err != nil {
		t.Fatalf("GetVTEPs after upsert: %v", err)
	}
	if len(vteps) != 2 {
		t.Fatalf("expected still 2 VTEPs after upsert, got %d", len(vteps))
	}
}

func TestSyncFloodEntries(t *testing.T) {
	var calls [][]string
	execCommand = func(name string, args ...string) ([]byte, error) {
		calls = append(calls, append([]string{name}, args...))
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// Insert two VTEPs: localhost and a peer
	if err := UpsertVTEP(ctx, db, "net-flood", "host1", "10.10.0.1", 200); err != nil {
		t.Fatalf("UpsertVTEP host1: %v", err)
	}
	if err := UpsertVTEP(ctx, db, "net-flood", "host2", "10.10.0.2", 200); err != nil {
		t.Fatalf("UpsertVTEP host2: %v", err)
	}

	if err := SyncFloodEntries(ctx, db, "net-flood", "host1", 200); err != nil {
		t.Fatalf("SyncFloodEntries: %v", err)
	}

	// Should have called FloodEntry only for host2
	if len(calls) != 1 {
		t.Fatalf("expected 1 flood call (for host2 only), got %d: %v", len(calls), calls)
	}
	// Verify it's for host2's VTEP
	found := false
	for _, a := range calls[0] {
		if a == "10.10.0.2" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected flood entry for 10.10.0.2; calls: %v", calls)
	}
}
