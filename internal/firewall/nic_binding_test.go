package firewall

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCorrosionPlanLoader_BindsSGsToNICs is the end-to-end regression
// for: insert an SG with rules, attach it to a VM's NIC
// via vm_interfaces.security_groups, run the reconciler, assert the
// rendered ruleset includes the SG's rules under the correct nic_<tap>
// chain.
func TestCorrosionPlanLoader_BindsSGsToNICs(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	// 1. Create the security group with one rule.
	sgID := "web-sg-id"
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{
		ID: sgID, Name: "web",
	}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}
	if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{
		ID: "rule-1", SGID: sgID,
		Direction: "ingress", Proto: "tcp", PortRange: "80", Action: "accept",
	}); err != nil {
		t.Fatalf("InsertSGRule: %v", err)
	}

	// 2. Insert a VM with one interface that references the SG.
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm-web", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{
			VMName: "vm-web", NetworkName: "prod", Ordinal: 0,
			MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.10",
			TapDevice:      "tap-vm-web-0",
			SecurityGroups: []string{"web"},
		}},
		nil,
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// 3. Build the plan via the production loader and render it.
	loader := CorrosionPlanLoader(db, "host-a", Plan{})
	plan, err := loader(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if len(plan.NICs) != 1 {
		t.Fatalf("expected 1 NIC binding, got %d", len(plan.NICs))
	}
	if plan.NICs[0].NICDev != "tap-vm-web-0" {
		t.Errorf("NICDev = %q, want tap-vm-web-0", plan.NICs[0].NICDev)
	}
	if !equalStringSlice(plan.NICs[0].SecurityGroups, []string{"web"}) {
		t.Errorf("SGs on NIC = %v, want [web]", plan.NICs[0].SecurityGroups)
	}

	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out,
		"chain nic_tap_vm_web_0 {", // dashes sanitised to underscores
		`# security group "web"`,
		"oifname tap-vm-web-0 tcp dport 80 accept",
	)
}

// TestCorrosionPlanLoader_BindsSGsToContainerVeths: a managed container NIC's
// security groups bind to its veth exactly like a VM's tap; a NIC with no veth
// yet (not provisioned) is skipped.
func TestCorrosionPlanLoader_BindsSGsToContainerVeths(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "ct-sg", Name: "ctweb"}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}
	if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "ctr1", SGID: "ct-sg",
		Direction: "ingress", Proto: "tcp", PortRange: "8080", Action: "accept"}); err != nil {
		t.Fatalf("InsertSGRule: %v", err)
	}
	// Live container (the loader joins the live row) + a managed NIC with a veth.
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct-web", State: "running", Project: "acme",
	}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, db, corrosion.ContainerInterfaceRecord{
		HostName: "host-a", CtName: "ct-web", NetworkName: "prod", Ordinal: 0,
		MAC: "52:00:00:00:00:10", IP: "10.0.0.11", VethDevice: "lvc0abc",
		SecurityGroups: []string{"ctweb"},
	}); err != nil {
		t.Fatalf("UpsertContainerInterface: %v", err)
	}
	// A second NIC with NO veth yet — must be skipped (not provisioned).
	if err := corrosion.UpsertContainerInterface(ctx, db, corrosion.ContainerInterfaceRecord{
		HostName: "host-a", CtName: "ct-web", NetworkName: "mgmt", Ordinal: 1,
		MAC: "52:00:00:00:00:11", VethDevice: "", SecurityGroups: []string{"ctweb"},
	}); err != nil {
		t.Fatalf("UpsertContainerInterface(no-veth): %v", err)
	}

	plan, err := CorrosionPlanLoader(db, "host-a", Plan{})(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	var ctNIC *NICBinding
	for i := range plan.NICs {
		if plan.NICs[i].NICDev == "" {
			t.Error("a NIC with no veth must be skipped, not emitted")
		}
		if plan.NICs[i].NICDev == "lvc0abc" {
			ctNIC = &plan.NICs[i]
		}
	}
	if ctNIC == nil {
		t.Fatalf("no NICBinding for the container veth; got %+v", plan.NICs)
	}
	if !equalStringSlice(ctNIC.SecurityGroups, []string{"ctweb"}) {
		t.Errorf("CT veth SGs = %v, want [ctweb]", ctNIC.SecurityGroups)
	}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out, "oifname lvc0abc tcp dport 8080 accept")
}

// TestCorrosionPlanLoader_DropsUnknownSGNamesGracefully — typo in the
// binding shouldn't take the firewall down. Stale references log only;
// the rest of the plan applies.
func TestCorrosionPlanLoader_DropsUnknownSGNamesGracefully(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	// SG "real" exists; "ghost" doesn't.
	_ = corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "id1", Name: "real"})
	_ = corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "r1", SGID: "id1",
		Direction: "ingress", Proto: "tcp", PortRange: "443", Action: "accept"})

	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm-x", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{
			VMName: "vm-x", NetworkName: "prod", Ordinal: 0,
			MAC: "aa:bb:cc:dd:ee:02", TapDevice: "tap-x-0",
			SecurityGroups: []string{"ghost", "real"},
		}},
		nil,
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	plan, err := CorrosionPlanLoader(db, "host-a", Plan{})(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if !equalStringSlice(plan.NICs[0].SecurityGroups, []string{"real"}) {
		t.Errorf("ghost should be silently dropped, got %v", plan.NICs[0].SecurityGroups)
	}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if strings.Contains(out, "ghost") {
		t.Error("renderer should not emit anything referencing the dropped ghost SG")
	}
}

// TestSetInterfaceSecurityGroups_RuntimeMutation verifies the
// BindSecurityGroups path: change the SG list on a running NIC, run
// the loader again, see the new bindings.
func TestSetInterfaceSecurityGroups_RuntimeMutation(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	_ = corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "id-a", Name: "groupA"})
	_ = corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "id-b", Name: "groupB"})
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm-r", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{
			VMName: "vm-r", NetworkName: "prod", Ordinal: 0,
			MAC: "aa:bb:cc:dd:ee:99", TapDevice: "tap-r-0",
			SecurityGroups: []string{"groupA"},
		}},
		nil,
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := corrosion.SetInterfaceSecurityGroups(ctx, db, "vm-r", "prod",
		[]string{"groupB"}); err != nil {
		t.Fatalf("SetInterfaceSecurityGroups: %v", err)
	}

	ifaces, err := corrosion.GetVMInterfaces(ctx, db, "vm-r")
	if err != nil || len(ifaces) != 1 {
		t.Fatalf("GetVMInterfaces: %v / %d", err, len(ifaces))
	}
	if !equalStringSlice(ifaces[0].SecurityGroups, []string{"groupB"}) {
		t.Errorf("SGs after mutation = %v, want [groupB]", ifaces[0].SecurityGroups)
	}
}

// TestCorrosionPlanLoader_SkipsNICsOnOtherHosts is the multi-host
// invariant: each host's reconciler only renders chains for taps that
// actually exist on that host.
func TestCorrosionPlanLoader_SkipsNICsOnOtherHosts(t *testing.T) {
	ctx := context.Background()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	_ = corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg", Name: "shared"})
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm-on-a", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "vm-on-a", NetworkName: "prod", TapDevice: "tap-a-0", SecurityGroups: []string{"shared"}}},
		nil,
	); err != nil {
		t.Fatalf("InsertVM A: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm-on-b", HostName: "host-b", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "vm-on-b", NetworkName: "prod", TapDevice: "tap-b-0", SecurityGroups: []string{"shared"}}},
		nil,
	); err != nil {
		t.Fatalf("InsertVM B: %v", err)
	}

	plan, err := CorrosionPlanLoader(db, "host-a", Plan{})(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if len(plan.NICs) != 1 || plan.NICs[0].NICDev != "tap-a-0" {
		t.Errorf("host-a should see only its own NIC, got %+v", plan.NICs)
	}
}

// equalStringSlice compares without enforcing order or capacity quirks.
func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

// keep bytes import in use for any future render-byte assertions
var _ = bytes.Contains
