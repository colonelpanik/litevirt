// Fleet scenario: GetHostStats' per-row RBAC filter must survive a forward.
//
// internal/grpcapi covers GetHostStats' LOCAL per-row canReadVM filter with a
// single-node, single-process test — but that filter is applied on whichever
// node actually computes the answer, and for a remote host's stats that is the
// OWNING node, reached by a server-to-server forward under the FORWARDING
// node's own host certificate (admin, unless auth.forwarded_identity is on and
// ForwardedIdentityV1 has latched — default off). A single-process test
// structurally cannot reach this: there is no second identity to lose. Only a
// real two-node fleet, with a real forwarded RPC under a real peer
// certificate, proves the entry node re-applies the ORIGINAL caller's scope
// to what the owner sends back, rather than relaying the owner's
// (unfiltered, because it saw "admin") answer verbatim.
package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func TestFleet_GetHostStats_ForwardRespectsCallerScope(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	entry, owner := c.Node("node-0"), c.Node("node-1")

	// Two VMs on the REMOTE node: one in the caller's own project, one in a
	// project the caller must not see.
	for _, v := range []struct{ name, project string }{{"a1", "acme"}, {"b1", "beta"}} {
		if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
			Name: v.name, HostName: owner.Name, State: "running", Project: v.project,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM(%s): %v", v.name, err)
		}
		owner.Virt.SetState(v.name, libvirtfake.StateRunning)
	}
	// Replicate the owner's vms rows to the entry node. GetHostStats' per-row
	// filter (wherever it runs) reads LOCALLY off corrosion — same requirement
	// InspectVM/GetVMStats/ListVMHardware/etc. already have — so the entry
	// node must hold these rows before it can judge them at all.
	dump := pullDump(t, c, owner)
	if err := entry.DB.MergeStateBytesLWW(dump); err != nil {
		t.Fatalf("merge owner's state into entry: %v", err)
	}

	// The fleet harness does not wire a path-based auth engine by default (no
	// existing fleet scenario exercises role bindings) — without one,
	// RequirePerm/RequirePermResolved skip straight to the legacy
	// no-bindings role fallback for every caller, which would pass carol on
	// role alone and prove nothing about scope. Wire a real engine on the
	// entry node, the same way a daemon does at startup.
	engine := auth.NewEngine(entry.DB)
	if err := auth.SeedBuiltinRoles(ctx, entry.DB); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	entry.Server.SetAuthEngine(engine)

	// A real scoped user, authenticated end-to-end: bound at /projects/acme,
	// Viewer role, with a real session token — not an injected ctx.
	if _, err := c.SelfClient(entry).CreateUser(ctx, &pb.CreateUserRequest{
		Username: "carol", Password: "carols-password-0123456789", Role: "viewer",
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := c.SelfClient(entry).GrantRole(ctx, &pb.GrantRoleRequest{
		Path: "/projects/acme", Role: "Viewer", Principal: "user:carol@local", Propagate: true,
	}); err != nil {
		t.Fatalf("GrantRole: %v", err)
	}
	login, err := c.SelfClient(entry).Login(ctx, &pb.LoginRequest{
		Username: "carol", Password: "carols-password-0123456789",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	carol := c.bearerClient(entry, login.Token)

	// Ask the ENTRY node for the OWNER's host stats: entry.hostName !=
	// owner.hostName, so this drives the forward — the owner computes the
	// answer and sees the call under entry's host certificate (admin).
	resp, err := carol.GetHostStats(ctx, &pb.GetHostStatsRequest{Name: owner.Name})
	if err != nil {
		t.Fatalf("GetHostStats (forwarded): %v", err)
	}
	var names []string
	for _, vs := range resp.GetVmStats() {
		names = append(names, vs.GetName())
	}
	if len(names) != 1 || names[0] != "a1" {
		t.Fatalf("forwarded VmStats = %v, want exactly [a1] — b1 (carol's scope does not cover "+
			"project beta) leaked through the forward, which answers under the entry node's own "+
			"host identity rather than carol's", names)
	}
}
