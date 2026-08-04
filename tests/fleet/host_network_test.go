package fleet

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// hostNetRow reads one host_networks row from a node's OWN DB.
func hostNetRow(t *testing.T, n *Node, host, name string) (state, lastErr string, generation int64, exists bool) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT state, COALESCE(last_error,'') le, generation FROM host_networks
		 WHERE host_name = ? AND name = ? AND deleted_at IS NULL`, host, name)
	if err != nil {
		t.Fatalf("read %s host_networks: %v", n.Name, err)
	}
	if len(rows) == 0 {
		return "", "", 0, false
	}
	return rows[0].String("state"), rows[0].String("le"), rows[0].Int64("generation"), true
}

// TestFleet_HostNetworkApplyIsForwardedAndReplicated drives the whole spine
// from another node, the way an operator's `lv` pointed anywhere does: intent
// upsert for host B via node A (forwarded), plan via A (forwarded — shows B's
// rendered file), apply via A (forwarded — B's netplan file actually written),
// and the applied outcome replicated back to A.
func TestFleet_HostNetworkApplyIsForwardedAndReplicated(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	cli := c.SelfClient(a) // operator talks to A; the target host is B

	if _, err := cli.UpsertHostNetwork(ctx, &pb.UpsertHostNetworkRequest{Network: &pb.HostNetwork{
		HostName: b.Name, Name: "vmbr0", Kind: "bridge",
		Members: []string{"eth1"}, Addressing: `{"dhcp4":true}`,
	}}); err != nil {
		t.Fatalf("forwarded upsert: %v", err)
	}

	plan, err := cli.PlanHostNetwork(ctx, &pb.PlanHostNetworkRequest{HostName: b.Name})
	if err != nil {
		t.Fatalf("forwarded plan: %v", err)
	}
	if plan.NoOp || !strings.Contains(plan.Rendered, "vmbr0:") {
		t.Fatalf("plan must show B's rendered change: no_op=%v rendered=%q", plan.NoOp, plan.Rendered)
	}

	if _, err := cli.ApplyHostNetwork(ctx, &pb.ApplyHostNetworkRequest{HostName: b.Name}); err != nil {
		t.Fatalf("forwarded apply: %v", err)
	}
	// The TARGET's netplan file — not A's — carries the change.
	if file, exists := b.HostNet.File(); !exists || !strings.Contains(file, "vmbr0:") {
		t.Fatalf("B's managed file after apply: exists=%v %q", exists, file)
	}
	if file, exists := a.HostNet.File(); exists && strings.Contains(file, "vmbr0:") {
		t.Fatalf("A's netplan must be untouched, got %q", file)
	}
	if state, _, gen, ok := hostNetRow(t, b, b.Name, "vmbr0"); !ok || state != "applied" || gen != 1 {
		t.Fatalf("B row after apply: state=%q gen=%d ok=%v", state, gen, ok)
	}

	// The outcome replicates: A's view of B's wiring converges.
	pumpMutations(t, c, b, a)
	if state, _, gen, ok := hostNetRow(t, a, b.Name, "vmbr0"); !ok || state != "applied" || gen != 1 {
		t.Fatalf("A's replicated view: state=%q gen=%d ok=%v", state, gen, ok)
	}
}

// TestFleet_HostNetworkFailedConfirmRollsBackClusterWide: the apply that
// breaks connectivity reverts on the host AND the rolled_back outcome (with
// its cause) is what the rest of the cluster sees — an operator anywhere
// learns why, not just the node that broke.
func TestFleet_HostNetworkFailedConfirmRollsBackClusterWide(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	cli := c.SelfClient(a)

	if _, err := cli.UpsertHostNetwork(ctx, &pb.UpsertHostNetworkRequest{Network: &pb.HostNetwork{
		HostName: b.Name, Name: "vmbr9", Kind: "bridge",
	}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	b.HostNet.FailConfirm(errors.New("gateway unreachable"))

	_, err := cli.ApplyHostNetwork(ctx, &pb.ApplyHostNetworkRequest{HostName: b.Name})
	if err == nil {
		t.Fatal("an apply whose confirm fails must error")
	}
	if file, exists := b.HostNet.File(); exists && strings.Contains(file, "vmbr9:") {
		t.Fatalf("B's managed file must be restored after rollback, got %q", file)
	}
	state, lastErr, gen, ok := hostNetRow(t, b, b.Name, "vmbr9")
	if !ok || state != "rolled_back" || gen != 0 || lastErr == "" {
		t.Fatalf("B row after rollback: state=%q gen=%d lastErr=%q", state, gen, lastErr)
	}

	pumpMutations(t, c, b, a)
	if state, lastErr, _, ok := hostNetRow(t, a, b.Name, "vmbr9"); !ok || state != "rolled_back" || lastErr == "" {
		t.Fatalf("the rollback and its cause must replicate: state=%q lastErr=%q ok=%v", state, lastErr, ok)
	}

	// And the row recovers: confirm healthy again → the SAME intent applies.
	b.HostNet.FailConfirm(nil)
	if _, err := cli.ApplyHostNetwork(ctx, &pb.ApplyHostNetworkRequest{HostName: b.Name}); err != nil {
		t.Fatalf("re-apply after heal: %v", err)
	}
	if state, _, gen, _ := hostNetRow(t, b, b.Name, "vmbr9"); state != "applied" || gen != 1 {
		t.Fatalf("healed apply: state=%q gen=%d", state, gen)
	}
}

// TestFleet_HostNetworkCutoffNeedsANamedForce: the self-cutoff refusal and its
// written-confirmation override travel the full RPC path (forwarded), and the
// refusal names the interface the operator is about to disconnect.
func TestFleet_HostNetworkCutoffNeedsANamedForce(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	cli := c.SelfClient(a)

	// Enslave B's cluster interface (the fake reports net1 as the carrier).
	if _, err := cli.UpsertHostNetwork(ctx, &pb.UpsertHostNetworkRequest{Network: &pb.HostNetwork{
		HostName: b.Name, Name: "vmbr0", Kind: "bridge", Members: []string{"net1"},
	}}); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	plan, err := cli.PlanHostNetwork(ctx, &pb.PlanHostNetworkRequest{HostName: b.Name})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if plan.CutoffReason == "" || plan.ClusterInterface != "net1" {
		t.Fatalf("the plan must surface the cutoff before anyone applies: %+v", plan)
	}

	if _, err := cli.ApplyHostNetwork(ctx, &pb.ApplyHostNetworkRequest{HostName: b.Name}); err == nil ||
		!strings.Contains(err.Error(), "net1") {
		t.Fatalf("unforced apply must refuse naming the carrier: %v", err)
	}
	if _, err := cli.ApplyHostNetwork(ctx, &pb.ApplyHostNetworkRequest{
		HostName: b.Name, ForceInterface: "eth7",
	}); err == nil {
		t.Fatal("force naming the wrong interface must refuse")
	}
	if applies := b.HostNet.Applies(); applies != 0 {
		t.Fatalf("refused applies must never reach netplan, got %d", applies)
	}
	if _, err := cli.ApplyHostNetwork(ctx, &pb.ApplyHostNetworkRequest{
		HostName: b.Name, ForceInterface: "net1",
	}); err != nil {
		t.Fatalf("force naming the carrier must proceed: %v", err)
	}
	if state, _, _, _ := hostNetRow(t, b, b.Name, "vmbr0"); state != "applied" {
		t.Fatalf("forced apply outcome: %q", state)
	}
}
