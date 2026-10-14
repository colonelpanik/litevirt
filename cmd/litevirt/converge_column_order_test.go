package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/tests/fleet"
)

// `lv cluster converge` over a real two-node fleet whose replicas hold one
// identical snapshot row, node-1's `snapshots` laid out as a database founded
// at schema 0 and upgraded holds it (type, vmstate_path, vmstate_size_bytes
// after deleted_at). That pair is converged, and the report must say so: the
// table is not listed, and in particular not as DIVERGENT.
//
// Before digest_v2 was the default, every host was compared on the
// positional v1 hash, and this table read DIVERGENT on every run, for good.
//
// Mutation: default digestV2On to false for an unset predicate — the
// snapshots row comes back as `snapshots v1 DIVERGENT`.
func TestConverge_OlderFoundedReplicaReadsConverged(t *testing.T) {
	c := fleet.New(t, fleet.Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	for _, n := range []*fleet.Node{a, b} {
		if err := n.DB.Execute(ctx, `INSERT INTO snapshots
			(id, vm_name, host_name, name, state, size_bytes, type, vmstate_path, vmstate_size_bytes, created_at, updated_at)
			VALUES ('snap-colorder', 'colorder-vm', ?, 'before-upgrade', 'ready', 4096, 'memory', '/vmstate/x', 512,
			        '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`, a.Name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := b.DB.RefoundTableForTest(ctx, "snapshots", 0); err != nil {
		t.Fatal(err)
	}

	dig, err := c.SelfClient(b).GetClusterStateDigest(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if len(dig.GetHosts()) != 2 {
		t.Fatalf("precondition: the report should cover both hosts, got %d", len(dig.GetHosts()))
	}
	out := captureStdout(t, func() { printConvergence(dig) })
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "snapshots") {
			t.Fatalf("identical rows in another column order are reported, not converged:\n%s", out)
		}
	}
}
