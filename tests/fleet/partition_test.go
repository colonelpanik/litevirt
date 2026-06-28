package fleet

import (
	"context"
	"io"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// peerPull pulls target's full-state dump while presenting source's identity —
// the real direction anti-entropy dials (a node pulls a peer using its OWN
// cert). Returns the reassembled blob, or the RPC error (e.g. when partitioned).
func peerPull(c *Cluster, source, target *Node) ([]byte, error) {
	stream, err := c.PeerClient(source, target).StreamStateDump(context.Background(), &emptypb.Empty{})
	if err != nil {
		return nil, err
	}
	var blob []byte
	for {
		chunk, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
		blob = append(blob, chunk.Data...)
	}
	return blob, nil
}

// TestFleet_PartitionBlocksReplication proves the harness partition gate drops
// replication/state-sync RPCs (both streaming and unary) from a partitioned peer
// while leaving non-replication RPCs alone, and that Heal restores them.
func TestFleet_PartitionBlocksReplication(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Node("node-0"), c.Node("node-1")
	ctx := context.Background()

	// Healthy: b can pull a's dump and read its digest.
	if _, err := peerPull(c, b, a); err != nil {
		t.Fatalf("pre-partition StreamStateDump should succeed: %v", err)
	}
	if _, err := c.PeerClient(b, a).GetStateDigest(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("pre-partition GetStateDigest should succeed: %v", err)
	}

	c.Partition(a, b)

	// Streaming dump is refused (stream interceptor).
	if _, err := peerPull(c, b, a); status.Code(err) != codes.Unavailable {
		t.Fatalf("partitioned StreamStateDump: got %v, want Unavailable", err)
	}
	// Unary digest is refused (unary interceptor).
	if _, err := c.PeerClient(b, a).GetStateDigest(ctx, &emptypb.Empty{}); status.Code(err) != codes.Unavailable {
		t.Fatalf("partitioned GetStateDigest: got %v, want Unavailable", err)
	}
	// A non-replication RPC is unaffected by the partition.
	if _, err := c.PeerClient(b, a).Ping(ctx, &pb.PingRequest{}); err != nil {
		t.Fatalf("partition must not block non-replication RPCs (Ping): %v", err)
	}

	c.Heal(a, b)

	if _, err := peerPull(c, b, a); err != nil {
		t.Fatalf("post-heal StreamStateDump should succeed: %v", err)
	}
	if _, err := c.PeerClient(b, a).GetStateDigest(ctx, &emptypb.Empty{}); err != nil {
		t.Fatalf("post-heal GetStateDigest should succeed: %v", err)
	}
}

// TestFleet_PartitionHealReconverges writes on one side of a partition, confirms
// the other side cannot pull it across the severed link, then heals and confirms
// anti-entropy (the real StreamStateDump→merge path) reconverges the lagging node.
func TestFleet_PartitionHealReconverges(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Node("node-0"), c.Node("node-1")
	ctx := context.Background()

	if err := corrosion.InsertHost(ctx, a.DB, corrosion.HostRecord{
		Name: "wl", Address: "10.0.0.9", SSHUser: "root", CertSerial: "s", State: "active",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}

	c.Partition(a, b)

	// Write a VM on a while partitioned.
	if err := corrosion.InsertVM(ctx, a.DB,
		corrosion.VMRecord{Name: "vm1", HostName: "wl", Spec: "{}", State: "running"}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	// b cannot pull it across the partition, so it stays behind.
	if _, err := peerPull(c, b, a); status.Code(err) != codes.Unavailable {
		t.Fatalf("partitioned pull: got %v, want Unavailable", err)
	}
	if got := rowCount(t, b, "SELECT count(*) AS n FROM vms WHERE name = ?", "vm1"); got != 0 {
		t.Fatalf("b should not have vm1 while partitioned, count=%d", got)
	}

	// Heal → anti-entropy pull succeeds → b reconverges.
	c.Heal(a, b)
	blob, err := peerPull(c, b, a)
	if err != nil {
		t.Fatalf("post-heal pull: %v", err)
	}
	b.DB.MergeStateBytesLWW(blob)
	if got := rowCount(t, b, "SELECT count(*) AS n FROM vms WHERE name = ?", "vm1"); got != 1 {
		t.Fatalf("b should have vm1 after heal+merge, count=%d (reconvergence failed)", got)
	}
}
