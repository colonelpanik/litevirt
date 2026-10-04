package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// colonelpanik/litevirt#229: `lv host add` run from a workstation has no local
// config to back-fill, so the founder keeps `join_peers: []`. refuseIfAlreadyAMember
// reads only that field, so `lv host init` pointed back at the founder — the
// natural-looking rebuild after its disk is lost — is not refused, and the
// rebuilt founder mints its own admin. The workstation can still see the
// cluster, and the cluster lists the founder beside its peers.

type initMemberTestClient struct {
	pb.LiteVirtClient
	hosts []*pb.Host
	err   error
}

func (c *initMemberTestClient) ListHosts(context.Context, *pb.ListHostsRequest, ...grpc.CallOption) (*pb.ListHostsResponse, error) {
	if c.err != nil {
		return nil, c.err
	}
	return &pb.ListHostsResponse{Hosts: c.hosts}, nil
}

func TestHostInit_RefusesAFounderTheClusterStillLists(t *testing.T) {
	c := &initMemberTestClient{hosts: []*pb.Host{
		{Name: "node-1", Address: "10.0.50.10"},
		{Name: "node-2", Address: "10.0.50.11"},
	}}
	err := refuseInitOfAClusterMember(context.Background(), c, "10.0.50.10")
	if err == nil {
		t.Fatal("init against a host the cluster lists beside other members was allowed; " +
			"its founder would mint an admin of its own")
	}
	for _, want := range []string{"node-1", "lv host rm node-1", "lv host add", "--force"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q: %v", want, err)
		}
	}
}

// Re-running init against a half-finished FIRST node is the normal repair, and
// that node is the only host its cluster lists.
func TestHostInit_AllowsTheOnlyHostOfItsCluster(t *testing.T) {
	c := &initMemberTestClient{hosts: []*pb.Host{{Name: "node-1", Address: "10.0.50.10"}}}
	if err := refuseInitOfAClusterMember(context.Background(), c, "10.0.50.10"); err != nil {
		t.Fatalf("re-initialising a cluster's only host was refused: %v", err)
	}
}

func TestHostInit_AllowsAnAddressTheClusterDoesNotList(t *testing.T) {
	c := &initMemberTestClient{hosts: []*pb.Host{
		{Name: "node-1", Address: "10.0.50.10"},
		{Name: "node-2", Address: "10.0.50.11"},
	}}
	if err := refuseInitOfAClusterMember(context.Background(), c, "10.0.60.10"); err != nil {
		t.Fatalf("a fresh address was refused: %v", err)
	}
}

// No cluster to ask is what a genesis looks like from a workstation; the
// target-side checks and the daemon's genesis gate still apply.
func TestHostInit_AnUnreadableClusterDoesNotBlockInit(t *testing.T) {
	c := &initMemberTestClient{err: errors.New("connection refused")}
	if err := refuseInitOfAClusterMember(context.Background(), c, "10.0.50.10"); err != nil {
		t.Fatalf("an unreachable cluster blocked init: %v", err)
	}
}
