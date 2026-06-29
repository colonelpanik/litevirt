package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
)

// TestGetVMIPRemote_PeerGatedAndContainer: the remote-IP discovery RPC is now
// peer-only (an operator/bearer caller is rejected — it was previously ungated),
// and owner_kind="ct" resolves a container by name via lxc-info.
func TestGetVMIPRemote_PeerGatedAndContainer(t *testing.T) {
	s := testServer(t) // hostName = "test-host"
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer-1", Address: "127.0.0.1", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	s.SetContainerRuntime(&fakeCTRuntime{ipByName: map[string]string{"web": "10.0.0.77"}})

	// Operator/bearer (non-peer) caller is REJECTED.
	if _, err := s.GetVMIPRemote(adminCtx(), &pb.GetVMIPRequest{Mac: "52:54:00:00:00:01"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator caller: got %v, want PermissionDenied", err)
	}
	// An unknown peer CN is also rejected.
	if _, err := s.GetVMIPRemote(mtlsCtx("ghost"), &pb.GetVMIPRequest{Mac: "52:54:00:00:00:01"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("unknown peer: got %v, want PermissionDenied", err)
	}
	// Peer mTLS with a known host CN is accepted; owner_kind=ct resolves via lxc-info.
	resp, err := s.GetVMIPRemote(mtlsCtx("peer-1"), &pb.GetVMIPRequest{OwnerKind: "ct", OwnerName: "web"})
	if err != nil {
		t.Fatalf("peer CT lookup: %v", err)
	}
	if resp.Ip != "10.0.0.77" {
		t.Errorf("CT IP = %q, want 10.0.0.77", resp.Ip)
	}

	// A wire-supplied bad container name is rejected BEFORE any runtime/DB touch.
	rt := s.containerRuntime.(*fakeCTRuntime)
	before := len(rt.ipCalls)
	if _, err := s.GetVMIPRemote(mtlsCtx("peer-1"), &pb.GetVMIPRequest{OwnerKind: "ct", OwnerName: "../bad"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad owner_name: got %v, want InvalidArgument", err)
	}
	if len(rt.ipCalls) != before {
		t.Errorf("runtime IPContainer was called for an invalid name: %v", rt.ipCalls)
	}
	// An empty container name is likewise rejected.
	if _, err := s.GetVMIPRemote(mtlsCtx("peer-1"), &pb.GetVMIPRequest{OwnerKind: "ct", OwnerName: ""}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty owner_name: got %v, want InvalidArgument", err)
	}
}

// TestDeleteContainer_RemovesDNSRecord: the delete cascade tombstones the
// container's auto DNS record (prompt — a lingering record could resolve to a
// freed/reassigned IP).
func TestDeleteContainer_RemovesDNSRecord(t *testing.T) {
	s := testServer(t)
	s.dnsDomain = "litevirt.local"
	s.SetContainerRuntime(&fakeCTRuntime{})
	ctx := adminCtx()

	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: s.hostName, Name: "ct1", State: "stopped", Project: "acme",
		Labels: map[string]string{corrosion.LabelStack: "prod"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := dns.UpsertRecord(ctx, s.db, "ct1.prod.litevirt.local", "10.0.0.5"); err != nil {
		t.Fatal(err)
	}

	if _, err := s.DeleteContainer(ctx, &pb.DeleteContainerRequest{Name: "ct1", HostName: s.hostName}); err != nil {
		t.Fatalf("DeleteContainer: %v", err)
	}
	if dnsRecordActive(t, s, "ct1.prod.litevirt.local") {
		t.Error("container DNS record was not removed on delete")
	}
}
