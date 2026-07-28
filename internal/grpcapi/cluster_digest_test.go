package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type fakeAE struct{ ran bool }

func (f fakeAE) RunOnce(context.Context) bool { return f.ran }

// TestTriggerAntiEntropy_Local: the local kick reports triggered vs debounced from RunOnce.
func TestTriggerAntiEntropy_Local(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()

	s.antiEntropy = fakeAE{ran: true}
	r, err := s.TriggerAntiEntropy(ctx, &pb.TriggerAntiEntropyRequest{All: false})
	if err != nil {
		t.Fatalf("TriggerAntiEntropy: %v", err)
	}
	if len(r.GetTriggered()) != 1 || r.GetTriggered()[0] != s.hostName {
		t.Fatalf("triggered = %v, want [%s]", r.GetTriggered(), s.hostName)
	}
	if len(r.GetDebounced()) != 0 {
		t.Fatalf("debounced = %v, want none", r.GetDebounced())
	}

	s.antiEntropy = fakeAE{ran: false}
	r, _ = s.TriggerAntiEntropy(ctx, &pb.TriggerAntiEntropyRequest{All: false})
	if len(r.GetDebounced()) != 1 {
		t.Fatalf("debounced = %v, want [%s]", r.GetDebounced(), s.hostName)
	}
}

// TestGetClusterStateDigest_SelfOnly: with no active peers, the aggregation returns just this host.
func TestGetClusterStateDigest_SelfOnly(t *testing.T) {
	s := testServer(t)
	r, err := s.GetClusterStateDigest(adminCtx(), &emptypb.Empty{})
	if err != nil {
		t.Fatalf("GetClusterStateDigest: %v", err)
	}
	if len(r.GetHosts()) != 1 || r.GetHosts()[0].GetHostName() != s.hostName {
		t.Fatalf("hosts = %v, want self only", r.GetHosts())
	}
}
