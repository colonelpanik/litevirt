package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// DeleteVM refuses to free disks that still back live linked clones, because
// removing a backing file corrupts every overlay on top of it — unrecoverably,
// since the overlay holds only the delta.
//
// That guard was `gErr == nil && len(clones) > 0`, so a failed lookup meant "no
// clones" and the delete proceeded. The sibling guard in ConvertToTemplate
// (templates.go) fails closed on the same call, and DeleteVM itself fails closed
// on an unreadable NIC list seventy lines further down, so this was an
// inconsistency rather than a policy.
//
// vm_disks is dropped to make the lookup fail deterministically.
func TestDeleteVM_AFailedLinkedCloneLookupRefusesRatherThanDeletes(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "base", HostName: s.hostName, State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := s.db.Execute(ctx, `DROP TABLE vm_disks`); err != nil {
		t.Fatalf("DROP TABLE vm_disks: %v", err)
	}

	_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "base"})

	if err == nil {
		t.Fatal("DeleteVM proceeded with an unreadable vm_disks; a failed linked-clone " +
			"lookup must not read as 'no clones depend on this'")
	}
	if code := status.Code(err); code != codes.Internal {
		t.Errorf("code = %s, want Internal (the lookup failed; nothing about the request was wrong)", code)
	}
}
