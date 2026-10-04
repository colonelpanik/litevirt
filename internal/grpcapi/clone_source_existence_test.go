package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestCloneVM_DoesNotLeakSourceExistence: CloneVM resolved the source and
// reported NotFound before any authorization ran, so an authenticated caller
// with no rights in the source's project could enumerate VM names by reading
// the status code — NotFound means the name is free, PermissionDenied means
// another tenant owns it. VM names routinely encode customer and service
// identity.
//
// The clone itself was always refused; the leak was existence and naming. A
// caller with no rights must get the SAME answer, code and message, whether
// the source exists or not.
func TestCloneVM_DoesNotLeakSourceExistence(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "acme-billing-db", HostName: s.hostName, State: "stopped", Project: "acme",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	// Control: the source really is there, so a difference below cannot come
	// from both lookups missing.
	if vm, err := corrosion.GetVM(ctx, s.db, "acme-billing-db"); err != nil || vm == nil {
		t.Fatalf("seeded source not readable: vm=%v err=%v", vm, err)
	}

	for _, caller := range []struct {
		name string
		ctx  context.Context
	}{
		{"authenticated viewer with no bindings", viewerCtx()},
		{"no principal", context.Background()},
	} {
		t.Run(caller.name, func(t *testing.T) {
			_, errPresent := s.CloneVM(caller.ctx, &pb.CloneVMRequest{Source: "acme-billing-db", Target: "mine"})
			_, errAbsent := s.CloneVM(caller.ctx, &pb.CloneVMRequest{Source: "no-such-vm-anywhere", Target: "mine"})
			if errPresent == nil || errAbsent == nil {
				t.Fatalf("a caller with no rights was not refused (present=%v absent=%v)", errPresent, errAbsent)
			}
			present, absent := status.Convert(errPresent), status.Convert(errAbsent)
			if present.Code() == codes.NotFound || absent.Code() == codes.NotFound {
				t.Fatalf("CloneVM answered NotFound before authorizing (present=%v absent=%v); "+
					"that is a cross-tenant existence oracle", errPresent, errAbsent)
			}
			if present.Code() != absent.Code() || present.Message() != absent.Message() {
				t.Errorf("a present and an absent source answered differently:\n present: %v %q\n  absent: %v %q\n"+
					"the difference is the oracle", present.Code(), present.Message(), absent.Code(), absent.Message())
			}
		})
	}
}
