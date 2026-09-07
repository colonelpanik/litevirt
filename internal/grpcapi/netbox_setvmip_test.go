package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// SetVMIP against a network whose addresses NetBox owns.
//
// `lv config --ip` is a RECORD-ONLY edit: it writes an operator-supplied value
// into `vm_interfaces.ip` and updates DNS. On an unbound network that is
// inventory bookkeeping. On a BOUND one the address of record is NetBox's — the
// allocator claimed it, the lease row names the NetBox object, and the mirror
// keeps the assignment. An operator overwriting that field is describing a
// reality nothing enforces, and it is the boundary's job to say so, exactly as
// it already does for a container on a bound network.

// bindNetwork records a live binding for netName, making it a network whose
// addresses NetBox owns.
func bindNetwork(t *testing.T, s *Server, netName string, prefixID int) {
	t.Helper()
	if _, err := corrosion.ClaimBinding(context.Background(), s.db, corrosion.BindingRecord{
		PrefixID: prefixID, Network: netName, ObservedCIDR: "10.0.5.0/24", VRFID: 3,
		ClusterFingerprint: "abcdef0123456789",
	}); err != nil {
		t.Fatalf("ClaimBinding: %v", err)
	}
}

// TestSetVMIPRefusedOnABoundNetwork is the refusal.
//
// Two things go wrong without it, and the second is the one that damages state:
// the recorded value is a claim litevirt cannot honour, and the mirror joins a
// NIC to its NetBox address object through the lease — so an edited IP is also
// what makes the sweep stop recognising the assignment it is looking at.
func TestSetVMIPRefusedOnABoundNetwork(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "vm-1", "test-host", "running")
	bindNetwork(t, s, "bound", 7)

	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{
		Name: "vm-1", NetworkName: "bound", Ip: "10.0.5.200",
	})
	if err == nil {
		t.Fatal("recording an operator-chosen IP on a NetBox-bound network must be refused")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (%v)", c, err)
	}
	// The message must name the binding, not some generic failure: an operator
	// reading it has to know which network to look at and why.
	if !strings.Contains(err.Error(), "bound") {
		t.Fatalf("the error must name the bound network, got %v", err)
	}
}

// TestSetVMIPStillWorksOnAnUnboundNetwork is the control.
//
// The refusal is scoped to bound networks. On every other network the recorded
// IP is what the ARP and DHCP scanners fill in and what the UI shows, so a
// blanket refusal would break the ordinary case.
func TestSetVMIPStillWorksOnAnUnboundNetwork(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "vm-1", "test-host", "running")
	// A binding exists — on a DIFFERENT network. A refusal keyed on "any
	// binding at all" rather than on this VM's network would fail here.
	bindNetwork(t, s, "bound", 7)

	if _, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{
		Name: "vm-1", NetworkName: "unbound", Ip: "10.9.0.5",
	}); err != nil {
		t.Fatalf("SetVMIP on an unbound network: %v", err)
	}
}

// TestSetVMIPRefusedWhenTheBindingReadFails pins the fail-CLOSED direction.
//
// The container guard on this same question was once fail-open — a swallowed
// read error turned "could not read the record" into "the network names no
// prefix" and the write went ahead. A guard that cannot read its evidence has
// not cleared the operation.
func TestSetVMIPRefusedWhenTheBindingReadFails(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "vm-1", "test-host", "running")
	// Drop the table the guard reads. Nothing else on this path touches it, so
	// the only way through is a guard that treats an unreadable answer as "no
	// binding".
	if err := s.db.Execute(ctx, `DROP TABLE netbox_bindings`); err != nil {
		t.Fatalf("drop netbox_bindings: %v", err)
	}

	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{
		Name: "vm-1", NetworkName: "bound", Ip: "10.0.5.200",
	})
	if err == nil {
		t.Fatal("a binding read that failed must refuse the edit, not allow it")
	}
}

// TestSetVMIPRefusedWhenTheDefNamesAPrefixWithNoBinding is the state a direct
// binding read cannot see.
//
// A network whose CONFIG names a NetBox prefix while no binding row exists was
// never validated against NetBox and holds no claim on that prefix — the
// disagreement allocatorFor refuses loudly for every other address decision in
// this server. Read the binding row directly and the answer is "nil, therefore
// unbound", and an operator-chosen address is recorded across a space somebody
// believes is externally managed. Reachable from a compose file written before
// the refusal existed, or a binding released while its network survived.
func TestSetVMIPRefusedWhenTheDefNamesAPrefixWithNoBinding(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	insertTestVMR2(t, ctx, s.db, "vm-1", "test-host", "running")
	// The def names prefix 7; no ClaimBinding call, so there is no binding row.
	seedNetworkDef(t, s, "half-bound", compose.NetworkDef{
		Type: "bridge", Subnet: "10.0.5.0/24", NetBoxPrefixID: 7,
	})

	_, err := s.SetVMIP(ctx, &pb.SetVMIPRequest{
		Name: "vm-1", NetworkName: "half-bound", Ip: "10.0.5.200",
	})
	if err == nil {
		t.Fatal("a network whose config names a NetBox prefix with no binding row must be " +
			"refused, not treated as unbound")
	}
	if c := status.Code(err); c != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (%v)", c, err)
	}
	if !strings.Contains(err.Error(), "no binding exists") {
		t.Fatalf("the refusal must name the missing binding, got %v", err)
	}
}
