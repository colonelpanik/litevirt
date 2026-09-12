package grpcapi

import (
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// boundRefusalServer is a server that CAN resolve a bound network: a real
// NetBox client (pointed at a port nothing listens on — allocatorFor never calls
// it, and a claim that did would fail loudly rather than silently pass).
func boundRefusalServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	client, err := netbox.New(netbox.Config{BaseURL: "http://127.0.0.1:1", TokenPath: writeTokenFile(t)})
	if err != nil {
		t.Fatalf("netbox.New: %v", err)
	}
	s.SetNetBoxClient(client)
	return s
}

// TestRefuseIfBoundRefusesEveryUnsafeShape pins the shared refusal the four
// VM-creating paths that do NOT claim now run — clone, restore, import and a
// renamed promote.
//
// Two of those cannot be driven end-to-end from the fleet harness: an import
// needs a foreign-hypervisor source archive to parse, and a promotion needs a
// disk replica plus a proof-grade fence. So the helper itself is pinned here,
// and TestEveryNonClaimingCreatePathCallsTheRefusal pins that each of the four
// still calls it.
//
// The refusal resolves through allocatorFor rather than reading the binding row
// itself, so the fail-closed cases below are INHERITED from the selector.
// Pinning them here is what stops a later "simplification" into a bare
// `GetBindingByNetwork() != nil` check, which would silently drop all of them.
func TestRefuseIfBoundRefusesEveryUnsafeShape(t *testing.T) {
	ctx := context.Background()

	t.Run("bound network, naming the op and the network", func(t *testing.T) {
		s := boundRefusalServer(t)
		seedNetworkDef(t, s, "bound", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24", NetBoxPrefixID: 7})
		seedBinding(t, s, "bound", 7, false)

		err := s.refuseIfBound(ctx, "clone", []string{"bound"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("want FailedPrecondition, got %v", err)
		}
		if !strings.Contains(err.Error(), "clone") {
			t.Fatalf("the refusal must name the operation, got: %v", err)
		}
		if !strings.Contains(err.Error(), `"bound"`) {
			t.Fatalf("the refusal must name the network, got: %v", err)
		}
		if !strings.Contains(err.Error(), "lv run") {
			t.Fatalf("the refusal must say what to do instead, got: %v", err)
		}
	})

	t.Run("unbound network is allowed", func(t *testing.T) {
		s := boundRefusalServer(t)
		seedNetworkDef(t, s, "plain", compose.NetworkDef{Type: "bridge", Subnet: "10.0.5.0/24"})

		if err := s.refuseIfBound(ctx, "clone", []string{"plain"}); err != nil {
			t.Fatalf("an unbound network must not be refused: %v", err)
		}
	})

	t.Run("a flat bridge with no record at all is allowed", func(t *testing.T) {
		s := boundRefusalServer(t)
		if err := s.refuseIfBound(ctx, "clone", []string{"br0"}); err != nil {
			t.Fatalf("a bare bridge name must not be refused: %v", err)
		}
	})

	t.Run("a config naming a prefix with no binding is refused", func(t *testing.T) {
		// The disagreement case: something believes the prefix is externally
		// managed, but nothing validated or claimed it. Allocating around it is
		// the silent double-allocation the design exists to prevent, so a create
		// onto it must not proceed either.
		s := boundRefusalServer(t)
		seedNetworkDef(t, s, "half-bound", compose.NetworkDef{Type: "bridge", NetBoxPrefixID: 7})

		err := s.refuseIfBound(ctx, "restore", []string{"half-bound"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("want FailedPrecondition, got %v", err)
		}
		if !strings.Contains(err.Error(), "no binding exists") {
			t.Fatalf("the refusal must explain the disagreement, got: %v", err)
		}
	})

	t.Run("a suspended binding is refused", func(t *testing.T) {
		s := boundRefusalServer(t)
		seedNetworkDef(t, s, "bound", compose.NetworkDef{Type: "bridge", NetBoxPrefixID: 7})
		seedBinding(t, s, "bound", 7, true)

		err := s.refuseIfBound(ctx, "import", []string{"bound"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("want FailedPrecondition, got %v", err)
		}
		if !strings.Contains(err.Error(), "suspended") {
			t.Fatalf("the refusal must name the suspension, got: %v", err)
		}
	})

	t.Run("one bound NIC among several is enough", func(t *testing.T) {
		s := boundRefusalServer(t)
		seedNetworkDef(t, s, "plain", compose.NetworkDef{Type: "bridge", Subnet: "10.0.9.0/24"})
		seedNetworkDef(t, s, "bound", compose.NetworkDef{Type: "bridge", NetBoxPrefixID: 7})
		seedBinding(t, s, "bound", 7, false)

		err := s.refuseIfBound(ctx, "promote --new-name", []string{"plain", "bound"})
		if err == nil {
			t.Fatal("a VM with ANY NIC on a bound network must be refused")
		}
		if !strings.Contains(err.Error(), `"bound"`) {
			t.Fatalf("the refusal must name the BOUND network, got: %v", err)
		}
	})

	t.Run("an empty network list is allowed", func(t *testing.T) {
		s := boundRefusalServer(t)
		if err := s.refuseIfBound(ctx, "clone", nil); err != nil {
			t.Fatalf("a NIC-less VM must not be refused: %v", err)
		}
	})
}

// TestRefuseRebuildIfBoundReadsTheNICRowsNotTheSpec pins where the rebuild
// refusal gets its network list.
//
// A hot-attached NIC exists as a vm_nics row long before any stored spec names
// it, and the rebuild copies its addresses from the ROWS. A refusal that read
// the spec instead would wave through exactly the VM whose NIC was added after
// creation — and hotplug onto a bound network is the case that claims.
func TestRefuseRebuildIfBoundReadsTheNICRowsNotTheSpec(t *testing.T) {
	s := boundRefusalServer(t)
	ctx := context.Background()
	seedNetworkDef(t, s, "bound", compose.NetworkDef{Type: "bridge", NetBoxPrefixID: 7})
	seedBinding(t, s, "bound", 7, false)

	// A VM whose stored spec declares NO networks at all, with a NIC row that
	// does — the shape a hot attach leaves behind.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm-1", HostName: s.hostName, State: "running",
			Spec: `{"name":"vm-1","uuid":"6f1b0c2e-0000-4000-8000-0000000000aa"}`},
		[]corrosion.InterfaceRecord{{
			VMName: "vm-1", NetworkName: "bound", Ordinal: 0,
			MAC: "52:54:00:0a:0b:0c", IP: "10.0.5.100",
		}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	err := s.refuseRebuildIfBound(ctx, "vm-1")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
	if !strings.Contains(err.Error(), "rebuild") || !strings.Contains(err.Error(), `"bound"`) {
		t.Fatalf("the refusal must name the operation and the network, got: %v", err)
	}
	if !strings.Contains(err.Error(), "delete and recreate") {
		t.Fatalf("the refusal must say what to do instead, got: %v", err)
	}
}

// TestRefuseRebuildIfBoundAllowsAnUnboundVM is the control: rebuild must keep
// working everywhere else.
func TestRefuseRebuildIfBoundAllowsAnUnboundVM(t *testing.T) {
	s := boundRefusalServer(t)
	ctx := context.Background()
	seedNetworkDef(t, s, "plain", compose.NetworkDef{Type: "bridge", Subnet: "10.0.9.0/24"})

	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "vm-1", HostName: s.hostName, State: "running",
			Spec: `{"name":"vm-1","uuid":"6f1b0c2e-0000-4000-8000-0000000000ab"}`},
		[]corrosion.InterfaceRecord{{
			VMName: "vm-1", NetworkName: "plain", Ordinal: 0, MAC: "52:54:00:0a:0b:0d",
		}}, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	if err := s.refuseRebuildIfBound(ctx, "vm-1"); err != nil {
		t.Fatalf("a VM on an unbound network must still be rebuildable: %v", err)
	}
}

// TestEveryNonClaimingCreatePathCallsTheRefusal is a SOURCE guard.
//
// The defect this change answers was not a wrong implementation, it was a
// MISSING CALL: the claim/release pair was wired into CreateVM and DeleteVM and
// into nothing else, while four other paths minted VM rows without it. Nothing
// in the type system says a new create path has to consult the allocator, and
// two of these four cannot be driven from the fleet harness at all — so the only
// thing that can notice a call going missing again is a check that it is there.
//
// Matched on the OP LITERAL, not just the function name: a call with the wrong
// op string produces a refusal naming the wrong operation, which is the
// difference between an operator fixing their command and filing a bug.
func TestEveryNonClaimingCreatePathCallsTheRefusal(t *testing.T) {
	cases := []struct {
		file string
		want string
		why  string
	}{
		{"templates.go", `s.refuseIfBound(ctx, "clone"`,
			"CloneVM rebuilds the source's NICs and persists them without claiming"},
		{"restore_live_autostart.go", `s.refuseIfBound(ctx, "restore"`,
			"autoDefineRestoredVM rebuilds NIC rows from the backed-up spec, addresses included"},
		{"vmimport.go", `s.refuseIfBound(ctx, "import"`,
			"importRecords builds NIC rows from a foreign hypervisor's NICs"},
		{"promote.go", `s.refuseIfBound(ctx, "promote --new-name"`,
			"a renamed promotion writes a SECOND VM row while the original still holds its addresses"},
		{"vm.go", "s.refuseRebuildIfBound(ctx,",
			"RebuildVM destroys the disks and the row before its recreate can be refused"},
	}
	for _, tc := range cases {
		src, err := os.ReadFile(tc.file)
		if err != nil {
			t.Fatalf("read %s: %v", tc.file, err)
		}
		if !strings.Contains(string(src), tc.want) {
			t.Errorf("%s no longer calls %s — %s", tc.file, tc.want, tc.why)
		}
	}
}

// TestEveryVMRowDeletingPathReleasesItsLeases is the other half of that source
// guard.
//
// Four paths tombstone a VM row. DeleteVM releases inline and SURFACES a failure;
// a stale-record cleanup runs because the VM is gone everywhere and a rebuild
// re-creates immediately, so both call the best-effort form. Either way the
// release must be there: a lease that outlives its row is one the sweeper's
// live-lease veto can never reclaim.
//
// Cutover is the exception, and deliberately so. Releasing before its transition
// meant a delete that then declined left a LIVE VM whose address had already gone
// back to the pool — and a best-effort release that failed stranded the address
// under a cutover reporting success. It captures the addresses in its operation
// manifest instead and gives them back in a journaled, retryable phase after the
// transition commits, so this guards that mechanism rather than the call.
func TestEveryVMRowDeletingPathReleasesItsLeases(t *testing.T) {
	src, err := os.ReadFile("vm.go")
	if err != nil {
		t.Fatalf("read vm.go: %v", err)
	}
	for _, op := range []string{"delete-stale-record", "rebuild"} {
		want := `s.releaseNICLeasesBestEffort(ctx, ` // op is the trailing argument
		if !strings.Contains(string(src), want+"vm, \""+op+"\")") &&
			!strings.Contains(string(src), want+"oldVM, \""+op+"\")") {
			t.Errorf("the %q path no longer releases its NIC leases before tombstoning the VM row", op)
		}
	}
	if !strings.Contains(string(src), "manifest.Leases = leases") {
		t.Error("the cutover path no longer captures the replaced VM's addresses into its manifest")
	}
	cleanup, err := os.ReadFile("vm_replace_cleanup.go")
	if err != nil {
		t.Fatalf("read vm_replace_cleanup.go: %v", err)
	}
	for _, want := range []string{"releaseReplacedVMAddresses", "corrosion.OpStepReleased"} {
		if !strings.Contains(string(cleanup), want) {
			t.Errorf("the cutover path no longer releases its addresses through %s", want)
		}
	}
}
