// Fleet scenarios for CONVERT-TO-TEMPLATE on a NetBox-bound network.
//
// A template is invisible to the inventory mirror: desiredState skips it. So a
// VM converted while holding a NetBox address leaves the mirror's next pass to
// delete the `virtual_machine` object, cascade away the `vminterface` under it,
// and unassign the address — while the local `ip_allocations` row stays LIVE.
//
// That live row is exactly what the orphan sweeper's absence proof vetoes on, and
// vetoes on correctly: a live lease is litevirt still holding the address. The
// result is an address carrying a litevirt identity, assigned to nothing, named
// by no inventory object, held indefinitely, and invisible to BOTH reclaim paths
// — the sweeper because the lease is live, the mirror because the VM is a
// template.
//
// None of it is reachable from a single-package test: it needs a real bound
// prefix, a real claim, and a real mirror pass.

package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestConvertToTemplateRefusedOnABoundNetwork.
//
// The refusal is the same shape as the clone, restore, import and rebuild
// refusals: a VM on a bound network is not put through a path that would hand
// out — or here, abandon — an address the external IPAM is the authority for.
func TestConvertToTemplateRefusedOnABoundNetwork(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	ctx := context.Background()

	mustCreateVMWithDiskOnNetwork(t, c, n, "src", orphanNetwork)
	mustStopVM(t, c, n, "src")

	_, err := c.SelfClient(n).ConvertToTemplate(ctx, &pb.ConvertToTemplateRequest{Name: "src"})
	if err == nil {
		t.Fatal("converting a VM that holds a NetBox address to a template must be refused: " +
			"the mirror skips templates, so the next sweep deletes the inventory naming the " +
			"address while the live lease keeps the orphan sweeper from ever reclaiming it")
	}
	if !strings.Contains(err.Error(), orphanNetwork) {
		t.Fatalf("the refusal must name the bound network, got: %v", err)
	}
	if !strings.Contains(err.Error(), "template") {
		t.Fatalf("the refusal must name the operation it declined, got: %v", err)
	}

	// Nothing may have moved. The flag is the destructive step here — once it is
	// set the mirror stops accounting for the VM.
	vm, gerr := corrosion.GetVM(ctx, n.DB, "src")
	if gerr != nil || vm == nil {
		t.Fatalf("read the VM back: %v", gerr)
	}
	if vm.IsTemplate {
		t.Fatal("a refused conversion must leave the VM a VM")
	}
	if got := leaseCount(t, n, orphanNetwork); got != 1 {
		t.Fatalf("lease rows = %d, want the VM's one — a refused conversion releases nothing", got)
	}
	if got := len(nb.Identities()); got != 1 {
		t.Fatalf("NetBox identities = %d, want the VM's one", got)
	}
}

// TestConvertToTemplateStillWorksOnAnUnboundNetwork is the control: the refusal
// must be about the BOUND network, not about templates.
func TestConvertToTemplateStillWorksOnAnUnboundNetwork(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	seedClusterRow(t, c)
	seedContainerNetwork(t, c)
	setHostCapacity(t, c, n.Name, 64, 65536, nil)

	mustCreateVMWithDiskOnNetwork(t, c, n, "src", ctNetName)
	mustStopVM(t, c, n, "src")

	if _, err := c.SelfClient(n).ConvertToTemplate(context.Background(),
		&pb.ConvertToTemplateRequest{Name: "src"}); err != nil {
		t.Fatalf("converting a VM on an UNBOUND network must still work: %v", err)
	}
	vm, err := corrosion.GetVM(context.Background(), n.DB, "src")
	if err != nil || vm == nil {
		t.Fatalf("read the VM back: %v", err)
	}
	if !vm.IsTemplate {
		t.Fatal("the conversion reported success but the VM is not a template")
	}
}
