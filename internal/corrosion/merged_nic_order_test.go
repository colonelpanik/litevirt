package corrosion

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// MergedVMNICs collapses vm_nics and vm_interfaces through a Go map and then
// ranges over it, so the returned order is the map's — randomised per
// iteration by the runtime.
//
// That order reaches the guest. xmlgen emits <interface> elements in the order
// it is handed, and Linux names NICs by the order the devices appear, so a
// regenerate can swap eth0 and eth1 on a VM nobody touched: static addressing
// lands on the wrong segment, and a firewall rule written against a tap device
// follows the other NIC.
//
// GetVMInterfaces has ordered by ordinal all along; the merged path simply
// never did. Ordinal is the ordering, MAC breaks an ordinal tie so the answer
// is total.
func TestMergedVMNICs_IsOrderedByOrdinal(t *testing.T) {
	c := newTestDB(t)
	ctx := context.Background()
	const vmName = "order-probe"
	ts := time.Now().UTC().Format(time.RFC3339)

	// Inserted deliberately out of order, and enough of them that a map that
	// happens to come back sorted is not worth considering.
	for _, ordinal := range []int{5, 2, 7, 0, 3, 6, 1, 4} {
		mac := fmt.Sprintf("52:54:00:00:00:%02x", ordinal)
		if err := c.Execute(ctx,
			`INSERT INTO vm_nics (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			vmName, fmt.Sprintf("%s-%d", vmName, ordinal), "default", "virtio", mac, ordinal, "", "", "", ts); err != nil {
			t.Fatalf("insert nic %d: %v", ordinal, err)
		}
	}

	// Repeated because map iteration order is re-randomised per range, so one
	// accidental pass proves nothing.
	for attempt := 0; attempt < 20; attempt++ {
		got, err := MergedVMNICs(ctx, c, vmName)
		if err != nil {
			t.Fatalf("MergedVMNICs: %v", err)
		}
		if len(got) != 8 {
			t.Fatalf("got %d NICs, want 8", len(got))
		}
		for i, n := range got {
			if n.Ordinal != i {
				t.Fatalf("attempt %d: position %d holds ordinal %d — the merged NIC list "+
					"is in map order, so the guest's NIC enumeration can change on a "+
					"regenerate that altered nothing", attempt, i, n.Ordinal)
			}
		}
	}
}

// The ordinal tiebreak must fold MAC case, because nicJoinKey does. If it does
// not, two spellings of one MAC are a single NIC to the merge but two distinct
// sort keys here — so rewriting a row in the other case reorders the guest's
// interfaces with nothing substantive changed, which is the defect the sort was
// added to remove.
func TestMergedVMNICs_TiebreakFoldsMACCaseLikeTheJoinDoes(t *testing.T) {
	c := newTestDB(t)
	ctx := context.Background()
	const vmName = "case-probe"
	ts := time.Now().UTC().Format(time.RFC3339)

	// Same ordinal, so only the MAC breaks the tie. Upper-case sorts before
	// lower-case bytewise, so an unfolded compare orders them the other way.
	for i, mac := range []string{"AA:BB:CC:00:00:02", "aa:bb:cc:00:00:01"} {
		if err := c.Execute(ctx,
			`INSERT INTO vm_nics (vm_name, id, network_name, model, mac, ordinal, ip, tap_device, security_groups, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)`,
			vmName, fmt.Sprintf("%s-%d", vmName, i), "default", "virtio", mac, 0, "", "", "", ts); err != nil {
			t.Fatalf("insert nic %s: %v", mac, err)
		}
	}

	got, err := MergedVMNICs(ctx, c, vmName)
	if err != nil {
		t.Fatalf("MergedVMNICs: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d NICs, want 2", len(got))
	}
	if strings.ToLower(got[0].MAC) != "aa:bb:cc:00:00:01" {
		t.Errorf("first NIC is %q; the tiebreak compared raw MACs, so case decided "+
			"the order instead of the address", got[0].MAC)
	}
}
