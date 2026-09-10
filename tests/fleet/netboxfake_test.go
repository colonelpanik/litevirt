// Contract tests for NetBoxFake itself.
//
// The fake is only useful if it disagrees with the shipped netbox.Client in the
// same places a real NetBox would. A fake and a client that agree only with each
// other is the classic way an integration suite stays green while every call
// fails against the real server — so these drive the fake through the SHIPPED
// client, not raw HTTP.

package fleet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/netbox"
)

// netboxClientFor builds a real netbox.Client (token file and all) against nb.
func netboxClientFor(t *testing.T, nb *NetBoxFake) *netbox.Client {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := netbox.New(netbox.Config{BaseURL: nb.URL(), TokenPath: tokenPath, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestNetBoxFakeRoundTripsTheRealClient exercises every operation the allocator
// uses against the same decoder production runs.
func TestNetBoxFakeRoundTripsTheRealClient(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := netboxClientFor(t, nb)
	ctx := context.Background()

	p, err := c.GetPrefix(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if p.Prefix != "10.0.5.0/24" || p.VRFID != 3 {
		t.Fatalf("GetPrefix = %+v", p)
	}
	unique, err := c.VRFEnforcesUnique(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !unique {
		t.Fatal("VRFEnforcesUnique = false, want true")
	}

	const identity = "lv:fp:uuid:52:54:00:aa:bb:cc"
	claimed, err := c.ClaimAvailableIP(ctx, 7, identity)
	if err != nil {
		t.Fatal(err)
	}
	if claimed.Address != "10.0.5.100/24" || claimed.Identity != identity || claimed.VRFID != 3 {
		t.Fatalf("ClaimAvailableIP = %+v", claimed)
	}

	// The scoped identity lookup — the allocator's ONLY dynamic recovery path.
	found, err := c.LookupByIdentity(ctx, identity, 3, "10.0.5.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != 1 || found[0].ID != claimed.ID {
		t.Fatalf("LookupByIdentity = %+v, want just object %d", found, claimed.ID)
	}
	// Out of scope in either dimension must find NOTHING, or the scope is not
	// really being applied — the fake would then hide a lookup that adopts an
	// object which has moved VRF or prefix.
	if out, lerr := c.LookupByIdentity(ctx, identity, 9, "10.0.5.0/24"); lerr != nil || len(out) != 0 {
		t.Fatalf("a lookup in the wrong VRF must be empty, got %+v (err %v)", out, lerr)
	}
	if out, lerr := c.LookupByIdentity(ctx, identity, 3, "10.9.9.0/24"); lerr != nil || len(out) != 0 {
		t.Fatalf("a lookup outside the prefix must be empty, got %+v (err %v)", out, lerr)
	}

	byAddr, err := c.LookupByAddress(ctx, "10.0.5.100/24", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(byAddr) != 1 || byAddr[0].ID != claimed.ID {
		t.Fatalf("LookupByAddress = %+v", byAddr)
	}

	// A second explicit claim of the same address is the duplicate 400 — the
	// error whose "definite" classification the allocator must NOT act on.
	if _, derr := c.ClaimSpecificIP(ctx, "10.0.5.100/24", 3, identity); derr == nil {
		t.Fatal("a duplicate address must be refused")
	} else if netbox.Classify(derr) != netbox.ClassClient {
		t.Fatalf("duplicate classify = %v, want ClassClient", netbox.Classify(derr))
	}

	// The orphan sweeper's enumeration.
	all, err := c.ListIPsByPrefix(ctx, "10.0.5.0/24", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].Identity != identity {
		t.Fatalf("ListIPsByPrefix = %+v", all)
	}

	if err := c.ReleaseIP(ctx, claimed.ID); err != nil {
		t.Fatal(err)
	}
	if got := nb.Released(); len(got) != 1 || got[0] != claimed.ID {
		t.Fatalf("Released() = %v, want [%d]", got, claimed.ID)
	}
	if left, lerr := c.LookupByIdentity(ctx, identity, 3, "10.0.5.0/24"); lerr != nil || len(left) != 0 {
		t.Fatalf("a released object must be gone, got %+v (err %v)", left, lerr)
	}
}

// TestNetBoxFakePaginates pins that the fake actually pages. The client walks
// every page; a fake that returned everything in one response would leave that
// walk untested, and the failure it guards against — a truncated list making the
// orphan sweeper believe live objects vanished — is destructive.
func TestNetBoxFakePaginates(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.4.0/22", 3, true)

	c := netboxClientFor(t, nb)
	ctx := context.Background()

	// The client asks for limit=200, so exceed that.
	const want = 250
	for i := 0; i < want; i++ {
		if _, cerr := c.ClaimAvailableIP(ctx, 7, fmt.Sprintf("lv:fp:uuid:%d", i)); cerr != nil {
			t.Fatalf("claim %d: %v", i, cerr)
		}
	}
	all, err := c.ListIPsByPrefix(ctx, "10.0.4.0/22", 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != want {
		t.Fatalf("ListIPsByPrefix returned %d of %d — the page walk lost rows", len(all), want)
	}
}

// TestRecidrPrefixMovesTheBoundCIDR pins the drift helper a later task needs:
// the prefix's CIDR changes under a bound network while the addresses already
// handed out stay where they were.
func TestRecidrPrefixMovesTheBoundCIDR(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(7, "10.0.5.0/24", 3, true)

	c := netboxClientFor(t, nb)
	ctx := context.Background()
	if _, err := c.ClaimAvailableIP(ctx, 7, "lv:fp:uuid:aa:bb"); err != nil {
		t.Fatal(err)
	}

	nb.RecidrPrefix(7, "10.0.9.0/24")

	p, err := c.GetPrefix(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}
	if p.Prefix != "10.0.9.0/24" {
		t.Fatalf("GetPrefix after re-CIDR = %q, want 10.0.9.0/24", p.Prefix)
	}
	if p.VRFID != 3 {
		t.Fatalf("a re-CIDR must not move the VRF, got %d", p.VRFID)
	}
	// The address handed out before the re-CIDR did NOT move with it — that is
	// precisely the state that leaves a live lease outside its bound prefix.
	if got := nb.Addresses(); len(got) != 1 || got[0] != "10.0.5.100/24" {
		t.Fatalf("Addresses() = %v, want the pre-re-CIDR address to stay put", got)
	}
}

// TestNetBoxFakeIDForAddressIsScopedToTheVRF pins the fake's own determinism.
//
// `enforce_unique` is per-VRF — which is the whole reason a bind requires a VRF
// — so the same address legitimately exists in two of them. IDForAddress walks a
// MAP, so an address-only match returned whichever of the two Go's iteration
// order reached first: a helper that answers differently on different runs,
// under an equality assertion. That is a test that fails one time in two for no
// reason anybody can reproduce.
func TestNetBoxFakeIDForAddressIsScopedToTheVRF(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)

	// One address, two VRFs — a co-tenant installation sharing the NetBox
	// instance, which is a shape this branch supports and tests elsewhere.
	ours := nb.SeedIP("10.0.5.100/24", 3, "lv:ours:uuid:aa:bb", time.Now().UTC())
	theirs := nb.SeedIP("10.0.5.100/24", 9, "lv:theirs:uuid:cc:dd", time.Now().UTC())
	if ours == theirs {
		t.Fatal("precondition: the two objects must be distinct")
	}

	// Repeated, because the failure is a map-iteration coin flip: one pass could
	// pass by luck.
	for i := 0; i < 20; i++ {
		if got := nb.IDForAddress("10.0.5.100/24", 3); got != ours {
			t.Fatalf("IDForAddress in VRF 3 = %d, want %d (ours)", got, ours)
		}
		if got := nb.IDForAddress("10.0.5.100/24", 9); got != theirs {
			t.Fatalf("IDForAddress in VRF 9 = %d, want %d (theirs)", got, theirs)
		}
	}
	if got := nb.IDForAddress("10.0.5.100/24", 42); got != 0 {
		t.Fatalf("IDForAddress in an unrelated VRF = %d, want 0", got)
	}
}
