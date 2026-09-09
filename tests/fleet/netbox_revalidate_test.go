// Fleet scenarios for continuous binding revalidation and the CA re-key.
//
// Bind-time validation goes stale. A prefix can be re-CIDRed, a VRF's
// uniqueness flag switched off, a prefix dragged into the global table — all
// under an operator's hands in NetBox, long after the bind succeeded. The
// prefix ID keeps naming the same object, so nothing SILENTLY rebinds, but a
// stable identity is not continued validity.
//
// Every scenario here asserts on the same pair of properties: drift must refuse
// NEW allocations, and it must leave running VMs completely alone. The two are
// asserted together deliberately — a "suspension" that stopped a guest would be
// a far worse outage than the drift it responds to.

package fleet

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/netbox"
)

// errNetBoxPatchRefused is what a NetBox that refuses an identity rewrite looks
// like to the re-key: a definite answer, not a lost connection.
var errNetBoxPatchRefused = errors.New("no write permission on this object")

// ── helpers ─────────────────────────────────────────────────────────────────

// mustRevalidate runs one revalidation pass on n.
//
// A pass NEVER errors because a binding drifted — drift is a suspension, not a
// failure — so an error here means revalidation itself broke.
func mustRevalidate(t *testing.T, n *Node) {
	t.Helper()
	if err := n.Server.RevalidateBindingsOnce(context.Background()); err != nil {
		t.Fatalf("RevalidateBindingsOnce on %s: %v", n.Name, err)
	}
}

// rekey drives the RekeyBinding RPC over the harness's mTLS loopback, returning
// the error unchanged so refusal scenarios can assert on it.
func rekey(c *Cluster, n *Node, network string) error {
	_, err := c.SelfClient(n).RekeyBinding(context.Background(),
		&pb.RekeyBindingRequest{Network: network})
	return err
}

func mustRekey(t *testing.T, c *Cluster, n *Node, network string) {
	t.Helper()
	if err := rekey(c, n, network); err != nil {
		t.Fatalf("RekeyBinding(%s) on %s: %v", network, n.Name, err)
	}
}

// resumeBinding drives the ResumeBinding RPC, returning the error unchanged so
// the refusal scenarios can read the reason out of it.
func resumeBinding(c *Cluster, n *Node, network string) error {
	_, err := c.SelfClient(n).ResumeBinding(context.Background(),
		&pb.ResumeBindingRequest{Network: network})
	return err
}

func mustResume(t *testing.T, c *Cluster, n *Node, network string) {
	t.Helper()
	if err := resumeBinding(c, n, network); err != nil {
		t.Fatalf("ResumeBinding(%s) on %s: %v", network, n.Name, err)
	}
}

// inCIDR reports whether addr is inside cidr. Used to prove a resumed binding
// allocates out of the range it PINNED, not whatever NetBox reports now.
func inCIDR(t *testing.T, addr, cidr string) bool {
	t.Helper()
	_, netw, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %q: %v", cidr, err)
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		t.Fatalf("VM has no address to check against %s", cidr)
	}
	return netw.Contains(ip)
}

// bindingSuspended reports the binding's suspension flag as the cluster stores
// it. Asserted alongside a refused create rather than instead of it: the flag is
// the mechanism, the refusal is the behaviour operators actually see.
func bindingSuspended(t *testing.T, n *Node, prefixID int) bool {
	return binding(t, n, prefixID).Suspended
}

func bindingSuspendReason(t *testing.T, n *Node, prefixID int) string {
	return binding(t, n, prefixID).SuspendReason
}

func binding(t *testing.T, n *Node, prefixID int) corrosion.BindingRecord {
	t.Helper()
	b, err := corrosion.GetBindingByPrefix(context.Background(), n.DB, prefixID)
	if err != nil {
		t.Fatalf("GetBindingByPrefix(%d) on %s: %v", prefixID, n.Name, err)
	}
	if b == nil {
		t.Fatalf("no binding for prefix %d on %s", prefixID, n.Name)
	}
	return *b
}

// vmRunning reads the domain's state from the node's libvirt fake — the guest's
// actual state, not a replicated row that could agree with a stopped domain.
func vmRunning(t *testing.T, n *Node, name string) bool {
	t.Helper()
	st, err := n.Virt.DomainState(name)
	if err != nil {
		t.Fatalf("DomainState(%s) on %s: %v", name, n.Name, err)
	}
	return st == "running"
}

// clusterFP is the fingerprint this cluster currently derives from its CA.
func clusterFP(t *testing.T, n *Node) string {
	t.Helper()
	fp, err := corrosion.ClusterFingerprint(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("ClusterFingerprint on %s: %v", n.Name, err)
	}
	return fp
}

// identityFingerprint pulls the cluster component out of an identity string.
func identityFingerprint(t *testing.T, identity string) string {
	t.Helper()
	parts := strings.SplitN(identity, ":", 4)
	if len(parts) < 4 || parts[0] != "lv" {
		t.Fatalf("identity %q is not in the lv:<fp>:<uuid>:<mac> form", identity)
	}
	return parts[1]
}

// ── drift suspends ──────────────────────────────────────────────────────────

func TestBindingSuspendsOnCIDRChange(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	mustCreateVMOnNetwork(t, c, n, "vm-1", orphanNetwork) // running before the change

	nb.RecidrPrefix(orphanPrefixID, "10.0.6.0/24")
	mustRevalidate(t, n)

	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a re-CIDRed prefix must suspend the binding")
	}
	if _, err := createVMOnNetwork(c, n, "vm-2", orphanNetwork); err == nil {
		t.Fatal("a suspended binding must refuse new creates")
	}
	if !vmRunning(t, n, "vm-1") {
		t.Fatal("suspension must not disturb running VMs")
	}
}

func TestBindingSuspendsOnCAReplacement(t *testing.T) {
	_, c := boundCluster(t, 1)
	n := c.Nodes[0]
	mustCreateVMOnNetwork(t, c, n, "vm-1", orphanNetwork)

	c.MoveClusterFingerprint()
	mustRevalidate(t, n)

	if _, err := createVMOnNetwork(c, n, "vm-2", orphanNetwork); err == nil {
		t.Fatal("a fingerprint mismatch must suspend the binding")
	}
	// The reason has to name the way out. A suspension an operator cannot
	// resolve from the message is an outage, not a safety property.
	if reason := bindingSuspendReason(t, n, orphanPrefixID); !strings.Contains(reason, "netbox rekey") {
		t.Fatalf("suspend reason = %q, want the re-key command an operator has to run", reason)
	}
	if !vmRunning(t, n, "vm-1") {
		t.Fatal("a moved cluster fingerprint must not disturb running VMs")
	}
}

func TestBindingSuspendsWhenVRFStopsEnforcingUniqueness(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]

	nb.SetVRFEnforceUnique(orphanVRF, false)
	mustRevalidate(t, n)

	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a VRF that stopped enforcing uniqueness must suspend the binding")
	}
	if _, err := createVMOnNetwork(c, n, "vm-1", orphanNetwork); err == nil {
		t.Fatal("without uniqueness enforcement every claim guarantee is gone; the create must refuse")
	}
}

func TestBindingSuspendsWhenPrefixMovesToGlobalTable(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]

	nb.MovePrefixToGlobalTable(orphanPrefixID)
	mustRevalidate(t, n)

	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a prefix moved to the global table must suspend the binding")
	}
	// Global-table uniqueness is not readable through any supported NetBox API,
	// which is why bind refuses it in the first place — the reason must say so
	// rather than blaming the VRF lookup that never ran.
	if reason := bindingSuspendReason(t, n, orphanPrefixID); !strings.Contains(reason, "global table") {
		t.Fatalf("suspend reason = %q, want it to name the global table", reason)
	}
}

// TestBindingSuspendsWhenPrefixMovesToAnotherUniquenessEnforcingVRF.
//
// The uniqueness check asks about the prefix's CURRENT VRF, which is a weaker
// fact than the one the binding needs. Both VRFs here enforce uniqueness, so
// nothing but comparing the VRF ID against the one PINNED on the binding can
// tell this apart from a healthy binding — and while it goes unnoticed, the
// binding's allocation scope is a VRF the prefix has left: dynamic claims fail
// the returned-VRF validation, and explicit ones are addressed to the old VRF.
func TestBindingSuspendsWhenPrefixMovesToAnotherUniquenessEnforcingVRF(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("control: the binding must start live")
	}

	// Same prefix, same CIDR, a DIFFERENT VRF that also enforces uniqueness.
	nb.AddPrefix(orphanPrefixID, orphanSubnet, orphanVRF+1, true)
	mustRevalidate(t, n)

	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("moving a prefix into another uniqueness-enforcing VRF left its binding live " +
			"under the OLD VRF as its allocation scope")
	}
	// And the reason must not read as a repin: the scope stays pinned where it
	// was proved, because uniqueness in the new VRF says nothing about the
	// addresses this network's guests already hold there.
	reason := bindingSuspendReason(t, n, orphanPrefixID)
	for _, want := range []string{"VRF 3", "VRF 4"} {
		if !strings.Contains(reason, want) {
			t.Errorf("suspend reason = %q, want both VRFs named (%s)", reason, want)
		}
	}
	if binding(t, n, orphanPrefixID).VRFID != orphanVRF {
		t.Errorf("the binding's pinned VRF was rewritten to %d; re-pinning moves the "+
			"allocation scope without re-proving anything inside it",
			binding(t, n, orphanPrefixID).VRFID)
	}
}

// TestResumeRefusesWhenNetBoxCannotBeRead is the finding this whole signature
// change came from.
//
// The binding is suspended because its VRF stopped enforcing uniqueness — a
// repair an operator makes in NetBox — and NetBox is then unreachable. A resume
// re-proves rather than taking the repair on trust, so a re-proof that could not
// RUN must refuse: the drift predicate used to answer an unreadable NetBox with
// the same empty string a clean re-validation gives, and the resume read that as
// permission and lifted the suspension while uniqueness was still switched off.
func TestResumeRefusesWhenNetBoxCannotBeRead(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	if err := corrosion.SuspendBinding(context.Background(), n.DB, orphanPrefixID,
		"VRF no longer enforces uniqueness"); err != nil {
		t.Fatalf("suspend the binding: %v", err)
	}
	// The cause is STILL THERE, which is the whole point: nothing was repaired.
	nb.SetVRFEnforceUnique(orphanVRF, false)
	nb.SetDown(true)

	if err := resumeBinding(c, n, orphanNetwork); err == nil {
		t.Fatal("a resume succeeded without reading the prefix or its VRF, although the " +
			"uniqueness enforcement it was suspended for is still disabled")
	}
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a validation that could not run lifted the suspension")
	}

	// AND IT IS NOT A BLANKET REFUSAL. Once NetBox answers and the repair is
	// really there, the same command resumes — otherwise this test would pass
	// against a resume that had simply stopped working.
	nb.SetDown(false)
	nb.SetVRFEnforceUnique(orphanVRF, true)
	mustResume(t, c, n, orphanNetwork)
	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a readable NetBox with the drift repaired must resume")
	}
}

// TestBindingNotSuspendedWhenNetBoxUnreachable is the negative control for the
// three above: an unreachable NetBox is not drift, it is silence.
//
// Suspension is STICKY — nothing un-suspends a binding except an operator's
// re-key — so suspending on a transport error would turn a NetBox maintenance
// window into a binding that refuses every create until a human intervenes,
// with no drift having occurred at all.
func TestBindingNotSuspendedWhenNetBoxUnreachable(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]

	nb.SetDown(true)
	mustRevalidate(t, n)
	nb.SetDown(false)

	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatalf("an unreachable NetBox must not suspend a binding, reason %q",
			bindingSuspendReason(t, n, orphanPrefixID))
	}
	if _, err := createVMOnNetwork(c, n, "vm-1", orphanNetwork); err != nil {
		t.Fatalf("the binding must still allocate once NetBox is back, got %v", err)
	}
}

// ── the re-key ──────────────────────────────────────────────────────────────

func TestRekeyRewritesIdentitiesAndResumes(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	mustCreateVMOnNetwork(t, c, n, "vm-1", orphanNetwork)
	before := nb.Identities()
	if len(before) != 1 {
		t.Fatalf("want exactly one identity before the re-key, got %v", before)
	}

	c.MoveClusterFingerprint()
	mustRevalidate(t, n)
	mustRekey(t, c, n, orphanNetwork)

	after := nb.Identities()
	if len(after) != len(before) {
		t.Fatalf("re-key must rewrite every identity, got %v", after)
	}
	if after[0] == before[0] {
		t.Fatal("re-key must actually change the identity, not just resume")
	}
	// Rewritten to the CURRENT fingerprint specifically: an identity changed to
	// anything else would resume a binding whose objects the next sweep could
	// not recognise as its own.
	if got, want := identityFingerprint(t, after[0]), clusterFP(t, n); got != want {
		t.Fatalf("rewritten identity carries fingerprint %q, want the new cluster fingerprint %q", got, want)
	}
	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a completed re-key must resume the binding")
	}
	if _, err := createVMOnNetwork(c, n, "vm-2", orphanNetwork); err != nil {
		t.Fatalf("binding must resume after a re-key, got %v", err)
	}
}

// TestRekeyPartialFailureLeavesBindingSuspended is the property that makes the
// re-key safe to retry: it resumes the binding only when EVERY object has been
// rewritten. Resuming after a partial rewrite would leave objects carrying the
// old fingerprint that this cluster no longer recognises as its own — invisible
// to the sweeper, and duplicated by any later mirror.
func TestRekeyPartialFailureLeavesBindingSuspended(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	mustCreateVMOnNetwork(t, c, n, "vm-1", orphanNetwork)
	mustCreateVMOnNetwork(t, c, n, "vm-2", orphanNetwork)
	oldFP := clusterFP(t, n)

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)
	mustRevalidate(t, n)

	var patches int
	nb.SetOnPatch(func(int) error {
		patches++
		if patches == 2 {
			return errNetBoxPatchRefused
		}
		return nil
	})
	if err := rekey(c, n, orphanNetwork); err == nil {
		t.Fatal("a refused rewrite must fail the re-key")
	}
	nb.SetOnPatch(nil)

	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a partial rewrite must leave the binding suspended")
	}
	if got := fingerprintCounts(t, nb); got[newFP] != 1 || got[oldFP] != 1 {
		t.Fatalf("after a partial rewrite want one identity under each fingerprint, got %v", got)
	}

	// Re-running is the whole recovery story: the already-rewritten object is
	// skipped, the remaining one is rewritten, and the binding resumes.
	mustRekey(t, c, n, orphanNetwork)
	if got := fingerprintCounts(t, nb); got[newFP] != 2 || got[oldFP] != 0 {
		t.Fatalf("a re-run must finish the rewrite, got %v", got)
	}
	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("the completed re-run must resume the binding")
	}
}

// fingerprintCounts groups every identity in the fake by its cluster component.
func fingerprintCounts(t *testing.T, nb *NetBoxFake) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, id := range nb.Identities() {
		out[identityFingerprint(t, id)]++
	}
	return out
}

func TestRekeyRefusedForUnboundNetwork(t *testing.T) {
	_, c := boundCluster(t, 1)
	n := c.Nodes[0]

	err := rekey(c, n, "no-such-network")
	if err == nil {
		t.Fatal("re-keying a network with no binding must be refused")
	}
	if !strings.Contains(err.Error(), "no-such-network") {
		t.Fatalf("the refusal must name the network, got %v", err)
	}
}

// ── two clusters, one NetBox ────────────────────────────────────────────────

// TestTwoClustersOneNetBoxDoNotCollide is why the identity carries a cluster
// FINGERPRINT rather than cluster.id (declared DEFAULT 'default', so identical
// in every installation) or the operator-chosen cluster name.
//
// Both halves matter and neither implies the other: the identities must be
// distinguishable, AND one cluster's sweeper must actually refuse to act on the
// other's objects. The seeded address is aged past the sweeper's grace window
// precisely so that nothing but the fingerprint scope stands between it and
// reclamation.
func TestTwoClustersOneNetBoxDoNotCollide(t *testing.T) {
	nb := NewNetBoxFake()
	t.Cleanup(nb.Close)
	nb.AddPrefix(orphanPrefixID, orphanSubnet, orphanVRF, true)

	a := NewClusterWithNetBox(t, 1, nb)
	latchNetBoxIPAM(t, a, gateAll(t, a))
	// The distinct node-name prefix is not decoration: the fleet's in-memory DBs
	// are named after the node, so a second cluster reusing "node-0" would share
	// cluster A's database — one cluster row, one fingerprint, and a scenario
	// that could not fail.
	b := NewClusterWithNetBoxNamed(t, 1, nb, "peer-") // its own CA, therefore its own fingerprint
	latchNetBoxIPAM(t, b, gateAll(t, b))

	mustCreateBoundNetwork(t, a, a.Nodes[0], orphanNetwork, orphanSubnet, orphanPrefixID)
	mustCreateBoundNetwork(t, b, b.Nodes[0], orphanNetwork, orphanSubnet, orphanPrefixID)
	mustCreateVMOnNetwork(t, a, a.Nodes[0], "vm-a", orphanNetwork)
	mustCreateVMOnNetwork(t, b, b.Nodes[0], "vm-b", orphanNetwork)

	ids := nb.Identities()
	if len(ids) != 2 || ids[0] == ids[1] {
		t.Fatalf("two clusters must produce distinct identities, got %v", ids)
	}
	if fpA, fpB := identityFingerprint(t, ids[0]), identityFingerprint(t, ids[1]); fpA == fpB {
		t.Fatalf("both clusters stamped the same cluster component %q — two installations sharing one NetBox would be indistinguishable", fpA)
	}

	// An address of cluster B's, old enough that only the fingerprint scope
	// keeps cluster A's sweeper off it.
	foreign := netbox.Identity(clusterFP(t, b.Nodes[0]),
		"6f1b0c2e-0000-4000-8000-0000000000bb", "52:54:00:0b:0b:0b")
	nb.SeedIP("10.0.5.180/24", orphanVRF, foreign, time.Now().UTC().Add(-orphanAge))

	mustSweep(t, a.Nodes[0])

	for _, id := range nb.Identities() {
		if id == foreign {
			return
		}
	}
	t.Fatalf("one cluster's sweeper reclaimed another cluster's address, left %v", nb.Identities())
}

// ── the resume ──────────────────────────────────────────────────────────────
//
// A re-key answers exactly one reason a binding suspends: the fingerprint pin.
// Every other drift is repaired by an operator in NetBox, and `lv netbox resume`
// is what re-checks the repair and lifts the flag. It is a re-VALIDATION, never
// an adoption: the binding's pinned facts are written back unchanged, so a
// prefix that is still drifted stays suspended however often it is run.

// TestResumeRefusesWhileStillDrifted is the property that makes resume safe to
// hand an operator: it is not a "clear the flag" switch. A binding whose drift
// is still present comes back refused, with the reason, and still suspended.
func TestResumeRefusesWhileStillDrifted(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]

	nb.RecidrPrefix(orphanPrefixID, "10.0.6.0/24")
	mustRevalidate(t, n)
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("setup: the re-CIDR must have suspended the binding")
	}

	err := resumeBinding(c, n, orphanNetwork)
	if err == nil {
		t.Fatal("resume must refuse while the drift that suspended the binding is still there")
	}
	// The reason, not a bare "refused": an operator reading this has to learn
	// what to repair in NetBox.
	if !strings.Contains(err.Error(), "re-CIDRed") {
		t.Fatalf("refusal = %v, want it to name the CIDR drift", err)
	}
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a refused resume must leave the binding suspended")
	}
	if _, err := createVMOnNetwork(c, n, "vm-1", orphanNetwork); err == nil {
		t.Fatal("the still-suspended binding must keep refusing creates")
	}
}

// TestResumeClearsAfterDriftRepaired is the other half: once the prefix is what
// the binding recorded again, resume actually lifts the suspension and the
// network allocates — out of the ORIGINAL range, which is the range the
// sweeper and lease repair enumerate.
func TestResumeClearsAfterDriftRepaired(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]

	nb.RecidrPrefix(orphanPrefixID, "10.0.6.0/24")
	mustRevalidate(t, n)
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("setup: the re-CIDR must have suspended the binding")
	}

	nb.RecidrPrefix(orphanPrefixID, orphanSubnet) // the operator reverts it
	mustResume(t, c, n, orphanNetwork)

	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatalf("a repaired binding must resume, still suspended with %q",
			bindingSuspendReason(t, n, orphanPrefixID))
	}
	if _, err := createVMOnNetwork(c, n, "vm-1", orphanNetwork); err != nil {
		t.Fatalf("the resumed binding must allocate again, got %v", err)
	}
	if addr := vmNICIP(t, n, "vm-1"); !inCIDR(t, addr, orphanSubnet) {
		t.Fatalf("address %q is outside the pinned range %s — a resumed binding must "+
			"keep allocating where the reclaim proof looks", addr, orphanSubnet)
	}
}

// TestResumeDoesNotAcceptNewCIDR pins the v1 limitation as a PROPERTY, not a
// doc sentence: resume re-validates against the pinned CIDR and writes it back
// unchanged. Adopting the new range instead would resume allocation into
// addresses the sweeper and lease repair — both of which enumerate NetBox by
// observed_cidr — could never see.
func TestResumeDoesNotAcceptNewCIDR(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]

	nb.RecidrPrefix(orphanPrefixID, "10.0.7.0/24")
	mustRevalidate(t, n)

	if err := resumeBinding(c, n, orphanNetwork); err == nil {
		t.Fatal("resume must refuse a prefix whose CIDR is not the one the binding pinned")
	}
	if got := binding(t, n, orphanPrefixID).ObservedCIDR; got != orphanSubnet {
		t.Fatalf("ObservedCIDR = %q after a refused resume, want the pinned %q — "+
			"a resume that re-observed the prefix would strand every later claim",
			got, orphanSubnet)
	}
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("the binding must stay suspended against a re-CIDRed prefix")
	}
}

// TestResumeIsIdempotentOnLiveBinding: resuming a binding that is already live
// is the state the caller asked for, so it succeeds and changes nothing.
func TestResumeIsIdempotentOnLiveBinding(t *testing.T) {
	_, c := boundCluster(t, 1)
	n := c.Nodes[0]

	mustResume(t, c, n, orphanNetwork)
	mustResume(t, c, n, orphanNetwork)

	if bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("resuming a live binding must not suspend it")
	}
	if _, err := createVMOnNetwork(c, n, "vm-1", orphanNetwork); err != nil {
		t.Fatalf("the binding must still allocate after a no-op resume, got %v", err)
	}
}

// TestRekeyRefusesToResumeWhileDrifted is the re-key's half of the same rule.
//
// A re-key rewrites identities; it does not repair a prefix. Resuming on the
// strength of a completed rewrite alone would lift a suspension the operation
// did nothing about — and on a re-CIDRed prefix that is silently destructive,
// because allocation restarts from the NEW NetBox range while the binding still
// records the OLD observed_cidr that the reclaim proof enumerates by.
func TestRekeyRefusesToResumeWhileDrifted(t *testing.T) {
	nb, c := boundCluster(t, 1)
	n := c.Nodes[0]
	mustCreateVMOnNetwork(t, c, n, "vm-1", orphanNetwork)

	c.MoveClusterFingerprint()
	newFP := clusterFP(t, n)
	nb.RecidrPrefix(orphanPrefixID, "10.0.6.0/24") // a SECOND, unrelated drift
	mustRevalidate(t, n)

	err := rekey(c, n, orphanNetwork)
	if err == nil {
		t.Fatal("a re-key must not report success while the binding stays suspended")
	}
	if !strings.Contains(err.Error(), "re-CIDRed") {
		t.Fatalf("the re-key error = %v, want it to name the drift it did not fix", err)
	}

	// The rewrite itself still happened — the two halves are independent, and a
	// re-key that silently skipped its own work would also pass the assertions
	// above.
	if got := fingerprintCounts(t, nb); got[newFP] != 1 {
		t.Fatalf("the re-key must still rewrite every identity, got %v", got)
	}
	if !bindingSuspended(t, n, orphanPrefixID) {
		t.Fatal("a re-key must leave a still-drifted binding suspended")
	}
	if reason := bindingSuspendReason(t, n, orphanPrefixID); !strings.Contains(reason, "re-CIDRed") {
		t.Fatalf("suspend reason = %q, want the drift the operator now has to repair", reason)
	}
	if _, err := createVMOnNetwork(c, n, "vm-2", orphanNetwork); err == nil {
		t.Fatal("the still-suspended binding must refuse new creates")
	}
}
