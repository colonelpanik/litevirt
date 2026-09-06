package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// driftBinding is the record a healthy bind leaves behind for the fake below.
func driftBinding(fp string) corrosion.BindingRecord {
	return corrosion.BindingRecord{
		Network: "bound", PrefixID: 7, ObservedCIDR: "10.0.5.0/24",
		VRFID: 3, ClusterFingerprint: fp,
	}
}

func liveFingerprint(t *testing.T, s *Server) string {
	t.Helper()
	fp, err := corrosion.ClusterFingerprint(context.Background(), s.db)
	if err != nil {
		t.Fatalf("ClusterFingerprint: %v", err)
	}
	return fp
}

// TestBindingDriftFingerprintMismatchNamesTheRekey pins BOTH halves of the pin:
// the comparison is against the RECORDED fingerprint, and the reason tells the
// operator the one command that resolves it.
func TestBindingDriftFingerprintMismatchNamesTheRekey(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	reason := s.bindingDrift(context.Background(), driftBinding("an-older-ca"), liveFingerprint(t, s))
	if reason == "" {
		t.Fatal("a binding pinned to another fingerprint must be drift")
	}
	if !strings.Contains(reason, "netbox rekey") {
		t.Fatalf("reason = %q, want the re-key command", reason)
	}
}

func TestBindingDriftCIDRChange(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.6.0/24", VRFID: 3}, // re-CIDRed
		enforceUnique: true,
	})
	fp := liveFingerprint(t, s)
	reason := s.bindingDrift(context.Background(), driftBinding(fp), fp)
	if !strings.Contains(reason, "10.0.6.0/24") {
		t.Fatalf("reason = %q, want it to name the CIDR NetBox now reports", reason)
	}
}

func TestBindingDriftPrefixMovedToGlobalTable(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix: netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 0}, // no VRF
	})
	fp := liveFingerprint(t, s)
	reason := s.bindingDrift(context.Background(), driftBinding(fp), fp)
	if !strings.Contains(reason, "global table") {
		t.Fatalf("reason = %q, want it to name the global table", reason)
	}
}

func TestBindingDriftVRFStoppedEnforcingUniqueness(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: false,
	})
	fp := liveFingerprint(t, s)
	reason := s.bindingDrift(context.Background(), driftBinding(fp), fp)
	if !strings.Contains(reason, "unique") {
		t.Fatalf("reason = %q, want it to name the uniqueness setting", reason)
	}
}

// TestBindingDriftNoneWhenNothingChanged is the negative control: without it a
// bindingDrift that returned a reason unconditionally would pass every test
// above.
func TestBindingDriftNoneWhenNothingChanged(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	fp := liveFingerprint(t, s)
	if reason := s.bindingDrift(context.Background(), driftBinding(fp), fp); reason != "" {
		t.Fatalf("an unchanged binding must not drift, got %q", reason)
	}
}

// TestRevalidateSuspendsTheDriftedRow drives the whole pass, not just the
// predicate: a drifted binding must come back from the DB suspended, with the
// reason recorded for the operator.
func TestRevalidateSuspendsTheDriftedRow(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(ctx, "bound", 7); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// The CA is replaced under the binding's feet; the pin no longer matches.
	if err := s.db.Execute(ctx, `UPDATE cluster SET ca_cert = ? WHERE id = 'default'`,
		"a-different-ca-cert"); err != nil {
		t.Fatalf("replace ca_cert: %v", err)
	}

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce: %v", err)
	}

	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil || b == nil {
		t.Fatalf("read binding: %v %v", b, err)
	}
	if !b.Suspended {
		t.Fatal("revalidation must suspend a binding whose fingerprint pin no longer matches")
	}
	if !strings.Contains(b.SuspendReason, "netbox rekey") {
		t.Fatalf("SuspendReason = %q, want the re-key command", b.SuspendReason)
	}
}

// TestRevalidateIsANoopWithoutANetBoxClient pins that a node with no netbox
// configuration does nothing at all. bindingDrift would dereference a nil
// client, so the guard is not cosmetic — and a node that cannot read NetBox has
// no standing to suspend a binding every other node can still validate.
func TestRevalidateIsANoopWithoutANetBoxClient(t *testing.T) {
	ctx := context.Background()
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(ctx, "bound", 7); err != nil {
		t.Fatalf("bind: %v", err)
	}
	if err := s.db.Execute(ctx, `UPDATE cluster SET ca_cert = ? WHERE id = 'default'`,
		"a-different-ca-cert"); err != nil {
		t.Fatalf("replace ca_cert: %v", err)
	}
	s.netbox = nil

	if err := s.RevalidateBindingsOnce(ctx); err != nil {
		t.Fatalf("RevalidateBindingsOnce: %v", err)
	}
	b, err := corrosion.GetBindingByPrefix(ctx, s.db, 7)
	if err != nil || b == nil {
		t.Fatalf("read binding: %v %v", b, err)
	}
	if b.Suspended {
		t.Fatal("a node with no netbox configuration must suspend nothing")
	}
}

// TestRekeyBindingRequiresAdmin pins the role gate. A re-key rewrites the
// identity of every object litevirt owns in a prefix — it is an admin
// operation, and the check has to come before anything is read or written.
func TestRekeyBindingRequiresAdmin(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	if err := s.validateAndBindPrefix(context.Background(), "bound", 7); err != nil {
		t.Fatalf("bind: %v", err)
	}

	viewer := context.WithValue(context.WithValue(context.Background(),
		ctxKeyUsername, "vera"), ctxKeyRole, "viewer")
	_, err := s.RekeyBinding(viewer, &pb.RekeyBindingRequest{Network: "bound"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer got %v, want PermissionDenied", err)
	}

	// The same call as admin gets PAST the gate — without this the test would
	// also pass against a handler that refused everyone.
	if _, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{Network: "bound"}); err != nil {
		t.Fatalf("admin re-key: %v", err)
	}
}

// TestRekeyBindingRefusesAnUnboundNetwork keeps the refusal a NotFound naming
// the network, rather than a nil-binding panic or a silent success.
func TestRekeyBindingRefusesAnUnboundNetwork(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})
	_, err := s.RekeyBinding(adminCtx(), &pb.RekeyBindingRequest{Network: "unbound"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("got %v, want NotFound", err)
	}
	if !strings.Contains(err.Error(), "unbound") {
		t.Fatalf("the refusal must name the network, got %v", err)
	}
}
