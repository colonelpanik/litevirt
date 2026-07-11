package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/health"
)

// fakeServerGate is a configurable serverGate isolating the Phase-1 decisions under
// test: whether the local ExecutionGate / DecisionGate pass, whether enforcement is
// latched, and which peers advertise the token.
type fakeServerGate struct {
	execOK   bool
	decideOK bool
	enforced bool
	supports map[string]bool
	healthy  []string // HealthyPeers (quorum-visible relay candidates)

	// Optional token-aware overrides (PR 2 — vip_demote_v1 vs vip_release_probe_v1). When
	// set they take precedence over the token-agnostic fields above, letting a test assert
	// that a site checks the RIGHT token. supportsTok: peer -> token -> supported (a peer
	// present here is authoritative; absent falls back to supports[peer]). enforcedTok:
	// token -> enforced (when non-nil, authoritative for Enforced/CapabilityActive).
	supportsTok map[string]map[string]bool
	enforcedTok map[string]bool
}

func (f fakeServerGate) ExecutionGate(context.Context) health.GateResult {
	if f.execOK {
		return health.GateResult{OK: true}
	}
	return health.GateResult{OK: false, Reason: health.ReasonNoQuorum}
}
func (f fakeServerGate) DecisionGate(context.Context) health.GateResult {
	if f.decideOK {
		return health.GateResult{OK: true}
	}
	return health.GateResult{OK: false, Reason: health.ReasonNoQuorum}
}
func (f fakeServerGate) CapabilityActive(_ context.Context, token string) (bool, string) {
	return f.enforcedFor(token), ""
}
func (f fakeServerGate) CapabilityActiveForHealth(_ context.Context, token string) (bool, string) {
	return f.enforcedFor(token), ""
}
func (f fakeServerGate) Enforced(_ context.Context, token string) bool { return f.enforcedFor(token) }
func (f fakeServerGate) Latched(token string) bool                     { return f.enforcedFor(token) }
func (f fakeServerGate) enforcedFor(token string) bool {
	if f.enforcedTok != nil {
		return f.enforcedTok[token]
	}
	return f.enforced
}
func (f fakeServerGate) PeerSupportsFresh(_ context.Context, peer, token string) bool {
	if toks, ok := f.supportsTok[peer]; ok {
		return toks[token]
	}
	return f.supports[peer]
}
func (f fakeServerGate) HealthyPeers(context.Context) []string { return f.healthy }

// A carried proof MARKER forces the ExecutionGate even when enforcement is NOT
// latched locally — the partition-safety property. Without a marker and without
// enforcement, the legacy (ungated) path is allowed.
func TestExecGateForAction_MarkerForcesGate(t *testing.T) {
	ctx := context.Background()

	// Not latched, ExecutionGate would refuse (no quorum).
	s := &Server{hostName: "h", gate: fakeServerGate{execOK: false, enforced: false}}

	// No marker + not enforced → legacy, not refused.
	if _, refused := s.execGateForAction(ctx, false); refused {
		t.Fatal("markerless + unenforced must take the legacy path (not refused)")
	}
	// Marker present → gate runs and refuses even though not latched.
	if reason, refused := s.execGateForAction(ctx, true); !refused || reason != health.ReasonNoQuorum {
		t.Fatalf("marker present must force the gate: refused=%v reason=%q; want true/no_quorum", refused, reason)
	}

	// With quorum, a marker present passes.
	sOK := &Server{hostName: "h", gate: fakeServerGate{execOK: true, enforced: false}}
	if _, refused := sOK.execGateForAction(ctx, true); refused {
		t.Fatal("marker present with quorum must pass")
	}
}

// A self-fenced node refuses BOTH decide and execute unconditionally — even a
// markerless/unenforced action and even with a nil gate — because it is doomed and
// waiting to reboot. This is the local hard gate on top of the checker-level one.
func TestGates_SelfFencedHardRefuse(t *testing.T) {
	ctx := context.Background()
	fenced := func() bool { return true }

	// Even with an otherwise-passing gate + quorum, fenced refuses.
	s := &Server{hostName: "h", gate: fakeServerGate{execOK: true, decideOK: true, enforced: true}}
	s.SetWatchdogFenced(fenced)
	if reason, refused := s.execGateForAction(ctx, false); !refused || reason != health.ReasonSelfFenced {
		t.Fatalf("fenced markerless execute: refused=%v reason=%q; want true/self_fenced", refused, reason)
	}
	if reason, refused := s.execGateForAction(ctx, true); !refused || reason != health.ReasonSelfFenced {
		t.Fatalf("fenced marker execute: refused=%v reason=%q; want true/self_fenced", refused, reason)
	}
	if reason, refused := s.decideGateRefused(ctx); !refused || reason != health.ReasonSelfFenced {
		t.Fatalf("fenced decide: refused=%v reason=%q; want true/self_fenced", refused, reason)
	}
	// Fenced with a NIL gate still refuses (the fenced check precedes the nil-gate legacy path).
	sNil := &Server{hostName: "h"}
	sNil.SetWatchdogFenced(fenced)
	if reason, refused := sNil.execGateForAction(ctx, false); !refused || reason != health.ReasonSelfFenced {
		t.Fatalf("fenced + nil gate execute: refused=%v reason=%q; want true/self_fenced", refused, reason)
	}
	// Not fenced → normal behavior (markerless + unenforced fails open).
	sOK := &Server{hostName: "h", gate: fakeServerGate{}}
	sOK.SetWatchdogFenced(func() bool { return false })
	if _, refused := sOK.execGateForAction(ctx, false); refused {
		t.Fatal("unfenced markerless+unenforced must fail open")
	}
}

// decideGateRefused blocks a leader-gated decide loop when enforced and DecisionGate
// is not OK — the CRDT lease alone is insufficient across a partition. Fail-open
// pre-activation and with a nil gate.
func TestDecideGateRefused(t *testing.T) {
	ctx := context.Background()

	if reason, refused := (&Server{hostName: "h", gate: fakeServerGate{decideOK: false, enforced: true}}).decideGateRefused(ctx); !refused || reason != health.ReasonNoQuorum {
		t.Fatalf("enforced + DecisionGate-no → refused=%v reason=%q; want true/no_quorum", refused, reason)
	}
	if _, refused := (&Server{hostName: "h", gate: fakeServerGate{decideOK: true, enforced: true}}).decideGateRefused(ctx); refused {
		t.Fatal("DecisionGate OK must not be refused")
	}
	if _, refused := (&Server{hostName: "h", gate: fakeServerGate{decideOK: false, enforced: false}}).decideGateRefused(ctx); refused {
		t.Fatal("pre-activation must fail-open (not refused)")
	}
	if _, refused := (&Server{hostName: "h"}).decideGateRefused(ctx); refused {
		t.Fatal("nil gate must fail-open (not refused)")
	}
}

// destSupportsGate fresh-Pings a peer (fail closed on unconfirmed) and short-circuits
// self via this build's advertised set.
func TestDestSupportsGate(t *testing.T) {
	ctx := context.Background()
	s := &Server{hostName: "h", gate: fakeServerGate{supports: map[string]bool{"peer-ok": true}}}

	if !s.destSupportsGate(ctx, "peer-ok") {
		t.Fatal("a peer advertising the gate must pass")
	}
	if s.destSupportsGate(ctx, "peer-no") {
		t.Fatal("a peer NOT advertising the gate must fail closed")
	}
	// Self resolves against this build's advertised set (empty while de-advertised).
	wantSelf := capabilities.Has(capabilities.Supported(), capabilities.SplitBrainGateV1)
	if got := s.destSupportsGate(ctx, "h"); got != wantSelf {
		t.Fatalf("self dest = %v; want %v (this build's Supported())", got, wantSelf)
	}
	// Nil gate fails closed.
	if (&Server{hostName: "h"}).destSupportsGate(ctx, "peer-ok") {
		t.Fatal("nil gate must fail closed")
	}
}

// removedHosts computes old∖new and must NOT skip self — if THIS host is the one
// being taken off the LB, it has to release the VIP too (the High-1 case).
func TestRemovedHosts(t *testing.T) {
	got := removedHosts([]string{"a", "self", "keep", ""}, []string{"keep", "c"})
	want := map[string]bool{"a": true, "self": true}
	if len(got) != len(want) {
		t.Fatalf("removed = %v, want keys %v", got, want)
	}
	for _, h := range got {
		if !want[h] {
			t.Fatalf("unexpected removed host %q in %v", h, got)
		}
	}
}

// removedHolderReleased: a removed holder counts as released ONLY when it's reachable
// and reports the VIP not assigned. Unreachable or still-assigned → not released
// (fail closed). Exercised through the probeHolder seam.
func TestRemovedHolderReleased(t *testing.T) {
	statuses := map[string]holderStatus{
		"released":    {reachable: true, assigned: false},
		"still-holds": {reachable: true, assigned: true},
		"unreachable": {reachable: false},
	}
	s := &Server{hostName: "self", probeHolder: func(_ context.Context, host, _ string) holderStatus {
		return statuses[host]
	}}
	if !s.removedHolderReleased(context.Background(), "released", "10.0.0.1") {
		t.Fatal("a reachable holder reporting not-assigned must count as released")
	}
	if s.removedHolderReleased(context.Background(), "still-holds", "10.0.0.1") {
		t.Fatal("a holder still assigned the VIP must NOT count as released")
	}
	if s.removedHolderReleased(context.Background(), "unreachable", "10.0.0.1") {
		t.Fatal("an unreachable holder must NOT count as released (fail closed)")
	}
}
