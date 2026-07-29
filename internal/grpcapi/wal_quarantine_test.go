package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// A node rolled back below a capability token it already latched must stop
// presenting itself as a healthy participant.
//
// This is the cluster-visible half of the quarantine. The write-side half (refuse
// to emit replicated writes) lives in internal/corrosion; this one keeps the
// cluster from latching FURTHER tokens across a member that could not honour them.
// CapabilityActive requires every voting-eligible host to advertise, so withholding
// advertisement holds the line without touching any peer already latched — that
// latch is monotone and stays enforced. The result is the bounded, observable state
// the design wants: majority latched, degraded member visible, nothing new latching.

func TestAdvertisedCapabilities_QuarantinedNodeAdvertisesNothing(t *testing.T) {
	s := &Server{}
	if len(s.advertisedCapabilities()) == 0 {
		t.Fatal("a healthy server advertises nothing; this test would pass vacuously")
	}

	quarantined := true
	s.SetWALQuarantined(func() bool { return quarantined })

	if got := s.advertisedCapabilities(); len(got) != 0 {
		t.Fatalf("a WAL-quarantined node advertised %v; the cluster could latch a new token "+
			"across a member running a binary that has never heard of it", got)
	}

	// It is a predicate, not a latch: an operator who reseeds, or an upgrade back
	// to a binary that knows the token, must restore a working member.
	quarantined = false
	if got := s.advertisedCapabilities(); len(got) == 0 {
		t.Fatal("advertisement did not resume once the quarantine cleared")
	}
}

// TestAdvertisedCapabilities_UnsetPredicateAdvertisesNormally guards the default —
// the overwhelmingly common case is no predicate at all.
func TestAdvertisedCapabilities_UnsetPredicateAdvertisesNormally(t *testing.T) {
	s := &Server{}
	got := s.advertisedCapabilities()
	if len(got) == 0 {
		t.Fatal("a server with no quarantine predicate advertised nothing")
	}
	if !capabilities.Has(got, capabilities.SplitBrainGateV1) {
		t.Errorf("advertised set %v is missing a token every build supports", got)
	}
}
