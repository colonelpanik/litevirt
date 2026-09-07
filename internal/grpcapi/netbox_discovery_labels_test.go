package grpcapi

import (
	"sort"
	"testing"

	"github.com/litevirt/litevirt/internal/metrics"
)

// TestDiscoveryReasonLabelsAreMaterialisedAtZero pins the two halves of the
// discovery counter's bounded label vocabulary against each other.
//
// litevirt_netbox_unclaimable_discoveries_total's reason labels are
// MATERIALISED at zero by internal/metrics, so a dashboard shows every series
// before the first occurrence — the same treatment the api-error classes and the
// mirror-sweep results already get, and for a sharper reason: reason=not_ours
// means two things are using one address, so it is the series an operator builds
// an alert on, and an alert on a series that does not exist until the first
// occurrence fires late or not at all.
//
// The reasons are PRODUCED here and MATERIALISED there, and internal/metrics
// cannot import this package (the dependency runs the other way), so the list is
// duplicated as literals on that side. This is the guard that keeps the two in
// step: a reason added here and not there would be a label with no zero series,
// which is exactly the state the materialisation exists to remove — and a
// reason removed here and left there would materialise a series nothing can
// ever increment.
func TestDiscoveryReasonLabelsAreMaterialisedAtZero(t *testing.T) {
	produced := []string{
		discoveryRefusedNotOurs,
		discoveryRefusedUnknown,
		discoveryRefusedNoAllocator,
		discoveryRefusedNoIdentity,
	}
	materialised := append([]string(nil), metrics.NetBoxDiscoveryReasons...)
	sort.Strings(produced)
	sort.Strings(materialised)

	if len(produced) != len(materialised) {
		t.Fatalf("this package produces %d discovery reasons %v but internal/metrics "+
			"materialises %d %v", len(produced), produced, len(materialised), materialised)
	}
	for i := range produced {
		if produced[i] != materialised[i] {
			t.Fatalf("discovery reason vocabularies disagree: produced %v, materialised %v",
				produced, materialised)
		}
	}
}
