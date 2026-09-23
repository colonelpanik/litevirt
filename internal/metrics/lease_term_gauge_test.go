package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// litevirt_leader_lease_term is the gauge docs/operating-model.md tells
// operators to alert on, and it must answer the same question the ALLOCATOR
// asks: what is the high-water term for this key?
//
// nextLeaseTerm computes `MAX(term) WHERE key = ?` with no deleted_at filter —
// deliberately, because a tombstoned tenure still consumed its term and reusing
// the number would mint a duplicate. The gauge filtered `deleted_at IS NULL`,
// so once the highest-term row was tombstoned the gauge STEPPED BACKWARDS while
// the real high-water kept climbing.
//
// A gauge that moves the opposite way from the thing it reports is worse than
// no gauge: an alert on "term regressed" fires on ordinary GC, and an operator
// reading it during an incident sees a lower tenure than the cluster is using.
func TestLeaseTermGauge_MatchesTheAllocatorNotTheLiveRows(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for _, tc := range []struct {
		term    int64
		deleted bool
	}{{1, false}, {2, false}, {3, true}} {
		del := interface{}(nil)
		if tc.deleted {
			del = now
		}
		if err := db.Execute(ctx,
			`INSERT INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			corrosion.LeaseKeyFailover, tc.term, "node-a", now, now, db.NowTS(), del); err != nil {
			t.Fatalf("seed term %d: %v", tc.term, err)
		}
	}

	// The ALLOCATOR's floor is MAX(term) over EVERY row — nextLeaseTerm does not
	// filter deleted_at, because a tombstoned tenure still consumed its number
	// and reusing it would mint a duplicate. Term 3 is tombstoned, so the floor
	// is 3, not the highest live row (2).
	//
	// Note CurrentLeaseTerm is a different question: it is the rejection
	// THRESHOLD and does filter tombstones. The gauge must track the allocator.
	const allocatorFloor = 3

	c := newCollector(db, nil, nil, "host-a")
	ch := make(chan prometheus.Metric, 200)
	c.Collect(ch)
	close(ch)

	got := keyGaugeValues(t, ch, "litevirt_leader_lease_term")
	if len(got) == 0 {
		t.Fatal("no litevirt_leader_lease_term series emitted")
	}
	if got[corrosion.LeaseKeyFailover] != allocatorFloor {
		t.Errorf("gauge = %v, allocator high-water = %d\n"+
			"the gauge filtered tombstones and the allocator does not, so GC of the "+
			"top term makes this gauge step backwards while the cluster's real term "+
			"keeps rising",
			got[corrosion.LeaseKeyFailover], allocatorFloor)
	}
}

// keyGaugeValues is peerGaugeValues for a gauge labelled by `key` rather than
// `peer`.
func keyGaugeValues(t *testing.T, ch <-chan prometheus.Metric, name string) map[string]float64 {
	t.Helper()
	out := map[string]float64{}
	for m := range ch {
		if !containsStr(m.Desc().String(), name) {
			continue
		}
		var dm dto.Metric
		if err := m.Write(&dm); err != nil {
			t.Fatalf("write metric %s: %v", name, err)
		}
		key := ""
		for _, lp := range dm.GetLabel() {
			if lp.GetName() == "key" {
				key = lp.GetValue()
			}
		}
		out[key] = dm.GetGauge().GetValue()
	}
	return out
}
