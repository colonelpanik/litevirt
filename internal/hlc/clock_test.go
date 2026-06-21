package hlc

import (
	"sync"
	"testing"
	"time"
)

func TestTimestampString(t *testing.T) {
	ts := Timestamp{PhysicalMS: 1710633600000, Logical: 3, NodeID: "node1"}
	got := ts.String()
	want := "1710633600000-0003-node1"
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		input string
		ok    bool
		want  Timestamp
	}{
		{"1710633600000-0003-node1", true, Timestamp{1710633600000, 3, "node1"}},
		{"0000000000001-0000-a", true, Timestamp{PhysicalMS: 1, Logical: 0, NodeID: "a"}},
		{"bad", false, Timestamp{}},
		{"123-456", false, Timestamp{}},
		{"abc-0001-node", false, Timestamp{}},
		{"123-abc-node", false, Timestamp{}},
		{"123-0001-", false, Timestamp{}},
	}
	for _, tt := range tests {
		got, ok := Parse(tt.input)
		if ok != tt.ok {
			t.Errorf("Parse(%q) ok = %v, want %v", tt.input, ok, tt.ok)
			continue
		}
		if ok && got != tt.want {
			t.Errorf("Parse(%q) = %+v, want %+v", tt.input, got, tt.want)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	ts := Timestamp{PhysicalMS: 1710633600000, Logical: 42, NodeID: "host-2"}
	got, ok := Parse(ts.String())
	if !ok {
		t.Fatal("round trip parse failed")
	}
	if got != ts {
		t.Errorf("round trip: got %+v, want %+v", got, ts)
	}
}

func TestTimestampAfter(t *testing.T) {
	a := Timestamp{100, 1, "a"}
	b := Timestamp{100, 1, "b"}
	c := Timestamp{100, 2, "a"}
	d := Timestamp{200, 0, "a"}

	if !b.After(a) {
		t.Error("b should be after a (node ID tiebreak)")
	}
	if a.After(b) {
		t.Error("a should not be after b")
	}
	if !c.After(a) {
		t.Error("c should be after a (logical)")
	}
	if !d.After(c) {
		t.Error("d should be after c (physical)")
	}
}

func TestClockMonotonicity(t *testing.T) {
	c := NewClock("test")
	prev := c.Now()
	for i := 0; i < 1000; i++ {
		cur := c.Now()
		if !cur.After(prev) {
			t.Fatalf("monotonicity violation at i=%d: %s not after %s", i, cur, prev)
		}
		prev = cur
	}
}

func TestClockMonotonicityConcurrent(t *testing.T) {
	c := NewClock("test")
	const goroutines = 10
	const perGoroutine = 100

	results := make([][]Timestamp, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				results[g] = append(results[g], c.Now())
			}
		}()
	}
	wg.Wait()

	// Within each goroutine, timestamps must be monotonically increasing.
	for g, ts := range results {
		for i := 1; i < len(ts); i++ {
			if !ts[i].After(ts[i-1]) {
				t.Errorf("goroutine %d: ts[%d] %s not after ts[%d] %s", g, i, ts[i], i-1, ts[i-1])
			}
		}
	}

	// All timestamps globally must be unique.
	seen := make(map[string]bool)
	for _, ts := range results {
		for _, v := range ts {
			s := v.String()
			if seen[s] {
				t.Errorf("duplicate timestamp: %s", s)
			}
			seen[s] = true
		}
	}
}

func TestClockUpdate(t *testing.T) {
	c := NewClock("local")
	local := c.Now()

	// Remote is far in the future.
	remote := Timestamp{PhysicalMS: local.PhysicalMS + 10000, Logical: 5, NodeID: "remote"}
	updated := c.Update(remote)

	if !updated.After(remote) {
		t.Errorf("Update should produce timestamp after remote: got %s, remote %s", updated, remote)
	}
	if !updated.After(local) {
		t.Errorf("Update should produce timestamp after local: got %s, local %s", updated, local)
	}
	if updated.NodeID != "local" {
		t.Errorf("Update should keep local node ID, got %q", updated.NodeID)
	}

	// Subsequent Now() should still be monotonic.
	next := c.Now()
	if !next.After(updated) {
		t.Errorf("Now after Update not monotonic: %s not after %s", next, updated)
	}
}

func TestClockUpdateLocalAhead(t *testing.T) {
	c := NewClock("local")
	// Advance local clock significantly.
	for i := 0; i < 100; i++ {
		c.Now()
	}
	local := c.Now()

	// Remote is behind.
	remote := Timestamp{PhysicalMS: local.PhysicalMS - 10000, Logical: 0, NodeID: "remote"}
	updated := c.Update(remote)

	if !updated.After(local) {
		t.Errorf("Update with old remote should still advance: got %s, local was %s", updated, local)
	}
}

func TestClockSamePhysical(t *testing.T) {
	fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	c := NewClock("test")
	c.nowFn = func() time.Time { return fixed }

	ts1 := c.Now()
	ts2 := c.Now()
	ts3 := c.Now()

	if ts1.Logical != 0 {
		t.Errorf("first logical should be 0, got %d", ts1.Logical)
	}
	if ts2.Logical != 1 {
		t.Errorf("second logical should be 1, got %d", ts2.Logical)
	}
	if ts3.Logical != 2 {
		t.Errorf("third logical should be 2, got %d", ts3.Logical)
	}
	if !ts3.After(ts2) || !ts2.After(ts1) {
		t.Error("timestamps should be strictly ordered")
	}
}

func TestIsHLC(t *testing.T) {
	if !IsHLC("1710633600000-0003-node1") {
		t.Error("should detect valid HLC")
	}
	if IsHLC("2024-03-17T12:00:00Z") {
		t.Error("should not detect RFC3339 as HLC")
	}
	if IsHLC("") {
		t.Error("should not detect empty string as HLC")
	}
}

func TestTimestampLexicographicOrder(t *testing.T) {
	// HLC string format should maintain lexicographic ordering.
	a := Timestamp{PhysicalMS: 100, Logical: 1, NodeID: "a"}.String()
	b := Timestamp{PhysicalMS: 100, Logical: 2, NodeID: "a"}.String()
	c := Timestamp{PhysicalMS: 200, Logical: 0, NodeID: "a"}.String()

	if a >= b {
		t.Errorf("lexicographic: %q should be < %q", a, b)
	}
	if b >= c {
		t.Errorf("lexicographic: %q should be < %q", b, c)
	}
}
