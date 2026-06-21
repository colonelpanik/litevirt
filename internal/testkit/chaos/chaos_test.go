package chaos

import (
	"errors"
	"testing"
	"time"
)

func TestClock_AdvanceMonotonic(t *testing.T) {
	start := time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC)
	c := NewClock(start)
	if !c.Now().Equal(start) {
		t.Fatalf("Now() = %v, want %v", c.Now(), start)
	}
	c.Advance(time.Second)
	if got := c.Now(); !got.Equal(start.Add(time.Second)) {
		t.Errorf("after Advance(1s) Now() = %v, want %v", got, start.Add(time.Second))
	}
	c.Advance(0) // no-op
	if got := c.Now(); !got.Equal(start.Add(time.Second)) {
		t.Errorf("after Advance(0) Now() = %v", got)
	}
}

func TestClock_TickFiresOnAdvance(t *testing.T) {
	c := NewClock(time.Now())
	tick := c.Tick()
	select {
	case <-tick:
		t.Fatal("tick fired before Advance")
	default:
	}
	c.Advance(time.Millisecond)
	select {
	case <-tick:
	default:
		t.Fatal("tick did not fire after Advance")
	}
}

func TestNet_PerfectLink_DeliversInOrder(t *testing.T) {
	c := NewClock(time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC))
	n := NewNet(c, 1)
	n.Connect("a")
	n.Connect("b")

	for i := 0; i < 5; i++ {
		if err := n.Send("a", "b", []byte{byte(i)}); err != nil {
			t.Fatalf("Send %d: %v", i, err)
		}
	}
	// Zero-delay: tick once should promote everything.
	if got := n.Tick(); got != 5 {
		t.Errorf("Tick promoted %d, want 5", got)
	}
	for i := 0; i < 5; i++ {
		m, ok := n.Recv("b")
		if !ok {
			t.Fatalf("Recv #%d: no message", i)
		}
		if len(m.Payload) != 1 || m.Payload[0] != byte(i) {
			t.Errorf("msg %d: got %v, want [%d]", i, m.Payload, i)
		}
	}
}

func TestNet_DropProbability_IsDeterministic(t *testing.T) {
	c := NewClock(time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC))

	count := func(seed int64) int {
		n := NewNet(c, seed)
		n.Connect("a")
		n.Connect("b")
		n.SetEdge("a", "b", EdgePolicy{DropProbability: 0.5})
		dropped := 0
		for i := 0; i < 1000; i++ {
			if err := n.Send("a", "b", nil); errors.Is(err, ErrDropped) {
				dropped++
			}
		}
		return dropped
	}
	a := count(42)
	b := count(42)
	if a != b {
		t.Errorf("same seed produced different drop counts: %d vs %d", a, b)
	}
	c2 := count(43)
	if a == c2 {
		t.Errorf("different seeds produced same drop count: %d", a)
	}
	// Sanity: 50% drop on 1000 messages should land near 500.
	if a < 400 || a > 600 {
		t.Errorf("unexpected drop count %d for p=0.5 over 1000 sends", a)
	}
}

func TestNet_Partition_BlocksThenHeal(t *testing.T) {
	c := NewClock(time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC))
	n := NewNet(c, 1)
	for _, id := range []NodeID{"a", "b", "c"} {
		n.Connect(id)
	}

	// Sanity: no partition, sends succeed.
	if err := n.Send("a", "b", []byte("hi")); err != nil {
		t.Fatalf("pre-partition send: %v", err)
	}
	n.Tick()
	if _, ok := n.Recv("b"); !ok {
		t.Fatal("pre-partition recv missing")
	}

	// Partition {a} from {b, c}; a↔b and a↔c are severed; b↔c stays connected.
	n.Partition([]NodeID{"a"}, []NodeID{"b", "c"})

	if err := n.Send("a", "b", nil); !errors.Is(err, ErrDropped) {
		t.Errorf("partitioned send a→b should be ErrDropped, got %v", err)
	}
	if err := n.Send("c", "a", nil); !errors.Is(err, ErrDropped) {
		t.Errorf("partitioned send c→a should be ErrDropped, got %v", err)
	}
	// b↔c still works.
	if err := n.Send("b", "c", []byte("ok")); err != nil {
		t.Errorf("intra-group send b→c failed: %v", err)
	}

	// Heal restores the edges.
	n.Heal([]NodeID{"a"}, []NodeID{"b", "c"})
	if err := n.Send("a", "b", []byte("post-heal")); err != nil {
		t.Errorf("post-heal send a→b: %v", err)
	}
}

func TestNet_DelayedDelivery_FollowsClock(t *testing.T) {
	start := time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC)
	c := NewClock(start)
	n := NewNet(c, 1)
	n.Connect("a")
	n.Connect("b")
	n.SetEdge("a", "b", EdgePolicy{MinDelay: 10 * time.Millisecond, MaxDelay: 10 * time.Millisecond})

	if err := n.Send("a", "b", nil); err != nil {
		t.Fatalf("Send: %v", err)
	}
	// Before the delay elapses, nothing should be deliverable.
	c.Advance(5 * time.Millisecond)
	if got := n.Tick(); got != 0 {
		t.Errorf("Tick at t+5ms: promoted=%d, want 0", got)
	}
	if _, ok := n.Recv("b"); ok {
		t.Error("recv at t+5ms returned a message; expected none")
	}
	// After full delay, message becomes deliverable.
	c.Advance(6 * time.Millisecond) // total 11ms
	if got := n.Tick(); got != 1 {
		t.Errorf("Tick at t+11ms: promoted=%d, want 1", got)
	}
	if _, ok := n.Recv("b"); !ok {
		t.Error("recv after delay: expected message")
	}
}

func TestNet_Drain_FlushesAllInflight(t *testing.T) {
	c := NewClock(time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC))
	n := NewNet(c, 1)
	n.Connect("a")
	n.Connect("b")
	n.SetEdge("a", "b", EdgePolicy{MinDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})

	for i := 0; i < 50; i++ {
		_ = n.Send("a", "b", nil)
	}
	if n.Pending() != 50 {
		t.Fatalf("Pending() = %d, want 50", n.Pending())
	}
	steps := n.Drain()
	if steps == 0 {
		t.Error("Drain() reported 0 steps for non-empty inflight")
	}
	if pending := n.Pending() - 50; pending != 0 {
		// inboxes hold all 50 after drain
		t.Errorf("after Drain inflight nonzero (Pending - delivered = %d)", pending)
	}
	// All 50 should be retrievable from b's inbox now.
	got := 0
	for {
		_, ok := n.Recv("b")
		if !ok {
			break
		}
		got++
	}
	if got != 50 {
		t.Errorf("Drained recv count = %d, want 50", got)
	}
}

func TestNet_Disconnect_DropsInflight(t *testing.T) {
	c := NewClock(time.Date(2026, 5, 9, 0, 0, 0, 0, time.UTC))
	n := NewNet(c, 1)
	n.Connect("a")
	n.Connect("b")
	n.SetEdge("a", "b", EdgePolicy{MinDelay: 100 * time.Millisecond, MaxDelay: 100 * time.Millisecond})

	for i := 0; i < 5; i++ {
		_ = n.Send("a", "b", nil)
	}
	if n.Pending() != 5 {
		t.Fatalf("pre-disconnect Pending = %d", n.Pending())
	}
	n.Disconnect("b")
	// Sending to a disconnected node returns an error.
	if err := n.Send("a", "b", nil); err == nil {
		t.Error("Send to disconnected node should error")
	}
}
