package events

import (
	"testing"
	"time"
)

func TestBus_PublishReceive(t *testing.T) {
	b := NewBus()
	ch, unsub := b.Subscribe()
	defer unsub()

	b.Publish(Event{Action: "vm.created", Target: "vm1", Detail: "test"})

	select {
	case e := <-ch:
		if e.Action != "vm.created" {
			t.Errorf("Action = %q, want vm.created", e.Action)
		}
		if e.Target != "vm1" {
			t.Errorf("Target = %q, want vm1", e.Target)
		}
		if e.Timestamp.IsZero() {
			t.Error("Timestamp should be auto-set")
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for event")
	}
}

func TestBus_MultipleSubscribers(t *testing.T) {
	b := NewBus()
	ch1, unsub1 := b.Subscribe()
	ch2, unsub2 := b.Subscribe()
	defer unsub1()
	defer unsub2()

	b.Publish(Event{Action: "vm.deleted", Target: "vm2"})

	for _, ch := range []<-chan Event{ch1, ch2} {
		select {
		case e := <-ch:
			if e.Action != "vm.deleted" {
				t.Errorf("Action = %q, want vm.deleted", e.Action)
			}
		case <-time.After(100 * time.Millisecond):
			t.Fatal("subscriber did not receive event")
		}
	}
}

func TestBus_Unsubscribe(t *testing.T) {
	b := NewBus()
	_, unsub := b.Subscribe()
	unsub() // unsubscribe before publishing

	// Should not panic
	b.Publish(Event{Action: "test"})
}

func TestBus_TimestampAutoSet(t *testing.T) {
	b := NewBus()
	ch, unsub := b.Subscribe()
	defer unsub()

	before := time.Now()
	b.Publish(Event{Action: "x"}) // no Timestamp set
	after := time.Now()

	select {
	case e := <-ch:
		if e.Timestamp.Before(before) || e.Timestamp.After(after) {
			t.Errorf("Timestamp %v outside expected range [%v, %v]", e.Timestamp, before, after)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out")
	}
}

func TestBus_ExplicitTimestamp(t *testing.T) {
	b := NewBus()
	ch, unsub := b.Subscribe()
	defer unsub()

	ts := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	b.Publish(Event{Action: "x", Timestamp: ts})

	select {
	case e := <-ch:
		if !e.Timestamp.Equal(ts) {
			t.Errorf("Timestamp = %v, want %v", e.Timestamp, ts)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out")
	}
}

func TestBus_NoSubscribers(t *testing.T) {
	b := NewBus()
	// Should not panic with no subscribers.
	b.Publish(Event{Action: "orphan"})
}
