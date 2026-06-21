// Package events provides a simple in-process pub/sub bus for cluster events.
package events

import (
	"sync"
	"time"
)

// Event is a single cluster event.
type Event struct {
	Action    string
	Target    string
	Detail    string
	Username  string
	Timestamp time.Time
}

// Bus broadcasts events to all current subscribers.
type Bus struct {
	mu   sync.RWMutex
	subs map[uint64]chan Event
	next uint64
}

// NewBus creates a new event bus.
func NewBus() *Bus {
	return &Bus{subs: make(map[uint64]chan Event)}
}

// Subscribe registers a listener and returns a receive-only channel plus an
// unsubscribe function. The caller must call unsubscribe when done.
func (b *Bus) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = ch
	b.mu.Unlock()

	return ch, func() {
		b.mu.Lock()
		delete(b.subs, id)
		b.mu.Unlock()
		close(ch)
	}
}

// Publish sends an event to all current subscribers. Slow subscribers are
// skipped (non-blocking send) to avoid backpressure.
func (b *Bus) Publish(e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default: // subscriber too slow — skip
		}
	}
}
