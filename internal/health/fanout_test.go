package health

import (
	"sync/atomic"
	"testing"
	"time"
)

// TestBoundedFanout_RespectsConcurrency is the C5b regression: peak concurrency
// must never exceed the cap, and every item must be processed.
func TestBoundedFanout_RespectsConcurrency(t *testing.T) {
	const n, limit = 200, 8
	var inFlight, peak, done int64

	work := func(int) {
		c := atomic.AddInt64(&inFlight, 1)
		for { // peak = max(peak, c)
			p := atomic.LoadInt64(&peak)
			if c <= p || atomic.CompareAndSwapInt64(&peak, p, c) {
				break
			}
		}
		time.Sleep(time.Millisecond) // hold the slot so overlap is observable
		atomic.AddInt64(&done, 1)
		atomic.AddInt64(&inFlight, -1)
	}

	boundedFanout(make([]int, n), limit, work)

	if peak > limit {
		t.Errorf("peak concurrency %d exceeded cap %d", peak, limit)
	}
	if peak < 2 {
		t.Errorf("expected some concurrency, peak was %d", peak)
	}
	if done != n {
		t.Errorf("processed %d items, want %d", done, n)
	}
}

// TestBoundedFanout_SerialAndEmpty covers the boundary cases.
func TestBoundedFanout_SerialAndEmpty(t *testing.T) {
	var done int64
	// concurrency < 1 is clamped to 1 (serial), still processes everything.
	boundedFanout([]int{1, 2, 3}, 0, func(int) { atomic.AddInt64(&done, 1) })
	if done != 3 {
		t.Errorf("serial: processed %d, want 3", done)
	}
	// empty input is a no-op (must not block).
	boundedFanout(nil, 4, func(int) { t.Fatal("work called on empty input") })
}
