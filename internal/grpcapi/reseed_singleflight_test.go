package grpcapi

import (
	"sync"
	"testing"
)

// Only one reseed at a time, and the slot comes back.
func TestReseedInFlight_AdmitsOneAndReleases(t *testing.T) {
	var r reseedInFlight

	release, ok := r.acquire()
	if !ok {
		t.Fatal("the first reseed was refused")
	}
	if _, ok := r.acquire(); ok {
		t.Fatal("a second reseed was admitted while the first was still running — the durable " +
			"marker is a single row, so the second REPLACES the first's and whichever finishes " +
			"first clears the login gate over a node still mid-discard")
	}
	release()
	second, ok := r.acquire()
	if !ok {
		t.Fatal("the slot was not released; one failed reseed would refuse every retry for the " +
			"life of the process, and a retry is exactly what a failed reseed needs")
	}
	second()
}

// Releasing twice must not open the gate for a third.
func TestReseedInFlight_ReleaseIsIdempotent(t *testing.T) {
	var r reseedInFlight
	release, _ := r.acquire()
	release()
	release()

	if _, ok := r.acquire(); !ok {
		t.Fatal("the slot is stuck after a double release")
	}
	if _, ok := r.acquire(); ok {
		t.Fatal("two reseeds admitted at once after a double release")
	}
}

// Under concurrency exactly one wins.
func TestReseedInFlight_ExactlyOneWinnerUnderRace(t *testing.T) {
	var r reseedInFlight
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := r.acquire(); ok {
				mu.Lock()
				won++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Errorf("%d reseeds were admitted concurrently, want exactly 1", won)
	}
}
