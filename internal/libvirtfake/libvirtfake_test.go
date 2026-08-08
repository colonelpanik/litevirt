package libvirtfake

import (
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// TestFake_FireEvent_NoCallbackIsNoOp pins the constraint that keeps the fake
// safe for the ~40 fleet scenarios that never register a callback: firing into
// a fake with nothing registered must return silently, not panic.
func TestFake_FireEvent_NoCallbackIsNoOp(t *testing.T) {
	New().FireEvent("vm1", libvirt.DomainEventCrashed, 0)
}

// TestFake_FireEvent_DeliversToRegisteredCallback is the dispatch property: the
// callback sees exactly the domain, event and detail that were fired, and a
// second registration replaces the first rather than fanning out to both.
func TestFake_FireEvent_DeliversToRegisteredCallback(t *testing.T) {
	f := New()

	type call struct {
		domain string
		event  libvirt.DomainEventType
		detail int
	}
	var first, second []call
	f.RegisterDomainEventCallback(func(domain string, event libvirt.DomainEventType, detail int) {
		first = append(first, call{domain, event, detail})
	})

	f.FireEvent("vm1", libvirt.DomainEventCrashed, 7)
	if len(first) != 1 {
		t.Fatalf("callback got %d calls, want 1: %+v", len(first), first)
	}
	if got, want := (first[0]), (call{"vm1", libvirt.DomainEventCrashed, 7}); got != want {
		t.Fatalf("callback saw %+v, want %+v", got, want)
	}

	// Re-registering must hand every subsequent event to the NEW callback only.
	f.RegisterDomainEventCallback(func(domain string, event libvirt.DomainEventType, detail int) {
		second = append(second, call{domain, event, detail})
	})
	f.FireEvent("vm2", libvirt.DomainEventStopped, 1)
	if len(first) != 1 {
		t.Fatalf("replaced callback still received: %+v", first)
	}
	if got, want := len(second), 1; got != want {
		t.Fatalf("new callback got %d calls, want %d", got, want)
	}
	if got, want := (second[0]), (call{"vm2", libvirt.DomainEventStopped, 1}); got != want {
		t.Fatalf("new callback saw %+v, want %+v", got, want)
	}
}

// TestFake_FireEvent_CallbackMayReenterTheFake is the lock-discipline test. The
// registered callback is arbitrary daemon code that may call straight back into
// the fake, and f.mu is not reentrant — so FireEvent must copy the callback out
// and RELEASE the lock before invoking it. Someone "simplifying" FireEvent to
// `defer f.mu.Unlock()` deadlocks here.
//
// The call runs in a goroutine behind a 2s deadline so that bug surfaces as a
// red test in two seconds instead of hanging the package until the 10-minute
// panic timeout.
func TestFake_FireEvent_CallbackMayReenterTheFake(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)

	var (
		mu     sync.Mutex
		exists bool
	)
	f.RegisterDomainEventCallback(func(domain string, _ libvirt.DomainEventType, _ int) {
		// Both of these take f.mu.
		ok := f.DomainExists(domain)
		f.SetState(domain, StateShutdown)
		mu.Lock()
		exists = ok
		mu.Unlock()
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		f.FireEvent("vm1", libvirt.DomainEventCrashed, 0)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("FireEvent did not return within 2s: the callback deadlocked on f.mu " +
			"(FireEvent must release the lock before invoking it)")
	}

	mu.Lock()
	sawDomain := exists
	mu.Unlock()
	if !sawDomain {
		t.Error("callback's DomainExists(vm1) returned false, want true")
	}
	if got, err := f.DomainState("vm1"); err != nil || got != string(StateShutdown) {
		t.Errorf("callback's SetState did not take effect: state=%q err=%v", got, err)
	}
}
