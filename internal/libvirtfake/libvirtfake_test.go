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

// TestFakeSetDomainOwnerEpoch_RefusesAPreEpochValue keeps the fake's marker
// contract identical to the real client's. A generation starts at 1, so 0 and
// negatives are refused — without this, a test could pass against a marker state
// internal/libvirt would never write.
func TestFakeSetDomainOwnerEpoch_RefusesAPreEpochValue(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	for _, epoch := range []int64{0, -1} {
		if err := f.SetDomainOwnerEpoch("vm1", epoch, true); err == nil {
			t.Errorf("the fake accepted epoch %d; the real client refuses it", epoch)
		}
	}
	if _, ok, _ := f.GetDomainOwnerEpoch("vm1"); ok {
		t.Error("a refused write still recorded a marker")
	}
	if err := f.SetDomainOwnerEpoch("vm1", 1, true); err != nil {
		t.Fatalf("epoch 1 is the first legal generation and must be accepted: %v", err)
	}
}

// Undefining an ACTIVE domain does not remove it: it survives as a TRANSIENT
// domain, keeps running and keeps its UUID — so it still holds its name, and a
// definition reusing that name with a different UUID must be refused.
//
// The contract matters because the production cutover depends on it: a handoff
// that undefined a running replacement and then redefined it under the new name
// would look like a rename here and fail against a real daemon.
func TestFake_TransientDomainStillHoldsItsName(t *testing.T) {
	f := New()
	if err := f.DefineDomain(`<domain><name>vm1</name><uuid>uuid-one</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := f.StartDomain("vm1"); err != nil {
		t.Fatal(err)
	}
	if err := f.UndefineDomainPreservingState("vm1"); err != nil {
		t.Fatal(err)
	}

	// Still there, still active, still holding the UUID.
	active, err := f.DomainIsActive("vm1")
	if err != nil || !active {
		t.Fatalf("an undefined ACTIVE domain must survive as transient: active=%v err=%v", active, err)
	}
	// Its name is not a free slot.
	if err := f.DefineDomain(`<domain><name>vm1</name><uuid>uuid-two</uuid></domain>`); err == nil {
		t.Error("a different UUID was accepted at a transient domain's name")
	}
	// Nor is its UUID available under another name.
	if err := f.DefineDomain(`<domain><name>vm2</name><uuid>uuid-one</uuid></domain>`); err == nil {
		t.Error("a transient domain's UUID was accepted under another name")
	}
	// Redefining it as ITSELF is how a transient domain is made persistent again.
	if err := f.DefineDomain(`<domain><name>vm1</name><uuid>uuid-one</uuid></domain>`); err != nil {
		t.Errorf("redefining a transient domain as itself must be allowed: %v", err)
	}

	// An INACTIVE domain, by contrast, is really gone after an undefine.
	if err := f.DefineDomain(`<domain><name>vm3</name><uuid>uuid-three</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := f.UndefineDomainPreservingState("vm3"); err != nil {
		t.Fatal(err)
	}
	if err := f.DefineDomain(`<domain><name>vm3</name><uuid>uuid-four</uuid></domain>`); err != nil {
		t.Errorf("a freed name must be reusable: %v", err)
	}
}
