package libvirt

import (
	"testing"
)

func TestClient_IsAlive_NilVirt(t *testing.T) {
	c := &Client{virt: nil}
	if c.isAlive() {
		t.Error("isAlive should return false when virt is nil")
	}
}

func TestClient_Close_NilVirt(t *testing.T) {
	c := &Client{virt: nil}
	if err := c.Close(); err != nil {
		t.Errorf("Close on nil virt should return nil, got %v", err)
	}
}

func TestClient_Libvirt_NilVirt(t *testing.T) {
	c := &Client{virt: nil}
	if v := c.Libvirt(); v != nil {
		t.Error("Libvirt() should return nil when virt is nil")
	}
}

func TestClient_RegisterDomainEventCallback(t *testing.T) {
	c := &Client{}
	called := false
	cb := func(domainName string, event DomainEventType, detail int) {
		called = true
	}
	c.RegisterDomainEventCallback(cb)

	c.mu.RLock()
	hasCB := c.eventCallback != nil
	c.mu.RUnlock()

	if !hasCB {
		t.Error("eventCallback should be set after RegisterDomainEventCallback")
	}

	// Invoke to verify it's callable.
	c.mu.RLock()
	c.eventCallback("test-vm", DomainEventCrashed, 0)
	c.mu.RUnlock()

	if !called {
		t.Error("callback was not invoked")
	}
}

func TestDomainEventTypeConstants(t *testing.T) {
	// Verify constants match expected values.
	if DomainEventStarted != 0 {
		t.Errorf("DomainEventStarted = %d, want 0", DomainEventStarted)
	}
	if DomainEventStopped != 1 {
		t.Errorf("DomainEventStopped = %d, want 1", DomainEventStopped)
	}
	if DomainEventCrashed != 2 {
		t.Errorf("DomainEventCrashed = %d, want 2", DomainEventCrashed)
	}
	if DomainEventShutdown != 3 {
		t.Errorf("DomainEventShutdown = %d, want 3", DomainEventShutdown)
	}
}

func TestReconnectConstants(t *testing.T) {
	if reconnectInterval <= 0 {
		t.Error("reconnectInterval should be positive")
	}
	if reconnectMaxBackoff <= reconnectInterval {
		t.Error("reconnectMaxBackoff should be greater than reconnectInterval")
	}
}
