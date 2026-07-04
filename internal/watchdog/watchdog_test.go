package watchdog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// watchdogTimeoutSec must stay comfortably above the pet interval (4×, floored at 30s) so a
// missed keepalive doesn't trip the watchdog.
func TestWatchdogTimeoutSec(t *testing.T) {
	for _, c := range []struct {
		interval time.Duration
		want     int
	}{
		{15 * time.Second, 60}, // default: 4× = 60
		{time.Second, 30},      // tiny interval → floor 30
		{30 * time.Second, 120},
	} {
		if got := watchdogTimeoutSec(c.interval); got != c.want {
			t.Errorf("watchdogTimeoutSec(%v) = %d, want %d", c.interval, got, c.want)
		}
	}
}

func TestHeartbeat_MissingDevice_NoOp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// Non-existent device should not panic or block.
	Heartbeat(ctx, "/dev/nonexistent-watchdog-litevirt-test", 50*time.Millisecond, nil)
}

func TestHeartbeat_WritesKeepalive(t *testing.T) {
	// Use a regular file as a stand-in for the watchdog device.
	tmp := filepath.Join(t.TempDir(), "fake-watchdog")
	if err := os.WriteFile(tmp, nil, 0600); err != nil {
		t.Fatalf("create fake watchdog: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	Heartbeat(ctx, tmp, 30*time.Millisecond, nil)

	data, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("read fake watchdog: %v", err)
	}
	// Should have at least one keepalive byte and the disarm 'V'.
	if len(data) < 2 {
		t.Errorf("expected at least 2 bytes written (keepalive + disarm), got %d: %q", len(data), data)
	}
	// Last byte should be the disarm 'V'.
	if data[len(data)-1] != 'V' {
		t.Errorf("expected last byte to be 'V' (disarm), got %q", data[len(data)-1])
	}
}

func TestHeartbeat_Disarms_OnCancel(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "fake-watchdog2")
	if err := os.WriteFile(tmp, nil, 0600); err != nil {
		t.Fatalf("create fake watchdog: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Heartbeat(ctx, tmp, 10*time.Second, nil) // long interval — only disarm matters
		close(done)
	}()

	// Cancel immediately.
	cancel()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Heartbeat did not return after cancel")
	}

	data, _ := os.ReadFile(tmp)
	if len(data) == 0 || data[len(data)-1] != 'V' {
		t.Errorf("expected disarm 'V' after cancel, got %q", data)
	}
}

// identityIsHardware must reject the software watchdog under BOTH the module name
// (softdog) and the identity string the kernel actually reports ("Software Watchdog"),
// plus any empty/unknown identity — case-insensitively — and accept a real driver.
func TestIdentityIsHardware(t *testing.T) {
	reject := []string{"", "  ", "softdog", "SoftDog", "Software Watchdog", "software watchdog", "SOFTWARE WATCHDOG"}
	for _, id := range reject {
		if identityIsHardware(id) {
			t.Errorf("identity %q must be rejected (not a trusted hardware watchdog)", id)
		}
	}
	accept := []string{"iTCO_wdt", "sp5100_tco", "hpwdt", "iamt_wdt"}
	for _, id := range accept {
		if !identityIsHardware(id) {
			t.Errorf("identity %q must be accepted as a hardware watchdog", id)
		}
	}
}

// A tripped Controller must make Heartbeat stop WITHOUT disarming — no 'V' is
// written, so the (real) hardware watchdog would fire and reboot the host.
func TestHeartbeat_SelfFence_LeavesArmed(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "fake-watchdog-fence")
	if err := os.WriteFile(tmp, nil, 0600); err != nil {
		t.Fatalf("create fake watchdog: %v", err)
	}

	ctrl := NewController()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		Heartbeat(ctx, tmp, 10*time.Second, ctrl) // long interval — only the fence matters
		close(done)
	}()

	ctrl.SelfFence()
	ctrl.SelfFence() // idempotent
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Heartbeat did not return after self-fence")
	}

	// Self-fence must NOT disarm: no 'V' written (the file stays empty here).
	data, _ := os.ReadFile(tmp)
	if len(data) > 0 && data[len(data)-1] == 'V' {
		t.Errorf("self-fence must NOT write disarm 'V'; got %q", data)
	}
}

// Fenced flips true once SelfFence is tripped (and is false before), so callers can
// de-advertise/stop trusting the node during the fence-timeout window. Nil-safe.
func TestFenced(t *testing.T) {
	var nilCtrl *Controller
	if nilCtrl.Fenced() {
		t.Fatal("nil controller must never report fenced")
	}
	ctrl := NewController()
	if ctrl.Fenced() {
		t.Fatal("a fresh controller is not fenced")
	}
	ctrl.SelfFence()
	if !ctrl.Fenced() {
		t.Fatal("SelfFence must flip Fenced() to true")
	}
	ctrl.SelfFence() // idempotent
	if !ctrl.Fenced() {
		t.Fatal("Fenced() stays true after a repeat SelfFence")
	}
}
