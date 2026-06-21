package watchdog

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHeartbeat_MissingDevice_NoOp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	// Non-existent device should not panic or block.
	Heartbeat(ctx, "/dev/nonexistent-watchdog-litevirt-test", 50*time.Millisecond)
}

func TestHeartbeat_WritesKeepalive(t *testing.T) {
	// Use a regular file as a stand-in for the watchdog device.
	tmp := filepath.Join(t.TempDir(), "fake-watchdog")
	if err := os.WriteFile(tmp, nil, 0600); err != nil {
		t.Fatalf("create fake watchdog: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancel()

	Heartbeat(ctx, tmp, 30*time.Millisecond)

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
		Heartbeat(ctx, tmp, 10*time.Second) // long interval — only disarm matters
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
