package fence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConnectTimeout_NoDeadline(t *testing.T) {
	ctx := context.Background()
	got := connectTimeout(ctx, 10)
	if got != 10 {
		t.Errorf("connectTimeout(no deadline, 10) = %d, want 10", got)
	}
}

func TestConnectTimeout_WithDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got := connectTimeout(ctx, 10)
	if got > 3 {
		t.Errorf("connectTimeout(3s deadline, 10) = %d, want <= 3", got)
	}
}

func TestConnectTimeout_DeadlineExceedsDefault(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	got := connectTimeout(ctx, 10)
	if got != 10 {
		t.Errorf("connectTimeout(60s deadline, 10) = %d, want 10", got)
	}
}

func TestFenceManual_Fields(t *testing.T) {
	h := HostConfig{
		Name:          "node-1",
		Address:       "10.0.0.10",
		FenceStrategy: "manual",
	}
	r := Execute(context.Background(), h)
	if r.Method != "manual" {
		t.Errorf("Method = %q, want manual", r.Method)
	}
	// Manual fence reports Success=false until an operator confirms via
	// `lv host fence-confirm`. The failover coordinator's split-brain
	// guard depends on this — see internal/failover/coordinator.go.
	if r.Success {
		t.Error("manual fence must report Success=false until operator confirms")
	}
	if r.Detail == "" {
		t.Error("Detail should not be empty")
	}
}

func TestFenceWatchdog_InvalidDevice(t *testing.T) {
	h := HostConfig{
		Name:          "node-2",
		FenceStrategy: "watchdog",
		WatchdogDev:   "/nonexistent/watchdog",
	}
	r := Execute(context.Background(), h)
	if r.Success {
		t.Error("watchdog fence with nonexistent device should fail")
	}
	if r.Method != "watchdog" {
		t.Errorf("Method = %q, want watchdog", r.Method)
	}
}

func TestFenceWatchdog_DefaultDevice(t *testing.T) {
	h := HostConfig{
		Name:          "node-3",
		FenceStrategy: "watchdog",
		WatchdogDev:   "", // should default to /dev/watchdog
	}
	r := Execute(context.Background(), h)
	// Will fail since /dev/watchdog likely doesn't exist in test env.
	if r.Method != "watchdog" {
		t.Errorf("Method = %q, want watchdog", r.Method)
	}
}

func TestFenceWatchdog_WithTempFile(t *testing.T) {
	// Create a temp file to simulate a watchdog device.
	tmp := t.TempDir()
	dev := filepath.Join(tmp, "watchdog")
	if err := os.WriteFile(dev, []byte(""), 0644); err != nil {
		t.Fatalf("create temp watchdog: %v", err)
	}

	h := HostConfig{
		Name:          "node-4",
		FenceStrategy: "watchdog",
		WatchdogDev:   dev,
	}
	r := Execute(context.Background(), h)
	if !r.Success {
		t.Errorf("watchdog fence with writable file should succeed: %s", r.Detail)
	}
	if r.Method != "watchdog" {
		t.Errorf("Method = %q, want watchdog", r.Method)
	}
}

func TestFenceSSH_Strict_Fails(t *testing.T) {
	h := HostConfig{
		Name:          "ssh-test",
		Address:       "192.0.2.1", // TEST-NET
		SSHUser:       "root",
		SSHPort:       22,
		FenceStrategy: "ssh",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r := Execute(ctx, h)
	if r.Success {
		t.Error("strict SSH fence to unreachable host should fail")
	}
	if r.Method != "ssh" {
		t.Errorf("Method = %q, want ssh", r.Method)
	}
}

func TestFenceSSH_DefaultPort(t *testing.T) {
	h := HostConfig{
		Name:          "ssh-defaults",
		Address:       "192.0.2.2",
		SSHPort:       0,  // should default to 22
		SSHUser:       "", // should default to root
		FenceStrategy: "ssh",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := Execute(ctx, h)
	// Should still be SSH method, just failing.
	if r.Method != "ssh" {
		t.Errorf("Method = %q, want ssh", r.Method)
	}
}

func TestFenceIPMI_NoAddress(t *testing.T) {
	h := HostConfig{
		Name:          "ipmi-test",
		FenceStrategy: "ipmi",
		IPMIAddress:   "",
	}
	r := Execute(context.Background(), h)
	if r.Success {
		t.Error("IPMI without address should fail")
	}
	if r.Method != "ipmi" {
		t.Errorf("Method = %q, want ipmi", r.Method)
	}
	if r.Detail != "ipmi_address not configured on host" {
		t.Errorf("Detail = %q", r.Detail)
	}
}

func TestFenceBestEffort_WithPort(t *testing.T) {
	h := HostConfig{
		Name:          "best-effort-port",
		Address:       "192.0.2.5",
		SSHUser:       "admin",
		SSHPort:       2222,
		FenceStrategy: "best-effort",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := Execute(ctx, h)
	if !r.Success {
		t.Errorf("best-effort should succeed: %s", r.Detail)
	}
	if r.Method != "best-effort-ssh" {
		t.Errorf("Method = %q", r.Method)
	}
}

func TestFenceEmpty_Strategy(t *testing.T) {
	h := HostConfig{
		Name:          "empty-strat",
		Address:       "192.0.2.6",
		FenceStrategy: "",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := Execute(ctx, h)
	if !r.Success {
		t.Error("empty strategy (best-effort) should succeed")
	}
}

func TestFenceUnknown_FallsToBestEffort(t *testing.T) {
	h := HostConfig{
		Name:          "unknown-strat",
		Address:       "192.0.2.7",
		FenceStrategy: "UnknownSTRATEGY",
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r := Execute(ctx, h)
	if !r.Success {
		t.Error("unknown strategy should fall back to best-effort and succeed")
	}
	if r.Method != "best-effort-ssh" {
		t.Errorf("Method = %q, want best-effort-ssh", r.Method)
	}
}

func TestResult_Struct(t *testing.T) {
	r := Result{
		Method:  "test",
		Detail:  "some detail",
		Success: true,
	}
	if r.Method != "test" || r.Detail != "some detail" || !r.Success {
		t.Errorf("Result fields: %+v", r)
	}
}

func TestHostConfig_Fields(t *testing.T) {
	h := HostConfig{
		Name:          "host1",
		Address:       "10.0.0.1",
		SSHUser:       "admin",
		SSHPort:       2222,
		FenceStrategy: "ipmi",
		IPMIAddress:   "10.0.0.100",
		IPMIUser:      "admin",
		IPMIPass:      "password",
		WatchdogDev:   "/dev/watchdog0",
	}
	if h.Name != "host1" || h.IPMIAddress != "10.0.0.100" || h.WatchdogDev != "/dev/watchdog0" {
		t.Errorf("HostConfig fields: %+v", h)
	}
}
