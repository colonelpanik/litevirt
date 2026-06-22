package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSystemctlProps(t *testing.T) {
	in := "KillMode=process\nDelegate=no\nNotAPair\n\nFoo=bar=baz\n"
	got := parseSystemctlProps(in)
	want := map[string]string{
		"KillMode": "process",
		"Delegate": "no",
		"Foo":      "bar=baz",
	}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("[%s] = %q, want %q", k, got[k], v)
		}
	}
}

// TestPreflight_NotUnderSystemdSkips verifies the check is a no-op when
// not running under systemd (no INVOCATION_ID env var).
func TestPreflight_NotUnderSystemdSkips(t *testing.T) {
	t.Setenv("INVOCATION_ID", "")
	if err := preflightUnitCheck(); err != nil {
		t.Errorf("non-systemd preflight returned error: %v", err)
	}
}

// TestPreflight_OverrideEnv verifies the unsafe override skips the check.
func TestPreflight_OverrideEnv(t *testing.T) {
	t.Setenv("LITEVIRT_UNSAFE_NO_KILLMODE_CHECK", "1")
	t.Setenv("INVOCATION_ID", "fake")
	if err := preflightUnitCheck(); err != nil {
		t.Errorf("override should skip; got error: %v", err)
	}
}

// An empty WatchdogDev means watchdog fencing is disabled — the check is a no-op.
func TestPreflightWatchdog_DisabledWhenUnset(t *testing.T) {
	if err := preflightWatchdog(""); err != nil {
		t.Errorf("empty watchdog_dev should be a no-op, got %v", err)
	}
}

// A configured device that's a real character device passes. /dev/null is a
// char device on Linux, so it stands in for /dev/watchdog without needing root
// or arming a real watchdog.
func TestPreflightWatchdog_CharDeviceOK(t *testing.T) {
	fi, err := os.Stat("/dev/null")
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		t.Skip("/dev/null not a char device on this platform")
	}
	if err := preflightWatchdog("/dev/null"); err != nil {
		t.Errorf("char device should pass, got %v", err)
	}
}

// A configured but missing device is fatal (split-brain risk).
func TestPreflightWatchdog_MissingDeviceFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "watchdog-does-not-exist")
	if err := preflightWatchdog(missing); err == nil {
		t.Error("missing watchdog device should refuse to start, got nil")
	}
}

// A regular file is not a character device → refuse to start.
func TestPreflightWatchdog_RegularFileFails(t *testing.T) {
	f := filepath.Join(t.TempDir(), "notadevice")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := preflightWatchdog(f); err == nil {
		t.Error("regular file should not pass as a watchdog device, got nil")
	}
}

// The unsafe override lets a missing device through (operator's risk).
func TestPreflightWatchdog_OverrideEnv(t *testing.T) {
	t.Setenv("LITEVIRT_UNSAFE_SKIP_WATCHDOG_CHECK", "1")
	missing := filepath.Join(t.TempDir(), "watchdog-does-not-exist")
	if err := preflightWatchdog(missing); err != nil {
		t.Errorf("override should skip the check, got %v", err)
	}
}
