// Package watchdog manages the hardware watchdog device for litevirtd.
// As long as the daemon is running, it writes a keepalive byte to the watchdog
// device at half the configured timeout interval. If the daemon dies, the
// watchdog fires and reboots the node — enabling self-fencing.
//
// The watchdog is optional: if the device path is empty or the device doesn't
// exist, the heartbeat is silently skipped.
package watchdog

import (
	"context"
	"log/slog"
	"os"
	"time"
)

const (
	// defaultDev is the standard Linux watchdog device.
	defaultDev = "/dev/watchdog"
	// keepaliveByte is written each interval to reset the watchdog timer.
	keepaliveByte = byte('1')
	// defaultInterval is how often to write; should be < hardware timeout / 2.
	defaultInterval = 15 * time.Second
)

// Heartbeat sends periodic keepalives to the watchdog device.
// It blocks until ctx is cancelled, at which point it writes the magic close
// byte ('V') to disarm the watchdog gracefully before returning.
func Heartbeat(ctx context.Context, devPath string, interval time.Duration) {
	// A non-empty devPath means the operator explicitly enabled watchdog
	// fencing (and preflightWatchdog already validated the device exists). An
	// empty path is the auto/optional case — fall back to the default device
	// but stay quiet if it's absent.
	configured := devPath != ""
	if devPath == "" {
		devPath = defaultDev
	}
	if interval <= 0 {
		interval = defaultInterval
	}

	f, err := os.OpenFile(devPath, os.O_WRONLY, 0)
	if err != nil {
		if configured {
			// Startup preflight passed, so a failure to open the configured
			// device now (e.g. permissions, device yanked) means self-fencing
			// is silently dead — make it loud, not a Debug line.
			slog.Error("watchdog device configured but cannot be opened; self-fencing is DISABLED",
				"dev", devPath, "error", err)
		} else {
			// No device configured — optional, stay quiet.
			slog.Debug("watchdog device unavailable, heartbeat disabled", "dev", devPath, "error", err)
		}
		return
	}
	defer func() {
		// Graceful shutdown: write 'V' to disarm so the watchdog doesn't fire.
		_, _ = f.Write([]byte("V"))
		f.Close()
		slog.Info("watchdog disarmed", "dev", devPath)
	}()

	slog.Info("watchdog heartbeat started", "dev", devPath, "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := f.Write([]byte{keepaliveByte}); err != nil {
				slog.Error("watchdog keepalive failed", "dev", devPath, "error", err)
				// Don't return — keep trying; an open file error may recover.
			}
		}
	}
}
