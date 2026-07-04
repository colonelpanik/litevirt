//go:build !linux

package watchdog

import "errors"

// isHardwareWatchdog is a no-op off Linux (the watchdog device is Linux-only). It
// reports "not a hardware watchdog" so self-fencing capability is never advertised on
// a platform where WDIOC_GETSUPPORT isn't available.
func isHardwareWatchdog(uintptr) (bool, string) { return false, "" }

// The watchdog ioctls are Linux-only; these are no-ops off Linux. petWatchdog returns an
// error so Heartbeat falls back to the keepalive byte-write.
func armWatchdog(uintptr, int)             {}
func petWatchdog(uintptr) error            { return errors.New("watchdog ioctls unsupported off linux") }
func watchdogTimeLeft(uintptr) (int, bool) { return 0, false }
func disarmWatchdog(uintptr)               {}
