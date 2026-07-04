//go:build linux

package watchdog

import (
	"strings"

	"golang.org/x/sys/unix"
)

// isHardwareWatchdog identifies an open watchdog device via WDIOC_GETSUPPORT and reports
// whether it is a real HARDWARE watchdog (one that can reboot a wedged kernel), delegating
// the identity decision to identityIsHardware. Returns (false, "") when the identity can't
// be read (unknown device → not trusted). The identity string is returned for logging.
func isHardwareWatchdog(fd uintptr) (bool, string) {
	info, err := unix.IoctlGetWatchdogInfo(int(fd))
	if err != nil {
		return false, "" // can't identify → untrusted (fail closed)
	}
	id := string(info.Identity[:])
	if i := strings.IndexByte(id, 0); i >= 0 {
		id = id[:i] // trim the NUL-padded fixed-width field
	}
	id = strings.TrimSpace(id)
	return identityIsHardware(id), id
}

// Linux watchdog ioctls (linux/watchdog.h; 'W' magic = 0x57, int arg). golang.org/x/sys/unix
// exposes WDIOC_GETSUPPORT + WDIOC_KEEPALIVE as helpers but not these request numbers, so
// compute them: _IOR('W',n,int) = (2<<30)|(4<<16)|(0x57<<8)|n ; _IOWR('W',n,int) = (3<<30)|…
const (
	wdiocSetOptions  = 0x80045704 // WDIOC_SETOPTIONS   _IOR ('W', 4, int)
	wdiocSetTimeout  = 0xc0045706 // WDIOC_SETTIMEOUT   _IOWR('W', 6, int)
	wdiocGetTimeLeft = 0x8004570a // WDIOC_GETTIMELEFT  _IOR ('W', 10, int)

	wdiosDisableCard = 0x0001 // WDIOS_DISABLECARD
	wdiosEnableCard  = 0x0002 // WDIOS_ENABLECARD
)

// armWatchdog explicitly ENABLES the timer (WDIOS_ENABLECARD) and sets its timeout. Opening
// the device arms most modern watchdog-FRAMEWORK drivers, but the LEGACY ipmi_watchdog device
// does NOT start its BMC timer on open + a keepalive byte-write — an explicit enable is
// required (the same start a raw `ipmitool mc watchdog reset` performs). Best-effort: a driver
// lacking SETTIMEOUT/SETOPTIONS returns ENOTTY, which we ignore — the open already armed those
// drivers, and any real arm is verified afterwards via watchdogTimeLeft.
func armWatchdog(fd uintptr, timeoutSec int) {
	if timeoutSec > 0 {
		_ = unix.IoctlSetPointerInt(int(fd), wdiocSetTimeout, timeoutSec)
	}
	_ = unix.IoctlSetPointerInt(int(fd), wdiocSetOptions, wdiosEnableCard)
}

// petWatchdog resets the timer via WDIOC_KEEPALIVE — the canonical keepalive. Preferred over a
// raw byte-write: no risk of an accidental 'V' magic-close, and it resets drivers whose write
// path does not (observed with ipmi_watchdog). Returns the ioctl error so the caller can fall
// back to a byte-write when the ioctl is unsupported (ENOTTY / non-framework device).
func petWatchdog(fd uintptr) error { return unix.IoctlWatchdogKeepalive(int(fd)) }

// watchdogTimeLeft reports the seconds left on the timer (WDIOC_GETTIMELEFT). ok=false when the
// device doesn't support the ioctl (can't verify) — distinct from a real 0 (armed-but-stopped).
// Used to VERIFY the watchdog is actually counting before advertising self-fence, so a device
// that opens+enables cleanly yet silently never runs (seen on some BMCs' ipmi_watchdog) is
// caught instead of trusted.
func watchdogTimeLeft(fd uintptr) (secs int, ok bool) {
	n, err := unix.IoctlGetInt(int(fd), wdiocGetTimeLeft)
	if err != nil {
		return 0, false
	}
	return n, true
}

// disarmWatchdog explicitly disables the timer (WDIOS_DISABLECARD) — a belt to the magic-close
// 'V' write on graceful shutdown (covers a nowayout=1 device). Best-effort.
func disarmWatchdog(fd uintptr) {
	_ = unix.IoctlSetPointerInt(int(fd), wdiocSetOptions, wdiosDisableCard)
}
