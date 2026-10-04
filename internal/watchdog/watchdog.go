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
	"strings"
	"sync"
	"sync/atomic"
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

// Controller trips Heartbeat into SELF-FENCE mode: stop writing keepalives and do
// NOT disarm, so the hardware watchdog times out and reboots the host. Used when a
// partitioned host cannot complete an action it MUST (Phase 2 VIP demotion failure),
// and therefore has to guarantee itself DOWN so the majority can safely take over.
// Self-fence only actually reboots when a hardware watchdog is present; on a host
// without one, SelfFence is a loud no-op (the caller must still alert).
type Controller struct {
	fence   chan struct{}
	once    sync.Once
	armed   atomic.Bool
	tripped atomic.Bool

	// ownershipHeld reports whether this host still owns running workloads
	// (VMs, containers, a VIP). Consulted exactly once, at graceful shutdown,
	// to decide whether disarming is safe. Nil = not wired = disarm as always.
	ownershipMu   sync.RWMutex
	ownershipHeld func() bool
}

// SetOwnershipCheck wires the local-ownership probe consulted at graceful
// shutdown. While it reports true, Heartbeat refuses to disarm the watchdog on
// context cancellation: a daemon restart re-opens the device and resumes
// petting well inside the timeout, and a daemon STOP that abandons running
// workloads lets the watchdog fire — rebooting the host into a safely fenced
// state instead of leaving unmanaged workloads behind an unprotected node.
// Drain (or shutdown-workloads) first for planned maintenance.
func (c *Controller) SetOwnershipCheck(fn func() bool) {
	if c == nil {
		return
	}
	c.ownershipMu.Lock()
	c.ownershipHeld = fn
	c.ownershipMu.Unlock()
}

// holdsOwnership reports the wired probe's answer, false when none is wired.
// A probe that panics must not turn a graceful shutdown into a crash loop —
// it is treated as "held" (fail closed: refuse the disarm, keep the guarantee).
func (c *Controller) holdsOwnership() (held bool) {
	if c == nil {
		return false
	}
	c.ownershipMu.RLock()
	fn := c.ownershipHeld
	c.ownershipMu.RUnlock()
	if fn == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			held = true
		}
	}()
	return fn()
}

// NewController creates a watchdog controller. Pass it to Heartbeat.
func NewController() *Controller { return &Controller{fence: make(chan struct{})} }

// Armed reports whether Heartbeat has an OPEN watchdog device — i.e. a self-fence
// would actually reboot this host. Phase 2 conditions VIP self-demotion (and its
// advertised capability) on this: a node that can't self-fence must not self-demote
// (a stuck keepalived would otherwise dual-answer undetectably), and the majority
// must not trust it to release a VIP. False until Heartbeat opens the device (a
// brief startup window; fail-closed).
func (c *Controller) Armed() bool { return c != nil && c.armed.Load() }

// SelfFence trips the watchdog: Heartbeat stops petting it (without disarming) so it
// fires. Idempotent and safe to call from any goroutine. Nil-safe.
func (c *Controller) SelfFence() {
	if c == nil {
		return
	}
	c.tripped.Store(true)
	c.once.Do(func() { close(c.fence) })
}

// Fenced reports whether SelfFence has been tripped — true from the instant the fence
// decision is made until the hardware watchdog actually reboots this host. During that
// window the daemon is still live and serving, so callers use this to STOP TRUSTING this
// node (de-advertise capabilities, refuse runtime-ownership work): a node committed to
// fencing itself must not keep acting as a healthy member while it waits to go down.
// Nil-safe (a nil controller is never fenced).
func (c *Controller) Fenced() bool { return c != nil && c.tripped.Load() }

// wdiofMagicClose is WDIOF_MAGICCLOSE from linux/watchdog.h.
const wdiofMagicClose = 0x0100

// selfFenceMayClose reports whether closing the device leaves the watchdog
// RUNNING, which is the whole mechanism the self-fence path relies on.
//
// The kernel's watchdog_release() stops the timer when
// `expect_close == 42 || !(options & WDIOF_MAGICCLOSE)`. We never write the
// magic 'V' when self-fencing, so the first half is false — but the second half
// means a driver that does not ADVERTISE magic-close is stopped by the close
// itself. The host then never reboots while Fenced() reports true, which is the
// one state this subsystem exists to make impossible.
//
// known=false (identity unreadable, or not Linux) is treated as unsafe: the fd
// stays open, which keeps every driver armed.
func selfFenceMayClose(options uint32, known bool) bool {
	return known && options&wdiofMagicClose != 0
}

// armedDevices holds every watchdog file we must NOT close, for the life of
// the process.
//
// This is load-bearing, not bookkeeping. os.OpenFile returns a garbage-collected
// *os.File, and os.File.Fd's own documentation says the descriptor is valid only
// until the File is garbage collected — the runtime closes it for you. Simply
// declining to call Close therefore keeps nothing open: once Heartbeat returns,
// its local `f` is unreachable and the next GC issues the close, which is the
// very watchdog_release() that disarms a non-MAGICCLOSE driver.
//
// So the earlier "the fd is deliberately NOT closed" comment described an
// intention the code did not implement, and the disarm it set out to prevent
// came back on a nondeterministic timer inside the fence window.
var (
	armedMu      sync.Mutex
	armedDevices []*os.File
)

// retainArmed keeps f reachable from a package-level root so the runtime cannot
// finalize it and close the device out from under a fence.
func retainArmed(f *os.File) {
	armedMu.Lock()
	defer armedMu.Unlock()
	armedDevices = append(armedDevices, f)
}

// leaveArmed ends the heartbeat with the watchdog still counting, by whichever
// route the driver allows, and says which one it took.
//
// Both callers make the same promise — "this host will reboot at the timeout" —
// so both need the same care. Closing is safe only where the driver advertises
// WDIOF_MAGICCLOSE; everywhere else the descriptor is retained instead.
func leaveArmed(f *os.File, devPath, msg string, processSurvives bool) {
	opts, known := watchdogOptions(f.Fd())
	mayClose := selfFenceMayClose(opts, known)
	if mayClose {
		f.Close()
	} else {
		retainArmed(f)
	}
	d := armedGuarantee(mayClose, processSurvives)
	log := slog.Error
	attrs := []any{
		"dev", devPath,
		"magic_close", mayClose,
		"descriptor", map[bool]string{true: "closed", false: "retained"}[mayClose],
		"reboot_guaranteed", d.guaranteed,
	}
	if d.caveat != "" {
		attrs = append(attrs, "caveat", d.caveat)
	}
	log(msg, attrs...)
}

// armedDisposition is what actually happens to the timer, as distinct from what
// this process did with the descriptor.
type armedDisposition struct {
	guaranteed bool
	caveat     string
}

// armedGuarantee reports whether leaving the device armed actually guarantees
// the reboot, given the driver and whether THIS PROCESS survives the call.
//
// retainArmed only keeps the *os.File out of the garbage collector; it holds
// the descriptor "for the life of the process" and no longer. That is enough on
// the self-fence path, where the daemon keeps running until the watchdog
// reboots it. It is NOT enough on the shutdown-with-workloads path: daemon.Run
// returns, the process exits, and the kernel closes every descriptor it held.
//
// On a driver without WDIOF_MAGICCLOSE, watchdog_release() stops the timer on
// ANY close, including that implicit one -- which is precisely the driver class
// this code retains the descriptor FOR. So that path logged
// descriptor=retained and promised the host would reboot, on exactly the
// devices where it might not.
//
// The one thing that saves it is a driver built or configured with nowayout
// (WDOG_NO_WAY_OUT), where release cannot stop the timer. That is not
// detectable through the ioctl interface, so it is reported as a caveat rather
// than assumed either way.
func armedGuarantee(magicClose, processSurvives bool) armedDisposition {
	switch {
	case processSurvives:
		// The descriptor stays open (retained) or was closed on a driver that
		// documents close-is-safe. Either way the timer keeps counting.
		return armedDisposition{guaranteed: true}
	case magicClose:
		// Closing is the documented safe route on this driver, and we closed
		// explicitly rather than relying on process exit.
		return armedDisposition{guaranteed: true}
	default:
		return armedDisposition{
			guaranteed: false,
			caveat: "this process is exiting and the driver does not advertise MAGICCLOSE, " +
				"so the kernel's implicit close may STOP the timer and the host may not reboot; " +
				"only a driver with nowayout keeps counting. Drain this host or stop its " +
				"workloads rather than relying on the watchdog here",
		}
	}
}

// fenceCh returns the trip channel, or nil (which blocks forever in a select) when
// there is no controller — so the fence case never fires.
func (c *Controller) fenceCh() <-chan struct{} {
	if c == nil {
		return nil
	}
	return c.fence
}

// identityIsHardware decides, from a watchdog's WDIOC_GETSUPPORT identity string,
// whether it is a real hardware watchdog we can trust to fence this host. The software
// watchdog reports its identity as "Software Watchdog" (module: softdog) — it is only a
// kernel timer and cannot reboot a truly wedged kernel, so it (and any empty/unknown
// identity) is rejected. Case-insensitive. Pure + build-tag-free so it is unit-testable
// everywhere.
func identityIsHardware(identity string) bool {
	id := strings.ToLower(strings.TrimSpace(identity))
	switch id {
	case "", "softdog", "software watchdog":
		return false
	}
	return true
}

// Heartbeat sends periodic keepalives to the watchdog device. It blocks until ctx is
// cancelled (graceful: writes the magic close byte 'V' to DISARM) — UNLESS ctrl is
// tripped via SelfFence, in which case it stops petting WITHOUT disarming so the
// watchdog fires and reboots the host. ctrl may be nil (no self-fence path).
func Heartbeat(ctx context.Context, devPath string, interval time.Duration, ctrl *Controller) {
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
	// Choose the keepalive method once. Prefer the WDIOC_KEEPALIVE ioctl (canonical; no risk
	// of an accidental 'V' magic-close, and it resets drivers whose write path is a no-op —
	// e.g. legacy ipmi_watchdog). Fall back to a keepalive byte-write when the ioctl is
	// unsupported (ENOTTY / non-framework device / off Linux).
	petByIoctl := petWatchdog(f.Fd()) == nil
	pet := func() error {
		if petByIoctl {
			return petWatchdog(f.Fd())
		}
		_, werr := f.Write([]byte{keepaliveByte})
		return werr
	}
	if !petByIoctl {
		_ = pet() // first keepalive via byte-write (the ioctl path already petted above)
	}

	// A self-fence only reliably reboots this host on a HARDWARE watchdog (softdog is just a
	// kernel timer and can't fence a wedged kernel), so only a VERIFIED hardware watchdog is
	// marked armed. armed() is what the VIP demoter consults to decide whether an
	// UNCONFIRMABLE demotion self-fences (vs. staying up + raising HA-degraded); it does NOT
	// gate self-demotion itself, which runs regardless of any watchdog. Keep petting whatever
	// is open (so a softdog doesn't fire spuriously), but leave armed=false otherwise.
	if hw, id := isHardwareWatchdog(f.Fd()); !hw {
		slog.Error("watchdog is NOT a trusted hardware watchdog (softdog/unknown); self-fencing is not guaranteed — this host stays not-armed, so a demotion failure raises HA-degraded instead of self-fencing (it still self-demotes on quorum loss)",
			"dev", devPath, "identity", id)
	} else {
		// A successful open is NOT proof the timer runs: the legacy ipmi_watchdog needs an
		// EXPLICIT enable, and some BMCs silently keep it stopped. Enable + set the timeout,
		// pet, then require POSITIVE proof it is counting (WDIOC_GETTIMELEFT > 0) before
		// marking armed. FAIL CLOSED when we can't prove it — a watchdog we can't confirm is
		// running must never be trusted, or armed() reports true on false confidence and a
		// demotion failure would self-fence a host whose watchdog never actually reboots it.
		// Observed on some BMCs: ipmi_watchdog accepts SETOPTIONS/KEEPALIVE (returns success) yet
		// never starts the BMC timer AND doesn't support GETTIMELEFT — so it looks armed but
		// isn't. A node here stays not-armed (a demotion failure raises HA-degraded instead
		// of self-fencing), never a silent false-positive.
		armWatchdog(f.Fd(), watchdogTimeoutSec(interval))
		_ = pet()
		if left, ok := watchdogTimeLeft(f.Fd()); ok && left > 0 {
			slog.Info("hardware watchdog armed (self-fencing available; timer verified counting)", "dev", devPath, "identity", id, "timeleft_s", left)
			if ctrl != nil {
				ctrl.armed.Store(true)
			}
		} else {
			// Can't PROVE the timer is counting → do NOT advertise self-fence (armed stays
			// false). But KEEP PETTING (fall through to the loop below): some real watchdogs
			// arm on open() and won't disarm on close, so STOPPING keepalives here could
			// reboot the node when all we wanted was to withhold the capability. (ipmi_watchdog:
			// its timer never actually runs, so petting is a harmless no-op.) Graceful shutdown
			// still disarms via the defer's 'V'.
			slog.Error("watchdog timer NOT verifiably running (GETTIMELEFT unavailable or <=0 after enable+keepalive); self-fencing unavailable — this host stays not-armed (a demotion failure raises HA-degraded instead of self-fencing; self-demotion still runs). Still petting to avoid a spurious reboot. Verify the BMC/BIOS watchdog is enabled and the driver supports WDIOC_GETTIMELEFT.",
				"dev", devPath, "identity", id, "queryable", ok, "timeleft_s", left)
		}
	}
	fenced := false
	defer func() {
		// Also honor ctrl.Fenced(): if SelfFence was tripped but ctx.Done (graceful shutdown)
		// won the select race before the fence case ran, `fenced` is still false — disarming
		// here would defeat a self-fence the node already committed to. Leave it armed.
		if !fenced && !ctrl.Fenced() {
			// The clean-shutdown disarm hole (§B Phase 5): disarming while this
			// host still owns running workloads removes the self-fence guarantee
			// at the exact moment nothing manages those workloads. Refuse: leave
			// the device armed and counting. A restarting daemon re-opens and
			// pets it well inside the timeout; a daemon stopping for good with
			// workloads abandoned lets the watchdog reboot the host into a
			// safely fenced state. Operators drain before planned maintenance.
			if ctrl.holdsOwnership() {
				// processSurvives=false: daemon.Run returns right after this and
				// the process exits, so a retained descriptor is closed by the
				// kernel. See armedGuarantee.
				leaveArmed(f, devPath, "watchdog left ARMED on shutdown: this host still owns running workloads; "+
					"a successor daemon must resume petting before the timeout or the host reboots "+
					"(drain or stop workloads first for maintenance)", false)
				return
			}
			// Graceful shutdown: disable + write 'V' to disarm so the watchdog doesn't fire.
			if ctrl != nil {
				ctrl.armed.Store(false)
			}
			disarmWatchdog(f.Fd())      // explicit WDIOS_DISABLECARD …
			_, _ = f.Write([]byte("V")) // … plus the magic-close 'V' (covers a nowayout=1 device)
			f.Close()
			slog.Info("watchdog disarmed", "dev", devPath)
			return
		}
		// Self-fence: leave the watchdog ARMED so it fires and reboots this host.
		//
		// Closing the fd is only safe on a driver advertising WDIOF_MAGICCLOSE.
		// The kernel's watchdog_release() stops the timer when
		// `expect_close == 42 || !(options & WDIOF_MAGICCLOSE)`, and self-fence
		// deliberately never writes the magic 'V' — so on a driver without the
		// flag the close itself disarms the watchdog. The host would not reboot
		// while Fenced() reported true, and a coordinator would treat a live
		// node running its workloads as one being reset.
		//
		// Where the flag is absent or unreadable the descriptor is RETAINED
		// rather than merely left unclosed — see armedDevices for why those are
		// not the same thing. It holds one descriptor for the life of a process
		// that is seconds from resetting.
		// processSurvives=true: the daemon keeps running until the watchdog
		// reboots it, so a retained descriptor really does stay open.
		leaveArmed(f, devPath, "watchdog left ARMED (self-fence) — this host will reboot at the hardware watchdog timeout", true)
	}()

	slog.Info("watchdog heartbeat started", "dev", devPath, "interval", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ctrl.fenceCh():
			// SELF-FENCE tripped: stop petting so the watchdog reboots us. Wait for
			// shutdown so we never pet again; the defer leaves the device armed.
			fenced = true
			slog.Error("watchdog SELF-FENCE tripped — halting keepalives so the hardware watchdog reboots this host")
			return
		case <-ticker.C:
			if err := pet(); err != nil {
				slog.Error("watchdog keepalive failed", "dev", devPath, "error", err)
				// Don't return — keep trying; a transient error may recover.
			}
		}
	}
}

// watchdogTimeoutSec picks a hardware timeout comfortably larger than the pet interval (4×,
// floored at 30s) so a missed keepalive or two doesn't fire, while a genuinely stuck daemon
// still trips within a bounded time.
func watchdogTimeoutSec(interval time.Duration) int {
	if s := int(interval.Seconds()) * 4; s > 30 {
		return s
	}
	return 30
}
