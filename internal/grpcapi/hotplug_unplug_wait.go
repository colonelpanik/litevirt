package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// Device unplug is ASYNCHRONOUS. libvirt's own documentation is explicit:
//
//	Device unplug is asynchronous in most cases and requires guest cooperation.
//	This means that it's up to the discretion of the guest to disallow or delay
//	the unplug arbitrarily. As the libvirt API used in this command was designed
//	as synchronous it returns success after some timeout even if the device was
//	not unplugged yet [...] Callers which need to make sure that the device was
//	unplugged can use libvirt events to be notified when the device is removed.
//
// So a successful DetachDisk/DetachNIC/DetachHostdev means the unplug was
// REQUESTED, not that the device is gone, and a caller that reads the live domain
// once immediately afterwards reports a guest that has not answered yet as a
// detach that failed.
//
// Waiting alone is NOT enough, which measurement on real hardware settled. Runs
// against a 4-node lab, detaching a disk hot-added seconds earlier from a guest
// still booting:
//
//   - the request was not merely late — the disk was still in the live domain 12s,
//     60s and 120s later, and a further 75s of pure waiting never cleared it;
//   - a guest that has not yet enumerated the just-hot-added device never answers
//     the ACPI/PCI eject at all, so the request is DROPPED, not queued;
//   - re-issuing the same detach once the guest had booted removed it in under 5s.
//
// Hence: poll AND periodically re-request. The re-request is what lets the wait
// succeed rather than merely postpone the same failure. Re-sending is the
// documented remedy for a missed eject and is safe — the loop exits the moment the
// device is absent, and a re-request aimed at an already-removed device fails
// harmlessly, because there is nothing left to unplug.
//
// The robust form is to subscribe to VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED before
// issuing the detach (the event can arrive before the call returns). go-libvirt
// exposes it as DomainEventIDDeviceRemoved, but an event stream would still need
// the re-request to cover a dropped eject, so it buys latency, not correctness.

// DeviceUnplugPollInterval is the FIRST gap between live-domain reads. The gap
// doubles up to DeviceUnplugPollMaxInterval, so a guest that answers promptly is
// noticed almost immediately while a long wait does not spend its whole window
// re-reading domain XML four times a second.
var DeviceUnplugPollInterval = 250 * time.Millisecond

// DeviceUnplugPollMaxInterval caps that backoff.
var DeviceUnplugPollMaxInterval = 1 * time.Second

// DeviceUnplugReissueInterval is how often the detach is re-requested while the
// device is still present. 5s is long enough not to interrupt a guest mid-handshake
// with a redundant eject, short enough to land several attempts inside the timeout.
var DeviceUnplugReissueInterval = 5 * time.Second

// DeviceUnplugTimeout caps the whole wait. A cooperative guest completes a
// virtio/PCI unplug in well under a second; 30s matches the order of libvirt's own
// internal wait for the device-removal event before it gives up on the guest.
var DeviceUnplugTimeout = 30 * time.Second

// errUnplugTimeout reports that the device was still present when the wait expired.
// Callers translate it into their own device-specific "still present" message so the
// operator-facing wording is unchanged from the un-waited version.
var errUnplugTimeout = errors.New("device still present when the unplug wait expired")

// unplugWaitStats is the instrumentation for one wait: what it cost and how long it
// took, so the price of waiting is observable in the field rather than inferred.
type unplugWaitStats struct {
	Reads    int           // live-domain reads performed
	Reissues int           // detach re-requests issued
	Elapsed  time.Duration // wall time spent in the wait
}

// waitDeviceGone polls gone until it reports true, the deadline expires, or ctx is
// done, re-issuing the detach via reissue (when non-nil) every
// DeviceUnplugReissueInterval. It returns nil once the device is absent,
// errUnplugTimeout on expiry, and any READ error immediately — an unreadable domain
// FAILS CLOSED (absence is unproven, which is not the same as presence, and the
// detach paths route both to forward recovery rather than a re-attach).
//
// A failing re-request is NOT fatal: the device may have just left, or the guest may
// be mid-handshake. Only the reads decide the outcome.
//
// gone is called once before any sleeping or re-requesting, so an already-absent
// device — the overwhelmingly common case — costs exactly one read, no re-request
// and no delay.
func waitDeviceGone(ctx context.Context, gone func() (bool, error), reissue func() error) (unplugWaitStats, error) {
	start := time.Now()
	deadline := start.Add(DeviceUnplugTimeout)
	nextReissue := start.Add(DeviceUnplugReissueInterval)
	interval := DeviceUnplugPollInterval

	var st unplugWaitStats
	for {
		st.Reads++
		ok, err := gone()
		if err != nil {
			st.Elapsed = time.Since(start)
			return st, err
		}
		if ok {
			st.Elapsed = time.Since(start)
			return st, nil
		}

		now := time.Now()
		if !now.Before(deadline) {
			st.Elapsed = time.Since(start)
			return st, errUnplugTimeout
		}

		if reissue != nil && !now.Before(nextReissue) {
			st.Reissues++
			if rerr := reissue(); rerr != nil {
				slog.Debug("device unplug: re-request failed (device may have just left)", "error", rerr)
			}
			nextReissue = now.Add(DeviceUnplugReissueInterval)
		}

		select {
		case <-ctx.Done():
			st.Elapsed = time.Since(start)
			return st, ctx.Err()
		case <-time.After(interval):
		}
		if interval < DeviceUnplugPollMaxInterval {
			interval *= 2
			if interval > DeviceUnplugPollMaxInterval {
				interval = DeviceUnplugPollMaxInterval
			}
		}
	}
}

// logUnplugWait records what a wait cost. Emitted only when it actually waited (more
// than one read) or ended badly, so the common instant case stays silent.
func logUnplugWait(kind, vmName, device string, st unplugWaitStats, err error) {
	if st.Reads <= 1 && err == nil {
		return
	}
	slog.Info("device unplug wait",
		"kind", kind, "vm", vmName, "device", device,
		"reads", st.Reads, "reissues", st.Reissues,
		"elapsed_ms", st.Elapsed.Milliseconds(), "confirmed", err == nil)
}
