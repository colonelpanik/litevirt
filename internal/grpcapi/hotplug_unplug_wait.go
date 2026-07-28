package grpcapi

import (
	"context"
	"errors"
	"time"
)

// Device unplug is ASYNCHRONOUS. libvirt's own documentation is explicit about it:
//
//	Device unplug is asynchronous in most cases and requires guest cooperation.
//	This means that it's up to the discretion of the guest to disallow or delay
//	the unplug arbitrarily. As the libvirt API used in this command was designed
//	as synchronous it returns success after some timeout even if the device was
//	not unplugged yet [...] Callers which need to make sure that the device was
//	unplugged can use libvirt events to be notified when the device is removed.
//
// So a successful DetachDisk/DetachNIC/DetachHostdev means "the unplug was
// REQUESTED", not "the device is gone". Reading the live domain immediately after
// therefore races the guest and reports a device that is on its way out as one that
// failed to leave. The persistent (inactive) definition is NOT subject to this — a
// config-only change applies synchronously — so only the LIVE read needs to wait.
//
// The robust form is to subscribe to VIR_DOMAIN_EVENT_ID_DEVICE_REMOVED before
// issuing the detach (the event can arrive before the call returns). go-libvirt
// exposes it as DomainEventIDDeviceRemoved, but wiring an event stream through the
// libvirt client and both fakes is a much larger change; bounded polling gets the
// same correctness with the same failure semantics, and the timeout — not a single
// unlucky read — is what makes a detach a failure.

// DeviceUnplugPollInterval controls how often the live domain is re-read while
// waiting for a requested unplug to land. 250ms mirrors LiveMoverPollInterval: fast
// enough that a healthy guest's sub-second unplug is not padded noticeably, slow
// enough not to hammer libvirt.
var DeviceUnplugPollInterval = 250 * time.Millisecond

// DeviceUnplugTimeout caps that wait. A cooperative guest completes a virtio/PCI
// unplug in well under a second; 30s matches the order of libvirt's own internal
// wait for the device-removal event before it gives up on the guest.
var DeviceUnplugTimeout = 30 * time.Second

// errUnplugTimeout reports that the device was still present when the wait expired.
// Callers translate it into their own device-specific "still present" message so the
// operator-facing wording is unchanged from the un-waited version.
var errUnplugTimeout = errors.New("device still present when the unplug wait expired")

// waitDeviceGone polls gone until it reports true, the deadline expires, or ctx is
// done. It returns nil once the device is absent, errUnplugTimeout on expiry, and
// any read error immediately — an unreadable domain FAILS CLOSED (absence is
// unproven, which is not the same as presence, and the detach paths route both to
// forward recovery rather than a re-attach).
//
// gone is called once before any sleeping, so a synchronous unplug — and every test
// backend that models one — costs exactly one read and no delay.
func waitDeviceGone(ctx context.Context, gone func() (bool, error)) error {
	deadline := time.Now().Add(DeviceUnplugTimeout)
	for {
		ok, err := gone()
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if !time.Now().Before(deadline) {
			return errUnplugTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(DeviceUnplugPollInterval):
		}
	}
}
