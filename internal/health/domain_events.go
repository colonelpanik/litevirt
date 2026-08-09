package health

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// DomainEventHandler turns libvirt domain lifecycle events into cluster state —
// the event-driven counterpart of VMChecker's polling sweep, and it shares
// VMChecker's rules: act only on this host's VMs, and never on one an operator
// stopped on purpose.
//
// It lives here rather than inline in daemon.Run so the decision logic is a
// callable unit a test can drive (the daemon registers the very same handler;
// see internal/daemon.Run and tests/fleet/domain_event_test.go).
//
// Note for anyone reading this expecting production coverage: internal/libvirt
// never subscribes to go-libvirt's lifecycle-event stream, so nothing in
// production invokes this today. Real VM-death detection comes from the polling
// VMChecker/Reconciler. Wiring the event stream up is a separate change.
type DomainEventHandler struct {
	hostName string
	db       *corrosion.Client

	// onStateWriteFail observes an authoritative state write that failed (nil-safe);
	// wired to the litevirt_state_write_failures_total counter by the daemon.
	onStateWriteFail func(op, class string)
}

// NewDomainEventHandler returns a handler that records crashes for hostName's VMs.
func NewDomainEventHandler(hostName string, db *corrosion.Client) *DomainEventHandler {
	return &DomainEventHandler{hostName: hostName, db: db}
}

// SetStateWriteFailObserver wires the state-write-failure metric hook (nil-safe).
func (h *DomainEventHandler) SetStateWriteFailObserver(fn func(op, class string)) {
	h.onStateWriteFail = fn
}

func (h *DomainEventHandler) noteStateWriteFail(op string, err error) {
	if h.onStateWriteFail != nil {
		h.onStateWriteFail(op, corrosion.ClassifyWriteErr(err))
	}
}

// Callback returns the lv.DomainEventCallback to register on a libvirt client.
// The returned closure runs synchronously on the caller's goroutine and does its
// corrosion reads/writes under ctx. Anything other than a crash or a stop is
// ignored: a start/shutdown event carries no failure to record.
func (h *DomainEventHandler) Callback(ctx context.Context) lv.DomainEventCallback {
	return func(domName string, event lv.DomainEventType, detail int) {
		switch event {
		case lv.DomainEventCrashed, lv.DomainEventStopped:
			vm, err := corrosion.GetVM(ctx, h.db, domName)
			if err != nil || vm == nil || vm.HostName != h.hostName {
				return
			}
			if vm.StateDetail == "operator-stop" {
				return // don't act on intentional stops
			}
			slog.Warn("domain event: VM stopped/crashed", "vm", domName, "event", event, "detail", detail)
			if err := corrosion.UpdateVMState(ctx, h.db, domName, "error",
				fmt.Sprintf("domain event: stopped (detail=%d). Check host dmesg for OOM.", detail)); err != nil {
				slog.Error("domain event: failed to record crash state — reconciler will re-detect", "vm", domName, "error", err)
				h.noteStateWriteFail(corrosion.OpVMState, err)
			}
		}
	}
}
