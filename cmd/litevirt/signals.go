package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/litevirt/litevirt/internal/metrics"
)

// clockCleanExitSignals are the signals systemd counts as a CLEAN termination.
//
// systemd.service(5) defines a clean exit as status 0 OR death by SIGHUP, SIGINT,
// SIGTERM or SIGPIPE, and Restart=on-failure restarts on neither. SIGINT and
// SIGTERM are fine — those are how an operator or systemd itself asks us to stop,
// and the daemon handles them gracefully. The other two are not asking for
// anything: SIGHUP is what needrestart and unattended-upgrades send, and SIGPIPE
// can arrive from a peer connection dying mid-write. Letting either terminate the
// process leaves the node down indefinitely with the unit reporting success
// (kvm001, 2026-07-24, ~3h), because from systemd's side nothing failed.
var cleanExitSignals = []os.Signal{syscall.SIGHUP, syscall.SIGPIPE}

// drainIgnoredSignals installs a handler for the signals that must never
// terminate the daemon, and returns a channel reporting each one observed.
//
// This deliberately uses signal.Notify with a drain rather than signal.Ignore.
// Ignore sets SIG_IGN at the OS level, which is INHERITED ACROSS execve — so a
// self-upgrade re-exec would silently keep the disposition, correct but invisible
// and impossible to test. Notify keeps the handling in this process, in this
// function, where a journal line records that it happened.
//
// SIGHUP conventionally means "reload your configuration", and this does not do
// that on purpose: the daemon reads its config once during startup and most of it
// (ports, listeners, PKI and data directories) is consumed while wiring up
// subsystems. There is no coherent reload to offer, and inventing a partial one
// that re-reads the few safe fields would be a new class of bug. Logging and
// dropping the signal is the honest behaviour.
//
// The returned channel is buffered and non-blocking to send on, so a test can
// observe deliveries without the handler ever stalling in production, where
// nothing reads it.
func drainIgnoredSignals(ctx context.Context) <-chan os.Signal {
	incoming := make(chan os.Signal, 1)
	signal.Notify(incoming, cleanExitSignals...)

	observed := make(chan os.Signal, 8)
	go func() {
		defer signal.Stop(incoming)
		for {
			select {
			case sig := <-incoming:
				slog.Warn("ignoring signal: the daemon neither terminates nor reloads on it; "+
					"dying here would look like a clean exit to systemd and leave this node down",
					"signal", sig.String())
				metrics.SignalIgnored(sig.String())
				select {
				case observed <- sig:
				default:
				}
			case <-ctx.Done():
				return
			}
		}
	}()
	return observed
}
