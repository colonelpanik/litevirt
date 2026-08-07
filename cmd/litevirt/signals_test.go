package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// kvm001 sat down for about three hours on 2026-07-24 because a SIGHUP — the
// class of signal needrestart and unattended-upgrades send — killed the daemon
// and systemd never restarted it.
//
// The reason is a systemd rule that is easy to miss: systemd.service(5) counts
// termination by SIGHUP, SIGINT, SIGTERM or SIGPIPE as a CLEAN exit, and
// Restart=on-failure explicitly does not restart on those four. So the unit
// reported Result=success with NRestarts=0 and left the node down; libvirtd went
// with it and both VMs stopped. No amount of restart-storm hardening reaches this
// path, because nothing ever fails.
//
// The daemon therefore has to refuse to die on the signal in the first place. It
// installs no SIGHUP handler today, so Go's runtime takes the die-from-signal
// path: none of the graceful shutdown runs — no markRestarting, so peers see an
// abrupt disappearance and briefly consider the node a fence candidate, and the
// DB and libvirt connections close dirty.

// TestSIGHUPDoesNotKillTheProcess is as direct as a signal test can be: if the
// drain is not installed, SIGHUP kills the test binary itself and the whole
// package run dies. There is no way for this to pass vacuously.
func TestSIGHUPDoesNotKillTheProcess(t *testing.T) {
	assertSignalDrained(t, syscall.SIGHUP)
}

// TestSIGPIPEDoesNotKillTheProcess covers the same systemd clean-exit class. A
// daemon that loses a peer mid-write can take SIGPIPE, and systemd would treat
// that death as clean too.
func TestSIGPIPEDoesNotKillTheProcess(t *testing.T) {
	assertSignalDrained(t, syscall.SIGPIPE)
}

func assertSignalDrained(t *testing.T, sig syscall.Signal) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	observed := drainIgnoredSignals(ctx)

	if err := syscall.Kill(os.Getpid(), sig); err != nil {
		t.Fatalf("kill self with %v: %v", sig, err)
	}
	select {
	case got := <-observed:
		if got != sig {
			t.Fatalf("drained %v, want %v", got, sig)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%v was never delivered to the drain; if the handler is not installed "+
			"this test does not fail here — the process is killed outright", sig)
	}
}
