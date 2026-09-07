package grpcapi

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// The mirror's startup line has to name the cadence the mirror actually runs at.
//
// `netbox.sweep_interval_sec` defaults to 0 and the daemon passes it through
// unexamined, so an operator who never set the key hands StartNetBoxMirror a
// zero. Every consumer normalises it to 15 minutes — the reconciler's ticker and
// the leader-lease TTL sized from it — and the log line did not, so it printed
// `sweep_interval=0s` for a mirror sweeping every fifteen minutes.
//
// That is not cosmetic here. This line exists precisely so a fleet-wide
// disagreement is findable by comparing logs across nodes; a value that is not
// the value in use makes the comparison say nothing.

// TestMirrorStartLogsTheEffectiveInterval drives the real entry point with the
// argument an unset config key produces.
func TestMirrorStartLogsTheEffectiveInterval(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	// Cancelled immediately: the goroutine the start spawns must not outlive the
	// test, and the line under test is written before it is spawned.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !s.StartNetBoxMirror(ctx, 0) {
		t.Fatal("a node with a NetBox client and a database must start the mirror")
	}

	line := buf.String()
	if !strings.Contains(line, "netbox mirror: starting") {
		t.Fatalf("no start line was logged: %q", line)
	}
	if strings.Contains(line, "sweep_interval=0s") {
		t.Fatalf("the start line reports sweep_interval=0s while the mirror sweeps every %v: %q",
			defaultNetBoxSweepInterval, line)
	}
	if !strings.Contains(line, "sweep_interval="+defaultNetBoxSweepInterval.String()) {
		t.Fatalf("start line = %q, want the effective cadence %v", line, defaultNetBoxSweepInterval)
	}
}

// TestMirrorStartLogsAConfiguredInterval is the control: an interval the
// operator DID set must be logged as given, not replaced by the default.
func TestMirrorStartLogsAConfiguredInterval(t *testing.T) {
	s := newTestServerWithNetBox(t, fakeNetBox{
		prefix:        netboxPrefix{ID: 7, Prefix: "10.0.5.0/24", VRFID: 3},
		enforceUnique: true,
	})

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if !s.StartNetBoxMirror(ctx, 5*time.Minute) {
		t.Fatal("a node with a NetBox client and a database must start the mirror")
	}

	if line := buf.String(); !strings.Contains(line, "sweep_interval=5m0s") {
		t.Fatalf("start line = %q, want the configured cadence 5m0s", line)
	}
}
