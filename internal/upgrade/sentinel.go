// Package upgrade holds the node-local artifacts shared between the upgrade RPC
// (which stages a new binary) and the daemon's post-upgrade health watchdog
// (which verifies the new binary or rolls it back). It is a leaf package (stdlib
// only) so both internal/grpcapi and internal/daemon can import it without a cycle.
package upgrade

import (
	"encoding/json"
	"os"
	"time"
)

// Sentinel marks that the binary at its sibling path was just swapped in by an
// upgrade and must prove itself intrinsically healthy (local gRPC pingable) or be
// rolled back to <binary>.old. It is written next to the daemon binary, is
// node-local, and survives the re-exec.
type Sentinel struct {
	Timestamp   string `json:"ts"`
	PrevVersion string `json:"prev_version"`
	Attempt     int    `json:"attempt"` // rollbacks already made — the flap guard
}

// SentinelPath returns the sentinel file path for a given daemon binary path.
func SentinelPath(binaryPath string) string { return binaryPath + ".upgrade-pending" }

// Arm writes a fresh sentinel (attempt=0) next to binaryPath.
func Arm(binaryPath, prevVersion string) error {
	return write(binaryPath, Sentinel{
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		PrevVersion: prevVersion,
	})
}

// Read returns the sentinel and true if one is present and well-formed.
func Read(binaryPath string) (Sentinel, bool) {
	b, err := os.ReadFile(SentinelPath(binaryPath))
	if err != nil {
		return Sentinel{}, false
	}
	var s Sentinel
	if json.Unmarshal(b, &s) != nil {
		return Sentinel{}, false
	}
	return s, true
}

// Clear removes the sentinel (health confirmed). Best-effort.
func Clear(binaryPath string) { _ = os.Remove(SentinelPath(binaryPath)) }

// BumpAttempt rewrites the sentinel with Attempt incremented — called just before
// a rollback so the restored binary's watchdog knows a rollback already happened
// and won't roll back again.
func BumpAttempt(binaryPath string, s Sentinel) {
	s.Attempt++
	_ = write(binaryPath, s)
}

func write(binaryPath string, s Sentinel) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(SentinelPath(binaryPath), b, 0644)
}

// ResolveBinaryPath returns the running daemon binary path (os.Executable),
// falling back to the canonical install path. It matches grpcapi.daemonBinary so
// the upgrade RPC (writer) and the watchdog (reader/rollback) agree on the
// sentinel and .old locations.
func ResolveBinaryPath() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		return exe
	}
	return "/usr/local/bin/litevirt"
}
