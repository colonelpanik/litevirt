package daemon

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// preflightUnitCheck verifies the systemd unit serving litevirtd has the
// expected critical fields. The single most-dangerous regression is
// `KillMode` switching from `process` to `control-group` (the systemd
// default), which would kill every QEMU child process whenever the daemon
// stopped — turning a routine restart into a cluster-wide VM massacre.
//
// We refuse to start if KillMode != process. Operators can override with
// LITEVIRT_UNSAFE_NO_KILLMODE_CHECK=1 (e.g., when running outside systemd
// for testing — but then they're on the hook for the consequences).
//
// Returns nil if the check passes or doesn't apply (non-systemd hosts).
func preflightUnitCheck() error {
	if os.Getenv("LITEVIRT_UNSAFE_NO_KILLMODE_CHECK") == "1" {
		return nil
	}
	// If systemctl isn't on PATH we're probably running outside systemd
	// (containers, dev shells). Skip.
	if _, err := exec.LookPath("systemctl"); err != nil {
		return nil
	}
	// If we weren't started by systemd, the unit doesn't apply to this run.
	// Detect via the INVOCATION_ID env var systemd sets for service units.
	if os.Getenv("INVOCATION_ID") == "" {
		return nil
	}

	out, err := exec.Command("systemctl", "show", "litevirt.service",
		"-p", "KillMode", "-p", "Delegate").CombinedOutput()
	if err != nil {
		// systemctl reachable but the unit doesn't exist (e.g., development
		// install). Don't block; just log.
		slog.Warn("preflight: systemctl show litevirt.service failed (continuing)",
			"error", err, "output", strings.TrimSpace(string(out)))
		return nil
	}
	props := parseSystemctlProps(string(out))
	if km := props["KillMode"]; km != "" && km != "process" {
		return fmt.Errorf(
			"unsafe systemd unit: KillMode=%q (want \"process\"); a daemon stop "+
				"would kill child QEMU processes. Fix /etc/systemd/system/litevirt.service "+
				"and run `systemctl daemon-reload`. Override with "+
				"LITEVIRT_UNSAFE_NO_KILLMODE_CHECK=1 if you understand the risk.",
			km)
	}
	if d := props["Delegate"]; d == "yes" {
		// Delegate=yes gives the daemon's cgroup subtree to the unit; with
		// KillMode=process this is mostly fine, but a future regression to
		// control-group would then nuke QEMU. We refuse to be subtle: warn
		// loudly so an operator notices.
		slog.Warn("preflight: systemd unit has Delegate=yes; consider Delegate=no for safer KillMode interaction")
	}
	return nil
}

// parseSystemctlProps parses `systemctl show --property` output (KEY=VALUE
// per line) into a map.
func parseSystemctlProps(s string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, '=')
		if i < 0 {
			continue
		}
		out[line[:i]] = line[i+1:]
	}
	return out
}
