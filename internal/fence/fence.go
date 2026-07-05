// Package fence implements host fencing strategies for litevirt.
// Fencing = cutting off a host before stealing its workloads to prevent split-brain.
// Strategies are tried in order; callers choose which to use via HostRecord.FenceStrategy.
package fence

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Result is returned by every fence strategy.
type Result struct {
	Method  string
	Detail  string
	Success bool
}

// HostConfig is the subset of corrosion.HostRecord fields needed for fencing.
// Using a local struct avoids a circular import.
type HostConfig struct {
	Name          string
	Address       string
	SSHUser       string
	SSHPort       int
	FenceStrategy string
	// IPMI — only used when FenceStrategy = "ipmi"
	IPMIAddress string
	IPMIUser    string
	IPMIPass    string
	// Watchdog — only used when FenceStrategy = "watchdog" (self-fencing)
	WatchdogDev string
}

// Execute runs the fencing strategy specified by h.FenceStrategy.
// Strategies:
//
//	"best-effort"  – try SSH poweroff; succeed regardless (never blocks failover)
//	"ssh"          – SSH poweroff; report failure if unreachable
//	"ipmi"         – IPMI/BMC power off via ipmitool; must succeed
//	"manual"       – log an alert and return success immediately (human confirms)
//	"watchdog"     – write to /dev/watchdog to stop heartbeat (self-fencing, caller is local)
//	""             – treated as "best-effort"
func Execute(ctx context.Context, h HostConfig) Result {
	raw := strings.ToLower(strings.TrimSpace(h.FenceStrategy))
	strategy := ResolveStrategy(h.FenceStrategy)
	if strategy == "best-effort" && raw != "" && raw != "best-effort" {
		slog.Warn("unknown fence strategy, falling back to best-effort", "strategy", raw, "host", h.Name)
	}

	switch strategy {
	case "ipmi":
		return fenceIPMI(ctx, h)
	case "ssh":
		return fenceSSH(ctx, h, false)
	case "manual":
		return fenceManual(h)
	case "watchdog":
		return fenceWatchdog(h)
	default: // "best-effort" — lenient fire-and-forget SSH
		return fenceSSH(ctx, h, true)
	}
}

// ResolveStrategy returns the effective fence strategy Execute will run for a
// (possibly empty, mixed-case, or unknown) configured value. "", an unrecognized
// value, and "best-effort" all resolve to "best-effort" (lenient SSH). This is
// the SINGLE source of that normalization: any caller that must reason about
// which effective strategy will run — notably the safe-fence policy, which gates
// the best-effort path — MUST use this so it sees exactly what Execute sees and
// can't drift (e.g. a host with fence_strategy="" or a typo'd value would
// otherwise slip past a literal "best-effort" comparison).
func ResolveStrategy(raw string) string {
	switch s := strings.ToLower(strings.TrimSpace(raw)); s {
	case "ipmi", "ssh", "manual", "watchdog":
		return s
	default:
		return "best-effort"
	}
}

// fenceSSH sends "systemctl poweroff" to the host over SSH.
// If lenient=true, failures are reported as successful (best-effort mode).
func fenceSSH(ctx context.Context, h HostConfig, lenient bool) Result {
	port := h.SSHPort
	if port == 0 {
		port = 22
	}
	user := h.SSHUser
	if user == "" {
		user = "root"
	}
	target := fmt.Sprintf("%s@%s", user, h.Address)

	slog.Info("fencing host via SSH", "host", h.Name, "target", target, "lenient", lenient)

	cmd := exec.CommandContext(ctx, "ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "BatchMode=yes",
		"-o", fmt.Sprintf("ConnectTimeout=%d", connectTimeout(ctx, 10)),
		"-p", fmt.Sprintf("%d", port),
		target,
		"systemctl poweroff 2>/dev/null || poweroff 2>/dev/null || true",
	)
	out, runErr := cmd.CombinedOutput()
	detail := fmt.Sprintf("SSH poweroff to %s: %s", target, strings.TrimSpace(string(out)))

	if runErr != nil {
		if lenient {
			slog.Warn("SSH fence failed (best-effort, ignoring)", "host", h.Name, "error", runErr)
			return Result{
				Method:  "best-effort-ssh",
				Detail:  fmt.Sprintf("SSH failed (%v), proceeding anyway: %s", runErr, strings.TrimSpace(string(out))),
				Success: true,
			}
		}
		return Result{Method: "ssh", Detail: detail, Success: false}
	}
	return Result{Method: "ssh", Detail: detail, Success: true}
}

// fenceIPMI powers off the host via ipmitool chassis power off.
// Requires ipmitool to be installed on the managing host.
func fenceIPMI(ctx context.Context, h HostConfig) Result {
	if h.IPMIAddress == "" {
		return Result{
			Method:  "ipmi",
			Detail:  "ipmi_address not configured on host",
			Success: false,
		}
	}

	slog.Info("fencing host via IPMI", "host", h.Name, "bmc", h.IPMIAddress)

	args := []string{
		"-I", "lanplus",
		"-H", h.IPMIAddress,
		"-U", h.IPMIUser,
		"-P", h.IPMIPass,
		"chassis", "power", "off",
	}
	cmd := exec.CommandContext(ctx, "ipmitool", args...)
	out, runErr := cmd.CombinedOutput()
	detail := fmt.Sprintf("ipmitool chassis power off %s: %s", h.IPMIAddress, strings.TrimSpace(string(out)))

	if runErr != nil {
		return Result{Method: "ipmi", Detail: detail, Success: false}
	}

	// Verify power is actually off (optional — give BMC up to 15s).
	if verified := verifyIPMIPowerOff(ctx, h); !verified {
		slog.Warn("IPMI fence sent but power-off not confirmed", "host", h.Name)
		return Result{
			Method:  "ipmi",
			Detail:  detail + " (power-off not confirmed within 15s)",
			Success: false,
		}
	}

	return Result{Method: "ipmi", Detail: detail, Success: true}
}

// verifyIPMIPowerOff polls "chassis power status" up to 15 seconds.
func verifyIPMIPowerOff(ctx context.Context, h HostConfig) bool {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		args := []string{
			"-I", "lanplus",
			"-H", h.IPMIAddress,
			"-U", h.IPMIUser,
			"-P", h.IPMIPass,
			"chassis", "power", "status",
		}
		out, err := exec.CommandContext(ctx, "ipmitool", args...).Output()
		if err == nil && strings.Contains(string(out), "off") {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(2 * time.Second):
		}
	}
	return false
}

// fenceManual logs an alert but does not attempt any automated action.
// The operator is expected to manually power off the host and acknowledge.
//
// Returns Success=false so the coordinator's split-brain guard refuses to
// reschedule VMs without operator confirmation. A separate path (e.g.
// "lv host fence-confirm <host>") writes a fencing_log row with method
// "manual-confirmed" that the coordinator can detect via recentlyFenced
// before its next failover cycle.
//
// Old behavior (Success=true) silently bypassed the split-brain guard and
// could cause the same VM to run on two hosts simultaneously when the
// operator hadn't actually pulled the plug.
func fenceManual(h HostConfig) Result {
	msg := fmt.Sprintf("MANUAL FENCE REQUIRED: host %q (address %s) must be powered off by an operator and confirmed via 'lv host fence-confirm %s' before its VMs are restarted elsewhere", h.Name, h.Address, h.Name)
	slog.Warn(msg, "host", h.Name, "fence_strategy", "manual")
	// In a real deployment you would fire a webhook/alert here.
	return Result{
		Method:  "manual",
		Detail:  msg,
		Success: false,
	}
}

// fenceWatchdog stops the local watchdog heartbeat so the hardware watchdog
// reboots this node. Only meaningful when running on the node being fenced.
func fenceWatchdog(h HostConfig) Result {
	dev := h.WatchdogDev
	if dev == "" {
		dev = "/dev/watchdog"
	}
	slog.Warn("self-fencing via watchdog — stopping heartbeat", "dev", dev)

	f, err := os.OpenFile(dev, os.O_WRONLY, 0)
	if err != nil {
		return Result{
			Method:  "watchdog",
			Detail:  fmt.Sprintf("open %s: %v", dev, err),
			Success: false,
		}
	}
	// Deliberately do NOT write 'V' (magic close) — just close without keepalive.
	// The watchdog driver will expire and reboot the system.
	f.Close()

	return Result{
		Method:  "watchdog",
		Detail:  fmt.Sprintf("watchdog heartbeat stopped on %s; system will reboot", dev),
		Success: true,
	}
}

// connectTimeout returns min(seconds, remaining ctx seconds).
func connectTimeout(ctx context.Context, seconds int) int {
	if dl, ok := ctx.Deadline(); ok {
		rem := int(time.Until(dl).Seconds())
		if rem < seconds {
			return rem
		}
	}
	return seconds
}
