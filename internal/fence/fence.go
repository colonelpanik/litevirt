// Package fence implements host fencing strategies for litevirt.
// Fencing = cutting off a host before stealing its workloads to prevent split-brain.
// Strategies are tried in order; callers choose which to use via HostRecord.FenceStrategy.
package fence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"
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
//	"manual"       – log an alert and return Success=false; the coordinator will NOT
//	                 reschedule until an operator confirms via `lv host fence-confirm`
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

	cmd, cancel := ipmitoolCmd(ctx, h, "chassis", "power", "off")
	out, runErr := cmd.CombinedOutput()
	cancel()
	detail := fmt.Sprintf("ipmitool chassis power off %s: %s", h.IPMIAddress, strings.TrimSpace(string(out)))

	if runErr != nil {
		return Result{Method: "ipmi", Detail: fmt.Sprintf("%s (%v)", detail, runErr), Success: false}
	}

	// The power-off command returning 0 means the BMC ACCEPTED the request, not
	// that the chassis is down. Only the polled status proves the host cannot
	// still be writing to shared storage, so an unconfirmed fence is a failure.
	verified, verifyErr := verifyIPMIPowerOff(ctx, h)
	if !verified {
		slog.Warn("IPMI fence sent but power-off not confirmed",
			"host", h.Name, "within", PowerOffVerifyTimeout, "error", verifyErr)
		return Result{
			Method: "ipmi",
			Detail: fmt.Sprintf("%s (power-off not confirmed within %s: %v)",
				detail, PowerOffVerifyTimeout, verifyErr),
			Success: false,
		}
	}

	return Result{Method: "ipmi", Detail: detail, Success: true}
}

// ipmitoolPerCallTimeout bounds ONE ipmitool invocation. Without it a BMC that
// accepts the TCP connection and then stops answering hangs the call for as
// long as the caller's context allows — during a fence that is the whole
// failover budget spent on a single unresponsive controller.
const ipmitoolPerCallTimeout = 8 * time.Second

// The power-off verification budget. These are vars rather than consts ONLY so
// tests can shrink them; nothing in production reassigns them.
var (
	// PowerOffVerifyTimeout is the total wall-clock budget for confirming the
	// chassis is off, across however many polls fit inside it.
	PowerOffVerifyTimeout = 15 * time.Second
	powerOffPollInterval  = 2 * time.Second
)

// chassisPowerOff is ipmitool's power-status line for a chassis that is off,
// lowercased. Matched as a SUFFIX, never as a substring — see isChassisOff.
const chassisPowerOff = "chassis power is off"

// ipmitoolCmd builds one ipmitool invocation against h's BMC, with the password
// passed through the environment instead of argv.
//
// `-P <pass>` puts the BMC password in the process table, where every local
// user can read it off `ps` for the lifetime of the call. `-E` makes ipmitool
// read it from the environment instead, which is not world-readable.
//
// Both IPMI_PASSWORD and IPMITOOL_PASSWORD are set to the same value on
// purpose. Under `-E` ipmitool PREFERS IPMITOOL_PASSWORD, so setting only
// IPMI_PASSWORD would let a value inherited from the daemon's own environment
// silently override the per-host credential — every fence would then
// authenticate with the wrong password and fail closed cluster-wide.
//
// `-N 1 -R 2` bounds the RMCP retry behaviour so an unreachable BMC fails in
// about a second instead of sitting in ipmitool's default retry loop; the
// returned CancelFunc must be called by the caller to release the timeout.
func ipmitoolCmd(ctx context.Context, h HostConfig, ipmiArgs ...string) (*exec.Cmd, context.CancelFunc) {
	cctx, cancel := context.WithTimeout(ctx, ipmitoolPerCallTimeout)
	args := append([]string{
		"-I", "lanplus",
		"-H", h.IPMIAddress,
		"-U", h.IPMIUser,
		"-E",
		"-N", "1",
		"-R", "2",
	}, ipmiArgs...)
	cmd := exec.CommandContext(cctx, "ipmitool", args...)
	cmd.Env = append(os.Environ(),
		"IPMI_PASSWORD="+h.IPMIPass,
		"IPMITOOL_PASSWORD="+h.IPMIPass,
	)
	// SIGTERM first so ipmitool can close its RMCP session; SIGKILL follows if
	// it ignores that. Without WaitDelay a wedged child keeps the pipes open and
	// Output() blocks past the timeout it was supposed to enforce.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	return cmd, cancel
}

// verifyIPMIPowerOff polls "chassis power status" until the BMC reports the
// chassis off, the budget expires, or ctx is done.
//
// It returns (true, nil) ONLY on a positive, anchored power-off reading. Any
// other outcome returns false plus the last substantive READING — the BMC said
// the chassis is still on, or the BMC refused, or it never answered — so the
// caller can record WHY it could not confirm. Those are very different facts
// about a host that may still be writing to shared storage, and the old bool
// return collapsed them into one indistinguishable false.
//
// "Substantive" excludes a call this function's own budget killed: that error is
// "signal: terminated", which describes our timeout rather than the BMC, and
// letting it win would erase the reading it interrupted. Reporting the earlier
// reading is deliberate, so a caller must not read the returned error as
// describing the FINAL attempt. When no reading landed at all, the error says
// exactly that.
func verifyIPMIPowerOff(ctx context.Context, h HostConfig) (bool, error) {
	vctx, cancel := context.WithTimeout(ctx, PowerOffVerifyTimeout)
	defer cancel()

	lastErr := errors.New("no power-status reading was taken")
	for {
		// Checked at the top so an already-expired budget cannot slip one more
		// ipmitool call past the deadline.
		if vctx.Err() != nil {
			return false, lastErr
		}

		started := time.Now()
		cmd, cancelCall := ipmitoolCmd(vctx, h, "chassis", "power", "status")
		out, err := cmd.Output()
		cancelCall()

		switch {
		case err != nil:
			// A call OUR OWN budget killed is not a reading, and must not
			// overwrite one. cmd.Output() reports the SIGTERM as "signal:
			// terminated", which carries neither the exit status nor the BMC's
			// stderr — so letting it win replaces the operator's only
			// explanation of why the power-off was unconfirmed with a
			// description of our timeout. fencing_log.detail is where that
			// explanation is read, when deciding whether to run
			// `lv host fence-confirm` on a host that may still be running.
			//
			// Whichever substantive reading came before is the one worth
			// keeping. If none did, lastErr still says no reading was taken,
			// which is both true and more use than the signal name.
			if vctx.Err() != nil {
				return false, lastErr
			}
			lastErr = ipmitoolError(err)
		case isChassisOff(out):
			return true, nil
		default:
			lastErr = fmt.Errorf("chassis not off: %q", strings.TrimSpace(string(out)))
		}

		// Pace from the START of the attempt, not its end: a call that already
		// spent the interval should poll again immediately rather than adding
		// another interval on top and wasting the budget.
		if wait := powerOffPollInterval - time.Since(started); wait > 0 {
			select {
			case <-vctx.Done():
				return false, lastErr
			case <-time.After(wait):
			}
		}
	}
}

// isChassisOff reports whether out is ipmitool's power-status line for an off
// chassis.
//
// The match is anchored at the end of the trimmed output. A substring search
// for "off" — which is what this used to do — reads as confirmed power-off on
// text that says nothing of the kind: an authentication failure mentioning
// "Set Session Privilege Level failed", a "Powering off" transitional line, or
// any BMC banner containing those three letters. Confirming a fence that never
// happened is the one error this function must not make: it is the last check
// between a live host and another node starting its VMs on the same disks.
func isChassisOff(out []byte) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSpace(string(out))), chassisPowerOff)
}

// ipmitoolError folds a failed run's stderr into the returned error. exec's
// ExitError prints only "exit status 1", which tells an operator reading the
// fence log nothing about whether the BMC refused the credentials, was
// unreachable, or rejected the command.
func ipmitoolError(err error) error {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if msg := strings.TrimSpace(string(ee.Stderr)); msg != "" {
			return fmt.Errorf("%w: %s", err, msg)
		}
	}
	return err
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
