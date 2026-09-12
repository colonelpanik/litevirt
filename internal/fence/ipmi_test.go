package fence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testBMCPassword = "s3cret-bmc-pw"

func testIPMIHost() HostConfig {
	return HostConfig{
		Name:          "kvm-test",
		FenceStrategy: "ipmi",
		// TEST-NET-1 (RFC 5737): never routable, so a test that escapes the fake
		// ipmitool below fails fast instead of reaching someone's real BMC.
		IPMIAddress: "192.0.2.9",
		IPMIUser:    "admin",
		IPMIPass:    testBMCPassword,
	}
}

// fakeIpmitool puts an `ipmitool` on PATH that prints `stdout`, sleeps `delay`,
// and appends one line per invocation to a log file recording its argv and the
// two password environment variables it actually received.
//
// Exercising the real exec path matters: the properties under test here are
// argv contents, environment precedence, and output matching, and a stubbed
// function seam would assert none of them.
func fakeIpmitool(t *testing.T, stdout string, delay time.Duration, exitCode int) (logPath string) {
	t.Helper()
	return fakeIpmitoolStreams(t, stdout, "", delay, exitCode)
}

// fakeIpmitoolStreams is fakeIpmitool with control over stderr as well.
// ipmitool reports failures on stderr, and cmd.Output() captures ONLY stderr
// into ExitError.Stderr — a fake that writes its message to stdout cannot
// exercise the error-reporting path at all.
func fakeIpmitoolStreams(t *testing.T, stdout, stderr string, delay time.Duration, exitCode int) (logPath string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "invocations.log")

	script := fmt.Sprintf(`#!/bin/sh
{
  printf 'ARGV:%%s\n' "$*"
  printf 'IPMI_PASSWORD:%%s\n' "$IPMI_PASSWORD"
  printf 'IPMITOOL_PASSWORD:%%s\n' "$IPMITOOL_PASSWORD"
} >> %q
sleep %v
printf '%%s\n' %q
printf '%%s\n' %q >&2
exit %d
`, logPath, delay.Seconds(), stdout, stderr, exitCode)

	path := filepath.Join(dir, "ipmitool")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake ipmitool: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return logPath
}

// shrinkVerifyKnobs makes a "not off" verdict cheap: that verdict is reached by
// exhausting the budget, so the real 15s would be paid by every negative case.
// Budgets stay well above process-fork cost so a loaded machine does not turn a
// cancelled poll into a false negative.
func shrinkVerifyKnobs(t *testing.T, budget, interval time.Duration) {
	t.Helper()
	origBudget, origInterval := PowerOffVerifyTimeout, powerOffPollInterval
	PowerOffVerifyTimeout, powerOffPollInterval = budget, interval
	t.Cleanup(func() {
		PowerOffVerifyTimeout, powerOffPollInterval = origBudget, origInterval
	})
}

func readInvocations(t *testing.T, logPath string) []string {
	t.Helper()
	b, err := os.ReadFile(logPath)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func countInvocations(t *testing.T, logPath string) int {
	t.Helper()
	n := 0
	for _, line := range readInvocations(t, logPath) {
		if strings.HasPrefix(line, "ARGV:") {
			n++
		}
	}
	return n
}

// TestIpmitool_PasswordNeverInArgv is a security regression guard, asserted on
// the command as actually executed.
//
// `-P <pass>` puts the BMC password in argv, and argv is world-readable via
// /proc/<pid>/cmdline — so any local user could read the credential that powers
// off the fleet straight out of `ps` during a fence.
func TestIpmitool_PasswordNeverInArgv(t *testing.T) {
	logPath := fakeIpmitool(t, "Chassis Power is off", 0, 0)

	if _, err := verifyIPMIPowerOff(context.Background(), testIPMIHost()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	lines := readInvocations(t, logPath)
	if len(lines) == 0 {
		t.Fatal("fake ipmitool was never invoked; the test proves nothing")
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "ARGV:") && strings.Contains(line, testBMCPassword) {
			t.Errorf("BMC password present in argv: %q", line)
		}
		if strings.HasPrefix(line, "ARGV:") && strings.Contains(line, "-P ") {
			t.Errorf("argv still passes -P: %q", line)
		}
	}
}

// TestIpmitool_OverridesInheritedIpmitoolPassword pins the precedence hazard.
//
// Under -E, ipmitool reads IPMI_PASSWORD or IPMITOOL_PASSWORD and
// IPMITOOL_PASSWORD WINS. Since the command inherits the daemon environment, a
// systemd EnvironmentFile / container -e / exported operator variable would
// otherwise override every per-host credential and fail auth fleet-wide.
func TestIpmitool_OverridesInheritedIpmitoolPassword(t *testing.T) {
	t.Setenv("IPMITOOL_PASSWORD", "inherited-wrong-password")
	logPath := fakeIpmitool(t, "Chassis Power is off", 0, 0)

	if _, err := verifyIPMIPowerOff(context.Background(), testIPMIHost()); err != nil {
		t.Fatalf("verify: %v", err)
	}

	var sawCorrect bool
	for _, line := range readInvocations(t, logPath) {
		if after, ok := strings.CutPrefix(line, "IPMITOOL_PASSWORD:"); ok {
			if after == "inherited-wrong-password" {
				t.Fatal("inherited IPMITOOL_PASSWORD reached ipmitool and takes precedence over " +
					"IPMI_PASSWORD — every host would authenticate with the wrong credential")
			}
			if after == testBMCPassword {
				sawCorrect = true
			}
		}
	}
	if !sawCorrect {
		t.Error("IPMITOOL_PASSWORD was not set to this host's password, so an inherited value could win")
	}
}

// TestVerifyIPMIPowerOff_RequiresAnchoredOffStatus is the false-positive guard.
//
// This predicate is the sole proof authorizing a shared-disk cross-host
// transfer, so a false positive means two hosts writing one disk. `chassis
// status` prints "Power Restore Policy : always-off" while the system is ON —
// an unanchored substring match certifies a running host as fenced.
func TestVerifyIPMIPowerOff_RequiresAnchoredOffStatus(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   bool
	}{
		{"off", "Chassis Power is off", true},
		{"off with padding", "  Chassis Power is off  ", true},
		{"mixed case", "CHASSIS POWER IS OFF", true},
		{"on", "Chassis Power is on", false},
		{"policy field mentions off while powered on", "System Power : on\nPower Restore Policy   : always-off", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fakeIpmitool(t, tc.stdout, 0, 0)
			shrinkVerifyKnobs(t, 2*time.Second, 50*time.Millisecond)

			got, _ := verifyIPMIPowerOff(context.Background(), testIPMIHost())
			if got != tc.want {
				t.Errorf("verifyIPMIPowerOff on %q = %v, want %v", tc.stdout, got, tc.want)
			}
		})
	}
}

// TestVerifyIPMIPowerOff_PacesPollsFromCallStart pins the actual behavioural
// fix, so reverting it goes red.
//
// The old loop slept powerOffPollInterval AFTER each call, so a slow BMC ate the
// budget in call+sleep chunks; pacing from the call's START makes the poll count
// a function of the budget instead of the BMC's latency. With a 200ms call and a
// 2s interval, the old shape fits ~1 poll in this window and the new one fits
// several.
func TestVerifyIPMIPowerOff_PacesPollsFromCallStart(t *testing.T) {
	// Mirrors the measured shape: the call is SLOWER than the interval, which is
	// the only regime where pacing differs from sleeping.
	logPath := fakeIpmitool(t, "Chassis Power is on", 300*time.Millisecond, 0)
	shrinkVerifyKnobs(t, 2*time.Second, 200*time.Millisecond)

	if verified, _ := verifyIPMIPowerOff(context.Background(), testIPMIHost()); verified {
		t.Fatal("a chassis reporting on must not verify as off")
	}

	polls := countInvocations(t, logPath)
	// Paced: ~300ms per poll -> ~6. Old shape (call + full interval): ~500ms -> ~4.
	if polls < 5 {
		t.Errorf("only %d poll(s) in a %s budget with a 300ms call and a %s interval; "+
			"an unconditional post-call sleep would fit about %d, so pacing is not in effect",
			polls, PowerOffVerifyTimeout, powerOffPollInterval,
			int(PowerOffVerifyTimeout/(300*time.Millisecond+powerOffPollInterval)))
	}
}

// TestVerifyIPMIPowerOff_ReportsWhyItFailed pins that an auth-style failure is
// distinguishable from a chassis that is simply still on. Both refuse the fence,
// but only the latter makes refusing to reschedule the correct outcome, and the
// reason is what an operator reads out of fencing_log during an incident.
//
// "exit status 1" alone is NOT enough to assert here: exec's own ExitError
// already says that much, so a check for it passes whether or not the stderr
// text is folded in. The BMC's own message is the part that has to survive.
func TestVerifyIPMIPowerOff_ReportsWhyItFailed(t *testing.T) {
	const bmcError = "Error: Unable to establish IPMI v2 / RMCP+ session"
	fakeIpmitoolStreams(t, "", bmcError, 0, 1)
	shrinkVerifyKnobs(t, 2*time.Second, 50*time.Millisecond)

	verified, err := verifyIPMIPowerOff(context.Background(), testIPMIHost())

	if verified {
		t.Fatal("a failing ipmitool must not verify as off")
	}
	if err == nil {
		t.Fatal("no error reported, so the fence detail cannot say why the power-off was unconfirmed")
	}
	if !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("error does not carry the invocation failure: %v", err)
	}
	if !strings.Contains(err.Error(), bmcError) {
		t.Errorf("error drops the BMC's own stderr, so the fence detail cannot say WHY: %v", err)
	}
}

// TestVerifyIPMIPowerOff_HonoursCancelledContext pins that verification gives up
// on a cancelled context rather than burning its whole budget: the fence runs
// inside a failover cycle and must not outlive its caller.
func TestVerifyIPMIPowerOff_HonoursCancelledContext(t *testing.T) {
	fakeIpmitool(t, "Chassis Power is on", 0, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan bool, 1)
	start := time.Now()
	go func() {
		verified, _ := verifyIPMIPowerOff(ctx, testIPMIHost())
		done <- verified
	}()

	select {
	case verified := <-done:
		if verified {
			t.Error("a cancelled context must not report a verified power-off")
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Errorf("took %s to abandon a cancelled verification", elapsed)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("verifyIPMIPowerOff ignored a cancelled context")
	}
}

// TestFenceIPMI_UnconfirmedDetailNamesTheBudgetAndCause pins the operator-facing
// record. This string lands in fencing_log.detail and is what an operator reads
// when deciding whether to run `lv host fence-confirm`, so a hardcoded duration
// that drifts from the constant misinforms an incident review.
func TestFenceIPMI_UnconfirmedDetailNamesTheBudgetAndCause(t *testing.T) {
	// Power-off succeeds; status never reports off.
	fakeIpmitool(t, "Chassis Power is on", 0, 0)
	shrinkVerifyKnobs(t, 2*time.Second, 50*time.Millisecond)

	r := fenceIPMI(context.Background(), testIPMIHost())

	if r.Success {
		t.Fatal("an unconfirmed power-off must not report success (FenceProofGrade would accept it)")
	}
	if !strings.Contains(r.Detail, PowerOffVerifyTimeout.String()) {
		t.Errorf("detail does not name the verification budget %s: %q", PowerOffVerifyTimeout, r.Detail)
	}
	if strings.Contains(r.Detail, testBMCPassword) {
		t.Errorf("fence detail leaks the BMC password into fencing_log: %q", r.Detail)
	}
}
