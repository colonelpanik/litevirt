package systemdunit

import (
	"fmt"
	"strings"
	"testing"
)

// TestMainUnitRestartsOnACleanExit is the kvm001 outage in one assertion.
//
// systemd.service(5): a service that dies from SIGHUP, SIGINT, SIGTERM or SIGPIPE
// has exited CLEANLY, and Restart=on-failure restarts on none of them. So a SIGHUP
// from needrestart left the daemon dead with the unit reporting Result=success and
// NRestarts=0, and nothing ever brought it back — roughly three hours, with
// libvirtd and both VMs down alongside it.
func TestMainUnitRestartsOnACleanExit(t *testing.T) {
	if strings.Contains(Main, "Restart=on-failure") {
		t.Error("Restart=on-failure cannot recover a SIGHUP'd daemon: systemd counts that " +
			"death as a clean exit and never restarts, so the node stays down indefinitely")
	}
	if !strings.Contains(Main, "Restart=always") {
		t.Errorf("main unit must use Restart=always:\n%s", Main)
	}
}

// TestMainUnitDoesNotRestartAfterUninstall guards the cost of Restart=always.
// Uninstall deletes the unit files and the binary and then exits; without this
// systemd would restart a unit whose ExecStart no longer exists.
func TestMainUnitDoesNotRestartAfterUninstall(t *testing.T) {
	want := fmt.Sprintf("RestartPreventExitStatus=%d", UninstallExitCode)
	if !strings.Contains(Main, want) {
		t.Errorf("main unit must carry %q so the uninstall exit is not restarted; "+
			"the constant and the unit have to agree:\n%s", want, Main)
	}
}

// TestMainUnitKeepsQEMUOutOfSystemdsReach pins the two settings that keep systemd
// from reaching into the QEMU children in our cgroup subtree.
func TestMainUnitKeepsQEMUOutOfSystemdsReach(t *testing.T) {
	for _, want := range []string{"KillMode=process", "Delegate=no"} {
		if !strings.Contains(Main, want) {
			t.Errorf("main unit lost %q:\n%s", want, Main)
		}
	}
}

// TestMainUnitStartLimitIsGenerous: a burst of EXTERNAL restarts (needrestart
// during an apt run) must not trip the start limit, because that fires
// OnFailure=litevirt-rollback against a perfectly healthy binary.
func TestMainUnitStartLimitIsGenerous(t *testing.T) {
	if !strings.Contains(Main, "StartLimitBurst=10") {
		t.Errorf("expected StartLimitBurst=10:\n%s", Main)
	}
	if strings.Contains(Main, "StartLimitBurst=3") {
		t.Error("StartLimitBurst is back to 3 — a restart burst would trip the rollback unit")
	}
}

// TestRollbackIsGatedOnTheUpgradeSentinel is the 2026-07-15 docker004 outage.
// Without the gate, ANY failed state — including a restart storm against a healthy
// binary — downgrades that binary and can burn the only .old.
//
// This lives here rather than only in internal/grpcapi because the installer used
// to ship its own ungated copy, and this is now the single text both use.
func TestRollbackIsGatedOnTheUpgradeSentinel(t *testing.T) {
	sentinel := strings.Index(Rollback, "litevirt.upgrade-pending")
	if sentinel < 0 {
		t.Fatal("rollback unit no longer checks the .upgrade-pending sentinel — a non-upgrade " +
			"failure could downgrade a healthy binary")
	}
	swap := strings.Index(Rollback, "mv /usr/local/bin/litevirt.old")
	if swap < 0 {
		t.Fatal("rollback unit no longer restores .old")
	}
	if sentinel > swap {
		t.Error("the sentinel check must come BEFORE the .old restore, or a missing sentinel " +
			"does not skip the rollback")
	}
	if !strings.Contains(Rollback, "NOT rolling back") {
		t.Error("the no-sentinel branch must say out loud that it is not rolling back")
	}
}

// TestNeedrestartBlacklistsLitevirt: a stateful orchestrator must not be bounced
// mid-operation by a library upgrade.
func TestNeedrestartBlacklistsLitevirt(t *testing.T) {
	if !strings.Contains(Needrestart, "blacklist_rc") || !strings.Contains(Needrestart, `litevirt\.service`) {
		t.Errorf("needrestart drop-in must blacklist litevirt.service:\n%s", Needrestart)
	}
}

// TestUnitsAreHeredocSafe: both units are written by the installer through a
// quoted shell heredoc terminated by UNIT / DROPIN on its own line. A body
// containing that terminator would end the heredoc early and write a truncated
// unit — silently, and only on freshly-installed nodes.
func TestUnitsAreHeredocSafe(t *testing.T) {
	for name, body := range map[string]string{"Main": Main, "Rollback": Rollback, "Needrestart": Needrestart} {
		if !strings.HasSuffix(body, "\n") {
			t.Errorf("%s must end in a newline, or the heredoc terminator lands on its last line", name)
		}
		for _, term := range []string{"\nUNIT\n", "\nDROPIN\n"} {
			if strings.Contains(body, term) {
				t.Errorf("%s contains the heredoc terminator %q and would be truncated on install", name, strings.TrimSpace(term))
			}
		}
	}
}
