package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Container host-loss relocation against a real cluster.
//
// This one is DESTRUCTIVE and cannot be driven by the CLI at all, for two
// independent reasons in the product:
//
//  1. `lv host fence` does not relocate. FenceHost (grpcapi/host.go:565) runs the
//     fence and sets host state to "offline"; it never enumerates VMs or
//     containers. Rescheduling lives only in the coordinator's failed-host path.
//  2. Fencing from the CLI actively PREVENTS relocation: the coordinator skips
//     any host already in offline/fenced/maintenance (failover/coordinator.go:364),
//     which is exactly the state the CLI just put it in.
//
// (Note the consequence for operators: `lv host fence-confirm` reports
// "coordinator may now reschedule", but that only holds when the COORDINATOR
// fenced and is awaiting confirmation. After an operator-initiated fence,
// nothing reschedules.)
//
// So the trigger has to be the victim's daemon genuinely dying, which needs
// out-of-band control the harness does not have.
//
// So the way to bring a host down is INJECTED. Provide commands with a {host}
// placeholder and an explicit opt-in:
//
//	E2E_DESTRUCTIVE=1 \
//	E2E_HOST_DOWN_CMD='ssh -i ~/lab/key -p 22 root@{host} systemctl stop litevirt' \
//	E2E_HOST_UP_CMD='ssh -i ~/lab/key -p 22 root@{host} systemctl start litevirt' \
//	go test ./tests/e2e -run TestContainer_Relocate
//
// Without all three it skips. It is opt-in rather than clever because it takes a
// node out of service for minutes and, on a real fence strategy, powers it off.
//
// This is the scenario that surfaced the relocate-recreate template bug: the
// reconciler handed lxc-create the container's DISPLAY image ("alpine:3.21")
// instead of its create-spec template, so a relocated container retried forever
// and never came back. The fleet tier could not see it — its runtime fake
// accepts any template string.

// hostDownUp returns the injected down/up commands, or skips.
func hostDownUp(t *testing.T) (down, up string) {
	t.Helper()
	if os.Getenv("E2E_DESTRUCTIVE") != "1" {
		t.Skip("destructive: set E2E_DESTRUCTIVE=1 to take a host out of service")
	}
	down, up = os.Getenv("E2E_HOST_DOWN_CMD"), os.Getenv("E2E_HOST_UP_CMD")
	if down == "" || up == "" {
		t.Skip("set E2E_HOST_DOWN_CMD and E2E_HOST_UP_CMD ({host} placeholder) so the test can stop and restart a host's daemon")
	}
	return down, up
}

// runHostCmd expands {host} and runs the injected command.
func runHostCmd(t *testing.T, tmpl, host string) {
	t.Helper()
	cmd := strings.ReplaceAll(tmpl, "{host}", host)
	out, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("host command %q: %v\n%s", cmd, err, out)
	}
}

// ctHost returns the host currently owning the container, or "".
func ctHost(t *testing.T, name string) string {
	t.Helper()
	for _, line := range strings.Split(lv(t, "ct", "ls"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == name {
			return f[0]
		}
	}
	return ""
}

// TestContainer_RelocateOnHostLoss: when a host is lost, a container that opted
// into image-recreate must come back on a survivor as a REAL running container,
// and one that opted out must not be moved.
func TestContainer_RelocateOnHostLoss(t *testing.T) {
	requireLXC(t)
	requireHosts(t, 3) // victim + survivor + quorum
	down, up := hostDownUp(t)

	victim := otherHost(t) // never ourselves: we need the CLI to keep working
	relocating := uniqueName("ct")
	staying := uniqueName("ct")

	restored := false
	cleanup(t, func() {
		if !restored {
			runHostCmd(t, up, victim)
			lvErr(t, "host", "undrain", victim)
		}
		for _, n := range []string{relocating, staying} {
			lvErr(t, "ct", "stop", n)
			for _, h := range hostNames {
				lvErr(t, "ct", "rm", n, "--host", h)
			}
		}
	})

	if out, err := lvErr(t, "ct", "create", relocating, "--host", victim,
		"--on-host-failure", "image-recreate"); err != nil {
		t.Skipf("cannot create a container on %s: %v\n%s", victim, err, out)
	}
	if out, err := lvErr(t, "ct", "create", staying, "--host", victim); err != nil {
		t.Skipf("cannot create the opted-out container on %s: %v\n%s", victim, err, out)
	}

	// ── lose the host ──────────────────────────────────────────────────────
	runHostCmd(t, down, victim)

	// The coordinator needs health quorum before it fences; on the lab that took
	// ~2 minutes, so allow generously.
	var moved string
	deadline := time.Now().Add(6 * time.Minute)
	for time.Now().Before(deadline) {
		if h := ctHost(t, relocating); h != "" && h != victim {
			moved = h
			break
		}
		time.Sleep(15 * time.Second)
	}
	if moved == "" {
		t.Fatalf("container %s was never relocated off the lost host %s (state: %s)",
			relocating, victim, strings.TrimSpace(lv(t, "ct", "ls")))
	}
	t.Logf("relocated %s: %s → %s", relocating, victim, moved)

	// Opted out → must NOT have moved.
	if h := ctHost(t, staying); h != victim {
		t.Errorf("container %s has on_host_failure=none but moved to %q — relocation must leave it alone", staying, h)
	}

	// The row moving is not enough: it must become a REAL container again. The
	// bug this guards left it stuck in "pending" retrying lxc-create forever, so
	// asserting only on ownership would have passed while nothing ran.
	deadline = time.Now().Add(4 * time.Minute)
	var last string
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(lv(t, "ct", "ls"), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[1] == relocating {
				last = f[2]
			}
		}
		if last == "running" || last == "stopped" {
			break
		}
		time.Sleep(15 * time.Second)
	}
	if last != "running" && last != "stopped" {
		t.Fatalf("relocated container %s never left state %q — it was re-homed but never rebuilt (check the recreate template)", relocating, last)
	}

	// ── restore ────────────────────────────────────────────────────────────
	runHostCmd(t, up, victim)
	lvErr(t, "host", "undrain", victim)
	restored = true
}
