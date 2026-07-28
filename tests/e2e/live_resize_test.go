package e2e

import (
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Live CPU resize is the one capability whose fleet tests structurally cannot
// tell the truth: tests/fleet injects internal/libvirtfake, whose SetVCPUs just
// records that it was called. A guest either gains a vCPU or it does not, and
// only a real hypervisor can say which.
//
// So this pins the behaviour against a live cluster, and — when it can reach
// virsh — verifies through libvirt directly rather than through litevirt's own
// report of what litevirt did.
//
// Requires `enforcement.live_resize: true` on EVERY node (the token latches on
// build uniformity, but each node ANDs it with its own config flag before
// originating a resize). Without that the ceiling can't be set and the test
// skips rather than reporting a false failure.

// virshAvailable reports whether we can query libvirt directly — true when the
// suite runs on a cluster node (localMode). From a remote workstation there is
// no libvirt to ask, and the CLI-level assertions carry the test alone.
func virshAvailable() bool {
	if !localMode {
		return false
	}
	_, err := exec.LookPath("virsh")
	return err == nil
}

// hostWithFreeVCPU returns a host with at least need free vCPUs, PREFERRING the
// local one so the virsh assertions apply. It skips the test when the cluster
// is full rather than failing: "no spare capacity" is a lab state, not a defect,
// and it otherwise surfaces as a confusing ResourceExhausted mid-test.
//
// A live GROW consumes fresh capacity, so a test needs headroom beyond the VM's
// initial size — blindly using hostNames[0] fails on whichever node happens to
// be carrying the cluster's other workloads.
func hostWithFreeVCPU(t *testing.T, need int) string {
	t.Helper()
	// `lv host ls` rows: NAME ADDRESS STATE CPU MEMORY VMs VERSION, CPU as "1/4".
	var best string
	for _, line := range strings.Split(lv(t, "host", "ls"), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || !strings.Contains(f[3], "/") {
			continue
		}
		used, total, ok := strings.Cut(f[3], "/")
		if !ok {
			continue
		}
		u, err1 := strconv.Atoi(used)
		tot, err2 := strconv.Atoi(total)
		if err1 != nil || err2 != nil || tot-u < need {
			continue
		}
		if f[0] == localHost {
			return f[0] // local wins — it is the only one virsh can inspect
		}
		if best == "" {
			best = f[0]
		}
	}
	if best == "" {
		t.Skipf("no host has %d free vCPUs; cluster is at capacity", need)
	}
	return best
}

// virshVCPUs returns a domain's LIVE current vCPU count as libvirt sees it.
func virshVCPUs(t *testing.T, domain string) int {
	t.Helper()
	out, err := exec.Command("virsh", "-c", "qemu:///system", "vcpucount", domain).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh vcpucount %s: %v\n%s", domain, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// "current      live           2"
		if len(f) == 3 && f[0] == "current" && f[1] == "live" {
			n, cerr := strconv.Atoi(f[2])
			if cerr != nil {
				t.Fatalf("parse vcpucount line %q: %v", line, cerr)
			}
			return n
		}
	}
	t.Fatalf("no 'current live' row in vcpucount output:\n%s", out)
	return 0
}

// qemuPID returns the pid of the domain's qemu process, or "" if not running.
// A changed pid means the VM was stopped and restarted — the opposite of live.
func qemuPID(domain string) string {
	out, err := exec.Command("pgrep", "-f", "guest="+domain).Output()
	if err != nil {
		return ""
	}
	lines := strings.Fields(string(out))
	if len(lines) == 0 {
		return ""
	}
	return lines[0]
}

// TestVM_LiveCPUGrow_WithinCeiling is the headline behaviour: a running VM gains
// vCPUs in place, with no stop and no --restart-if-needed.
func TestVM_LiveCPUGrow_WithinCeiling(t *testing.T) {
	requireImage(t)
	name := uniqueName("live")
	host := hostWithFreeVCPU(t, 2) // 1 to boot with, 1 for the grow
	cleanup(t, func() { lvErr(t, "rm", name, "--force") })

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", "1024", "--disk", "5G",
		"--host", host)
	waitVM(t, name, "RUNNING", 2*time.Minute)

	// The hotplug ceiling can only be set while stopped, and only once the
	// cluster has latched live_resize. A refusal here means the fleet has not
	// opted in — skip rather than fail, since that is a cluster config state and
	// not a product defect.
	lv(t, "stop", name)
	waitVM(t, name, "STOPPED", 1*time.Minute)
	if _, err := lvErr(t, "update", name, "--max-cpu", "4"); err != nil {
		t.Skipf("cannot set max_cpu (live_resize not enabled+latched cluster-wide?): %v", err)
	}
	lv(t, "start", name)
	waitVM(t, name, "RUNNING", 2*time.Minute)

	pidBefore := qemuPID(name)
	if virshAvailable() {
		if got := virshVCPUs(t, name); got != 1 {
			t.Fatalf("libvirt reports %d live vCPUs before the grow, want 1", got)
		}
	}

	// The grow itself: no --restart-if-needed, VM stays up.
	if out, err := lvErr(t, "update", name, "--cpu", "2"); err != nil {
		t.Fatalf("live CPU grow within the ceiling must succeed without --restart-if-needed: %v\n%s", err, out)
	}

	// litevirt's own view…
	if out := lv(t, "inspect", name); !strings.Contains(out, "RUNNING") {
		t.Errorf("VM is not RUNNING after a live grow — it should never have stopped:\n%s", out)
	}

	// …and libvirt's, which is the one that settles it.
	if virshAvailable() {
		if got := virshVCPUs(t, name); got != 2 {
			t.Errorf("libvirt reports %d live vCPUs after growing to 2 — litevirt recorded the change without the hypervisor making it", got)
		}
		if pidAfter := qemuPID(name); pidBefore != "" && pidAfter != pidBefore {
			t.Errorf("qemu pid changed %s → %s: the VM was restarted, so this was not a live resize", pidBefore, pidAfter)
		}
	} else {
		t.Log("virsh not reachable (not running on a cluster node) — CLI-level assertions only; " +
			"run this suite on a node for the hypervisor-level check")
	}
}

// TestVM_LiveCPUGrow_BeyondCeilingRefused: the ceiling is baked into the domain
// at boot, so growing past it genuinely needs a restart. Refusing — instead of
// silently restarting — is what keeps `update` safe to run on a live workload.
func TestVM_LiveCPUGrow_BeyondCeilingRefused(t *testing.T) {
	requireImage(t)
	name := uniqueName("live")
	host := hostWithFreeVCPU(t, 2) // 1 to boot with, 1 for the grow
	cleanup(t, func() { lvErr(t, "rm", name, "--force") })

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "1", "--memory", "1024", "--disk", "5G",
		"--host", host)
	waitVM(t, name, "RUNNING", 2*time.Minute)
	lv(t, "stop", name)
	waitVM(t, name, "STOPPED", 1*time.Minute)
	if _, err := lvErr(t, "update", name, "--max-cpu", "4"); err != nil {
		t.Skipf("cannot set max_cpu (live_resize not enabled+latched cluster-wide?): %v", err)
	}
	lv(t, "start", name)
	waitVM(t, name, "RUNNING", 2*time.Minute)

	out, err := lvErr(t, "update", name, "--cpu", "5")
	if err == nil {
		t.Fatal("growing beyond the vCPU ceiling succeeded on a running VM; it must be refused without --restart-if-needed")
	}
	if !strings.Contains(out+err.Error(), "restart") {
		t.Errorf("refusal should tell the operator a restart is needed, got: %v\n%s", err, out)
	}
	// And the VM must still be up — a refused update may not disturb it.
	if got := lv(t, "inspect", name); !strings.Contains(got, "RUNNING") {
		t.Errorf("VM is not RUNNING after a REFUSED update:\n%s", got)
	}
}

// TestVM_CPUShrinkOnRunningVMRefused: only growth is live. A shrink must refuse
// rather than quietly restart the guest to achieve it.
func TestVM_CPUShrinkOnRunningVMRefused(t *testing.T) {
	requireImage(t)
	name := uniqueName("live")
	cleanup(t, func() { lvErr(t, "rm", name, "--force") })

	lv(t, "run", "--name", name, "--image", testImage,
		"--cpu", "2", "--memory", "1024", "--disk", "5G",
		"--host", hostWithFreeVCPU(t, 2))
	waitVM(t, name, "RUNNING", 2*time.Minute)

	out, err := lvErr(t, "update", name, "--cpu", "1")
	if err == nil {
		t.Fatal("a vCPU shrink succeeded on a running VM; it must be refused without --restart-if-needed")
	}
	if !strings.Contains(out+err.Error(), "restart") {
		t.Errorf("refusal should mention needing a restart, got: %v\n%s", err, out)
	}
	if got := lv(t, "inspect", name); !strings.Contains(got, "RUNNING") {
		t.Errorf("VM is not RUNNING after a REFUSED shrink:\n%s", got)
	}
}
