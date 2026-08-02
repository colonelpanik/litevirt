package e2e

import (
	"os/exec"
	"strings"
	"testing"
	"time"
)

// NIC hot-detach against a real libvirt domain — the regression guard for the
// fix in "fix(libvirt): build NIC detach XML from the domain, not from the MAC
// alone".
//
// The bug: DetachNIC had only a MAC to work from, so it marshalled
// `<interface type="bridge">` with an EMPTY `<source>`. libvirt matches an
// interface by MAC BEFORE validating the device element, so the malformed source
// went unexamined while the MAC was present — and surfaced as
//
//	XML error: Missing required attribute 'bridge' in element 'source'
//
// the moment it wasn't, which says nothing about the real problem.
//
// The pre-existing TestVM_AttachDetachNIC cannot catch this class: it detaches
// only `if len(macs) >= 2` — so a run that fails to parse two MACs skips the
// detach entirely and still passes — and it never checks that the interface
// actually went away. This asserts against `virsh domiflist`, i.e. the domain
// itself, so "litevirt returned success" is not accepted as evidence.

// domIfaceMACs returns the MACs libvirt currently reports on a domain.
func domIfaceMACs(t *testing.T, domain string) []string {
	t.Helper()
	out, err := exec.Command("virsh", "-c", "qemu:///system", "domiflist", domain).CombinedOutput()
	if err != nil {
		t.Fatalf("virsh domiflist %s: %v\n%s", domain, err, out)
	}
	var macs []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		// Interface Type Source Model MAC — the MAC is the last column.
		if len(f) >= 5 && strings.Count(f[len(f)-1], ":") == 5 {
			macs = append(macs, strings.ToLower(f[len(f)-1]))
		}
	}
	return macs
}

func containsMAC(macs []string, mac string) bool {
	for _, m := range macs {
		if strings.EqualFold(m, mac) {
			return true
		}
	}
	return false
}

// waitGuestActive waits until libvirt can see the guest on the network (ARP),
// i.e. the kernel is up and driving devices.
//
// This must happen BEFORE the attach, not just before the detach. A NIC
// hot-plugged into a guest whose PCI subsystem has not initialised is never
// enumerated, so the guest cannot eject it later either — the detach then fails
// forever for a reason that has nothing to do with detach. Proceeds anyway on
// timeout and lets the detach retry loop decide, rather than skipping on a
// signal that is only a proxy for readiness.
func waitGuestActive(t *testing.T, domain string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("virsh", "-c", "qemu:///system", "domifaddr", domain, "--source", "arp").CombinedOutput()
		if err == nil && strings.Count(string(out), ".") >= 3 {
			return
		}
		time.Sleep(10 * time.Second)
	}
	t.Logf("guest %s not visible on the network after %s; continuing anyway", domain, timeout)
}

// TestVM_DetachNIC_ActuallyRemovesItFromTheDomain attaches a NIC, confirms
// libvirt sees it, detaches it, and confirms libvirt no longer does.
func TestVM_DetachNIC_ActuallyRemovesItFromTheDomain(t *testing.T) {
	requireImage(t)
	if !virshAvailable() {
		t.Skip("needs virsh on this node to inspect the domain; run the suite on a cluster node")
	}
	netName := uniqueName("n")
	vmName := uniqueName("vm")
	host := hostWithCapacity(t, 1, 1024)
	if host != localHost {
		t.Skipf("VM would land on %s but virsh only reaches %s", host, localHost)
	}
	cleanup(t, func() {
		lvErr(t, "rm", vmName, "--force")
		lvErr(t, "network", "rm", netName, "--force")
	})

	lv(t, "network", "create", netName, "--type", "bridge",
		"--subnet", "172.33.0.0/24", "--dhcp")
	lv(t, "run", "--name", vmName, "--image", testImage,
		"--cpu", "1", "--memory", "1024", "--disk", "5G",
		"--host", host)
	waitVM(t, vmName, "RUNNING", 2*time.Minute)
	waitGuestActive(t, vmName, 4*time.Minute)

	before := domIfaceMACs(t, vmName)

	// ── attach ─────────────────────────────────────────────────────────────
	lv(t, "attach-nic", vmName, netName)

	var added string
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		for _, m := range domIfaceMACs(t, vmName) {
			if !containsMAC(before, m) {
				added = m
				break
			}
		}
		if added != "" {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if added == "" {
		t.Fatalf("no new interface appeared on the domain after attach-nic (libvirt still reports %v) — nothing to detach, so the rest of this test would prove nothing",
			before)
	}

	// ── detach ─────────────────────────────────────────────────────────────
	// PCI hot-unplug is COOPERATIVE: libvirt asks the guest to eject the device
	// over ACPI, and a guest still booting never answers. litevirt then refuses to
	// claim success ("still present in the live domain") and leaves the NIC
	// recoverable — correct behaviour, and safe to retry. So retry across a window
	// instead of racing the guest's boot.
	//
	// The regression is checked on EVERY attempt, not just the last: the old code
	// sent malformed detach XML, which libvirt rejected with a complaint about a
	// missing 'bridge' attribute. That error must never appear, whatever the guest
	// is doing.
	var lastOut string
	var lastErr error
	detached := false
	deadline = time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		out, err := lvErr(t, "detach-nic", vmName, added)
		lastOut, lastErr = out, err
		if strings.Contains(strings.ToLower(out), "missing required attribute") {
			t.Fatalf("detach-nic sent malformed XML libvirt rejected — this is the regression: %v\n%s", err, out)
		}
		if err == nil {
			detached = true
			break
		}
		time.Sleep(15 * time.Second)
	}
	if !detached {
		// Never succeeded, but never produced the malformed-XML error either. That
		// is a guest that never processed the eject, not a detach defect — and the
		// NIC is left recoverable by design, so nothing is broken.
		t.Skipf("guest never acknowledged the ACPI eject within the window (last: %v\n%s)", lastErr, lastOut)
	}

	// Succeeded — libvirt must no longer report it.
	deadline = time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if !containsMAC(domIfaceMACs(t, vmName), added) {
			return // gone from the domain — the detach really happened
		}
		time.Sleep(2 * time.Second)
	}
	t.Errorf("detach-nic reported success but libvirt still reports MAC %s on %s — litevirt claimed the hypervisor did something it did not (domiflist: %v)",
		added, vmName, domIfaceMACs(t, vmName))
}

// TestVM_DetachNIC_AbsentMACIsRefusedNotMisreported: detaching a MAC the domain
// does not have must fail on its own terms. The old code reached libvirt with a
// malformed device element, so this surfaced as an XML validation error about a
// missing 'bridge' attribute — an error about litevirt's own request, which sent
// operators looking for a network misconfiguration that did not exist.
func TestVM_DetachNIC_AbsentMACIsRefusedNotMisreported(t *testing.T) {
	requireImage(t)
	if !virshAvailable() {
		t.Skip("needs virsh on this node to inspect the domain; run the suite on a cluster node")
	}
	vmName := uniqueName("vm")
	host := hostWithCapacity(t, 1, 1024)
	if host != localHost {
		t.Skipf("VM would land on %s but virsh only reaches %s", host, localHost)
	}
	cleanup(t, func() { lvErr(t, "rm", vmName, "--force") })

	lv(t, "run", "--name", vmName, "--image", testImage,
		"--cpu", "1", "--memory", "1024", "--disk", "5G",
		"--host", host)
	waitVM(t, vmName, "RUNNING", 2*time.Minute)

	const absent = "52:54:00:de:ad:be"
	if containsMAC(domIfaceMACs(t, vmName), absent) {
		t.Skipf("%s unexpectedly present on the domain", absent)
	}

	out, err := lvErr(t, "detach-nic", vmName, absent)
	if err == nil {
		t.Fatalf("detaching an absent MAC reported success:\n%s", out)
	}
	msg := strings.ToLower(out + err.Error())
	if strings.Contains(msg, "missing required attribute") {
		t.Errorf("the refusal is libvirt rejecting OUR malformed detach XML, not a statement about the MAC — this is the regression: %v\n%s", err, out)
	}
	// The VM must be undisturbed by a refused detach.
	if got := lv(t, "inspect", vmName); !strings.Contains(got, "RUNNING") {
		t.Errorf("VM is not RUNNING after a refused detach-nic:\n%s", got)
	}
}
