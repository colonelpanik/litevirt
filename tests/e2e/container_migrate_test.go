package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Container cold-migration against REAL LXC across two real hosts.
//
// tests/fleet covers the same path with an in-process runtime fake, which can
// prove litevirt drove the handoff correctly but not that a rootfs actually
// moved between machines. This does the latter: it plants a marker file inside
// the container's rootfs, migrates the container away and back, and reads the
// marker off the local disk afterwards — so the bytes are verified through the
// filesystem, not through litevirt's report of its own work.
//
// Evidence comes from two directions. On the SOURCE we check the filesystem
// directly — the container's directory must be gone. On the TARGET, whose disk
// we cannot reach from here, we start the migrated container and read the marker
// back out of it with `ct exec`: that runs lxc-attach on the target host, so the
// bytes are being read by the target's own kernel out of the rootfs that landed
// there. A migration that moved no data cannot produce that file.
//
// Requires `enforcement.operation_protocol: true` cluster-wide (all container
// hotplug/journalled paths do) and the lxc-* tools installed.

// lxcRoot is where the lxc runtime keeps container directories.
const lxcRoot = "/var/lib/lxc"

// requireLXC skips unless we're on a node with the lxc tooling present.
func requireLXC(t *testing.T) {
	t.Helper()
	if !localMode {
		t.Skip("container rootfs verification needs local filesystem access; run this suite on a cluster node")
	}
	if _, err := exec.LookPath("lxc-create"); err != nil {
		t.Skip("lxc-create not installed on this node")
	}
}

// otherHost returns a cluster host that is not the local one.
func otherHost(t *testing.T) string {
	t.Helper()
	for _, h := range hostNames {
		if h != localHost {
			return h
		}
	}
	t.Skip("need a second host to migrate to")
	return ""
}

// lvAt runs the CLI against a SPECIFIC host's daemon by overriding LV_HOST.
//
// `ct migrate` has no --host flag by design: it must run on the daemon that owns
// the container, because only that daemon holds the authoritative runtime state
// (it says so — "Run against the owning host (set LV_HOST)"). Migrating a
// container back therefore means talking to its new owner, not to us.
func lvAt(t *testing.T, host string, args ...string) (string, error) {
	t.Helper()
	addr := hostIPs[host]
	if addr == "" {
		t.Fatalf("no address known for host %q (topology: %v)", host, hostIPs)
	}
	cmd := exec.Command(lvBin, args...)
	cmd.Env = append(os.Environ(), "LV_HOST="+addr)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// ctDir is the on-disk directory for a container on THIS node.
func ctDir(name string) string { return filepath.Join(lxcRoot, name) }

// ctExists reports whether the container's directory is present locally —
// checked with the filesystem, deliberately not with litevirt.
func ctExists(name string) bool {
	_, err := os.Stat(ctDir(name))
	return err == nil
}

// TestContainer_Migrate_MovesRealRootfsToTheTarget is the end-to-end proof that
// a migration relocates actual bytes, not just a database row.
func TestContainer_Migrate_MovesRealRootfsToTheTarget(t *testing.T) {
	requireLXC(t)
	requireHosts(t, 2)
	target := otherHost(t)

	name := uniqueName("ct")
	cleanup(t, func() {
		// The container may have ended up on either host; ask both.
		lvErr(t, "ct", "rm", name, "--host", localHost)
		lvErr(t, "ct", "rm", name, "--host", target)
	})

	if out, err := lvErr(t, "ct", "create", name, "--host", localHost); err != nil {
		t.Skipf("cannot create a container on %s (lxc image server reachable?): %v\n%s", localHost, err, out)
	}
	if !ctExists(name) {
		t.Fatalf("no %s after create — the runtime did not lay down a container directory", ctDir(name))
	}

	// A marker only this host's copy has, planted from OUTSIDE litevirt. If the
	// target can serve it back from inside the container, the rootfs travelled.
	const marker = "e2e-rootfs-marker-do-not-edit"
	markerPath := filepath.Join(ctDir(name), "rootfs", marker)
	payload := "payload-" + name
	if err := os.WriteFile(markerPath, []byte(payload), 0o644); err != nil {
		t.Fatalf("plant marker in the container rootfs: %v", err)
	}

	// A staging repo on the source. Migration streams the manifest to the target
	// over peer mTLS, so it only has to exist here — but it DOES have to be
	// initialised; an unopened repo fails the migrate at its first step.
	repo := filepath.Join(t.TempDir(), "migrate-repo")
	lv(t, "backup", "repo", "init", repo)

	// ── migrate ────────────────────────────────────────────────────────────
	if out, err := lvErr(t, "ct", "migrate", name, target, "--repo", repo); err != nil {
		t.Fatalf("migrate %s → %s: %v\n%s", localHost, target, err, out)
	}

	// Source-side evidence: the filesystem, not litevirt.
	if ctExists(name) {
		t.Errorf("%s still exists on the source after a landed migrate — the container is now on two hosts", ctDir(name))
	}
	if out := lv(t, "ct", "ls"); !strings.Contains(out, target) || !strings.Contains(out, name) {
		t.Errorf("after migrate, ct ls does not show %s on %s:\n%s", name, target, out)
	}

	// Target-side evidence: start the migrated container and read the marker from
	// INSIDE it. lxc-attach runs on the target host, so this file can only exist
	// if the rootfs actually arrived there.
	if out, err := lvErr(t, "ct", "start", name, "--host", target); err != nil {
		t.Fatalf("start the migrated container on %s: %v\n%s", target, err, out)
	}
	waitCT(t, name, "running", 60*time.Second)

	got, err := lvErr(t, "ct", "exec", name, "--host", target, "--", "cat", "/"+marker)
	if err != nil {
		t.Fatalf("read the marker from inside the migrated container: %v\n%s", err, got)
	}
	if !strings.Contains(got, payload) {
		t.Errorf("marker inside the migrated container = %q, want it to contain %q — the rootfs on the target is not the one that left",
			got, payload)
	}
}

// waitCT polls until the container reports the wanted state.
func waitCT(t *testing.T, name, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(lv(t, "ct", "ls"), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[1] == name {
				last = f[2]
				if last == want {
					return
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("container %s did not reach state %q within %s (last: %q)", name, want, timeout, last)
}

// TestContainer_Migrate_RefusesOntoAnOccupiedName pins the collision refusal on
// real hosts: container names are unique per host, so the target may legitimately
// already run one. Refusing BEFORE the source is stopped is what keeps a mistaken
// migrate from causing an outage.
func TestContainer_Migrate_RefusesOntoAnOccupiedName(t *testing.T) {
	requireLXC(t)
	requireHosts(t, 2)
	target := otherHost(t)

	name := uniqueName("ct")
	cleanup(t, func() {
		lvErr(t, "ct", "rm", name, "--host", localHost)
		lvErr(t, "ct", "rm", name, "--host", target)
	})

	if out, err := lvErr(t, "ct", "create", name, "--host", localHost); err != nil {
		t.Skipf("cannot create a container on %s: %v\n%s", localHost, err, out)
	}
	if out, err := lvErr(t, "ct", "create", name, "--host", target); err != nil {
		t.Skipf("cannot create the colliding container on %s: %v\n%s", target, err, out)
	}

	repo := filepath.Join(t.TempDir(), "migrate-repo")
	lv(t, "backup", "repo", "init", repo)

	out, err := lvErr(t, "ct", "migrate", name, target, "--repo", repo)
	if err == nil {
		t.Fatal("migrate onto a name the target already holds succeeded; it must be refused")
	}
	if !strings.Contains(strings.ToLower(out+err.Error()), "already exists") {
		t.Errorf("refusal should name the collision, got: %v\n%s", err, out)
	}
	// The source must be untouched — still present locally.
	if !ctExists(name) {
		t.Error("the source container was removed by a REFUSED migrate")
	}
}
