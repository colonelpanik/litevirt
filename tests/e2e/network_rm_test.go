package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"
	"time"
)

// Network teardown against real hosts: the Linux bridge and the record of who
// created it (/run/litevirt/bridges) are host facts no in-process test can
// see. Every assertion reads `ip link` and the record ON THE NODE, never
// litevirt's report.

// netRmPass bounds how long a network change may take to show on a node.
const netRmPass = 2 * time.Minute

// sshTarget is what to hand ssh to reach a cluster host: E2E_SSH_<name> when
// set, else the host's address, else its name.
func sshTarget(host string) string {
	if v := os.Getenv("E2E_SSH_" + strings.ReplaceAll(host, "-", "_")); v != "" {
		return v
	}
	if ip := hostIPs[host]; ip != "" {
		return ip
	}
	return host
}

// nodeOut runs a shell script on a cluster host (locally for the host the suite
// runs on) and returns its combined output.
func nodeOut(host, script string) (string, error) {
	var cmd *exec.Cmd
	if host == localHost && localHost != "" {
		cmd = exec.Command("sh", "-c", script)
	} else {
		cmd = exec.Command("timeout", "60", "ssh", "-o", "ConnectTimeout=10", "-o", "BatchMode=yes",
			"-o", "StrictHostKeyChecking=no", sshTarget(host), script)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// shortNetName returns a name that fits a Linux interface name (15 bytes) so a
// bridge network may take it as its bridge name; uniqueName's can exceed it.
func shortNetName(tag string) string {
	return fmt.Sprintf("e2%s%d", tag, os.Getpid()%100000)
}

// onHosts runs script on each host and returns the hosts for which it exited 0,
// sorted, plus the outputs of those for which it did not.
func onHosts(hosts []string, script string) (ok []string, failed map[string]string) {
	failed = map[string]string{}
	for _, h := range hosts {
		if out, err := nodeOut(h, script); err == nil {
			ok = append(ok, h)
		} else {
			failed[h] = fmt.Sprintf("%v: %s", err, strings.TrimSpace(out))
		}
	}
	sort.Strings(ok)
	return ok, failed
}

// waitOnHosts polls until script exits 0 on every one of hosts, or budget
// passes; it returns the hosts where it still fails, with their output.
func waitOnHosts(hosts []string, script string, budget time.Duration) map[string]string {
	deadline := time.Now().Add(budget)
	for {
		_, failed := onHosts(hosts, script)
		if len(failed) == 0 || time.Now().After(deadline) {
			return failed
		}
		time.Sleep(5 * time.Second)
	}
}

func bridgePresent(br string) string { return "ip link show " + br + " >/dev/null 2>&1" }
func bridgeAbsent(br string) string  { return "! ip link show " + br + " >/dev/null 2>&1" }
func recordPresent(br string) string { return "test -e /run/litevirt/bridges/" + br }
func recordAbsent(br string) string  { return "! test -e /run/litevirt/bridges/" + br }

// delTestLink removes link on every host if it is still there. Only for names
// this file generated (shortNetName / e2tap…), in a cleanup.
func delTestLink(t *testing.T, link string) {
	t.Helper()
	if !strings.HasPrefix(link, "e2") {
		t.Logf("refusing to delete %q: not a name this test generated", link)
		return
	}
	for _, h := range hostNames {
		if out, err := nodeOut(h, "if ip link show "+link+" >/dev/null 2>&1; then ip link del "+link+"; fi"); err != nil {
			t.Logf("cleanup: ip link del %s on %s: %v\n%s", link, h, err, out)
		}
	}
}

// (a) A bridge network created without --interface makes its bridge, and a
// record of it, on the host that serves the create; `lv network rm` removes
// both from the host that made them.
func TestNetwork_RmRemovesTheBridgeLitevirtCreated(t *testing.T) {
	requireHosts(t, 1)
	name := shortNetName("nb")
	subnet := fmt.Sprintf("10.237.%d.0/24", 20+os.Getpid()%200)
	cleanup(t, func() {
		lvErr(t, "network", "rm", name, "--force")
		delTestLink(t, name)
	})
	lv(t, "network", "create", name, "--type", "bridge", "--subnet", subnet, "--dhcp")

	var made []string
	deadline := time.Now().Add(netRmPass)
	for {
		made, _ = onHosts(hostNames, bridgePresent(name)+" && "+recordPresent(name))
		if len(made) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Second)
	}
	if len(made) == 0 {
		t.Fatalf("bridge %s with its record /run/litevirt/bridges/%s is on no host after %s", name, name, netRmPass)
	}

	lv(t, "network", "rm", name)

	if failed := waitOnHosts(made, bridgeAbsent(name)+" && "+recordAbsent(name), netRmPass); len(failed) > 0 {
		t.Errorf("after `lv network rm %s`, bridge %s (or its record) still on %d host(s) after %s: %v",
			name, name, len(failed), netRmPass, failed)
	}
}

// (b) A bridge an operator made outside litevirt, which a bridge network uses
// with --interface, survives `lv network rm` on every node, and litevirt never
// records it as its own.
func TestNetwork_RmKeepsAnOperatorsBridge(t *testing.T) {
	requireHosts(t, 2)
	br := shortNetName("ob")
	name := shortNetName("on")
	cleanup(t, func() {
		lvErr(t, "network", "rm", name, "--force")
		delTestLink(t, br)
	})
	// The operator's bridge exists before litevirt hears of it.
	if _, failed := onHosts(hostNames, "ip link add "+br+" type bridge && ip link set "+br+" up"); len(failed) > 0 {
		t.Fatalf("creating operator bridge %s: %v", br, failed)
	}
	lv(t, "network", "create", name, "--type", "bridge", "--interface", br)

	time.Sleep(netRmPass / 2)
	if _, failed := onHosts(hostNames, recordAbsent(br)); len(failed) > 0 {
		t.Errorf("litevirt recorded operator bridge %s as one it created on: %v", br, failed)
	}

	lv(t, "network", "rm", name)
	// Give the teardown time to run, then the bridge must still be there.
	time.Sleep(netRmPass)
	if _, failed := onHosts(hostNames, bridgePresent(br)); len(failed) > 0 {
		t.Errorf("`lv network rm %s` removed operator bridge %s on: %v", name, br, failed)
	}
}
