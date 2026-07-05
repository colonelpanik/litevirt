package network

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// localResolverDomain/Port name the embedded DNS server that per-bridge dnsmasq
// instances chain to for the litevirt domain. Set once at daemon start via
// SetLocalResolver, before any network is provisioned. Empty domain / zero port
// (the default) leaves dnsmasq forwarding everything upstream, as before.
var (
	localResolverDomain string
	localResolverPort   int
)

// SetLocalResolver configures the embedded-DNS domain + port that new dnsmasq
// instances forward that domain's queries to (127.0.0.1#port). Call once at
// daemon start before reconcileNetworks.
func SetLocalResolver(domain string, port int) {
	localResolverDomain = strings.TrimSuffix(domain, ".")
	localResolverPort = port
}

// startDHCPFunc is the active DHCP starter; replaced in tests to avoid spawning real dnsmasq.
var startDHCPFunc = StartDHCP

// StartDHCP spawns a dnsmasq process for DHCP on an isolated bridge.
// gateway is the IP/CIDR to assign to the bridge interface (v4 or v6).
// rangeStart and rangeEnd define the DHCP range. mask is the dotted-decimal
// subnet mask for IPv4 (e.g., "255.255.255.0") or the prefix-length string
// for IPv6 (e.g., "64") — `SubnetRange` returns the right shape for either.
//
// IPv6 specifics:
//   - When the gateway parses as v6, dnsmasq is invoked with --enable-ra
//     so SLAAC-only guests still get a default route.
//   - dhcp-range still works for stateful DHCPv6 leases.
//   - Bridges get the gateway address with `ip -6 addr add`, automatic.
// dnsmasqArgs builds the dnsmasq command line for a per-bridge DHCP+DNS
// instance. Pure function so the argument set is unit-testable without
// spawning dnsmasq.
//
// --except-interface=lo is load-bearing: dnsmasq listens on the loopback
// address (127.0.0.1:53) for its DNS service by DEFAULT, even with
// --interface=<bridge> --bind-dynamic. With one DHCP bridge per network on a
// host, the FIRST dnsmasq grabs 127.0.0.1:53 and every subsequent instance
// exits 2 ("address already in use"), so only one network on a host could ever
// have DHCP. litevirt only serves DNS to guests via the bridge gateway IP, so
// the loopback listener is pure liability — exclude it. Each instance then
// binds only its own bridge gateway IP:53, which never collides.
// dnsmasqLeaseDir is where litevirt's per-bridge dnsmasq writes its lease
// files. It MUST match the directory the IP scanner reads
// (grpcapi.IPScanner → GetIPFromDHCPLeases) — otherwise the lease-based IP
// fallback never fires and runtime IP discovery silently relies on ARP alone
// (so a just-booted or quiet VM can show no IP). Without --dhcp-leasefile,
// dnsmasq writes to its compiled-in default (/var/lib/misc/...), which the
// scanner doesn't read.
const dnsmasqLeaseDir = "/var/lib/libvirt/dnsmasq"

func dnsmasqArgs(bridge, rangeStart, rangeEnd, mask, gateway, pidFile string, upstreamDNS []string, localDomain string, localPort int) []string {
	args := []string{
		"--interface=" + bridge,
		"--except-interface=lo",
		"--dhcp-range=" + rangeStart + "," + rangeEnd + "," + mask + ",12h",
		"--dhcp-leasefile=" + dnsmasqLeaseDir + "/litevirt-" + bridge + ".leases",
		"--bind-dynamic",
		"--no-daemon",
		"--pid-file=" + pidFile,
		"--log-dhcp",
		"--no-hosts",
	}
	// IPv6: enable router advertisements so SLAAC-only guests get a default
	// route and dnsmasq's DHCPv6 server is announced.
	if isIPv6Gateway(gateway) {
		args = append(args, "--enable-ra", "--dhcp-authoritative")
	}
	// Domain-specific forward to the embedded DNS: guests get dnsmasq (the gateway)
	// as their resolver, and dnsmasq forwards ONLY <localDomain> queries to the
	// local embedded server, so litevirt VM/container/anycast names resolve while
	// everything else still goes upstream. Without this the embedded server is
	// orphaned and guests can't resolve litevirt names.
	if localDomain != "" && localPort > 0 {
		dom := strings.TrimSuffix(localDomain, ".")
		args = append(args, fmt.Sprintf("--server=/%s/127.0.0.1#%d", dom, localPort))
	}
	for _, dns := range upstreamDNS {
		args = append(args, "--server="+dns)
	}
	// If we found explicit servers, use --no-resolv to avoid reading resolv.conf
	// (which may point to a local stub like 127.0.0.53). Otherwise let dnsmasq
	// read resolv.conf as fallback.
	if len(upstreamDNS) > 0 {
		args = append(args, "--no-resolv")
	}
	return args
}

func StartDHCP(bridge, gateway, rangeStart, rangeEnd, mask, pidFile string) error {
	// Assign gateway IP to the bridge (idempotent — ignore "already assigned").
	out, err := execCommand("ip", "addr", "add", gateway, "dev", bridge)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("assign gateway to %s: %w: %s", bridge, err, out)
	}

	// Resolve upstream DNS servers from the host's /etc/resolv.conf and build the
	// arg set we'd launch with NOW. Computed before the already-running check so we
	// can detect config drift against the live process.
	upstreamDNS := resolveUpstreamDNS()
	desiredArgs := dnsmasqArgs(bridge, rangeStart, rangeEnd, mask, gateway, pidFile, upstreamDNS, localResolverDomain, localResolverPort)

	// If dnsmasq is already running for this bridge, leave it alone — UNLESS its
	// live command line has drifted from what we'd launch now. Re-provisioning
	// (e.g. during VM creation) must not bounce a healthy DHCP server for no
	// reason: that opens a window with no DHCP and can cost a VM its lease. But a
	// stale process — most importantly one started before the embedded-DNS
	// resolver was configured (so it lacks the --server=/<domain>/ forward and
	// guests can't resolve litevirt names) — must be replaced. The desired args
	// are compared against /proc/<pid>/cmdline so the decision survives a daemon
	// re-exec with no in-memory state. The procIsOurDnsmasq guard ensures a stale
	// pidfile whose PID was recycled to an unrelated process is treated as "not
	// running" (start fresh) rather than being stopped/killed as if it were ours.
	if pid := readPidFile(pidFile); pid > 0 && processRunning(pid) && procIsOurDnsmasq(pid, pidFile) {
		if dnsmasqArgsCurrent(pid, desiredArgs) {
			slog.Debug("dnsmasq already running", "bridge", bridge, "pid", pid)
			return nil
		}
		slog.Info("dnsmasq config drifted; restarting to apply new args", "bridge", bridge, "pid", pid)
		_ = StopDHCP(pidFile)
		// Wait for the old process to actually exit before launching the
		// replacement. StopDHCP only signals — it doesn't wait — so the outgoing
		// dnsmasq may still hold the bridge gateway IP:53 and cause the new one to
		// die with a bind failure. Escalate to SIGKILL if it lingers past the
		// graceful window.
		waitProcessExit(pid, 3*time.Second)
	}

	// Ensure the lease directory exists (it doubles as the IP scanner's read
	// path). libvirt usually creates it, but a KVM-less / fresh host may not.
	os.MkdirAll(dnsmasqLeaseDir, 0o755) //nolint:errcheck

	// Spawn and verify it stays up. A just-stopped predecessor can hold the socket
	// for a brief moment, so an immediate exit (bind failure) is retried once after
	// a short backoff before giving up to the caller's reconcile.
	var startErr error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(300 * time.Millisecond)
		}
		if startErr = spawnDnsmasq(bridge, pidFile, rangeStart, rangeEnd, desiredArgs); startErr == nil {
			return nil
		}
	}
	return startErr
}

// spawnDnsmasq launches one dnsmasq with args and confirms it survives a brief
// settling window. An immediate exit usually means a bind conflict with a
// not-yet-released predecessor; the caller retries. Returns nil once confirmed up.
func spawnDnsmasq(bridge, pidFile, rangeStart, rangeEnd string, args []string) error {
	cmd := exec.Command("dnsmasq", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdout = nil
	cmd.Stderr = nil

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start dnsmasq on %s: %w", bridge, err)
	}

	// Write PID file ourselves as a fallback (dnsmasq --no-daemon doesn't always write it immediately).
	os.WriteFile(pidFile, []byte(strconv.Itoa(cmd.Process.Pid)), 0644) //nolint:errcheck

	// Reap the child process in the background; record whether it exited.
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	// Verify dnsmasq is still alive after a brief settling period.
	// If it exits immediately, it typically means a bind failure (port
	// conflict from a previous instance that hasn't fully released the
	// socket yet).
	select {
	case err := <-exited:
		return fmt.Errorf("dnsmasq on %s exited immediately: %v", bridge, err)
	case <-time.After(500 * time.Millisecond):
		// Still running — good.
	}

	slog.Info("dnsmasq started", "bridge", bridge, "range", rangeStart+"-"+rangeEnd, "pid", cmd.Process.Pid)
	return nil
}

// waitProcessExit waits up to timeout for pid to disappear, then escalates to
// SIGKILL and waits briefly for the kill to take. Best-effort: a recycled PID is
// unlikely in this sub-second window, and StopDHCP already matched the process by
// its unique --pid-file before we get here.
func waitProcessExit(pid int, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !processRunning(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	for i := 0; i < 20; i++ {
		if !processRunning(pid) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// isIPv6Gateway reports whether `gateway` (in IP or IP/prefix form) is a v6
// address.
func isIPv6Gateway(gateway string) bool {
	host, _, _ := net.ParseCIDR(gateway)
	if host == nil {
		host = net.ParseIP(gateway)
	}
	return host != nil && host.To4() == nil
}

// readPidFile reads a PID from a file, returning 0 if unreadable.
func readPidFile(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return pid
}

// processRunning checks if a process with the given PID is alive.
func processRunning(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

// dnsmasqArgsCurrent reports whether the live dnsmasq process `pid` was started
// with the same argument SET as `want`. It reads /proc/<pid>/cmdline, so the
// answer survives a daemon re-exec (no in-memory state). On any read/parse
// failure it returns true (assume current) so a transient error can't force a
// needless restart and DHCP gap.
func dnsmasqArgsCurrent(pid int, want []string) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return true
	}
	return cmdlineMatchesArgs(data, want)
}

// procIsOurDnsmasq reports whether the live process pid is one of OUR dnsmasq
// instances — its command line carries this bridge's unique --pid-file arg. It is
// the guard before signaling a pidfile's PID directly (or SIGKILLing it): a stale
// pidfile whose PID has been recycled to an unrelated process must NOT be signaled.
// A /proc read failure returns false (treat as not-ours; fall back to the
// pidfile-pattern pkill) — the conservative choice for a destructive action.
func procIsOurDnsmasq(pid int, pidFile string) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	return cmdlineHasPidFile(data, pidFile)
}

// cmdlineHasPidFile reports whether a raw /proc/<pid>/cmdline blob carries the
// exact --pid-file arg for pidFile (the unique discriminator for one of our
// dnsmasq instances). It matches whole argv elements, not substrings, so an
// unrelated process with an argument that merely CONTAINS the path (e.g.
// "--pid-file=<path>.bak", or the path embedded in some other flag) is not
// mistaken for ours.
func cmdlineHasPidFile(cmdline []byte, pidFile string) bool {
	want := "--pid-file=" + pidFile
	for _, f := range strings.Split(string(cmdline), "\x00") {
		if f == want {
			return true
		}
	}
	return false
}

// cmdlineMatchesArgs compares a raw /proc/<pid>/cmdline blob (NUL-separated,
// argv[0] first) against a desired dnsmasq arg set, order-insensitive. A blob
// with no args (≤1 field) is treated as matching so a read race can't trigger a
// restart.
func cmdlineMatchesArgs(cmdline []byte, want []string) bool {
	fields := strings.Split(strings.TrimRight(string(cmdline), "\x00"), "\x00")
	if len(fields) <= 1 {
		return true
	}
	return sameStringSet(fields[1:], want) // drop argv[0]
}

// sameStringSet reports whether two arg slices contain the same multiset of
// strings, ignoring order (dnsmasq doesn't care about flag order).
func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, s := range a {
		counts[s]++
	}
	for _, s := range b {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}

// StopDHCP kills the dnsmasq instance for a bridge. It first SIGTERMs the PID
// recorded in pidFile, then — as a backstop — kills any dnsmasq still running
// with this --pid-file argument. The backstop matters because a leaked dnsmasq
// (pid file deleted out-of-band, e.g. a stack record removed without a clean
// deprovision, or a stale/recycled PID) would otherwise survive indefinitely.
// Matching on the unique --pid-file path avoids the recycled-PID hazard of
// killing by number. Best-effort throughout.
func StopDHCP(pidFile string) error {
	if data, err := os.ReadFile(pidFile); err == nil {
		if pid, perr := strconv.Atoi(strings.TrimSpace(string(data))); perr == nil {
			// Only signal the recorded PID directly if it is verifiably still one of
			// our dnsmasq processes. A stale pidfile plus PID reuse could otherwise
			// SIGTERM an unrelated process; in that case skip the direct signal and
			// rely on the --pid-file pattern pkill below.
			if procIsOurDnsmasq(pid, pidFile) {
				if proc, ferr := os.FindProcess(pid); ferr == nil {
					if err := proc.Signal(syscall.SIGTERM); err != nil {
						slog.Debug("dnsmasq already stopped", "pid", pid)
					}
				}
			} else {
				slog.Debug("dnsmasq pidfile PID is not ours (stale/recycled); relying on pattern kill",
					"pid", pid, "pidfile", pidFile)
			}
		}
	}
	// Backstop: kill any straggler by its unique --pid-file argument. The
	// pattern omits the leading "--" so pkill doesn't parse it as a flag; the
	// path is litevirt-specific so it can't match an unrelated process. pkill
	// exits non-zero when nothing matched — expected, ignored.
	execCommand("pkill", "-f", "pid-file="+pidFile) //nolint:errcheck
	os.Remove(pidFile)                              //nolint:errcheck
	return nil
}

// SubnetRange derives gateway, DHCP start, DHCP end, and (for IPv4)
// dotted-decimal mask from a CIDR subnet.
//
// IPv4 example: "10.0.1.128/25" → gateway="10.0.1.129/25",
//
//	start="10.0.1.130", end="10.0.1.254", mask="255.255.255.128"
//
// IPv6 example: "2001:db8::/64" → gateway="2001:db8::1/64",
//
//	start="2001:db8::2", end="2001:db8::ffff", mask="64" (prefix length).
//
// IPv6 callers should use the prefix-length string for dnsmasq's
// --dhcp-range=<start>,<end>,<prefix>,<lease> form.
func SubnetRange(subnet string) (gateway, start, end, mask string, err error) {
	ip, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", "", "", "", fmt.Errorf("parse subnet %q: %w", subnet, err)
	}
	if v4 := ip.To4(); v4 != nil {
		return subnetRangeV4(ipNet)
	}
	return subnetRangeV6(ipNet)
}

func subnetRangeV4(ipNet *net.IPNet) (gateway, start, end, mask string, err error) {
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	if hostBits < 2 {
		return "", "", "", "", fmt.Errorf("subnet too small for DHCP")
	}
	gw := make(net.IP, 4)
	copy(gw, ipNet.IP.To4())
	ipInc(gw)
	gateway = fmt.Sprintf("%s/%d", gw.String(), ones)

	s := make(net.IP, 4)
	copy(s, gw)
	ipInc(s)
	start = s.String()

	broadcast := make(net.IP, 4)
	for i := range broadcast {
		broadcast[i] = ipNet.IP.To4()[i] | ^ipNet.Mask[i]
	}
	ipDec(broadcast)
	end = broadcast.String()

	mask = net.IP(ipNet.Mask).String()
	return gateway, start, end, mask, nil
}

// subnetRangeV6 returns a bounded /64-style host range starting at::2.
// The end is capped at network+0xffff (65k host addresses) — sufficient for
// any realistic stateful-DHCPv6 deployment, and well-bounded for tooling
// that has to scan it.
func subnetRangeV6(ipNet *net.IPNet) (gateway, start, end, mask string, err error) {
	ones, _ := ipNet.Mask.Size()
	if ones > 126 {
		return "", "", "", "", fmt.Errorf("ipv6 subnet too small for DHCP (prefix /%d)", ones)
	}
	gw := make(net.IP, 16)
	copy(gw, ipNet.IP.To16())
	addOne(gw)
	gateway = fmt.Sprintf("%s/%d", gw.String(), ones)

	startIP := make(net.IP, 16)
	copy(startIP, gw)
	addOne(startIP)
	start = startIP.String()

	// End at network + 0xffff (or smaller if the subnet itself is smaller).
	endIP := make(net.IP, 16)
	copy(endIP, ipNet.IP.To16())
	for i := 0; i < 0xffff; i++ {
		next := make(net.IP, 16)
		copy(next, endIP)
		addOne(next)
		if !ipNetContains(ipNet.IP.To16(), ipNet.Mask, next) {
			break
		}
		endIP = next
	}
	end = endIP.String()

	mask = fmt.Sprintf("%d", ones) // dnsmasq v6 takes a prefix length here
	return gateway, start, end, mask, nil
}

// ipInc increments a 4-byte IPv4 address by 1 (big-endian).
func ipInc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// ipDec decrements a 4-byte IPv4 address by 1 (big-endian).
func ipDec(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]--
		if ip[i] != 0xFF {
			break
		}
	}
}

// resolveUpstreamDNS reads /etc/resolv.conf and returns non-loopback nameservers.
// Many systems use systemd-resolved with 127.0.0.53 as the stub; in that case
// we fall back to well-known public DNS servers.
func resolveUpstreamDNS() []string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return []string{"8.8.8.8", "1.1.1.1"}
	}

	var servers []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "nameserver") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip := net.ParseIP(fields[1])
		if ip == nil {
			continue
		}
		// Skip loopback addresses (systemd-resolved stub).
		if ip.IsLoopback() {
			continue
		}
		servers = append(servers, fields[1])
	}

	if len(servers) == 0 {
		return []string{"8.8.8.8", "1.1.1.1"}
	}
	return servers
}

// RemoveNAT tears down the legacy iptables MASQUERADE + FORWARD rules a prior
// binary added for a managed subnet. Masquerade is now rendered as nft in the
// canonical litevirt-fw table; this remains for deprovision teardown and the
// one-time upgrade migration (RemoveLegacyBridgeFirewall). Idempotent.
func RemoveNAT(subnet, bridge string) error {
	execCommand("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE") //nolint:errcheck
	execCommand("iptables", "-D", "FORWARD", "-i", bridge, "-j", "ACCEPT")                                         //nolint:errcheck
	execCommand("iptables", "-D", "FORWARD", "-o", bridge, "-j", "ACCEPT")                                         //nolint:errcheck
	return nil
}
