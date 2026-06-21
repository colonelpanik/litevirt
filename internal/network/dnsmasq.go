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

func dnsmasqArgs(bridge, rangeStart, rangeEnd, mask, gateway, pidFile string, upstreamDNS []string) []string {
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

	// If dnsmasq is already running for this bridge, leave it alone.
	// Re-provisioning (e.g., during VM creation) should not restart a
	// healthy DHCP server — doing so creates a window where no DHCP is
	// available and can cause VMs to miss their lease.
	if pid := readPidFile(pidFile); pid > 0 && processRunning(pid) {
		slog.Debug("dnsmasq already running", "bridge", bridge, "pid", pid)
		return nil
	}

	// Ensure the lease directory exists (it doubles as the IP scanner's read
	// path). libvirt usually creates it, but a KVM-less / fresh host may not.
	os.MkdirAll(dnsmasqLeaseDir, 0o755) //nolint:errcheck

	// Resolve upstream DNS servers from the host's /etc/resolv.conf.
	// dnsmasq will forward DNS queries from guests to these servers.
	upstreamDNS := resolveUpstreamDNS()

	cmd := exec.Command("dnsmasq", dnsmasqArgs(bridge, rangeStart, rangeEnd, mask, gateway, pidFile, upstreamDNS)...)
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
			if proc, ferr := os.FindProcess(pid); ferr == nil {
				if err := proc.Signal(syscall.SIGTERM); err != nil {
					slog.Debug("dnsmasq already stopped", "pid", pid)
				}
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

// EnsureNAT sets up IP forwarding and iptables MASQUERADE so VMs on the bridge
// subnet can reach the internet through the host. Idempotent.
func EnsureNAT(subnet, bridge string) error {
	// Enable IP forwarding.
	out, err := execCommand("sysctl", "-w", "net.ipv4.ip_forward=1")
	if err != nil {
		return fmt.Errorf("enable ip forwarding: %w: %s", err, out)
	}

	// Add MASQUERADE rule (skip if already present).
	_, err = execCommand("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE")
	if err != nil {
		// Rule doesn't exist, add it.
		out, err = execCommand("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE")
		if err != nil {
			return fmt.Errorf("add masquerade rule: %w: %s", err, out)
		}
	}

	// Allow forwarding to/from the bridge.
	_, err = execCommand("iptables", "-C", "FORWARD", "-i", bridge, "-j", "ACCEPT")
	if err != nil {
		out, err = execCommand("iptables", "-A", "FORWARD", "-i", bridge, "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("add forward accept (in): %w: %s", err, out)
		}
	}
	_, err = execCommand("iptables", "-C", "FORWARD", "-o", bridge, "-j", "ACCEPT")
	if err != nil {
		out, err = execCommand("iptables", "-A", "FORWARD", "-o", bridge, "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("add forward accept (out): %w: %s", err, out)
		}
	}

	slog.Info("NAT configured", "subnet", subnet, "bridge", bridge)
	return nil
}

// RemoveNAT tears down the iptables rules added by EnsureNAT.
func RemoveNAT(subnet, bridge string) error {
	execCommand("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-o", bridge, "-j", "MASQUERADE") //nolint:errcheck
	execCommand("iptables", "-D", "FORWARD", "-i", bridge, "-j", "ACCEPT")                                         //nolint:errcheck
	execCommand("iptables", "-D", "FORWARD", "-o", bridge, "-j", "ACCEPT")                                         //nolint:errcheck
	return nil
}
