package lxc

import (
	"fmt"
	"sort"
	"strings"
)

// NetworkConfig renders a list of NetworkAttach into LXC config-file
// fragments. The container's existing /var/lib/lxc/<name>/config is
// rewritten by litevirt before lxc-start so the live config tracks
// compose changes.
//
// Returned fragment looks like:
//
//	lxc.net.0.type = veth
//	lxc.net.0.link = br0
//	lxc.net.0.flags = up
//	lxc.net.0.name = eth0
//	lxc.net.0.hwaddr = aa:bb:cc:dd:ee:ff
//	lxc.net.0.ipv4.address = 10.0.0.5/24
func NetworkConfig(attaches []NetworkAttach) string {
	if len(attaches) == 0 {
		return ""
	}
	sortedNames := make([]NetworkAttach, len(attaches))
	copy(sortedNames, attaches)
	// Stable ordering by Name so the config file stays diff-friendly.
	sort.Slice(sortedNames, func(i, j int) bool { return sortedNames[i].Name < sortedNames[j].Name })

	var b strings.Builder
	for i, n := range sortedNames {
		fmt.Fprintf(&b, "lxc.net.%d.type = veth\n", i)
		fmt.Fprintf(&b, "lxc.net.%d.link = %s\n", i, n.Bridge)
		fmt.Fprintf(&b, "lxc.net.%d.flags = up\n", i)
		if n.Name != "" {
			fmt.Fprintf(&b, "lxc.net.%d.name = %s\n", i, n.Name)
		}
		if n.MAC != "" {
			fmt.Fprintf(&b, "lxc.net.%d.hwaddr = %s\n", i, n.MAC)
		}
		if n.IP != "" {
			// LXC accepts both bare-IP and CIDR; we pass through verbatim.
			fmt.Fprintf(&b, "lxc.net.%d.ipv4.address = %s\n", i, n.IP)
		}
	}
	return b.String()
}

// ResourceConfig renders cgroup limits as LXC keys.
func ResourceConfig(cpuLimit, memMiB int) string {
	var b strings.Builder
	if cpuLimit > 0 {
		// cgroup v2 cpu.max syntax: "<quota> <period>"
		// LXC accepts either v1 or v2; we emit both for cross-distro
		// portability — the kernel ignores irrelevant keys.
		fmt.Fprintf(&b, "lxc.cgroup2.cpu.max = %d 100000\n", cpuLimit*1000)
		fmt.Fprintf(&b, "lxc.cgroup.cpu.shares = %d\n", cpuLimit*1024)
	}
	if memMiB > 0 {
		fmt.Fprintf(&b, "lxc.cgroup2.memory.max = %dM\n", memMiB)
		fmt.Fprintf(&b, "lxc.cgroup.memory.limit_in_bytes = %dM\n", memMiB)
	}
	return b.String()
}
