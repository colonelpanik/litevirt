package lxc

import (
	"fmt"
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
//	lxc.net.0.veth.pair = lvc<hash>
//	lxc.net.0.ipv4.address = 10.0.0.5/24
//
// It fails closed if any field contains a character that could inject extra
// config keys (newline/CR/control/NUL) — a NIC field is operator/request data,
// and an unchecked newline would let it forge arbitrary lxc.* directives. The
// veth name is additionally length-checked against IFNAMSIZ.
func NetworkConfig(attaches []NetworkAttach) (string, error) {
	if len(attaches) == 0 {
		return "", nil
	}
	// Preserve the caller's order: the lxc.net.N index MUST equal each NIC's
	// ordinal, because the cluster interface rows + the deterministic veth/MAC are
	// keyed on ordinal (and the clone path rewrites the config by that index).
	// Sorting by name here would desync the DB rows from the on-disk config for a
	// container whose NICs aren't requested in name order. The caller's order is
	// already stable (request / create-spec order), so the file stays diff-friendly.
	var b strings.Builder
	for i, n := range attaches {
		for _, v := range []string{n.Bridge, n.Name, n.MAC, n.IP, n.Veth} {
			if err := lxcConfigSafe(v); err != nil {
				return "", fmt.Errorf("network %q: %w", n.Name, err)
			}
		}
		if len(n.Veth) > maxIfnameLen {
			return "", fmt.Errorf("network %q: veth name %q exceeds IFNAMSIZ (%d bytes)", n.Name, n.Veth, maxIfnameLen)
		}
		fmt.Fprintf(&b, "lxc.net.%d.type = veth\n", i)
		fmt.Fprintf(&b, "lxc.net.%d.link = %s\n", i, n.Bridge)
		fmt.Fprintf(&b, "lxc.net.%d.flags = up\n", i)
		if n.Name != "" {
			fmt.Fprintf(&b, "lxc.net.%d.name = %s\n", i, n.Name)
		}
		if n.MAC != "" {
			fmt.Fprintf(&b, "lxc.net.%d.hwaddr = %s\n", i, n.MAC)
		}
		if n.Veth != "" {
			fmt.Fprintf(&b, "lxc.net.%d.veth.pair = %s\n", i, n.Veth)
		}
		if n.IP != "" {
			// LXC accepts both bare-IP and CIDR; we pass through verbatim.
			fmt.Fprintf(&b, "lxc.net.%d.ipv4.address = %s\n", i, n.IP)
		}
	}
	return b.String(), nil
}

// maxIfnameLen is the Linux IFNAMSIZ limit (16) minus the NUL terminator.
const maxIfnameLen = 15

// lxcConfigSafe rejects a value that could break out of its config line. NIC
// fields are request/operator data; an unescaped newline would forge arbitrary
// lxc.* directives.
func lxcConfigSafe(v string) error {
	for _, r := range v {
		if r == '\n' || r == '\r' || r == 0x00 || r < 0x20 || r == 0x7f {
			return fmt.Errorf("invalid control character in LXC config value %q", v)
		}
	}
	return nil
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
