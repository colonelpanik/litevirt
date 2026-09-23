package libvirt

import (
	"fmt"
	"strings"
)

// diskBacking decides how a storage driver's volume identifier has to be
// described to libvirt: the <disk type=…>, the <source> attributes that type
// requires, and the <driver type=…> that matches the medium.
//
// This exists because the drivers do not all return a file path. CreateDisk's
// contract is "the path / identifier to put in libvirt's <disk source>
// element", and the three families differ:
//
//   - local, nfs, dir, btrfs → a .qcow2 file        → type="file",    qcow2
//   - zfs, lvm-thin, iscsi   → a block device node  → type="block",   raw
//   - ceph                   → an "rbd:pool/image"  → type="network", raw
//
// Everything used to be emitted as type="file" with driver type="qcow2", so a
// zvol was handed to libvirt as though it were a qcow2 file and the domain
// simply did not start — after the volume had already been allocated.
//
// The driver type matters as much as the source. A raw block device and an RBD
// image have no qcow2 header; telling qemu to read one makes the disk
// unreadable even where the source is correct.
func diskBacking(path string) (diskType string, src diskSource, driverType string, err error) {
	switch {
	case strings.HasPrefix(path, "rbd:"):
		name, hosts, unsupported := parseRBDLocator(strings.TrimPrefix(path, "rbd:"))
		if len(unsupported) > 0 {
			// Refuse rather than quietly emit a domain that ignores them. The
			// ceph driver appends the pool's configured conf and keyring to the
			// identifier it returns (internal/storage/ceph.go), and libvirt's
			// <source protocol='rbd'> has nowhere to carry either: monitors are
			// <host> children, and authentication is a sibling <auth> element
			// naming a secret in libvirt's OWN store, not a path on disk.
			//
			// Dropping them produced a domain pointing at the right image with
			// the DEFAULT credentials and configuration. That fails at start
			// time, after the image has already been allocated, and nothing in
			// between reports that the settings were discarded — the operator
			// sees a pool that provisions fine and VMs that will not boot.
			return "", diskSource{}, "", fmt.Errorf(
				"ceph disk %q carries connection option(s) %s that libvirt cannot express in a "+
					"<disk type=\"network\"> source; libvirt authenticates RBD through a defined "+
					"secret and reads monitors from <host> elements, so configure the pool with "+
					"mon_host (and a libvirt ceph secret) instead of conf/keyring",
				name, strings.Join(unsupported, ", "))
		}
		return "network", diskSource{Protocol: "rbd", Name: name, Hosts: hosts}, "raw", nil
	case strings.HasPrefix(path, "/dev/"):
		return "block", diskSource{Dev: path}, "raw", nil
	default:
		return "file", diskSource{File: path}, "qcow2", nil
	}
}

// parseRBDLocator splits qemu's rbd URI body — "pool/image[:opt=val[:opt=val]]"
// — into the image name libvirt wants in <source name=…> and any monitor
// addresses carried in a mon_host option.
//
// Monitors are optional: with none, qemu resolves them from the host's
// ceph.conf, which is how the driver is configured today (it passes --conf/--id
// to the rbd CLI and keeps no monitor list of its own). Parsing them anyway
// means a pool that does carry them is not silently dropped.
func parseRBDLocator(body string) (name string, hosts []diskSourceHost, unsupported []string) {
	parts := strings.Split(body, ":")
	name = parts[0]
	for _, opt := range parts[1:] {
		key, value, ok := strings.Cut(opt, "=")
		if !ok {
			continue
		}
		if key != "mon_host" {
			// Every other option is reported, not skipped. mon_host is the only
			// one with a libvirt equivalent, so anything else here is a setting
			// the caller asked for that the generated domain would not carry.
			unsupported = append(unsupported, key)
			continue
		}
		// A qemu rbd URI escapes the separators inside an option value, and
		// ceph itself accepts both "," and ";" between monitors.
		value = strings.ReplaceAll(value, `\;`, ";")
		value = strings.ReplaceAll(value, `\:`, ":")
		for _, mon := range strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' }) {
			mon = strings.TrimSpace(mon)
			if mon == "" {
				continue
			}
			host, port := mon, ""
			// Only a host:port pair splits; a bare IPv6 literal has colons of
			// its own and is left whole.
			if h, p, found := strings.Cut(mon, ":"); found && !strings.Contains(h, ":") {
				host, port = h, p
			}
			hosts = append(hosts, diskSourceHost{Name: host, Port: port})
		}
	}
	return name, hosts, unsupported
}
