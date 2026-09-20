package libvirt

import "strings"

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
func diskBacking(path string) (diskType string, src diskSource, driverType string) {
	switch {
	case strings.HasPrefix(path, "rbd:"):
		name, hosts := parseRBDLocator(strings.TrimPrefix(path, "rbd:"))
		return "network", diskSource{Protocol: "rbd", Name: name, Hosts: hosts}, "raw"
	case strings.HasPrefix(path, "/dev/"):
		return "block", diskSource{Dev: path}, "raw"
	default:
		return "file", diskSource{File: path}, "qcow2"
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
func parseRBDLocator(body string) (name string, hosts []diskSourceHost) {
	parts := strings.Split(body, ":")
	name = parts[0]
	for _, opt := range parts[1:] {
		key, value, ok := strings.Cut(opt, "=")
		if !ok || key != "mon_host" {
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
	return name, hosts
}
