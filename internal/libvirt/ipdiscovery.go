package libvirt

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// GetIPFromARP scans /proc/net/arp to find the IP for a given MAC address.
// Returns empty string if not found.
func GetIPFromARP(mac string) string {
	mac = strings.ToLower(mac)
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// fields: IP, HW type, Flags, HW address, Mask, Device
		if len(fields) < 4 {
			continue
		}
		if strings.ToLower(fields[3]) == mac {
			return fields[0]
		}
	}
	return ""
}

// GetIPFromDHCPLeases scans dnsmasq lease files under leaseDir for a MAC address.
// Standard libvirt lease dir is /var/lib/libvirt/dnsmasq.
func GetIPFromDHCPLeases(leaseDir, mac string) string {
	mac = strings.ToLower(mac)
	pattern := filepath.Join(leaseDir, "*.leases")
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		return ""
	}

	for _, lf := range files {
		f, err := os.Open(lf)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// dnsmasq lease format: <expiry> <mac> <ip> <hostname> <clientid>
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 3 && strings.ToLower(fields[1]) == mac {
				f.Close()
				return fields[2]
			}
		}
		f.Close()
	}
	return ""
}
