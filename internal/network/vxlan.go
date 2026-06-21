package network

import (
	"fmt"
	"net"
	"strings"
	"sync"
)

// vxlanMu serializes concurrent EnsureVXLAN calls per VNI.
var vxlanMu sync.Map

func vniMutex(vni int) *sync.Mutex {
	v, _ := vxlanMu.LoadOrStore(vni, &sync.Mutex{})
	return v.(*sync.Mutex)
}

// vxlanBridgeName returns the bridge name for a given VNI.
func vxlanBridgeName(vni int) string {
	return fmt.Sprintf("br-vni%d", vni)
}

// vtepName returns the VXLAN interface name for a given VNI.
func vtepName(vni int) string {
	return fmt.Sprintf("vxlan%d", vni)
}

// isFileExists returns true if the command output contains "File exists".
func isFileExists(out []byte) bool {
	return strings.Contains(string(out), "File exists")
}

// EnsureVXLAN idempotently creates a VXLAN interface and bridge for the given VNI.
// Returns the bridge name "br-vni<VNI>".
func EnsureVXLAN(vni int, underlay, localIP string) (string, error) {
	mu := vniMutex(vni)
	mu.Lock()
	defer mu.Unlock()

	vxlan := vtepName(vni)
	bridge := vxlanBridgeName(vni)

	// 1. Create VXLAN interface
	out, err := execCommand("ip", "link", "add", vxlan, "type", "vxlan",
		"id", fmt.Sprintf("%d", vni), "dstport", "4789",
		"local", localIP, "dev", underlay, "nolearning")
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link add %s: %w: %s", vxlan, err, out)
	}

	// 2. Create bridge
	out, err = execCommand("ip", "link", "add", bridge, "type", "bridge")
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link add %s: %w: %s", bridge, err, out)
	}

	// 3. Attach VXLAN to bridge
	out, err = execCommand("ip", "link", "set", vxlan, "master", bridge)
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link set %s master %s: %w: %s", vxlan, bridge, err, out)
	}

	// 4. Bring VXLAN up
	out, err = execCommand("ip", "link", "set", vxlan, "up")
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link set %s up: %w: %s", vxlan, err, out)
	}

	// 5. Bring bridge up
	out, err = execCommand("ip", "link", "set", bridge, "up")
	if err != nil && !isFileExists(out) {
		return "", fmt.Errorf("ip link set %s up: %w: %s", bridge, err, out)
	}

	// 6. Set MTU: underlay MTU minus 50 bytes VXLAN overhead.
	if iface, err := net.InterfaceByName(underlay); err == nil && iface.MTU > 0 {
		vxlanMTU := fmt.Sprintf("%d", iface.MTU-50)
		execCommand("ip", "link", "set", vxlan, "mtu", vxlanMTU)  //nolint:errcheck
		execCommand("ip", "link", "set", bridge, "mtu", vxlanMTU) //nolint:errcheck
	}

	return bridge, nil
}

// DeprovisionVXLAN removes the bridge and VXLAN interface for the given VNI.
func DeprovisionVXLAN(vni int) error {
	bridge := vxlanBridgeName(vni)
	vxlan := vtepName(vni)

	if out, err := execCommand("ip", "link", "del", bridge); err != nil {
		if !isNoSuchDevice(out) {
			return fmt.Errorf("ip link del %s: %w: %s", bridge, err, out)
		}
	}

	if out, err := execCommand("ip", "link", "del", vxlan); err != nil {
		if !isNoSuchDevice(out) {
			return fmt.Errorf("ip link del %s: %w: %s", vxlan, err, out)
		}
	}

	return nil
}
