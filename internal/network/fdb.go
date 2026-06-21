package network

import (
	"fmt"
	"strings"
)

// isAlreadyExists returns true if the command output contains "File exists" or "already exists".
func isAlreadyExists(out []byte) bool {
	s := string(out)
	return strings.Contains(s, "File exists") || strings.Contains(s, "already exists") || strings.Contains(s, "already assigned")
}

// AddFDBEntry adds a unicast FDB entry: bridge fdb add <mac> dev vxlan<VNI> dst <remoteVTEP>
func AddFDBEntry(vni int, mac, remoteVTEP string) error {
	out, err := execCommand("bridge", "fdb", "add", mac,
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb add %s: %w: %s", mac, err, out)
	}
	return nil
}

// DeleteFDBEntry removes a unicast FDB entry: bridge fdb del <mac> dev vxlan<VNI> dst <remoteVTEP>
func DeleteFDBEntry(vni int, mac, remoteVTEP string) error {
	out, err := execCommand("bridge", "fdb", "del", mac,
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb del %s: %w: %s", mac, err, out)
	}
	return nil
}

// FloodEntry adds a BUM flood entry: bridge fdb add 00:00:00:00:00:00 dev vxlan<VNI> dst <remoteVTEP>
func FloodEntry(vni int, remoteVTEP string) error {
	out, err := execCommand("bridge", "fdb", "add", "00:00:00:00:00:00",
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb add flood %s: %w: %s", remoteVTEP, err, out)
	}
	return nil
}

// DeleteFloodEntry removes a BUM flood entry: bridge fdb del 00:00:00:00:00:00 dev vxlan<VNI> dst <remoteVTEP>
func DeleteFloodEntry(vni int, remoteVTEP string) error {
	out, err := execCommand("bridge", "fdb", "del", "00:00:00:00:00:00",
		"dev", vtepName(vni), "dst", remoteVTEP)
	if err != nil && !isAlreadyExists(out) {
		return fmt.Errorf("bridge fdb del flood %s: %w: %s", remoteVTEP, err, out)
	}
	return nil
}
