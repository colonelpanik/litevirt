package libvirt

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
)

// execVLAN is the hook used to run bridge commands for VLAN configuration.
// Tests may override this to inject a fake executor.
var execVLAN = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// ConfigureVLANTap finds the tap interface for a domain's network interface
// and sets the VLAN tag using `bridge vlan add`.
// bridge: Linux bridge name, mac: MAC of the VM interface, vlanID: VLAN tag (1–4094).
//
// Method form so the call site can go through grpcapi.LibvirtBackend
// (and the fleet's fake libvirt can stub it). The package-level alias
// below keeps existing callers compiling.
func (c *Client) ConfigureVLANTap(domainName, bridge, mac string, vlanID int) error {
	tapDev, err := findTapDevice(c, domainName, mac)
	if err != nil {
		return fmt.Errorf("find tap for %s/%s: %w", domainName, mac, err)
	}

	// bridge vlan add dev <tap> vid <vlan> pvid untagged
	// pvid: ingress untagged frames get this VLAN
	// untagged: egress frames are stripped of the tag (VM sees untagged traffic)
	return configureAccessBridgeVLAN(tapDev, vlanID)
}

// TapDevice returns the host-side tap interface name for a domain's NIC
// (matched by MAC) by reading the live domain XML. libvirt auto-assigns the
// tap (vnetN) at start, so this is the only way to learn it; the distributed
// firewall records it into vm_interfaces so the per-NIC tier can target it.
// Method form so the call goes through grpcapi.LibvirtBackend (fake-able).
func (c *Client) TapDevice(domainName, mac string) (string, error) {
	return findTapDevice(c, domainName, mac)
}

// ConfigureTrunkTap sets up a tap interface for VLAN trunk mode.
// All listed VLAN IDs are added without pvid/untagged — the VM sends and
// receives tagged frames and handles its own VLAN demux.
func (c *Client) ConfigureTrunkTap(domainName, bridge, mac string, vlanIDs []int) error {
	tapDev, err := findTapDevice(c, domainName, mac)
	if err != nil {
		return fmt.Errorf("find tap for %s/%s: %w", domainName, mac, err)
	}

	return configureTrunkBridgeVLANs(tapDev, vlanIDs)
}

// ConfigureVLANTap (package func) is retained for direct callers that
// don't want to dereference a *Client method (e.g. test fixtures that
// call configureAccessBridgeVLAN's wrapper). Prefer the method form.
func ConfigureVLANTap(c *Client, domainName, bridge, mac string, vlanID int) error {
	return c.ConfigureVLANTap(domainName, bridge, mac, vlanID)
}

func ConfigureTrunkTap(c *Client, domainName, bridge, mac string, vlanIDs []int) error {
	return c.ConfigureTrunkTap(domainName, bridge, mac, vlanIDs)
}

// configureAccessBridgeVLAN applies a single access-mode VLAN (pvid+untagged) to a tap device.
// This is the inner logic of ConfigureVLANTap, extracted so tests can call it without libvirt.
func configureAccessBridgeVLAN(tapDev string, vlanID int) error {
	out, err := execVLAN("bridge", "vlan", "add", "dev", tapDev,
		"vid", fmt.Sprintf("%d", vlanID), "pvid", "untagged")
	if err != nil {
		return fmt.Errorf("bridge vlan add %s vid %d: %w: %s", tapDev, vlanID, err, out)
	}
	return nil
}

// configureTrunkBridgeVLANs applies trunk-mode VLANs (no pvid/untagged) to a tap device.
// This is the inner logic of ConfigureTrunkTap, extracted so tests can call it without libvirt.
func configureTrunkBridgeVLANs(tapDev string, vlanIDs []int) error {
	for _, vid := range vlanIDs {
		out, err := execVLAN("bridge", "vlan", "add", "dev", tapDev,
			"vid", fmt.Sprintf("%d", vid))
		if err != nil {
			return fmt.Errorf("bridge vlan add %s vid %d (trunk): %w: %s", tapDev, vid, err, out)
		}
	}
	return nil
}

// NegotiateTrunkVLANs reads the current VLANs on a tap, computes a diff against
// desiredVLANs, and applies adds/removes to converge to the desired state.
func NegotiateTrunkVLANs(c *Client, domainName, bridge, mac string, desiredVLANs []int) error {
	tapDev, err := findTapDevice(c, domainName, mac)
	if err != nil {
		return fmt.Errorf("find tap for %s/%s: %w", domainName, mac, err)
	}

	// Ensure vlan_filtering is enabled on the bridge.
	out, err := execVLAN("bridge", "vlan", "show", "dev", bridge)
	if err != nil {
		return fmt.Errorf("bridge vlan show %s: %w: %s", bridge, err, out)
	}

	// Read current VLANs on the tap device.
	current, err := readTapVLANs(tapDev)
	if err != nil {
		return err
	}

	currentSet := make(map[int]bool, len(current))
	for _, v := range current {
		currentSet[v] = true
	}
	desiredSet := make(map[int]bool, len(desiredVLANs))
	for _, v := range desiredVLANs {
		desiredSet[v] = true
	}

	// Remove VLANs not in desired set.
	for _, v := range current {
		if !desiredSet[v] && v != 1 { // don't remove default VLAN 1
			out, err := execVLAN("bridge", "vlan", "del", "dev", tapDev,
				"vid", fmt.Sprintf("%d", v))
			if err != nil {
				return fmt.Errorf("bridge vlan del %s vid %d: %w: %s", tapDev, v, err, out)
			}
		}
	}

	// Add VLANs not yet present.
	for _, v := range desiredVLANs {
		if !currentSet[v] {
			out, err := execVLAN("bridge", "vlan", "add", "dev", tapDev,
				"vid", fmt.Sprintf("%d", v))
			if err != nil {
				return fmt.Errorf("bridge vlan add %s vid %d: %w: %s", tapDev, v, err, out)
			}
		}
	}

	return nil
}

// readTapVLANs parses `bridge vlan show dev <tap>` output to extract VLAN IDs.
func readTapVLANs(tapDev string) ([]int, error) {
	out, err := execVLAN("bridge", "vlan", "show", "dev", tapDev)
	if err != nil {
		return nil, fmt.Errorf("bridge vlan show %s: %w: %s", tapDev, err, out)
	}

	var vlans []int
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "port") {
			continue
		}
		// Lines look like: "100" or "100 PVID Egress Untagged" or "tapXXX  100..."
		fields := strings.Fields(line)
		for _, f := range fields {
			// Try to parse each field as a VLAN ID.
			vid := 0
			n, err := fmt.Sscanf(f, "%d", &vid)
			if err == nil && n == 1 && vid >= 1 && vid <= 4094 {
				vlans = append(vlans, vid)
				break // first number on the line is the VID
			}
		}
	}
	return vlans, nil
}

// findTapDevice returns the tap interface name for a given domain + MAC by
// inspecting the live domain XML (which libvirt populates with target dev after start).
func findTapDevice(c *Client, domainName, mac string) (string, error) {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return "", fmt.Errorf("lookup domain %s: %w", domainName, err)
	}
	xmlStr, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err != nil {
		return "", fmt.Errorf("get domain XML %s: %w", domainName, err)
	}
	return parseTapDevice(xmlStr, domainName, mac)
}

// parseTapDevice extracts a tap interface name from domain XML by matching a MAC address.
func parseTapDevice(xmlStr, domainName, mac string) (string, error) {
	var doc struct {
		Devices struct {
			Interfaces []struct {
				MAC struct {
					Address string `xml:"address,attr"`
				} `xml:"mac"`
				Target struct {
					Dev string `xml:"dev,attr"`
				} `xml:"target"`
			} `xml:"interface"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(xmlStr), &doc); err != nil {
		return "", fmt.Errorf("parse domain XML: %w", err)
	}

	mac = strings.ToLower(mac)
	for _, iface := range doc.Devices.Interfaces {
		if strings.ToLower(iface.MAC.Address) == mac {
			if iface.Target.Dev == "" {
				return "", fmt.Errorf("no target dev for interface %s", mac)
			}
			return iface.Target.Dev, nil
		}
	}
	return "", fmt.Errorf("interface with MAC %s not found in domain %s", mac, domainName)
}
