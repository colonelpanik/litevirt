package libvirt

import (
	"encoding/xml"
	"fmt"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// AttachDisk hot-attaches a disk to a running domain.
func (c *Client) AttachDisk(domainName string, path, targetDev, bus string) error {
	cache := "writeback"
	disk := diskDevice{
		Type:   "file",
		Device: "disk",
		Driver: diskDriver{Name: "qemu", Type: "qcow2", Cache: cache},
		Source: diskSource{File: path},
		Target: diskTarget{Dev: targetDev, Bus: bus},
	}
	return c.attachDeviceXML(domainName, disk)
}

// DetachDisk hot-detaches a disk from a running domain by target device name.
func (c *Client) DetachDisk(domainName, targetDev string) error {
	disk := diskDevice{
		Type:   "file",
		Device: "disk",
		Target: diskTarget{Dev: targetDev},
	}
	return c.detachDeviceXML(domainName, disk)
}

// AttachNIC hot-attaches a network interface to a running domain.
func (c *Client) AttachNIC(domainName, bridge, model, mac string) error {
	if model == "" {
		model = "virtio"
	}
	iface := interfaceDevice{
		Type:   "bridge",
		MAC:    ifaceMAC{Address: mac},
		Source: ifaceSource{Bridge: bridge},
		Model:  ifaceModel{Type: model},
	}
	return c.attachDeviceXML(domainName, iface)
}

// DetachNIC hot-detaches a network interface by MAC address.
func (c *Client) DetachNIC(domainName, mac string) error {
	iface := interfaceDevice{
		Type: "bridge",
		MAC:  ifaceMAC{Address: mac},
	}
	return c.detachDeviceXML(domainName, iface)
}

// AttachHostdev hot-attaches a PCI device to a running domain.
func (c *Client) AttachHostdev(domainName, pciAddress string) error {
	parsed := ParsePCIAddress(pciAddress)
	hd := hostdevDevice{
		Mode:    "subsystem",
		Type:    "pci",
		Managed: "yes",
		Source: hostdevSource{
			Address: hostdevAddress{
				Domain:   parsed.Domain,
				Bus:      parsed.Bus,
				Slot:     parsed.Slot,
				Function: parsed.Function,
			},
		},
	}
	return c.attachDeviceXML(domainName, hd)
}

// AttachHostdevWithAlias hot-attaches a PCI device to a running domain carrying a
// stable user alias (ua-<device>-<member>), so the device is addressable by that
// alias in the persistent definition (the topology-preserving reconcile keys
// hostdevs by their <alias>). An empty alias behaves exactly like AttachHostdev.
func (c *Client) AttachHostdevWithAlias(domainName, pciAddress, alias string) error {
	parsed := ParsePCIAddress(pciAddress)
	hd := hostdevDevice{
		Mode:    "subsystem",
		Type:    "pci",
		Managed: "yes",
		Source: hostdevSource{
			Address: hostdevAddress{
				Domain:   parsed.Domain,
				Bus:      parsed.Bus,
				Slot:     parsed.Slot,
				Function: parsed.Function,
			},
		},
	}
	if alias != "" {
		hd.Alias = &hostdevAlias{Name: alias}
	}
	return c.attachDeviceXML(domainName, hd)
}

// DetachHostdev hot-detaches a PCI device from a running domain.
func (c *Client) DetachHostdev(domainName, pciAddress string) error {
	parsed := ParsePCIAddress(pciAddress)
	hd := hostdevDevice{
		Mode:    "subsystem",
		Type:    "pci",
		Managed: "yes",
		Source: hostdevSource{
			Address: hostdevAddress{
				Domain:   parsed.Domain,
				Bus:      parsed.Bus,
				Slot:     parsed.Slot,
				Function: parsed.Function,
			},
		},
	}
	return c.detachDeviceXML(domainName, hd)
}

// DetachHostdevConfig removes a PCI device from a domain's PERSISTENT definition ONLY
// (DomainDeviceModifyConfig, no Live flag). It is the counterpart to DetachHostdev for a
// SHUT-OFF domain, whose nonexistent live instance would reject a Live-flagged modify:
// this detaches the hostdev from the config a cold boot loads without touching a live
// domain. Same device XML as DetachHostdev — only the modify flags differ.
func (c *Client) DetachHostdevConfig(domainName, pciAddress string) error {
	parsed := ParsePCIAddress(pciAddress)
	hd := hostdevDevice{
		Mode:    "subsystem",
		Type:    "pci",
		Managed: "yes",
		Source: hostdevSource{
			Address: hostdevAddress{
				Domain:   parsed.Domain,
				Bus:      parsed.Bus,
				Slot:     parsed.Slot,
				Function: parsed.Function,
			},
		},
	}
	return c.detachDeviceXMLConfig(domainName, hd)
}

// attachDeviceXML marshals a device to XML and attaches it via libvirt API (live + persistent).
func (c *Client) attachDeviceXML(domainName string, device any) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domainName, err)
	}
	data, err := xml.MarshalIndent(device, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal device XML: %w", err)
	}
	flags := uint32(golibvirt.DomainDeviceModifyLive | golibvirt.DomainDeviceModifyConfig)
	if err := c.virt.DomainAttachDeviceFlags(dom, string(data), flags); err != nil {
		return fmt.Errorf("attach device to %s: %w", domainName, err)
	}
	return nil
}

// detachDeviceXML marshals a device to XML and detaches it via libvirt API (live + persistent).
func (c *Client) detachDeviceXML(domainName string, device any) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domainName, err)
	}
	data, err := xml.MarshalIndent(device, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal device XML: %w", err)
	}
	flags := uint32(golibvirt.DomainDeviceModifyLive | golibvirt.DomainDeviceModifyConfig)
	if err := c.virt.DomainDetachDeviceFlags(dom, string(data), flags); err != nil {
		return fmt.Errorf("detach device from %s: %w", domainName, err)
	}
	return nil
}

// detachDeviceXMLConfig marshals a device to XML and detaches it from a domain's
// PERSISTENT definition ONLY (DomainDeviceModifyConfig, no Live flag) — the shut-off-safe
// detach that never touches a live domain.
func (c *Client) detachDeviceXMLConfig(domainName string, device any) error {
	dom, err := c.virt.DomainLookupByName(domainName)
	if err != nil {
		return fmt.Errorf("lookup domain %s: %w", domainName, err)
	}
	data, err := xml.MarshalIndent(device, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal device XML: %w", err)
	}
	flags := uint32(golibvirt.DomainDeviceModifyConfig)
	if err := c.virt.DomainDetachDeviceFlags(dom, string(data), flags); err != nil {
		return fmt.Errorf("detach device from %s config: %w", domainName, err)
	}
	return nil
}
