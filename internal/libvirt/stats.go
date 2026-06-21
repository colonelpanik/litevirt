package libvirt

import (
	"encoding/xml"
	"fmt"
	"sync"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// DomainStats holds live resource usage for a single domain.
type DomainStats struct {
	Name         string
	CPUPct       float64 // CPU usage % (0-100 * nVCPU)
	MemRSSBytes  int64   // resident memory in bytes
	MemTotalBytes int64  // allocated memory in bytes
	DiskRdBytes  int64
	DiskWrBytes  int64
	DiskRdReqs   int64
	DiskWrReqs   int64
	NetRxBytes   int64
	NetTxBytes   int64
}

// cpuSample stores a single CPU time reading for delta computation.
type cpuSample struct {
	cpuTimeNS int64
	timestamp time.Time
}

var (
	cpuSamplesMu sync.Mutex
	cpuSamples   = make(map[string]cpuSample) // keyed by domain name
)

// GetDomainStats returns live resource statistics for a running domain.
func (c *Client) GetDomainStats(name string) (*DomainStats, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	dom, err := c.virt.DomainLookupByName(name)
	if err != nil {
		return nil, fmt.Errorf("lookup domain %s: %w", name, err)
	}

	// DomainGetInfo: state, maxMem (KiB), memory (KiB), nrVirtCPU, cpuTime (ns)
	_, _, memory, nrCPU, cpuTime, err := c.virt.DomainGetInfo(dom)
	if err != nil {
		return nil, fmt.Errorf("get info %s: %w", name, err)
	}

	ds := &DomainStats{
		Name:          name,
		MemTotalBytes: int64(memory) * 1024, // KiB → bytes
	}

	// CPU percentage from time delta.
	cpuSamplesMu.Lock()
	prev, hasPrev := cpuSamples[name]
	now := time.Now()
	cpuSamples[name] = cpuSample{cpuTimeNS: int64(cpuTime), timestamp: now}
	cpuSamplesMu.Unlock()

	if hasPrev {
		elapsed := now.Sub(prev.timestamp).Nanoseconds()
		if elapsed > 0 {
			deltaCPU := int64(cpuTime) - prev.cpuTimeNS
			ds.CPUPct = float64(deltaCPU) / float64(elapsed) * 100.0
			if ds.CPUPct < 0 {
				ds.CPUPct = 0
			}
			// Cap at nVCPU * 100 (shouldn't exceed, but be safe).
			maxPct := float64(nrCPU) * 100.0
			if ds.CPUPct > maxPct {
				ds.CPUPct = maxPct
			}
		}
	}

	// Memory stats (RSS).
	memStats, err := c.virt.DomainMemoryStats(dom, 13, 0) // 13 = DomainMemoryStatNr
	if err == nil {
		for _, s := range memStats {
			if golibvirt.DomainMemoryStatTags(s.Tag) == golibvirt.DomainMemoryStatRss {
				ds.MemRSSBytes = int64(s.Val) * 1024 // KiB → bytes
			}
		}
	}

	// Block stats — parse domain XML to find disk targets.
	xmlDesc, err := c.virt.DomainGetXMLDesc(dom, 0)
	if err == nil {
		targets := parseDiskTargets(xmlDesc)
		for _, tgt := range targets {
			rdReq, rdBytes, wrReq, wrBytes, _, err := c.virt.DomainBlockStats(dom, tgt)
			if err != nil {
				continue
			}
			ds.DiskRdBytes += rdBytes
			ds.DiskWrBytes += wrBytes
			ds.DiskRdReqs += rdReq
			ds.DiskWrReqs += wrReq
		}

		// Interface stats.
		ifaces := parseInterfaceTargets(xmlDesc)
		for _, dev := range ifaces {
			rxBytes, _, _, _, txBytes, _, _, _, err := c.virt.DomainInterfaceStats(dom, dev)
			if err != nil {
				continue
			}
			ds.NetRxBytes += rxBytes
			ds.NetTxBytes += txBytes
		}
	}

	return ds, nil
}

// GetAllDomainStats returns stats for all running domains.
func (c *Client) GetAllDomainStats() ([]*DomainStats, error) {
	names, err := c.listRunningDomains()
	if err != nil {
		return nil, err
	}

	var stats []*DomainStats
	for _, name := range names {
		ds, err := c.GetDomainStats(name)
		if err != nil {
			continue // skip domains we can't stat
		}
		stats = append(stats, ds)
	}
	return stats, nil
}

// listRunningDomains returns names of active domains only.
func (c *Client) listRunningDomains() ([]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	domains, _, err := c.virt.ConnectListAllDomains(1, golibvirt.ConnectListDomainsActive)
	if err != nil {
		return nil, fmt.Errorf("list running domains: %w", err)
	}

	names := make([]string, len(domains))
	for i, d := range domains {
		names[i] = d.Name
	}
	return names, nil
}

// parseDiskTargets extracts block device target names (e.g. "vda", "sda") from domain XML.
func parseDiskTargets(xmlDesc string) []string {
	var doc struct {
		Devices struct {
			Disks []struct {
				Target struct {
					Dev string `xml:"dev,attr"`
				} `xml:"target"`
			} `xml:"disk"`
		} `xml:"devices"`
	}
	if xml.Unmarshal([]byte(xmlDesc), &doc) != nil {
		return nil
	}
	targets := make([]string, 0, len(doc.Devices.Disks))
	for _, d := range doc.Devices.Disks {
		if d.Target.Dev != "" {
			targets = append(targets, d.Target.Dev)
		}
	}
	return targets
}

// parseInterfaceTargets extracts network interface device names (e.g. "vnet0") from domain XML.
func parseInterfaceTargets(xmlDesc string) []string {
	var doc struct {
		Devices struct {
			Interfaces []struct {
				Target struct {
					Dev string `xml:"dev,attr"`
				} `xml:"target"`
			} `xml:"interface"`
		} `xml:"devices"`
	}
	if xml.Unmarshal([]byte(xmlDesc), &doc) != nil {
		return nil
	}
	var devs []string
	for _, iface := range doc.Devices.Interfaces {
		if iface.Target.Dev != "" {
			devs = append(devs, iface.Target.Dev)
		}
	}
	return devs
}
