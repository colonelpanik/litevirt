package placement

import (
	"sort"
	"strconv"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
)

// Topology scoring bonuses (per device pair).
const (
	bonusLinkClique = 40 // same NVLink/xGMI clique
	bonusPCIeBridge = 25 // same PCIe switch/bridge
	bonusPCIeRoot   = 15 // same PCIe root complex
	bonusNUMANode   = 8  // same NUMA node, different root
)

// TopologyScore evaluates how well a set of candidate devices satisfies a
// multi-device request, considering PCIe topology locality.
//
// It groups available devices by progressively coarser topology tiers and
// picks the tightest group that can satisfy the request. Returns the total
// bonus score and the selected device addresses.
func TopologyScore(devices []corrosion.PCIDeviceRecord, req DeviceRequest) (score int, selected []string) {
	count := req.Count
	if count <= 0 {
		count = 1
	}

	// Filter by vendor if specified.
	var candidates []corrosion.PCIDeviceRecord
	for _, d := range devices {
		if req.Vendor != "" && d.VendorID != req.Vendor {
			continue
		}
		if req.Model != "" && d.DeviceName != req.Model {
			continue
		}
		candidates = append(candidates, d)
	}

	if len(candidates) < count {
		return 0, nil
	}

	// Single device — no pair bonus, just return first available.
	if count == 1 {
		// Prefer device in requested clique if specified.
		if req.Clique != "" {
			for _, d := range candidates {
				if d.LinkClique == req.Clique {
					return bonusLinkClique, []string{d.Address}
				}
			}
		}
		return 0, []string{candidates[0].Address}
	}

	// Try each tier in order of tightest locality.
	type tierFunc struct {
		groupKey func(d corrosion.PCIDeviceRecord) string
		bonus    int
	}
	tiers := []tierFunc{
		{groupKey: func(d corrosion.PCIDeviceRecord) string { return d.LinkClique }, bonus: bonusLinkClique},
		{groupKey: func(d corrosion.PCIDeviceRecord) string { return d.PCIeBridge }, bonus: bonusPCIeBridge},
		{groupKey: func(d corrosion.PCIDeviceRecord) string { return d.PCIeRootPort }, bonus: bonusPCIeRoot},
		{groupKey: func(d corrosion.PCIDeviceRecord) string { return intToString(d.NUMANode) }, bonus: bonusNUMANode},
	}

	// If a specific clique is requested, try it first.
	if req.Clique != "" {
		var cliqued []corrosion.PCIDeviceRecord
		for _, d := range candidates {
			if d.LinkClique == req.Clique {
				cliqued = append(cliqued, d)
			}
		}
		if len(cliqued) >= count {
			addrs := pickN(cliqued, count)
			return pairBonus(count, bonusLinkClique), addrs
		}
	}

	for _, tier := range tiers {
		groups := groupDevices(candidates, tier.groupKey)
		// Sort group keys for deterministic selection.
		keys := make([]string, 0, len(groups))
		for k := range groups {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			group := groups[k]
			if len(group) >= count {
				addrs := pickN(group, count)
				return pairBonus(count, tier.bonus), addrs
			}
		}
	}

	// Fallback: can satisfy but devices span topologies — no bonus.
	addrs := pickN(candidates, count)

	// If SameNUMA is required but we couldn't find a single NUMA group, fail.
	if req.SameNUMA {
		return 0, nil
	}

	return 0, addrs
}

// groupDevices groups devices by a key function. Empty keys are skipped.
func groupDevices(devices []corrosion.PCIDeviceRecord, keyFn func(corrosion.PCIDeviceRecord) string) map[string][]corrosion.PCIDeviceRecord {
	groups := map[string][]corrosion.PCIDeviceRecord{}
	for _, d := range devices {
		k := keyFn(d)
		if k == "" {
			continue
		}
		groups[k] = append(groups[k], d)
	}
	return groups
}

// pickN returns the first n device addresses.
func pickN(devices []corrosion.PCIDeviceRecord, n int) []string {
	addrs := make([]string, n)
	for i := 0; i < n; i++ {
		addrs[i] = devices[i].Address
	}
	return addrs
}

// pairBonus computes the total bonus for n devices at a given tier.
// The bonus is applied per pair: n*(n-1)/2 pairs.
func pairBonus(n, bonusPerPair int) int {
	pairs := n * (n - 1) / 2
	return pairs * bonusPerPair
}

func intToString(n int) string {
	if n < 0 {
		return ""
	}
	return strconv.Itoa(n)
}

// scoreHostDevices checks device availability and computes a topology bonus.
func scoreHostDevices(devices []corrosion.PCIDeviceRecord, reqs []DeviceRequest) (ok bool, bonus int) {
	return scoreHostDevicesForHost(devices, reqs, nil, "")
}

func scoreHostDevicesForHost(
	devices []corrosion.PCIDeviceRecord,
	reqs []DeviceRequest,
	mappings map[string]map[string][]string,
	host string,
) (ok bool, bonus int) {
	for _, req := range reqs {
		count := req.Count
		if count <= 0 {
			count = 1
		}

		// Match the allocator's selector precedence exactly:
		// mapping → SR-IOV → type/vendor → exact address.
		if req.Mapping != "" {
			// ResolveMappingAddress, used by the allocator, deterministically
			// chooses the first address for this host.
			addresses := mappings[req.Mapping][host]
			if len(addresses) == 0 || !exactDeviceEligible(devices, addresses[0]) {
				return false, 0
			}
			continue
		}

		// SR-IOV: gate on an SR-IOV-capable PF (matching type/vendor/parent) being
		// present — VFs are created or reused on-demand by the owner's allocator, so a
		// currently-empty managed PF (no unassigned VF rows yet) must still qualify.
		// Placement never infers VF identity from an ordinary free device or pins a VF.
		if req.Sriov {
			if !sriovHostEligible(devices, req) {
				return false, 0
			}
			continue
		}

		if req.Type != "" || req.Vendor != "" {
			// Filter devices by type. An empty type with a vendor-only selector
			// matches all types, as the selector classification permits it.
			var typed []corrosion.PCIDeviceRecord
			for _, d := range devices {
				if (req.Type == "" || d.Type == req.Type) && d.VMName == "" {
					typed = append(typed, d)
				}
			}

			s, selected := TopologyScore(typed, req)
			if len(selected) < count {
				return false, 0
			}
			bonus += s
			continue
		}

		if req.Address == "" || count != 1 || !exactDeviceEligible(devices, req.Address) {
			return false, 0
		}
	}
	return true, bonus
}

func exactDeviceEligible(devices []corrosion.PCIDeviceRecord, address string) bool {
	want, wantOK := pci.CanonicalBDF(address)
	var selected *corrosion.PCIDeviceRecord
	for i := range devices {
		got, gotOK := pci.CanonicalBDF(devices[i].Address)
		if (wantOK && gotOK && got == want) || (!wantOK && devices[i].Address == address) {
			selected = &devices[i]
			break
		}
	}
	if selected == nil || selected.VMName != "" {
		return false
	}
	if selected.IOMMUGroup < 0 {
		return true
	}
	for _, sibling := range devices {
		if sibling.IOMMUGroup == selected.IOMMUGroup && sibling.VMName != "" {
			return false
		}
	}
	return true
}

// sriovHostEligible reports whether the host can satisfy an SR-IOV request: it
// requires an SR-IOV-capable PF of the requested type (matching vendor, model,
// and parent when specified). Inventory has no authoritative VF-to-PF relation,
// so an ordinary unassigned device never proves VF eligibility. The final
// managed-PF/create-or-reuse decision happens at allocation time on the owner.
func sriovHostEligible(devices []corrosion.PCIDeviceRecord, req DeviceRequest) bool {
	count := req.Count
	if count <= 0 {
		count = 1
	}
	wantParent, parentOK := pci.CanonicalBDF(req.Parent)
	for _, d := range devices {
		if d.Type != req.Type {
			continue
		}
		if req.Vendor != "" && d.VendorID != req.Vendor && d.VendorName != req.Vendor {
			continue
		}
		// SR-IOV-capable PF (matching the requested parent, if any).
		if !d.SRIOVCapable {
			continue
		}
		if req.Model != "" && d.DeviceName != req.Model {
			continue
		}
		if req.Parent != "" {
			gotParent, gotOK := pci.CanonicalBDF(d.Address)
			if !parentOK || !gotOK || gotParent != wantParent {
				continue
			}
		}
		if d.SRIOVVFsTotal > 0 && count > d.SRIOVVFsTotal {
			continue
		}
		return true
	}
	return false
}
