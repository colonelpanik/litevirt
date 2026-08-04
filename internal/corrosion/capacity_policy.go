package corrosion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// HostCapacityOverride is the capacity-affecting subset of HostRecord. Pointer
// reserves preserve the difference between inherit (nil) and explicit zero.
type HostCapacityOverride struct {
	CPUOvercommit float64 `json:"cpu_overcommit"`
	MemOvercommit float64 `json:"mem_overcommit"`
	CPUReserve    *int    `json:"cpu_reserve"`
	MemReserveMiB *int    `json:"mem_reserve_mib"`
}

type namedHostCapacityOverride struct {
	Host string `json:"host"`
	HostCapacityOverride
}

type canonicalCapacityPolicy struct {
	CPUOvercommit    float64                     `json:"cpu_overcommit"`
	MemOvercommit    float64                     `json:"mem_overcommit"`
	CPUReserve       int                         `json:"cpu_reserve"`
	MemReserveMiB    int                         `json:"mem_reserve_mib"`
	MemReservePct    int                         `json:"mem_reserve_pct"`
	VMMemOverheadMiB int                         `json:"vm_mem_overhead_mib"`
	HostOverrides    []namedHostCapacityOverride `json:"host_overrides"`
}

// HostCapacityOverrides extracts only the host fields that can change
// allocatable capacity. Hosts that inherit every cluster default are omitted.
func HostCapacityOverrides(hosts []HostRecord) map[string]HostCapacityOverride {
	out := make(map[string]HostCapacityOverride)
	for _, host := range hosts {
		override := HostCapacityOverride{
			CPUOvercommit: host.CPUOvercommit,
			MemOvercommit: host.MemOvercommit,
			CPUReserve:    cloneInt(host.CPUReserve),
			MemReserveMiB: cloneInt(host.MemReserveMiB),
		}
		if override.CPUOvercommit <= 0 {
			override.CPUOvercommit = 0
		}
		if override.MemOvercommit <= 0 {
			override.MemOvercommit = 0
		}
		if override.CPUOvercommit != 0 || override.MemOvercommit != 0 ||
			override.CPUReserve != nil || override.MemReserveMiB != nil {
			out[host.Name] = override
		}
	}
	return out
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

// CapacityPolicyFingerprint returns the SHA-256 of a canonical JSON
// representation of the normalized cluster policy and sorted host overrides.
func CapacityPolicyFingerprint(policy CapacityPolicy, overrides map[string]HostCapacityOverride) (string, error) {
	normalized := policy.normalize()
	hosts := make([]string, 0, len(overrides))
	for host := range overrides {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)

	canonical := canonicalCapacityPolicy{
		CPUOvercommit:    normalized.CPUOvercommit,
		MemOvercommit:    normalized.MemOvercommit,
		CPUReserve:       normalized.CPUReserve,
		MemReserveMiB:    normalized.MemReserveMiB,
		MemReservePct:    normalized.MemReservePct,
		VMMemOverheadMiB: normalized.VMMemOverheadMiB,
		HostOverrides:    make([]namedHostCapacityOverride, 0, len(hosts)),
	}
	for _, host := range hosts {
		override := overrides[host]
		if override.CPUOvercommit <= 0 {
			override.CPUOvercommit = 0
		}
		if override.MemOvercommit <= 0 {
			override.MemOvercommit = 0
		}
		canonical.HostOverrides = append(canonical.HostOverrides, namedHostCapacityOverride{
			Host: host, HostCapacityOverride: override,
		})
	}

	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}
