package placement

import "strconv"

func parseFloat(s string) (float64, error) { return strconv.ParseFloat(s, 64) }

// DimensionWeights collects all dimension weights so callers (and tests) can
// reconfigure them without touching the engine. Defaults match
type DimensionWeights struct {
	CPU      float64
	RAM      float64
	DiskIOPS float64
	NetBW    float64
	NUMA     float64
	HostGen  float64
	Power    float64
}

// DefaultWeights are the baseline weights from the design.
func DefaultWeights() DimensionWeights {
	return DimensionWeights{
		CPU:      25,
		RAM:      25,
		DiskIOPS: 15,
		NetBW:    10,
		NUMA:     10,
		HostGen:  5,
		Power:    5,
	}
}

// AllDimensions returns the dimension list with the given weights. Pass
// DefaultWeights() unless a test is exercising a specific weight ratio.
//
// Dimensions whose telemetry isn't yet wired (DiskIOPS, NetBW, Power) return
// Capacity=0, which the scoring loop treats as "skip this dimension." So the
// list is safe to use today even though only ships CPU+RAM+NUMA+HostGen.
func AllDimensions(w DimensionWeights) []Dimension {
	return []Dimension{
		cpuDim{w: w.CPU},
		ramDim{w: w.RAM},
		diskIOPSDim{w: w.DiskIOPS},
		netBWDim{w: w.NetBW},
		numaDim{w: w.NUMA},
		hostGenDim{w: w.HostGen},
		powerDim{w: w.Power},
	}
}

// ───────── CPU ─────────

type cpuDim struct{ w float64 }

func (d cpuDim) Name() string                                 { return "cpu" }
func (d cpuDim) Weight() float64                              { return d.w }
func (d cpuDim) Used(s *ClusterSnapshot, host string) float64 { return float64(s.CPUUsed[host]) }
func (d cpuDim) Capacity(s *ClusterSnapshot, host string) float64 {
	return float64(s.Hosts[host].CPUTotal)
}
func (d cpuDim) Demand(req *Request) float64 { return float64(req.CPUNeeded) }

// ───────── RAM ─────────

type ramDim struct{ w float64 }

func (d ramDim) Name() string                                 { return "ram" }
func (d ramDim) Weight() float64                              { return d.w }
func (d ramDim) Used(s *ClusterSnapshot, host string) float64 { return float64(s.MemUsed[host]) }
func (d ramDim) Capacity(s *ClusterSnapshot, host string) float64 {
	return float64(s.Hosts[host].MemTotal)
}
func (d ramDim) Demand(req *Request) float64 { return float64(req.MemMiBNeeded) }

// ───────── DiskIOPS (placeholder) ─────────
//
// Once internal/storage Driver Stats() returns IOPS rates we'll wire them
// here. Until then Capacity=0 → dimension skipped by scoreDimension.

type diskIOPSDim struct{ w float64 }

func (d diskIOPSDim) Name() string                                     { return "disk_iops" }
func (d diskIOPSDim) Weight() float64                                  { return d.w }
func (d diskIOPSDim) Used(s *ClusterSnapshot, host string) float64     { return 0 }
func (d diskIOPSDim) Capacity(s *ClusterSnapshot, host string) float64 { return 0 }
func (d diskIOPSDim) Demand(req *Request) float64                      { return 0 }

// ───────── Network bandwidth (placeholder) ─────────
//
// Wired once libvirt domain interface stats are sampled and aggregated.

type netBWDim struct{ w float64 }

func (d netBWDim) Name() string                                     { return "net_bw" }
func (d netBWDim) Weight() float64                                  { return d.w }
func (d netBWDim) Used(s *ClusterSnapshot, host string) float64     { return 0 }
func (d netBWDim) Capacity(s *ClusterSnapshot, host string) float64 { return 0 }
func (d netBWDim) Demand(req *Request) float64                      { return 0 }

// ───────── NUMA fit (label-driven for now) ─────────
//
// NUMA optimization will deepen with the storage Driver / PCI topology
// integration; for v1 we treat hosts with `numa.preferred=true` as bonus.
// Capacity=1 means every NUMA-preferred host gets the full bonus; non-NUMA
// hosts get 0 contribution.

type numaDim struct{ w float64 }

func (d numaDim) Name() string                                 { return "numa" }
func (d numaDim) Weight() float64                              { return d.w }
func (d numaDim) Used(s *ClusterSnapshot, host string) float64 { return 0 }
func (d numaDim) Capacity(s *ClusterSnapshot, host string) float64 {
	h, ok := s.Hosts[host]
	if !ok {
		return 0
	}
	if v, ok := h.Labels["numa.preferred"]; ok && (v == "true" || v == "yes" || v == "1") {
		return 1
	}
	return 0
}
func (d numaDim) Demand(req *Request) float64 {
	// Workloads with same-NUMA device requirements lean on this dimension.
	for _, dev := range req.Devices {
		if dev.SameNUMA {
			return 1
		}
	}
	return 0
}

// ───────── Host generation ─────────
//
// Host label `host.generation=N` (integer); newer hardware preferred.
// Used==capacity gives a flat bonus per generation step; demand is always 1
// so the contribution scales with weight × pressure-helper.

type hostGenDim struct{ w float64 }

func (d hostGenDim) Name() string                                 { return "host_gen" }
func (d hostGenDim) Weight() float64                              { return d.w }
func (d hostGenDim) Used(s *ClusterSnapshot, host string) float64 { return 0 }
func (d hostGenDim) Capacity(s *ClusterSnapshot, host string) float64 {
	h, ok := s.Hosts[host]
	if !ok {
		return 0
	}
	v, ok := h.Labels["host.generation"]
	if !ok || v == "" {
		return 0
	}
	gen, err := parseFloat(v)
	if err != nil || gen <= 0 {
		return 0
	}
	// Cap at 10 to bound the bonus per dimension; gen 1=baseline, gen 10=max.
	if gen > 10 {
		gen = 10
	}
	return gen / 10
}
func (d hostGenDim) Demand(req *Request) float64 { return 0 }

// ───────── Power / thermal (placeholder) ─────────

type powerDim struct{ w float64 }

func (d powerDim) Name() string                                     { return "power" }
func (d powerDim) Weight() float64                                  { return d.w }
func (d powerDim) Used(s *ClusterSnapshot, host string) float64     { return 0 }
func (d powerDim) Capacity(s *ClusterSnapshot, host string) float64 { return 0 }
func (d powerDim) Demand(req *Request) float64                      { return 0 }
