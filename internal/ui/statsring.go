package ui

import (
	"sync"
	"time"
)

const (
	ringCapacity   = 120 // 10 minutes at 5s intervals
	sampleInterval = 5 * time.Second
)

// StatsSample is one timestamped measurement for a resource (host or VM).
type StatsSample struct {
	Ts         int64   `json:"ts"`
	CPUPct     float64 `json:"cpu_pct"`
	MemPct     float64 `json:"mem_pct"`
	DiskRdRate float64 `json:"disk_rd_rate"`
	DiskWrRate float64 `json:"disk_wr_rate"`
	NetRxRate  float64 `json:"net_rx_rate"`
	NetTxRate  float64 `json:"net_tx_rate"`
}

// StatsRing is a fixed-size circular buffer of StatsSample.
type StatsRing struct {
	mu    sync.RWMutex
	buf   [ringCapacity]StatsSample
	head  int
	count int
	// Previous cumulative values for delta/rate computation.
	prevDiskRd int64
	prevDiskWr int64
	prevNetRx  int64
	prevNetTx  int64
}

// Push appends a sample and computes I/O rates from cumulative counter deltas.
func (r *StatsRing) Push(s StatsSample, diskRdCum, diskWrCum, netRxCum, netTxCum int64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.count > 0 {
		dt := sampleInterval.Seconds()
		s.DiskRdRate = clampZero(float64(diskRdCum-r.prevDiskRd) / dt)
		s.DiskWrRate = clampZero(float64(diskWrCum-r.prevDiskWr) / dt)
		s.NetRxRate = clampZero(float64(netRxCum-r.prevNetRx) / dt)
		s.NetTxRate = clampZero(float64(netTxCum-r.prevNetTx) / dt)
	}

	r.prevDiskRd = diskRdCum
	r.prevDiskWr = diskWrCum
	r.prevNetRx = netRxCum
	r.prevNetTx = netTxCum

	r.buf[r.head] = s
	r.head = (r.head + 1) % ringCapacity
	if r.count < ringCapacity {
		r.count++
	}
}

// Snapshot returns a time-ordered slice of all valid samples (oldest first).
func (r *StatsRing) Snapshot() []StatsSample {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]StatsSample, r.count)
	start := (r.head - r.count + ringCapacity) % ringCapacity
	for i := 0; i < r.count; i++ {
		out[i] = r.buf[(start+i)%ringCapacity]
	}
	return out
}

func clampZero(v float64) float64 {
	if v < 0 {
		return 0
	}
	return v
}
