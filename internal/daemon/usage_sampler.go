package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

const (
	usageSampleInterval = 30 * time.Second // how often to read libvirt domain stats
	usageMinWrite       = 5 * time.Minute  // backstop: write at least this often even if steady
	usageDeadbandIOPS   = 50               // skip a write unless IOPS moved more than this…
	usageDeadbandMbps   = 5                // …or Mbps moved more than this
)

// usageSampler turns cumulative per-host libvirt counters (disk ops, net bytes)
// into smoothed rates (IOPS, Mbps) written to host_runtime_usage, with a deadband
// to bound write churn. It is the pure, testable core of runRuntimeUsageSampler.
type usageSampler struct {
	haveBaseline bool
	lastOps      uint64
	lastBytes    uint64
	lastT        time.Time

	haveWritten        bool
	lastIOPS, lastMbps int64
	lastWriteT         time.Time
}

// observe ingests a cumulative reading and returns the current rates plus whether
// they should be persisted. The FIRST reading only records a baseline (no rate
// yet). Negative deltas (counter reset / domain restart) clamp to 0. A write
// fires on: the first rate, a value crossing to/from zero (so a host that sheds
// all load promptly reports 0 — never stuck "loaded forever"), a move beyond the
// deadband, or the min-interval backstop.
func (u *usageSampler) observe(totalOps, totalBytes uint64, now time.Time) (write bool, iops, mbps int64) {
	if !u.haveBaseline {
		u.lastOps, u.lastBytes, u.lastT, u.haveBaseline = totalOps, totalBytes, now, true
		return false, 0, 0
	}
	elapsed := now.Sub(u.lastT).Seconds()
	if elapsed <= 0 {
		return false, u.lastIOPS, u.lastMbps
	}
	iops = clampRate(totalOps, u.lastOps, elapsed)
	bytesPerSec := clampRate(totalBytes, u.lastBytes, elapsed)
	mbps = bytesPerSec * 8 / 1_000_000
	u.lastOps, u.lastBytes, u.lastT = totalOps, totalBytes, now

	crossedZero := (iops == 0) != (u.lastIOPS == 0) || (mbps == 0) != (u.lastMbps == 0)
	moved := absDiff(iops, u.lastIOPS) > usageDeadbandIOPS || absDiff(mbps, u.lastMbps) > usageDeadbandMbps
	stale := now.Sub(u.lastWriteT) >= usageMinWrite
	if !u.haveWritten || crossedZero || moved || stale {
		u.lastIOPS, u.lastMbps, u.haveWritten, u.lastWriteT = iops, mbps, true, now
		return true, iops, mbps
	}
	return false, iops, mbps
}

// clampRate is (cur-last)/elapsed as a non-negative rate; a counter reset
// (cur<last) clamps to 0 rather than reporting a bogus huge/negative delta.
func clampRate(cur, last uint64, elapsedSec float64) int64 {
	if cur < last {
		return 0
	}
	return int64(float64(cur-last) / elapsedSec)
}

func absDiff(a, b int64) int64 {
	if a < b {
		return b - a
	}
	return a - b
}

// runRuntimeUsageSampler periodically samples this host's aggregate libvirt
// domain disk/net counters and writes smoothed rates to host_runtime_usage for
// the placement engine (DiskIOPS/NetBW dimensions). Host-local; one row per host.
func (d *Daemon) runRuntimeUsageSampler(ctx context.Context) {
	if d.virt == nil {
		return
	}
	var s usageSampler
	ticker := time.NewTicker(usageSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		stats, err := d.virt.GetAllDomainStats()
		if err != nil {
			continue // transient libvirt hiccup; try next tick
		}
		var ops, bytes uint64
		for _, ds := range stats {
			ops += uint64(nonNeg(ds.DiskRdReqs)) + uint64(nonNeg(ds.DiskWrReqs))
			bytes += uint64(nonNeg(ds.NetRxBytes)) + uint64(nonNeg(ds.NetTxBytes))
		}
		write, iops, mbps := s.observe(ops, bytes, time.Now())
		if !write {
			continue
		}
		if err := corrosion.UpsertHostRuntimeUsage(ctx, d.db, d.cfg.HostName, iops, mbps); err != nil {
			slog.Warn("host runtime-usage sample", "error", err)
		}
	}
}

func nonNeg(v int64) int64 {
	if v < 0 {
		return 0
	}
	return v
}
