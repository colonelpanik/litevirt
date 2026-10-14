package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostupdates"
	"github.com/litevirt/litevirt/internal/notify"
)

// HostUpdatesConfig is host_updates in the daemon config.
type HostUpdatesConfig struct {
	Enabled      bool
	Interval     time.Duration
	RefreshIndex bool
	// Check replaces the package-manager probe (tests only).
	Check func(context.Context) hostupdates.Status
}

// SetHostUpdates configures the pending-OS-update check (host_updates).
func (s *Server) SetHostUpdates(cfg HostUpdatesConfig) { s.hostUpdates = cfg }

// RunHostUpdateLoop checks this host's pending OS package updates on an
// interval and publishes the result as host labels, a metric (the collector
// reads the labels back) and a notification. It is read-only: nothing is
// installed, and the package index is refreshed only when host_updates.
// refresh_index is set. With the check disabled it withdraws what an earlier
// run published, so no stale count stays on the host record.
func (s *Server) RunHostUpdateLoop(ctx context.Context) {
	cfg := s.hostUpdates
	if !cfg.Enabled {
		s.withdrawHostUpdateLabels(ctx)
		return
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.CheckHostUpdatesOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// withdrawHostUpdateLabels removes the published counts: the check is off, or
// this host has no package manager it can read.
func (s *Server) withdrawHostUpdateLabels(ctx context.Context) {
	if s.db == nil {
		return
	}
	if err := corrosion.SetHostLabels(ctx, s.db, s.hostName, nil,
		[]string{hostupdates.LabelPending, hostupdates.LabelSecurity}); err != nil {
		slog.Warn("host updates: withdraw labels failed", "error", err)
	}
}

// hostUpdateCounts is the last check that produced counts, kept apart from the
// published labels (which say "unknown" while a check fails) so a failed check
// between two identical results does not repeat the notification.
type hostUpdateCounts struct {
	Pending  int `json:"pending"`
	Security int `json:"security"`
}

func (s *Server) hostUpdateCountsPath() string { return filepath.Join(s.dataDir, "host-updates.json") }

// lastHostUpdateCounts reads the last known counts: the host-local record, or,
// before the first one is written, what this host last published.
func (s *Server) lastHostUpdateCounts(ctx context.Context) (hostUpdateCounts, bool) {
	if s.dataDir != "" {
		if b, err := os.ReadFile(s.hostUpdateCountsPath()); err == nil {
			var c hostUpdateCounts
			if json.Unmarshal(b, &c) == nil {
				return c, true
			}
		}
	}
	if h, err := corrosion.GetHost(ctx, s.db, s.hostName); err == nil && h != nil {
		if p, sec, ok := hostupdates.FromLabels(h.Labels); ok {
			return hostUpdateCounts{Pending: p, Security: sec}, true
		}
	}
	return hostUpdateCounts{}, false
}

func (s *Server) recordHostUpdateCounts(c hostUpdateCounts) {
	if s.dataDir == "" {
		return
	}
	b, _ := json.Marshal(c)
	if err := os.WriteFile(s.hostUpdateCountsPath(), b, 0o640); err != nil {
		slog.Warn("host updates: record last counts failed", "error", err)
	}
}

// CheckHostUpdatesOnce runs one check and publishes it in one label write. A
// notification goes out only when the counts differ from the last check that
// produced counts (kept host-locally, so neither a daemon restart nor a failed
// check in between repeats it), and only when something is pending: security
// updates are a warning, the rest info. A check that failed publishes "unknown"
// and notifies nothing. A host with no readable package manager publishes
// nothing, and withdraws what it published before.
func (s *Server) CheckHostUpdatesOnce(ctx context.Context) {
	cfg := s.hostUpdates
	check := cfg.Check
	if check == nil {
		check = func(ctx context.Context) hostupdates.Status {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			return hostupdates.Check(cctx, hostupdates.Options{RefreshIndex: cfg.RefreshIndex})
		}
	}
	st := check(ctx)
	if !st.Supported {
		s.withdrawHostUpdateLabels(ctx)
		return
	}
	last, known := s.lastHostUpdateCounts(ctx) // before the labels change under it
	if err := corrosion.SetHostLabels(ctx, s.db, s.hostName, st.Labels(), nil); err != nil {
		slog.Warn("host updates: publish labels failed", "error", err)
	}
	if st.Err != "" {
		slog.Warn("host updates: check incomplete", "manager", st.Manager, "error", st.Err)
	}
	if st.Err != "" && len(st.Packages) == 0 {
		return // no counts from this check
	}
	now := hostUpdateCounts{Pending: st.Pending, Security: st.Security}
	s.recordHostUpdateCounts(now)
	if st.Pending == 0 || (known && last == now) {
		return
	}
	kind, sev := "host.updates", notify.SevInfo
	detail := fmt.Sprintf("%d package update(s) pending via %s", st.Pending, st.Manager)
	if st.Security > 0 {
		kind, sev = "host.security_updates", notify.SevWarn
		detail = fmt.Sprintf("%d package update(s) pending via %s, %d of them security", st.Pending, st.Manager, st.Security)
	}
	if names := st.Names(8); len(names) > 0 {
		detail += ": " + strings.Join(names, ", ")
		if st.Pending > len(names) {
			detail += ", ..."
		}
	}
	s.notify(ctx, notify.Notification{Kind: kind, Severity: sev, Subject: s.hostName, Detail: detail})
}
