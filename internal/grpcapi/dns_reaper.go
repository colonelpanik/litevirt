package grpcapi

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
)

// dnsReapGrace is how stale an auto DNS record must be before the reaper will
// remove it. The window guards against a replication-lag false positive: a
// record freshly upserted on another node (whose VM hasn't replicated here yet)
// looks "orphaned" locally, so we leave recent records alone.
const dnsReapGrace = 30 * time.Minute

// ReapOrphanDNSRecords removes auto-managed dns_records that no longer
// correspond to an active VM — the backstop for the VM-delete cleanup, and the
// cleanup path for pre-existing orphans (e.g. records left by VMs deleted before
// the delete-path fix). Desired-state: it builds the set of records the current
// active VMs SHOULD have and soft-deletes any older auto record not in that set.
//
// Idempotent and safe to run on every node: soft-delete is LWW-convergent, the
// active-VM set comes from the replicated vms table (consistent cluster-wide),
// and the grace window prevents reaping records mid-replication. Only source=
// 'auto' records are touched — operator-created records are never reaped.
func (s *Server) ReapOrphanDNSRecords(ctx context.Context) {
	domain := s.dnsDomain
	if domain == "" {
		domain = "lv.local"
	}

	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		slog.Warn("dns reaper: list vms", "error", err)
		return
	}
	expected := make(map[string]bool, len(vms))
	for _, vm := range vms {
		ifaces, _ := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
		for _, ifc := range ifaces {
			if ifc.IP != "" {
				expected[strings.ToLower(dns.VMRecordName(vm.Name, vm.StackName, domain))] = true
				break
			}
		}
	}
	// Containers share the auto-DNS namespace: a live CT with a known managed-NIC
	// IP must be in the expected set, or the reaper would delete its record.
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		slog.Warn("dns reaper: list containers", "error", err)
		return
	}
	for _, ct := range cts {
		ifaces, _ := corrosion.GetContainerInterfaces(ctx, s.db, ct.HostName, ct.Name)
		for _, ifc := range ifaces {
			if ifc.IP != "" {
				expected[strings.ToLower(dns.ContainerRecordName(ct.Name, ct.Labels[corrosion.LabelStack], domain))] = true
				break
			}
		}
	}

	rows, err := s.db.Query(ctx,
		`SELECT name, updated_at FROM dns_records
		 WHERE source = 'auto' AND deleted_at IS NULL`)
	if err != nil {
		slog.Warn("dns reaper: list dns_records", "error", err)
		return
	}
	cutoff := time.Now().UTC().Add(-dnsReapGrace)
	reaped := 0
	for _, r := range rows {
		name := r.String("name")
		if expected[strings.ToLower(name)] {
			continue
		}
		// Skip records too fresh to be sure they're orphans (replication lag).
		// updated_at is the LWW key (RFC3339 or HLC) — parse via the both-format helper.
		if ts, ok := corrosion.ParseUpdatedAt(r.String("updated_at")); ok && ts.After(cutoff) {
			continue
		}
		if err := dns.DeleteRecord(ctx, s.db, name); err != nil {
			slog.Warn("dns reaper: delete orphan record", "name", name, "error", err)
			continue
		}
		slog.Info("dns reaper: removed orphaned record", "name", name)
		reaped++
	}
	if reaped > 0 {
		slog.Info("dns reaper: swept orphaned DNS records", "removed", reaped)
	}
}
