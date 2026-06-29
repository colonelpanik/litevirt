package grpcapi

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
)

// containerDNSName is the auto-DNS name for a container (ct.stack.domain, or
// ct.domain when standalone), or "" when no DNS domain is configured (DNS off).
// stack is the CT's litevirt.stack label.
func (s *Server) containerDNSName(ctName, stack string) string {
	if s.dnsDomain == "" {
		return ""
	}
	return dns.ContainerRecordName(ctName, stack, s.dnsDomain)
}

// upsertContainerDNS (re)writes the container's auto A record when DNS is on and
// an IP is known. Idempotent — a changed IP replaces the record (UpsertRecord is
// an upsert keyed on name). Best-effort: a DNS failure never fails the caller;
// the scanner re-runs and the reaper backstops.
func (s *Server) upsertContainerDNS(ctx context.Context, ctName, stack, ip string) {
	name := s.containerDNSName(ctName, stack)
	if name == "" || ip == "" {
		return
	}
	if err := dns.UpsertRecord(ctx, s.db, name, ip); err != nil {
		slog.Warn("container DNS upsert failed", "container", ctName, "name", name, "error", err)
	}
}

// deleteContainerDNS tombstones the container's auto A record — the delete and
// migrate-source cascades. Prompt removal matters: a lingering record could point
// at an IP the container no longer holds (freed/DHCP-reassigned to another
// workload → mis-routing). Best-effort; the reaper backstops a miss.
func (s *Server) deleteContainerDNS(ctx context.Context, ctName, stack string) {
	name := s.containerDNSName(ctName, stack)
	if name == "" {
		return
	}
	if err := dns.DeleteRecord(ctx, s.db, name); err != nil {
		slog.Warn("container DNS delete failed", "container", ctName, "name", name, "error", err)
	}
}

// containerStackLabel reads a container's stack from its labels ("" if none).
func containerStackLabel(ct corrosion.ContainerRecord) string {
	return ct.Labels[corrosion.LabelStack]
}
