package grpcapi

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// PreflightUpgrade reports conditions that would make a daemon restart on
// this host unsafe. The CLI surfaces "block" findings as errors and "warn"
// findings as advisory. Operators override blocks with `lv host upgrade
// --force`.
//
// Checks (none destructive — read-only):
//
//  1. In-flight VMs in transitional states sourced or targeted at this host.
//  2. This host holds the failover-leader lease AND a fence is recently
//     pending (per fencing_log) — a restart could orphan the fence in flight.
//  3. Replication watermark backlog: if mutation_log row count is high
//     relative to other peers, the daemon's restart would extend the gap.
//  4. NTP / HLC skew: if any peer reports clock_skew > 5s vs us, the new
//     daemon's HLC reset could land badly.
//  5. Witness role: refusing self-upgrade when the cluster would lose
//     quorum (e.g. 2-node + witness; witness up = no fence; restart of
//     witness during partition kills HA).
func (s *Server) PreflightUpgrade(ctx context.Context, req *pb.PreflightUpgradeRequest) (*pb.PreflightUpgradeResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	target := req.TargetHost
	if target == "" {
		target = s.hostName
	}
	if target != s.hostName {
		client, conn, err := s.peerClient(ctx, target)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "reach %s: %v", target, err)
		}
		defer conn.Close()
		return client.PreflightUpgrade(ctx, req)
	}

	var findings []*pb.PreflightFinding
	add := func(severity, code, message string) {
		findings = append(findings, &pb.PreflightFinding{
			Severity: severity, Code: code, Message: message,
		})
	}

	// 1. Active VMs in transient state on this host.
	if rows, err := s.db.Query(ctx,
		`SELECT name, state FROM vms
		 WHERE host_name = ? AND deleted_at IS NULL
		   AND state IN ('migrating','starting','creating','stopping','rebuilding')`,
		s.hostName); err == nil {
		for _, r := range rows {
			add("block", "vm-transient",
				fmt.Sprintf("VM %s is in state %q; upgrade would interrupt it",
					r.String("name"), r.String("state")))
		}
	}

	// 2. Migrations targeting this host (we'd be killing the destination side).
	if rows, err := s.db.Query(ctx,
		`SELECT name FROM vms
		 WHERE host_name = ? AND state = 'migrating' AND deleted_at IS NULL`,
		s.hostName); err == nil {
		for _, r := range rows {
			add("block", "migrate-incoming",
				fmt.Sprintf("VM %s is migrating to this host", r.String("name")))
		}
	}

	// 3. Failover-leader lease + recently active fence.
	if rows, err := s.db.Query(ctx,
		`SELECT holder, expires_at FROM leader_election
		 WHERE key = 'failover'`); err == nil && len(rows) > 0 {
		holder := rows[0].String("holder")
		expiresAt, _ := time.Parse(time.RFC3339, rows[0].String("expires_at"))
		if holder == s.hostName && time.Until(expiresAt) > 0 {
			// Lease is held by us. Check for a pending fence within the
			// last minute (a fence operation interrupted by a restart could
			// be re-run by the new leader against an already-fenced host).
			//
			// fencing_log.timestamp is RFC3339 ("2026-06-04T06:42:12Z"), so the
			// freshness bound must be formatted the same way — strftime with the
			// 'T'/'Z' literals. Comparing against a bare datetime('now',...) (which
			// is space-separated) is a lexical mismatch: 'T' (0x54) > ' ' (0x20)
			// makes every same-day stale fence look "newer than a minute ago",
			// permanently false-blocking the failover leader's own upgrade.
			if pending, err := s.db.Query(ctx,
				`SELECT COUNT(*) AS n FROM fencing_log
				 WHERE result NOT IN ('fenced','manual-confirmed')
				   AND timestamp > strftime('%Y-%m-%dT%H:%M:%SZ','now','-1 minute')`); err == nil && len(pending) > 0 {
				if pending[0].Int("n") > 0 {
					add("block", "leader-with-pending-fence",
						"this host holds the failover lease and has a fence in progress")
				}
			}
		}
	}

	// 4. Replication backlog — mutation_log row count.
	if rows, err := s.db.Query(ctx, `SELECT COUNT(*) AS n FROM mutation_log`); err == nil && len(rows) > 0 {
		if n := rows[0].Int("n"); n > 50000 {
			add("warn", "replication-backlog",
				fmt.Sprintf("mutation_log has %d rows; restart will extend replication lag", n))
		}
	}

	// 5. Clock skew with peers metric.
	if rows, err := s.db.Query(ctx,
		`SELECT target, skew_seconds FROM clock_skew
		 WHERE observer = ? AND ABS(skew_seconds) > 5
		   AND updated_at > strftime('%Y-%m-%dT%H:%M:%SZ','now','-10 minutes')`,
		s.hostName); err == nil {
		for _, r := range rows {
			add("warn", "clock-skew",
				fmt.Sprintf("skew with peer %s: %d seconds (HLC reset on restart could land badly)",
					r.String("target"), r.Int("skew_seconds")))
		}
	}

	// 6. Witness role — losing the witness during a partition kills quorum.
	h, err := corrosion.GetHost(ctx, s.db, s.hostName)
	if err == nil && h != nil && h.IsWitness() {
		// Count current cluster size.
		if rows, err := s.db.Query(ctx,
			`SELECT COUNT(*) AS n FROM hosts
			 WHERE state IN ('active','upgrading') AND deleted_at IS NULL AND role = 'worker'`); err == nil && len(rows) > 0 {
			n := rows[0].Int("n")
			if n%2 == 0 {
				// Even worker count + this witness = the witness IS the
				// tiebreaker. Restarting it during a partition is fatal.
				add("warn", "witness-restart",
					fmt.Sprintf("this is a witness host for a %d-worker even-N cluster; restart interrupts tiebreak", n))
			}
		}
	}

	ok := true
	for _, f := range findings {
		if f.Severity == "block" {
			ok = false
			break
		}
	}
	return &pb.PreflightUpgradeResponse{
		Ok:       ok,
		Host:     s.hostName,
		Findings: findings,
	}, nil
}
