package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func newPreflightTestServer(t *testing.T) *Server {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return &Server{db: db, hostName: "host-a"}
}

// makeLeader makes host-a hold the failover lease so the pending-fence preflight
// branch actually runs (it only fires for the lease holder).
func makeLeader(t *testing.T, s *Server) {
	t.Helper()
	exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	if err := s.db.Execute(context.Background(),
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', 'host-a', ?, datetime('now'))`, exp); err != nil {
		t.Fatalf("seed leader_election: %v", err)
	}
}

func seedFence(t *testing.T, s *Server, id, result, timestamp string) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES (?, 'host-b', 'ssh', ?, ?, '')`, id, result, timestamp); err != nil {
		t.Fatalf("seed fencing_log: %v", err)
	}
}

func hasFinding(resp *pb.PreflightUpgradeResponse, code string) bool {
	for _, f := range resp.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// TestPreflightUpgrade_StaleFenceNotPending is the regression for the RFC3339-vs-
// space timestamp bug: a stale (hours-old) partial fence must NOT count as
// in-progress. Before the fix, the stored "...T..Z" timestamp compared lexically
// greater than the space-separated datetime('now','-1 minute'), so ANY same-day
// fence permanently false-blocked the failover leader's own upgrade.
func TestPreflightUpgrade_StaleFenceNotPending(t *testing.T) {
	s := newPreflightTestServer(t)
	makeLeader(t, s)
	seedFence(t, s, "f1", "partial", time.Now().UTC().Add(-2*time.Hour).Format(time.RFC3339))

	resp, err := s.PreflightUpgrade(adminCtx(), &pb.PreflightUpgradeRequest{TargetHost: "host-a"})
	if err != nil {
		t.Fatalf("PreflightUpgrade: %v", err)
	}
	if hasFinding(resp, "leader-with-pending-fence") {
		t.Error("a 2h-old fence was wrongly flagged as in-progress (timestamp-format bug)")
	}
}

// TestPreflightUpgrade_RecentFencePending verifies the check still does its real
// job: a genuinely recent (<1 min) non-terminal fence blocks the leader's upgrade.
func TestPreflightUpgrade_RecentFencePending(t *testing.T) {
	s := newPreflightTestServer(t)
	makeLeader(t, s)
	seedFence(t, s, "f2", "partial", time.Now().UTC().Format(time.RFC3339))

	resp, err := s.PreflightUpgrade(adminCtx(), &pb.PreflightUpgradeRequest{TargetHost: "host-a"})
	if err != nil {
		t.Fatalf("PreflightUpgrade: %v", err)
	}
	if !hasFinding(resp, "leader-with-pending-fence") {
		t.Error("a fence within the last minute should block the leader's upgrade")
	}
}

// TestPreflightUpgrade_CompletedFenceNotPending verifies a terminal fence result
// ('fenced') never blocks, even when recent.
func TestPreflightUpgrade_CompletedFenceNotPending(t *testing.T) {
	s := newPreflightTestServer(t)
	makeLeader(t, s)
	seedFence(t, s, "f3", "fenced", time.Now().UTC().Format(time.RFC3339))

	resp, err := s.PreflightUpgrade(adminCtx(), &pb.PreflightUpgradeRequest{TargetHost: "host-a"})
	if err != nil {
		t.Fatalf("PreflightUpgrade: %v", err)
	}
	if hasFinding(resp, "leader-with-pending-fence") {
		t.Error("a completed (terminal) fence should not block an upgrade")
	}
}

// TestPreflightUpgrade_NonLeaderNoFenceCheck verifies the pending-fence check is
// scoped to the lease holder — a non-leader host isn't blocked by a recent fence.
func TestPreflightUpgrade_NonLeaderNoFenceCheck(t *testing.T) {
	s := newPreflightTestServer(t)
	// host-a does NOT hold the failover lease here.
	if err := s.db.Execute(context.Background(),
		`INSERT INTO leader_election (key, holder, expires_at, updated_at)
		 VALUES ('failover', 'host-b', ?, datetime('now'))`,
		time.Now().UTC().Add(time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatalf("seed leader_election: %v", err)
	}
	seedFence(t, s, "f4", "partial", time.Now().UTC().Format(time.RFC3339))

	resp, err := s.PreflightUpgrade(adminCtx(), &pb.PreflightUpgradeRequest{TargetHost: "host-a"})
	if err != nil {
		t.Fatalf("PreflightUpgrade: %v", err)
	}
	if hasFinding(resp, "leader-with-pending-fence") {
		t.Error("non-leader host should not get the pending-fence block")
	}
}
