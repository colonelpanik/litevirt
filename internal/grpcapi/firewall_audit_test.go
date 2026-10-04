package grpcapi

import (
	"context"
	"testing"
)

// Audit-row helpers for the firewall RPC tests, as on the fork's main.

// fwAuditRow is the newest audit_log row for one action.
type fwAuditRow struct {
	found                        bool
	user, target, detail, result string
}

func lastAuditRow(t *testing.T, s *Server, action string) fwAuditRow {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT username, target, detail, result FROM audit_log
		 WHERE action = ? ORDER BY seq DESC, timestamp DESC LIMIT 1`, action)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if len(rows) == 0 {
		return fwAuditRow{}
	}
	r := rows[0]
	return fwAuditRow{found: true, user: r.String("username"), target: r.String("target"),
		detail: r.String("detail"), result: r.String("result")}
}

func wantAudit(t *testing.T, s *Server, action, user, target, detail string) {
	t.Helper()
	got := lastAuditRow(t, s, action)
	if !got.found {
		t.Fatalf("%s: no audit row; the firewall changed and the signed chain says nothing did", action)
	}
	if got.user != user || got.target != target || got.detail != detail || got.result != "ok" {
		t.Errorf("%s audit row = user=%q target=%q detail=%q result=%q\n"+
			"                 want user=%q target=%q detail=%q result=\"ok\"",
			action, got.user, got.target, got.detail, got.result, user, target, detail)
	}
}
