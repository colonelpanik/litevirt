package corrosion

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func encodeSyncPayload(t *testing.T, payload *syncPayload) []byte {
	t.Helper()
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(data); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func payloadTableNames(t *testing.T, data []byte) []string {
	t.Helper()
	payload, err := decompressPayload(data)
	if err != nil {
		t.Fatalf("decompress payload: %v", err)
	}
	out := make([]string, 0, len(payload.Tables))
	for _, tbl := range payload.Tables {
		out = append(out, tbl.Name)
	}
	slices.Sort(out)
	return out
}

func tableCount(t *testing.T, c *Client, table string) int64 {
	t.Helper()
	rows, err := c.Query(context.Background(), "SELECT COUNT(*) AS n FROM "+table)
	if err != nil || len(rows) != 1 {
		t.Fatalf("count %s: rows=%d err=%v", table, len(rows), err)
	}
	return rows[0].Int64("n")
}

func oneString(t *testing.T, c *Client, query, col string, args ...interface{}) string {
	t.Helper()
	rows, err := c.Query(context.Background(), query, args...)
	if err != nil || len(rows) != 1 {
		t.Fatalf("query %q: rows=%d err=%v", query, len(rows), err)
	}
	return rows[0].String(col)
}

func TestPublicDumpExcludesSensitiveState(t *testing.T) {
	ctx := context.Background()
	c := mustTestClient(t)

	if err := UpsertRegistryCredential(ctx, c, RegistryCredential{
		ID: "rc1", Scope: RegistryScopeGlobal, Registry: "registry.example",
		Username: "robot", Secret: "super-secret-token",
	}); err != nil {
		t.Fatal(err)
	}
	if err := InsertNotificationTarget(ctx, c, NotificationTarget{
		ID: "nt1", Name: "ops", Type: "webhook", Config: `{"url":"https://hook.example/secret"}`, Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	if err := InsertNotificationRoute(ctx, c, NotificationRoute{
		ID: "nr1", EventPattern: "*", TargetID: "nt1", MinSeverity: "warn", Enabled: true,
	}); err != nil {
		t.Fatal(err)
	}
	// 2FA/recovery joined the sensitive lane in v32 — seed all three so the dump
	// covers them. InsertRecoveryCodes writes both recovery_codes and the
	// recovery_code_sets pointer.
	if err := InsertUser2FA(ctx, c, User2FARecord{
		Username: "alice", Method: "totp", Secret: "JBSWY3DPEHPK3PXP-totp-secret", Label: "phone",
	}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRecoveryCodes(ctx, c, "alice", []string{"$2a$10$hashone", "$2a$10$hashtwo"}); err != nil {
		t.Fatal(err)
	}
	// runtime_action_proofs joined the sensitive lane (v38): peer-only because a
	// proof carries a bearer relocation_token that must never reach the operator dump.
	if err := WriteActionProof(ctx, c, ActionProof{
		ID: "p1", Action: ActionRelocate, TargetKind: "container", TargetName: "ct1",
		DestHost: "host-b", Coordinator: "host-a", RelocationToken: "reloc-bearer-secret",
	}); err != nil {
		t.Fatal(err)
	}

	publicPayload, err := decompressPayload(c.DumpStateBytes())
	if err != nil {
		t.Fatalf("public dump decompress: %v", err)
	}
	for _, tbl := range publicPayload.Tables {
		if sensitiveTableSet[tbl.Name] {
			t.Fatalf("public dump included sensitive table %q", tbl.Name)
		}
	}
	plain, _ := json.Marshal(publicPayload)
	for _, secret := range []string{"super-secret-token", "hook.example/secret", "JBSWY3DPEHPK3PXP-totp-secret", "$2a$10$hashone", "reloc-bearer-secret"} {
		if strings.Contains(string(plain), secret) {
			t.Fatalf("public dump leaked sensitive row data (%q): %s", secret, plain)
		}
	}

	got := payloadTableNames(t, c.DumpSensitiveStateBytes())
	want := append([]string(nil), sensitiveTableNames...)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("sensitive dump tables = %v, want %v", got, want)
	}
}

// A proof missing on a peer (e.g. it was offline past MaxLogRetention and missed
// the WAL window) converges via the peer-only sensitive anti-entropy lane — and
// the merge is MONOTONE over that lane too, so a stale prepared copy can't
// resurrect a spent proof.
func TestSensitiveAE_ProofConverges(t *testing.T) {
	ctx := context.Background()
	src := mustTestClient(t)
	dst := mustTestClient(t)

	// Source has a completed proof; dst has never seen it.
	p := ActionProof{ID: "p1", Action: ActionRelocate, TargetKind: "container",
		TargetName: "ct1", DestHost: "h", Coordinator: "h"}
	if err := WriteActionProof(ctx, src, p); err != nil {
		t.Fatal(err)
	}
	if err := ClaimActionProof(ctx, src, "p1", "h"); err != nil {
		t.Fatal(err)
	}
	if err := CompleteActionProof(ctx, src, "p1", "h"); err != nil {
		t.Fatal(err)
	}

	// Convergence: dst merges src's sensitive dump → the proof appears (the AE
	// recovery path the WAL retention window assumes).
	dst.MergeSensitiveStateBytesLWW(src.DumpSensitiveStateBytes())
	pr, ok, err := GetActionProof(ctx, dst, "p1")
	if err != nil || !ok {
		t.Fatalf("proof did not converge to dst via sensitive AE: ok=%v err=%v", ok, err)
	}
	if pr.Status != ProofCompleted {
		t.Fatalf("converged status=%q; want completed", pr.Status)
	}

	// Monotone over the sensitive lane: a merge carrying a (newer) PREPARED copy
	// must not resurrect the spent proof.
	stale := mustTestClient(t)
	if err := WriteActionProof(ctx, stale, p); err != nil { // prepared, freshly-stamped
		t.Fatal(err)
	}
	dst.MergeSensitiveStateBytesLWW(stale.DumpSensitiveStateBytes())
	pr, _, _ = GetActionProof(ctx, dst, "p1")
	if pr.Status != ProofCompleted {
		t.Fatalf("status=%q after stale merge; want completed — sensitive-lane merge must be MONOTONE", pr.Status)
	}
}

// TestSensitiveAE_StepStateUnionBothDirections pins the forward-only step_state
// invariant on the merge path: whichever row WINS, the surviving row must carry the
// UNION of both sides' checkpoints — losing a recorded step (e.g. "started") could let a
// later promote resume destroy a running domain. Here the local row wins the merge (it is
// terminal, higher rank) but the incoming copy carries a step local lacks, so the union
// must be folded back into the surviving local row.
func TestSensitiveAE_StepStateUnionBothDirections(t *testing.T) {
	ctx := context.Background()
	dst := mustTestClient(t)
	src := mustTestClient(t)

	p := ActionProof{ID: "p-steps", Action: ActionPromote, TargetKind: "vm",
		TargetName: "vm1", DestHost: "h", Coordinator: "h"}

	// dst: terminal (completed) proof that recorded step "started".
	if err := WriteActionProof(ctx, dst, p); err != nil {
		t.Fatal(err)
	}
	if err := ClaimActionProof(ctx, dst, "p-steps", "h"); err != nil {
		t.Fatal(err)
	}
	if err := AppendProofStep(ctx, dst, "p-steps", "started"); err != nil {
		t.Fatal(err)
	}
	if err := CompleteActionProof(ctx, dst, "p-steps", "h"); err != nil {
		t.Fatal(err)
	}

	// src: a lower-rank (in_progress) copy that recorded a DIFFERENT step, "diskbuilt".
	if err := WriteActionProof(ctx, src, p); err != nil {
		t.Fatal(err)
	}
	if err := ClaimActionProof(ctx, src, "p-steps", "h"); err != nil {
		t.Fatal(err)
	}
	if err := AppendProofStep(ctx, src, "p-steps", "diskbuilt"); err != nil {
		t.Fatal(err)
	}

	// Merge src → dst. Local (completed) outranks incoming (in_progress) so local wins,
	// but the incoming step must still be folded in.
	dst.MergeSensitiveStateBytesLWW(src.DumpSensitiveStateBytes())

	pr, ok, err := GetActionProof(ctx, dst, "p-steps")
	if err != nil || !ok {
		t.Fatalf("proof missing after merge: ok=%v err=%v", ok, err)
	}
	if pr.Status != ProofCompleted {
		t.Fatalf("local terminal status must survive; got %q", pr.Status)
	}
	if !ProofStepDone(pr.StepState, "started") || !ProofStepDone(pr.StepState, "diskbuilt") {
		t.Fatalf("surviving row must carry BOTH checkpoints (union); got step_state=%q", pr.StepState)
	}
}

func TestSensitiveAndPublicMergeAllowlistsAreDisjoint(t *testing.T) {
	c := mustTestClient(t)

	c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name:    "users",
		Columns: []string{"username", "role", "password_hash", "realm", "created_at", "updated_at", "deleted_at"},
		Rows:    [][]interface{}{{"alice", "admin", "hash", "local", "old", "new", nil}},
	}}}))
	if n := tableCount(t, c, "users"); n != 0 {
		t.Fatalf("sensitive merge mutated public users table, count=%d", n)
	}

	c.MergeStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name:    "registry_credentials",
		Columns: []string{"id", "scope", "owner", "registry", "username", "secret", "created_at", "updated_at", "deleted_at"},
		Rows:    [][]interface{}{{"rc1", "global", "", "registry.example", "robot", "secret", "old", "new", nil}},
	}}}))
	if n := tableCount(t, c, "registry_credentials"); n != 0 {
		t.Fatalf("public merge mutated sensitive registry_credentials table, count=%d", n)
	}
}

func TestSensitiveMerge_TombstoneBeatsStaleLiveRowsAndRecreateClears(t *testing.T) {
	tests := []struct {
		name       string
		table      string
		columns    []string
		tombstone  []interface{}
		staleLive  []interface{}
		newLive    []interface{}
		keyWhere   string
		keyArgs    []interface{}
		liveColumn string
		wantLive   string
	}{
		{
			name:       "registry credential",
			table:      "registry_credentials",
			columns:    []string{"id", "scope", "owner", "registry", "username", "secret", "created_at", "updated_at", "deleted_at"},
			tombstone:  []interface{}{"rc1", "global", "", "registry.example", "robot", "old-secret", "t0", "t2", "t2"},
			staleLive:  []interface{}{"rc1", "global", "", "registry.example", "robot", "stale-secret", "t0", "t1", nil},
			newLive:    []interface{}{"rc1", "global", "", "registry.example", "robot", "fresh-secret", "t0", "t3", nil},
			keyWhere:   "id = ?",
			keyArgs:    []interface{}{"rc1"},
			liveColumn: "secret",
			wantLive:   "fresh-secret",
		},
		{
			name:       "notification target",
			table:      "notification_targets",
			columns:    []string{"id", "name", "type", "config", "enabled", "created_at", "updated_at", "deleted_at"},
			tombstone:  []interface{}{"nt1", "ops", "webhook", `{"url":"old"}`, 0, "t0", "t2", "t2"},
			staleLive:  []interface{}{"nt1", "ops", "webhook", `{"url":"stale"}`, 1, "t0", "t1", nil},
			newLive:    []interface{}{"nt1", "ops", "webhook", `{"url":"fresh"}`, 1, "t0", "t3", nil},
			keyWhere:   "id = ?",
			keyArgs:    []interface{}{"nt1"},
			liveColumn: "config",
			wantLive:   `{"url":"fresh"}`,
		},
		{
			name:       "notification route",
			table:      "notification_routes",
			columns:    []string{"id", "event_pattern", "target_id", "min_severity", "enabled", "created_at", "updated_at", "deleted_at"},
			tombstone:  []interface{}{"nr1", "*", "nt1", "warn", 0, "t0", "t2", "t2"},
			staleLive:  []interface{}{"nr1", "*", "nt1", "info", 1, "t0", "t1", nil},
			newLive:    []interface{}{"nr1", "*", "nt1", "error", 1, "t0", "t3", nil},
			keyWhere:   "id = ?",
			keyArgs:    []interface{}{"nr1"},
			liveColumn: "min_severity",
			wantLive:   "error",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := mustTestClient(t)
			c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
				Name: tc.table, Columns: tc.columns, Rows: [][]interface{}{tc.tombstone},
			}}}))
			c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
				Name: tc.table, Columns: tc.columns, Rows: [][]interface{}{tc.staleLive},
			}}}))
			q := "SELECT deleted_at FROM " + tc.table + " WHERE " + tc.keyWhere
			if deletedAt := oneString(t, c, q, "deleted_at", tc.keyArgs...); deletedAt == "" {
				t.Fatalf("stale live row resurrected tombstoned %s", tc.table)
			}

			c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
				Name: tc.table, Columns: tc.columns, Rows: [][]interface{}{tc.newLive},
			}}}))
			q = "SELECT deleted_at, " + tc.liveColumn + " FROM " + tc.table + " WHERE " + tc.keyWhere
			if deletedAt := oneString(t, c, q, "deleted_at", tc.keyArgs...); deletedAt != "" {
				t.Fatalf("new live row did not clear tombstone for %s; deleted_at=%q", tc.table, deletedAt)
			}
			if got := oneString(t, c, q, tc.liveColumn, tc.keyArgs...); got != tc.wantLive {
				t.Fatalf("%s after recreate = %q, want %q", tc.liveColumn, got, tc.wantLive)
			}
		})
	}
}
