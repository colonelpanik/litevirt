package corrosion

import (
	"context"
	"slices"
	"testing"
)

// activeSetID returns the user's current active recovery-code set pointer (or "").
func activeSetID(t *testing.T, c *Client, username string) string {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT active_set_id FROM recovery_code_sets WHERE username = ? AND deleted_at IS NULL`, username)
	if err != nil {
		t.Fatalf("read active_set_id: %v", err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].String("active_set_id")
}

func has2FA(t *testing.T, c *Client, username, method string) bool {
	t.Helper()
	fs, err := ListUser2FA(context.Background(), c, username)
	if err != nil {
		t.Fatalf("ListUser2FA: %v", err)
	}
	for _, f := range fs {
		if f.Method == method {
			return true
		}
	}
	return false
}

// TestUser2FA_SoftDeleteSurvivesStaleMerge: un-enrolling a factor must survive a
// stale peer that still has it live — RED while DeleteUser2FA was a hard delete
// (the union merge re-inserted it). Re-enroll then clears the tombstone.
func TestUser2FA_SoftDeleteSurvivesStaleMerge(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "totp", Secret: "s0", Label: ""}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser2FA(ctx, c, "alice", "totp", ""); err != nil {
		t.Fatal(err)
	}

	// Stale peer re-pushes the factor LIVE (deleted_at nil) with an OLDER updated_at.
	c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name:    "user_2fa",
		Columns: []string{"username", "method", "secret", "label", "enrolled_at", "last_used_at", "updated_at", "last_step", "deleted_at"},
		Rows:    [][]interface{}{{"alice", "totp", "s0", "", "2020-01-01T00:00:00Z", nil, "2020-01-01T00:00:00Z", 0, nil}},
	}}}))

	if has2FA(t, c, "alice", "totp") {
		t.Error("soft-deleted factor resurrected by a stale peer merge")
	}

	// Re-enroll reactivates (tombstone cleared, ratchet reset).
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "totp", Secret: "s1", Label: ""}); err != nil {
		t.Fatal(err)
	}
	fs, _ := ListUser2FA(ctx, c, "alice")
	if len(fs) != 1 || fs[0].Secret != "s1" {
		t.Errorf("re-enroll did not reactivate the factor: %+v", fs)
	}
}

// TestUser2FA_UnseenPeerFactorDoesNotResurrect is the finding-1 regression: a
// soft-delete tombstone can't cover a factor a partitioned peer holds that this
// node never saw. The active-factor epoch closes it — DeleteUser tombstones the
// pointer, so a resurrected old-epoch factor never validates, and a re-enroll
// after recreate mints a fresh epoch. RED with only the deleted_at filter.
func TestUser2FA_UnseenPeerFactorDoesNotResurrect(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "totp", Secret: "s0", Label: ""}); err != nil {
		t.Fatal(err)
	}
	epoch0, _, err := activeUser2FAEpoch(ctx, c, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser(ctx, c, "alice"); err != nil {
		t.Fatal(err)
	}

	// A partitioned peer resurrects a factor this node NEVER SAW (a different
	// label, so a different PK we couldn't have tombstoned), LIVE, under the OLD
	// epoch, with a future updated_at so LWW keeps it live.
	c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name:    "user_2fa",
		Columns: []string{"username", "method", "secret", "label", "enrolled_at", "last_used_at", "updated_at", "last_step", "deleted_at", "epoch"},
		Rows:    [][]interface{}{{"alice", "totp", "ghost-secret", "ghost", "2099-01-01T00:00:00Z", nil, "2099-01-01T00:00:00Z", 0, nil, epoch0}},
	}}}))

	// No live pointer after delete → nothing validates, including the ghost.
	if fs, _ := ListUser2FA(ctx, c, "alice"); len(fs) != 0 {
		t.Errorf("2FA visible after DeleteUser despite tombstoned pointer: %+v", fs)
	}

	// Recreate + re-enroll mints a fresh epoch; the old-epoch ghost stays hidden.
	if err := InsertUser(ctx, c, "alice", "operator", "ph"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "totp", Secret: "s1", Label: ""}); err != nil {
		t.Fatal(err)
	}
	fs, _ := ListUser2FA(ctx, c, "alice")
	for _, f := range fs {
		if f.Secret == "ghost-secret" || f.Label == "ghost" {
			t.Errorf("resurrected old-epoch factor came back after delete->recreate: %+v", f)
		}
	}
	if len(fs) != 1 || fs[0].Secret != "s1" {
		t.Errorf("expected only the re-enrolled factor, got %+v", fs)
	}
}

// TestRecordTOTPStep_RatchetSingleUse: the step ratchet consumes a given step
// once. A second update at the same (or lower) step changes zero rows and
// reports false, so the verifier won't authenticate a replay that raced past the
// Go-level pre-check.
func TestRecordTOTPStep_RatchetSingleUse(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "totp", Secret: "sek", Label: ""}); err != nil {
		t.Fatal(err)
	}
	if ok, err := RecordTOTPStep(ctx, c, "alice", "totp", "", "sek", 100); err != nil || !ok {
		t.Fatalf("first ratchet: ok=%v err=%v (want true)", ok, err)
	}
	if ok, err := RecordTOTPStep(ctx, c, "alice", "totp", "", "sek", 100); err != nil || ok {
		t.Errorf("replay at same step: ok=%v err=%v (want false)", ok, err)
	}
	if ok, _ := RecordTOTPStep(ctx, c, "alice", "totp", "", "sek", 50); ok {
		t.Error("ratchet moved backward")
	}
	if ok, err := RecordTOTPStep(ctx, c, "alice", "totp", "", "sek", 101); err != nil || !ok {
		t.Errorf("forward step: ok=%v err=%v (want true)", ok, err)
	}
}

// TestRecordTOTPStep_RejectsWrongSecretAndStaleEpoch: the ratchet only fires for
// the exact verified secret and the active epoch, so a re-enroll (new secret) or
// a disable (tombstoned pointer) landing between list-and-mark can't authenticate.
func TestRecordTOTPStep_RejectsWrongSecretAndStaleEpoch(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "totp", Secret: "sek", Label: ""}); err != nil {
		t.Fatal(err)
	}
	// Wrong secret (a re-enroll changed it) → no ratchet.
	if ok, _ := RecordTOTPStep(ctx, c, "alice", "totp", "", "STALE-secret", 100); ok {
		t.Error("ratchet fired for a stale secret")
	}
	// Disable the factor (last one → pointer tombstoned); the active epoch is gone.
	if err := DeleteUser2FA(ctx, c, "alice", "totp", ""); err != nil {
		t.Fatal(err)
	}
	if ok, _ := RecordTOTPStep(ctx, c, "alice", "totp", "", "sek", 100); ok {
		t.Error("ratchet fired with no live active-set pointer")
	}
}

// TestDeleteUser2FA_LastFactorTombstonesPointer (finding 3): removing the last
// live factor tombstones the active-set pointer, so a peer's unseen factor under
// that epoch can't silently re-enable 2FA. A non-last removal leaves it live.
func TestDeleteUser2FA_LastFactorTombstonesPointer(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "totp", Secret: "s", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "webauthn", Secret: "b", Label: "key"}); err != nil {
		t.Fatal(err)
	}
	epoch, _, _ := activeUser2FAEpoch(ctx, c, "alice")

	// Remove one of two factors → pointer stays live.
	if err := DeleteUser2FA(ctx, c, "alice", "webauthn", "key"); err != nil {
		t.Fatal(err)
	}
	if _, live, _ := activeUser2FAEpoch(ctx, c, "alice"); !live {
		t.Error("pointer tombstoned while a live factor remains")
	}

	// Remove the last factor → pointer tombstoned.
	if err := DeleteUser2FA(ctx, c, "alice", "totp", "phone"); err != nil {
		t.Fatal(err)
	}
	if _, live, _ := activeUser2FAEpoch(ctx, c, "alice"); live {
		t.Error("pointer still live after the last factor was removed")
	}

	// A peer resurrects an unseen factor under the now-stale epoch → must not render.
	c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name:    "user_2fa",
		Columns: []string{"username", "method", "secret", "label", "enrolled_at", "last_used_at", "updated_at", "last_step", "deleted_at", "epoch"},
		Rows:    [][]interface{}{{"alice", "totp", "ghost", "ghost", "2099-01-01T00:00:00Z", nil, "2099-01-01T00:00:00Z", 0, nil, epoch}},
	}}}))
	if fs, _ := ListUser2FA(ctx, c, "alice"); len(fs) != 0 {
		t.Errorf("2FA re-enabled by an unseen factor after the last factor was disabled: %+v", fs)
	}
}

// TestV32Backfill_DeletedUserNotRevived (finding 2): a user deleted under a
// pre-v32 binary (no auth cascade) keeps live orphan factors/codes and no
// pointer. The migration must give them a TOMBSTONED pointer (and tombstone the
// orphans), so reactivating the username doesn't revive old auth state.
func TestV32Backfill_DeletedUserNotRevived(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// Simulate pre-v32 on-disk state via raw writes (no cascade, no pointers).
	if err := c.execLocal(ctx,
		`INSERT INTO users (username, role, password_hash, created_at, updated_at, deleted_at)
		 VALUES ('ghost', 'viewer', 'x', '2021-01-01T00:00:00Z', '2021-06-01T00:00:00Z', '2021-06-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := c.execLocal(ctx,
		`INSERT INTO user_2fa (username, method, secret, label, enrolled_at, updated_at)
		 VALUES ('ghost', 'totp', 'oldsecret', '', '2021-01-01T00:00:00Z', '2021-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := c.execLocal(ctx,
		`INSERT INTO recovery_codes (username, code_hash, created_at) VALUES ('ghost', '$2a$old', '2021-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	if err := applyV32DataFixes(ctx, c, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	// The pointer must be tombstoned (not a live '' pointer).
	if _, live, _ := activeUser2FAEpoch(ctx, c, "ghost"); live {
		t.Error("deleted user got a LIVE 2FA pointer during migration")
	}
	if fs, _ := ListUser2FA(ctx, c, "ghost"); len(fs) != 0 {
		t.Errorf("deleted user's 2FA visible after migration: %+v", fs)
	}
	if got, _ := ListUnusedRecoveryCodes(ctx, c, "ghost"); len(got) != 0 {
		t.Errorf("deleted user's recovery codes valid after migration: %v", got)
	}

	// Reactivate the username — old auth state must stay dead.
	if err := InsertUser(ctx, c, "ghost", "viewer", "newpw"); err != nil {
		t.Fatal(err)
	}
	if fs, _ := ListUser2FA(ctx, c, "ghost"); len(fs) != 0 {
		t.Errorf("reactivation revived old 2FA: %+v", fs)
	}
	if got, _ := ListUnusedRecoveryCodes(ctx, c, "ghost"); len(got) != 0 {
		t.Errorf("reactivation revived old recovery codes: %v", got)
	}
}

// TestTouchUser2FA_RejectsDisabledOrStaleEpoch: the WebAuthn confirm-and-consume
// gate. Touching a live factor succeeds; once it's disabled (and its set
// deactivated) the touch changes zero rows, so a login can be rejected instead of
// authenticating against a stale loaded credential.
func TestTouchUser2FA_RejectsDisabledOrStaleEpoch(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "webauthn", Secret: "blob", Label: "key"}); err != nil {
		t.Fatal(err)
	}
	if ok, err := TouchUser2FA(ctx, c, "alice", "webauthn", "key"); err != nil || !ok {
		t.Fatalf("touch live credential: ok=%v err=%v (want true)", ok, err)
	}
	// Disable it (last factor → pointer tombstoned too).
	if err := DeleteUser2FA(ctx, c, "alice", "webauthn", "key"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := TouchUser2FA(ctx, c, "alice", "webauthn", "key"); ok {
		t.Error("touch succeeded for a disabled credential — stale assertion would authenticate")
	}
	// A peer resurrects the credential row LIVE, but its set is no longer active.
	c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name:    "user_2fa",
		Columns: []string{"username", "method", "secret", "label", "enrolled_at", "last_used_at", "updated_at", "last_step", "deleted_at", "epoch"},
		Rows:    [][]interface{}{{"alice", "webauthn", "blob", "key", "2099-01-01T00:00:00Z", nil, "2099-01-01T00:00:00Z", 0, nil, "stale-epoch"}},
	}}}))
	if ok, _ := TouchUser2FA(ctx, c, "alice", "webauthn", "key"); ok {
		t.Error("touch succeeded for a resurrected credential under a stale epoch")
	}
}

// TestUser2FA_MultipleFactorsShareEpoch: enrolling a second factor reuses the
// live epoch (doesn't orphan the first) — both render.
func TestUser2FA_MultipleFactorsShareEpoch(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "totp", Secret: "s", Label: "phone"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "alice", Method: "webauthn", Secret: "blob", Label: "key"}); err != nil {
		t.Fatal(err)
	}
	fs, _ := ListUser2FA(ctx, c, "alice")
	if len(fs) != 2 {
		t.Errorf("expected both factors to share the active epoch and render, got %d: %+v", len(fs), fs)
	}
}

// TestUser2FA_WritePathsNeverNullLabel pins the normalization contract: no write
// path leaves a NULL label (the composite-PK NULL trap). The column stays
// physically nullable, so this guards the writers, not the storage.
func TestUser2FA_WritePathsNeverNullLabel(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "bob", Method: "totp", Secret: "x", Label: ""}); err != nil {
		t.Fatal(err)
	}
	if err := DeleteUser2FA(ctx, c, "bob", "totp", ""); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM user_2fa WHERE label IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	if n := rows[0].Int("n"); n != 0 {
		t.Errorf("a write path produced %d NULL-label row(s); writes must normalize to ''", n)
	}
}

// TestUser2FA_DataFixNormalizesNullLabel: a pre-existing NULL-label row (from an
// old binary / manual edit) is normalized to ” by the InitSchema data fix, so it
// can't sit as a distinct PK component that duplicates a factor or dodges a tombstone.
func TestUser2FA_DataFixNormalizesNullLabel(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// Insert a raw NULL-label row (bypassing the normalized write paths).
	if err := c.execLocal(ctx,
		`INSERT INTO user_2fa (username, method, secret, label, enrolled_at, updated_at)
		 VALUES ('carol', 'totp', 's', NULL, '2020-01-01T00:00:00Z', '2020-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := applyV32DataFixes(ctx, c, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM user_2fa WHERE label IS NULL`)
	if err != nil {
		t.Fatal(err)
	}
	if n := rows[0].Int("n"); n != 0 {
		t.Errorf("data fix left %d NULL-label row(s)", n)
	}
}

// TestRecoveryCodes_OldSetNotAcceptedAfterReEnroll is the recovery-code OR-set
// regression: after re-enroll moves the active-set pointer, a peer that
// resurrects an old-set code LIVE (newer updated_at, deleted_at nil) must NOT
// have it accepted — validity is gated on set_id == active_set_id, not deletion.
func TestRecoveryCodes_OldSetNotAcceptedAfterReEnroll(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertRecoveryCodes(ctx, c, "alice", []string{"$2a$hashOLD"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRecoveryCodes(ctx, c, "alice", []string{"$2a$hashNEW"}); err != nil {
		t.Fatal(err) // re-enroll: pointer → new set, old code soft-deleted
	}

	// Peer resurrects the old-set code LIVE with a FUTURE updated_at (LWW would
	// keep the row live) but carrying the SUPERSEDED set_id.
	c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name:    "recovery_codes",
		Columns: []string{"username", "code_hash", "used_at", "created_at", "set_id", "updated_at", "deleted_at"},
		Rows:    [][]interface{}{{"alice", "$2a$hashOLD", nil, "2020-01-01T00:00:00Z", "superseded-set-id", "2099-01-01T00:00:00Z", nil}},
	}}}))

	got, err := ListUnusedRecoveryCodes(ctx, c, "alice")
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"$2a$hashNEW"}) {
		t.Errorf("verifier accepted an old-set code: got %v, want [$2a$hashNEW]", got)
	}
}

// TestRecoveryCodes_UsedBeatsUnusedLWW: marking a code used wins over a peer's
// stale "unused" copy of the SAME code (same active set) via updated_at LWW.
func TestRecoveryCodes_UsedBeatsUnusedLWW(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertRecoveryCodes(ctx, c, "alice", []string{"$2a$hashA"}); err != nil {
		t.Fatal(err)
	}
	setID := activeSetID(t, c, "alice")
	if consumed, err := MarkRecoveryCodeUsed(ctx, c, "alice", "$2a$hashA"); err != nil || !consumed {
		t.Fatalf("MarkRecoveryCodeUsed: consumed=%v err=%v (want consumed)", consumed, err)
	}

	// Peer pushes the SAME code (current set) UNUSED with an OLDER updated_at.
	c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name:    "recovery_codes",
		Columns: []string{"username", "code_hash", "used_at", "created_at", "set_id", "updated_at", "deleted_at"},
		Rows:    [][]interface{}{{"alice", "$2a$hashA", nil, "2020-01-01T00:00:00Z", setID, "2020-01-01T00:00:00Z", nil}},
	}}}))

	got, _ := ListUnusedRecoveryCodes(ctx, c, "alice")
	if slices.Contains(got, "$2a$hashA") {
		t.Errorf("a used code reverted to unused via a stale peer merge: %v", got)
	}
}

// TestRecoveryCodes_ConsumeIsSingleUse: consuming a code reports true exactly
// once; a second consume of the same code reports false — the caller must not
// authenticate a double-spend even if both racers listed it unused.
func TestRecoveryCodes_ConsumeIsSingleUse(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertRecoveryCodes(ctx, c, "alice", []string{"$2a$hashA"}); err != nil {
		t.Fatal(err)
	}
	if consumed, err := MarkRecoveryCodeUsed(ctx, c, "alice", "$2a$hashA"); err != nil || !consumed {
		t.Fatalf("first consume: consumed=%v err=%v (want true)", consumed, err)
	}
	consumed, err := MarkRecoveryCodeUsed(ctx, c, "alice", "$2a$hashA")
	if err != nil {
		t.Fatal(err)
	}
	if consumed {
		t.Error("a used code was consumed a second time — single-use violated")
	}
}

// TestRecoveryCodes_ConsumeFailsAfterReEnroll: a re-enroll landing between
// list-and-mark invalidates the old set, so consuming an old-set code reports
// false (zero rows) — the verifier must then NOT authenticate. This is the gap
// the active-set WHERE + RowsAffected check closes.
func TestRecoveryCodes_ConsumeFailsAfterReEnroll(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertRecoveryCodes(ctx, c, "alice", []string{"$2a$hashOLD"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRecoveryCodes(ctx, c, "alice", []string{"$2a$hashNEW"}); err != nil {
		t.Fatal(err) // re-enroll: old set superseded
	}
	consumed, err := MarkRecoveryCodeUsed(ctx, c, "alice", "$2a$hashOLD")
	if err != nil {
		t.Fatal(err)
	}
	if consumed {
		t.Error("a superseded old-set code was consumable after re-enroll")
	}
}

// TestRecoveryCodes_OldDumpMissingColumnsNotAccepted (mixed-version): an old
// (pre-v32) peer dumps recovery_codes WITHOUT set_id/updated_at/deleted_at,
// carrying a code LIVE. It lands with set_id=” (default); against a user whose
// active set is a real (non-”) id, it does not validate.
func TestRecoveryCodes_OldDumpMissingColumnsNotAccepted(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertRecoveryCodes(ctx, c, "alice", []string{"$2a$hashCurrent"}); err != nil {
		t.Fatal(err)
	}

	// OLD-shape dump: only the pre-v32 columns, a LIVE code.
	c.MergeSensitiveStateBytesLWW(encodeSyncPayload(t, &syncPayload{Tables: []syncTable{{
		Name:    "recovery_codes",
		Columns: []string{"username", "code_hash", "used_at", "created_at"},
		Rows:    [][]interface{}{{"alice", "$2a$hashLegacy", nil, "2020-01-01T00:00:00Z"}},
	}}}))

	got, _ := ListUnusedRecoveryCodes(ctx, c, "alice")
	if slices.Contains(got, "$2a$hashLegacy") {
		t.Errorf("old-shape ('' set_id) code accepted under a real active set: %v", got)
	}
}

// TestDeleteUser_CascadesAndNoResurrect: deleting a user tombstones its 2FA +
// recovery codes + set pointer, and recreating the user does not resurrect them.
func TestDeleteUser_CascadesAndNoResurrect(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := InsertUser(ctx, c, "dave", "operator", "ph"); err != nil {
		t.Fatal(err)
	}
	if err := InsertUser2FA(ctx, c, User2FARecord{Username: "dave", Method: "totp", Secret: "s", Label: ""}); err != nil {
		t.Fatal(err)
	}
	if err := InsertRecoveryCodes(ctx, c, "dave", []string{"$2a$hashD"}); err != nil {
		t.Fatal(err)
	}

	if err := DeleteUser(ctx, c, "dave"); err != nil {
		t.Fatal(err)
	}
	if has2FA(t, c, "dave", "totp") {
		t.Error("2FA factor survived DeleteUser")
	}
	if got, _ := ListUnusedRecoveryCodes(ctx, c, "dave"); len(got) != 0 {
		t.Errorf("recovery codes survived DeleteUser: %v", got)
	}

	// Recreate: no stale factor/codes come back.
	if err := InsertUser(ctx, c, "dave", "operator", "ph2"); err != nil {
		t.Fatal(err)
	}
	if has2FA(t, c, "dave", "totp") {
		t.Error("2FA factor resurrected after delete→recreate")
	}
	if got, _ := ListUnusedRecoveryCodes(ctx, c, "dave"); len(got) != 0 {
		t.Errorf("recovery codes resurrected after delete→recreate: %v", got)
	}
}

// TestRecoveryCodes_LegacyBackfillStillValidates: a pre-v32 DB has recovery_codes
// with set_id=” and NO pointer row. The InitSchema backfill gives them an
// active_set_id=” pointer so they keep validating; a later re-enroll supersedes
// them; re-running the backfill is a no-op for the re-enrolled user.
func TestRecoveryCodes_LegacyBackfillStillValidates(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	// Simulate a pre-v32 row: legacy shape (set_id/updated_at default to '', no pointer).
	if err := c.execLocal(ctx,
		`INSERT INTO recovery_codes (username, code_hash, created_at) VALUES ('erin', '$2a$legacy', '2021-06-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	// Before the backfill there is no pointer, so the code can't validate yet.
	if got, _ := ListUnusedRecoveryCodes(ctx, c, "erin"); len(got) != 0 {
		t.Fatalf("precondition: expected no valid codes before backfill, got %v", got)
	}

	if err := applyV32DataFixes(ctx, c, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if got, _ := ListUnusedRecoveryCodes(ctx, c, "erin"); !slices.Equal(got, []string{"$2a$legacy"}) {
		t.Errorf("legacy code did not validate after backfill: %v", got)
	}

	// Re-enroll supersedes the legacy set.
	if err := InsertRecoveryCodes(ctx, c, "erin", []string{"$2a$fresh"}); err != nil {
		t.Fatal(err)
	}
	// Re-running the backfill must NOT reset the re-enrolled user's pointer.
	if err := applyV32DataFixes(ctx, c, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	got, _ := ListUnusedRecoveryCodes(ctx, c, "erin")
	if !slices.Equal(got, []string{"$2a$fresh"}) {
		t.Errorf("re-enrolled set not active after backfill re-run: %v", got)
	}
}
