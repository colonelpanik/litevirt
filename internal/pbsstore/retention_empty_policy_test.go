package pbsstore

import "testing"

// An all-zero RetentionPolicy asked to keep nothing, and keepInBucket obliged:
// every manifest in the repo was planned for deletion.
//
// The blank web form at handle_repo_ops.go submits exactly that, and
// `lv backup repo prune <path> --apply` with no --keep flags does too. Only
// the scheduled path checked before calling; the CLI and the UI went straight
// to PlanPrune. That check is now this same predicate rather than a second copy
// of it on the schedule row. Chunks survive to the next GC so there is
// a recovery window, but the manifests are gone immediately — and a manifest is
// what makes a pile of chunks restorable.
//
// A prune that would delete everything is a mistake, not a policy.
func TestPlanPrune_RefusesAPolicyThatKeepsNothing(t *testing.T) {
	r := newTestRepo(t)
	for _, ts := range []string{
		"2026-05-09T01:00:00Z",
		"2026-05-09T02:00:00Z",
		"2026-05-10T01:00:00Z",
	} {
		if err := r.PutManifest(&Manifest{VMName: "vm", DiskName: "root", Timestamp: ts}); err != nil {
			t.Fatalf("PutManifest: %v", err)
		}
	}

	plan, err := PlanPrune(r, RetentionPolicy{})
	if err == nil {
		t.Fatalf("an empty policy planned %d deletions and %d keeps instead of "+
			"refusing; a blank prune form wipes the repo", len(plan.Delete), len(plan.Keep))
	}
	if len(plan.Delete) != 0 {
		t.Errorf("the refused plan still carries %d deletions", len(plan.Delete))
	}
}

// A policy that sets ONE bucket is a real policy, and the buckets it did not
// set keep nothing of their own — that is the Proxmox-style semantic the
// planner implements and the cascade depends on. Pinned here because the
// doc comment used to claim the opposite ("Zero means unlimited"), and reading
// it as unlimited would make --keep-yearly retain every daily forever.
func TestPlanPrune_AnUnsetBucketIsNotUnlimited(t *testing.T) {
	r := newTestRepo(t)
	for _, ts := range []string{
		"2024-05-09T01:00:00Z",
		"2025-05-09T01:00:00Z",
		"2026-05-09T01:00:00Z",
	} {
		if err := r.PutManifest(&Manifest{VMName: "vm", DiskName: "root", Timestamp: ts}); err != nil {
			t.Fatalf("PutManifest: %v", err)
		}
	}

	plan, err := PlanPrune(r, RetentionPolicy{KeepYearly: 2})
	if err != nil {
		t.Fatalf("PlanPrune: %v", err)
	}
	if len(plan.Keep) != 2 || len(plan.Delete) != 1 {
		t.Errorf("Keep=%d Delete=%d, want 2/1 — KeepYearly:2 keeps two years and "+
			"the unset buckets keep nothing extra", len(plan.Keep), len(plan.Delete))
	}
}
