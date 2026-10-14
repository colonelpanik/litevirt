package corrosion

import (
	"testing"
	"time"
)

// The ceiling is compared as a STRING, and the two sides are not the same
// format. A generated stamp is fixed-width nowTSLayout, while the ceiling read
// back from audit_log may be a legacy RFC3339Nano value with trailing zeros
// trimmed. When the new stamp extends the stored one as a prefix, '.' (0x2E)
// sorts before 'Z' (0x5A) — so a strictly LATER instant compares as smaller, the
// ceiling never rises past that row, and stampAfter then keeps handing out
// prev+1ns from the same unchanged ceiling. Every row written while the clock is
// behind gets an identical timestamp, which is the strict ordering the clamp was
// added to preserve.
func TestRaisesStampCeiling_ComparesInstantsNotStrings(t *testing.T) {
	cases := []struct {
		name    string
		stamp   string
		ceiling string
		want    bool
	}{
		{
			name:    "fixed-width nanosecond after a bare legacy second",
			stamp:   "2026-09-21T10:00:00.000000001Z",
			ceiling: "2026-09-21T10:00:00Z",
			want:    true,
		},
		{
			name:    "same instant, different spelling, does not raise",
			stamp:   "2026-09-21T10:00:00.000000000Z",
			ceiling: "2026-09-21T10:00:00Z",
			want:    false,
		},
		{
			name:    "genuinely earlier does not raise",
			stamp:   "2026-09-21T09:59:59.000000000Z",
			ceiling: "2026-09-21T10:00:00Z",
			want:    false,
		},
		{
			name:    "an empty ceiling is always raised",
			stamp:   "2026-09-21T10:00:00.000000000Z",
			ceiling: "",
			want:    true,
		},
		{
			name:    "plainly later in both formats",
			stamp:   "2026-09-21T11:00:00.000000000Z",
			ceiling: "2026-09-21T10:00:00.000000000Z",
			want:    true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := raisesStampCeiling(tc.stamp, tc.ceiling); got != tc.want {
				t.Errorf("raisesStampCeiling(%q, %q) = %v, want %v", tc.stamp, tc.ceiling, got, tc.want)
			}
		})
	}
}

// TestAuditChain_ALegacyTailStillLetsTheCeilingRise drives the same bug through
// InsertAuditLog, so the call site is pinned and not only the helper. After a
// restart the ceiling is read back verbatim from a legacy row with a trimmed
// stamp. With the clock behind it, the first generated row is the ceiling plus
// one nanosecond, which extends the stored stamp as a prefix. If that row does
// not raise the ceiling, the next row gets the identical stamp.
func TestAuditChain_ALegacyTailStillLetsTheCeilingRise(t *testing.T) {
	c := newAuditTestClient(t)

	ins(t, c, "legacy", "node-0", "2026-01-01T00:00:01Z")
	c.ResetAuditChainForTests()

	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c.nowFn = func() time.Time { return at }
	insNow(t, c, "behind-1", "node-0")
	insNow(t, c, "behind-2", "node-0")

	first, second := stampOf(t, c, "behind-1"), stampOf(t, c, "behind-2")
	if !second.After(first) {
		t.Errorf("behind-2 stamped %s, not after behind-1's %s: the ceiling did not rise past "+
			"a stamp that extends the legacy one as a prefix",
			second.Format(time.RFC3339Nano), first.Format(time.RFC3339Nano))
	}
}
