package corrosion

import (
	"context"
	"testing"
	"time"
)

func TestFenceProofGrade(t *testing.T) {
	for _, tc := range []struct {
		method, result string
		want           bool
	}{
		{"ipmi", "fenced", true},              // confirmed power-off
		{"manual", "manual-confirmed", true},  // operator confirmed
		{"ipmi", "manual-confirmed", true},    // result alone suffices for manual-confirmed
		{"ssh", "fenced", false},              // plain SSH — never confirms power-off
		{"best-effort-ssh", "fenced", false},  // lenient SSH success
		{"ipmi", "partial", false},            // IPMI failed
		{"manual", "partial", false},          // unconfirmed manual
		{"watchdog", "fenced", false},         // self-fence timer not positively verifiable
		{"best-effort-ssh", "partial", false}, // best-effort failure
	} {
		if got := FenceProofGrade(tc.method, tc.result); got != tc.want {
			t.Errorf("FenceProofGrade(%q, %q) = %v, want %v", tc.method, tc.result, got, tc.want)
		}
	}
}

func TestFenceEpochRoundTrip(t *testing.T) {
	ref := FenceEpochRef{Host: "h1", FenceID: "f-123", TS: "2026-07-12T10:00:00Z"}
	s := ref.String()
	if s == "" {
		t.Fatal("non-empty ref rendered empty")
	}
	got, ok := ParseFenceEpoch(s)
	if !ok || got != ref {
		t.Errorf("round trip: ParseFenceEpoch(%q) = %+v, %v; want %+v", s, got, ok, ref)
	}
	// No fence to bind ⇒ empty string ⇒ parses as not-ok.
	if (FenceEpochRef{Host: "h1"}).String() != "" {
		t.Error("ref with empty FenceID must render empty")
	}
	for _, bad := range []string{"", "garbage", "host=h1", "fence_id=x"} {
		if _, ok := ParseFenceEpoch(bad); ok {
			t.Errorf("ParseFenceEpoch(%q) = ok, want not-ok", bad)
		}
	}
}

func TestVMHasWritableSharedDisk(t *testing.T) {
	local := DiskRecord{StorageType: "local"}
	nfs := DiskRecord{StorageType: "nfs"}
	rbd := DiskRecord{StorageType: "RBD"} // case-insensitive
	if DiskIsShared(local) {
		t.Error("local disk must not be shared")
	}
	if !DiskIsShared(nfs) || !DiskIsShared(rbd) {
		t.Error("nfs/rbd disks must be shared")
	}
	if VMHasWritableSharedDisk([]DiskRecord{local, local}) {
		t.Error("all-local VM must not report a writable shared disk")
	}
	if !VMHasWritableSharedDisk([]DiskRecord{local, nfs}) {
		t.Error("one shared disk ⇒ VMHasWritableSharedDisk true (weakest-writable-disk)")
	}
	if VMHasWritableSharedDisk(nil) {
		t.Error("no disks ⇒ false")
	}
}

// seedFenceLog inserts a fencing_log row with an explicit timestamp (InsertFenceLog
// would stamp now(); tests need control over recency).
func seedFenceLog(t *testing.T, c *Client, id, host, method, result, ts string) {
	t.Helper()
	if err := c.Execute(context.Background(),
		`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail)
		 VALUES (?, ?, ?, ?, ?, '')`, id, host, method, result, ts); err != nil {
		t.Fatalf("seed fencing_log: %v", err)
	}
}

func TestCheckProofGradeFence(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	old := time.Now().Add(-2 * SharedDiskFenceWindow).UTC().Format(time.RFC3339)

	seedFenceLog(t, c, "ipmi-fresh", "old-owner", "ipmi", "fenced", now)
	seedFenceLog(t, c, "ssh-fresh", "old-owner", "best-effort-ssh", "fenced", now)
	seedFenceLog(t, c, "ipmi-stale", "old-owner", "ipmi", "fenced", old)
	epoch := func(id, host string) string {
		return FenceEpochRef{Host: host, FenceID: id, TS: now}.String()
	}

	cases := []struct {
		name       string
		fenceEpoch string
		oldOwner   string
		want       FenceCheck
	}{
		{"proof-grade ipmi (cross-checked owner)", epoch("ipmi-fresh", "old-owner"), "old-owner", FenceOK},
		{"proof-grade ipmi (trust-epoch, no owner)", epoch("ipmi-fresh", "old-owner"), "", FenceOK},
		{"empty fence_epoch ⇒ reject", "", "old-owner", FenceReject},
		{"best-effort ssh ⇒ reject", epoch("ssh-fresh", "old-owner"), "old-owner", FenceReject},
		{"stale ipmi ⇒ reject", epoch("ipmi-stale", "old-owner"), "old-owner", FenceReject},
		{"owner mismatch ⇒ reject", epoch("ipmi-fresh", "old-owner"), "different-owner", FenceReject},
		{"unknown fence_id ⇒ retry (not yet replicated)", epoch("no-such-id", "old-owner"), "old-owner", FenceRetry},
	}
	for _, tc := range cases {
		got, detail := CheckProofGradeFence(ctx, c, tc.fenceEpoch, tc.oldOwner, SharedDiskFenceWindow)
		if got != tc.want {
			t.Errorf("%s: got %v (%s), want %v", tc.name, got, detail, tc.want)
		}
	}
}
