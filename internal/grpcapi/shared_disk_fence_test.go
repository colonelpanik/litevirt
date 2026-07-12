package grpcapi

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestRequireProofGradeFence maps the shared corrosion.CheckProofGradeFence
// tri-state to the executor's gRPC contract: a proof-grade fence ⇒ nil; a
// not-yet-replicated fencing_log row ⇒ RETRYABLE Unavailable (never terminal); an
// empty/best-effort/stale binding ⇒ FailedPrecondition (storage_unverified).
func TestRequireProofGradeFence(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	now := time.Now().UTC().Format(time.RFC3339)
	seed := func(id, method, result string) {
		if err := s.db.Execute(ctx,
			`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail)
			 VALUES (?, 'old-owner', ?, ?, ?, '')`, id, method, result, now); err != nil {
			t.Fatalf("seed fencing_log: %v", err)
		}
	}
	seed("ipmi1", "ipmi", "fenced")
	seed("ssh1", "best-effort-ssh", "fenced")
	epoch := func(id string) string {
		return corrosion.FenceEpochRef{Host: "old-owner", FenceID: id, TS: now}.String()
	}

	for _, tc := range []struct {
		name       string
		fenceEpoch string
		wantCode   codes.Code
	}{
		{"proof-grade ipmi", epoch("ipmi1"), codes.OK},
		{"empty fence_epoch (mixed-version / no fence)", "", codes.FailedPrecondition},
		{"best-effort ssh", epoch("ssh1"), codes.FailedPrecondition},
		{"unknown fence_id not yet replicated", epoch("missing"), codes.Unavailable},
	} {
		err := s.requireProofGradeFence(ctx, tc.fenceEpoch, "old-owner")
		if status.Code(err) != tc.wantCode {
			t.Errorf("%s: code = %v (%v), want %v", tc.name, status.Code(err), err, tc.wantCode)
		}
	}
}
