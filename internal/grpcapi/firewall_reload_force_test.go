package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/emptypb"
)

// recordingReconciler distinguishes the plain tick from the forced one.
type recordingReconciler struct {
	reconcile int
	force     int
	err       error
}

func (r *recordingReconciler) Reconcile(context.Context) error {
	r.reconcile++
	return r.err
}

func (r *recordingReconciler) ReconcileForce(context.Context) error {
	r.force++
	return r.err
}

func (r *recordingReconciler) LastError() error    { return r.err }
func (r *recordingReconciler) LastTick() time.Time { return time.Time{} }

// TestReloadFirewall_ForcesThroughTheCache is the operator half of #187.
//
// ReloadFirewall called Reconcile, which goes through the Applier's
// change-detection cache — so `lv firewall reload` rendered the same bytes,
// skipped nft and reported success. The one command an operator runs when they
// believe the kernel drifted has to bypass the cache, because "the bytes I last
// sent" is not evidence about what is loaded.
func TestReloadFirewall_ForcesThroughTheCache(t *testing.T) {
	s := testServer(t)
	rec := &recordingReconciler{}
	s.SetFirewallReconciler(rec)

	if _, err := s.ReloadFirewall(adminCtx(), &emptypb.Empty{}); err != nil {
		t.Fatalf("ReloadFirewall: %v", err)
	}
	if rec.force != 1 {
		t.Errorf("ReconcileForce called %d times, want 1 — a reload that can be "+
			"short-circuited by the cache is the defect", rec.force)
	}
	if rec.reconcile != 0 {
		t.Errorf("plain Reconcile called %d times; reload must not take the cached path", rec.reconcile)
	}
}

// A failing forced reconcile still surfaces as an error.
func TestReloadFirewall_ForcedFailurePropagates(t *testing.T) {
	s := testServer(t)
	s.SetFirewallReconciler(&recordingReconciler{err: errors.New("kernel said no")})

	_, err := s.ReloadFirewall(adminCtx(), &emptypb.Empty{})
	if err == nil {
		t.Fatal("a failing reload must return an error")
	}
}
