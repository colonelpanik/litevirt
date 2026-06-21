package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func testStartDB(t *testing.T) *corrosion.Client {
	t.Helper()
	c, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	if err := corrosion.InitSchema(context.Background(), c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return c
}

func TestVMChecker_Start_CancelledContext(t *testing.T) {
	db := testStartDB(t)
	v := NewVMChecker("node1", db, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		v.Start(ctx)
		close(done)
	}()

	// Cancel immediately.
	cancel()

	select {
	case <-done:
		// Start returned — good.
	case <-time.After(2 * time.Second):
		t.Fatal("VMChecker.Start did not return after context cancelled")
	}
}

func TestReconciler_Start_CancelledContext(t *testing.T) {
	db := testStartDB(t)
	r := NewReconciler("host-a", "/var/lib/litevirt", db, nil)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		r.Start(ctx)
		close(done)
	}()

	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Reconciler.Start did not return after context cancelled")
	}
}
