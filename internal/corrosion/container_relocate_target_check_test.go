package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// swapRelocateTargetLookup replaces the read RelocateContainerWithToken makes
// of the target host before it writes, for the length of one test.
func swapRelocateTargetLookup(t *testing.T, fn func(context.Context, *Client, string, string) (*ContainerRecord, error)) {
	t.Helper()
	prev := relocateTargetLookup
	relocateTargetLookup = fn
	t.Cleanup(func() { relocateTargetLookup = prev })
}

// A target check that could not run is not a target that is free (#215).
//
// The check used to be `existing, _ := GetContainer(...)`: a failed read came
// back as (nil, err), the nil read as "no live container there", and the
// relocation went ahead to write the target row with INSERT OR REPLACE — over
// whatever live same-name container the read failed to see.
//
// Mutation: discard the error again (`existing, _ :=`) — the relocation
// succeeds, the source is tombstoned, and the first assertion goes red.
func TestRelocateContainerWithToken_AFailedTargetCheckRefuses(t *testing.T) {
	for _, lifecycle := range []bool{false, true} {
		name := "pre-epoch"
		if lifecycle {
			name = "guarded"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := newTestDB(t)
			seedRelocatableContainer(t, c, "host-a", "web", lifecycle)

			injected := errors.New("injected target read failure")
			swapRelocateTargetLookup(t, func(ctx context.Context, c *Client, host, name string) (*ContainerRecord, error) {
				if host == "host-b" {
					return nil, injected
				}
				return GetContainer(ctx, c, host, name)
			})

			err := RelocateContainerWithToken(ctx, c, "host-a", "web", "host-b", "tok-1")
			if err == nil {
				t.Fatal("the relocation went ahead although it could not tell whether the target " +
					"already holds a live container of the same name")
			}
			if !errors.Is(err, injected) {
				t.Errorf("err = %v, want it to wrap the read failure", err)
			}
			if src, gErr := GetContainer(ctx, c, "host-a", "web"); gErr != nil || src == nil {
				t.Fatalf("source must still be live after a refused relocation: rec=%v err=%v", src, gErr)
			}
		})
	}
}

// The target check also has to hold at the moment of the write, not only at
// the read before it. A same-name container that lands on the target between
// the two (replication, a concurrent create) was clobbered by the INSERT OR
// REPLACE just as surely as one the read failed to see.
//
// The test makes the pre-write read stale on purpose — it reports the target
// free while a live container sits there — which is the state that race leaves.
//
// Mutation: drop the target count from the guard closure — the relocation
// applies, the target's image becomes the source's, and the test goes red.
func TestRelocateContainerWithToken_ATargetThatAppearedAfterTheCheckIsNotClobbered(t *testing.T) {
	for _, lifecycle := range []bool{false, true} {
		name := "pre-epoch"
		if lifecycle {
			name = "guarded"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c := newTestDB(t)
			seedRelocatableContainer(t, c, "host-a", "web", lifecycle)
			if err := UpsertContainer(ctx, c, ContainerRecord{
				HostName: "host-b", Name: "web", State: "running", Image: "nginx",
				CPULimit: 1, MemMiB: 128, Project: "_default",
			}); err != nil {
				t.Fatalf("seed target: %v", err)
			}
			swapRelocateTargetLookup(t, func(ctx context.Context, c *Client, host, name string) (*ContainerRecord, error) {
				if host == "host-b" {
					return nil, nil // stale: the target's container arrived after this read
				}
				return GetContainer(ctx, c, host, name)
			})

			err := RelocateContainerWithToken(ctx, c, "host-a", "web", "host-b", "tok-1")
			if err == nil {
				t.Fatal("the relocation clobbered a live same-name container on the target")
			}
			if !strings.Contains(err.Error(), "refusing to clobber") {
				t.Errorf("err = %v, want the refuse-to-clobber error", err)
			}
			dst, gErr := GetContainer(ctx, c, "host-b", "web")
			if gErr != nil || dst == nil {
				t.Fatalf("target container must still be live: rec=%v err=%v", dst, gErr)
			}
			if dst.Image != "nginx" || dst.State != "running" {
				t.Errorf("target container was overwritten: image=%q state=%q, want nginx/running",
					dst.Image, dst.State)
			}
			if src, gErr := GetContainer(ctx, c, "host-a", "web"); gErr != nil || src == nil {
				t.Fatalf("source must still be live after a refused relocation: rec=%v err=%v", src, gErr)
			}
		})
	}
}
