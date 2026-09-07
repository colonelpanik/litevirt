package corrosion

import (
	"context"
	"testing"
)

// netbox_host_config is the per-host publication the mirror's uniformity check
// compares across live hosts. These pin the two properties the comparison rests
// on: a published value round-trips, and re-publishing the same value writes
// nothing at all.

func TestPublishNetBoxHostConfigRoundTrips(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := PublishNetBoxHostConfig(ctx, c, "node-a", "cluster-one"); err != nil {
		t.Fatalf("PublishNetBoxHostConfig: %v", err)
	}
	if err := PublishNetBoxHostConfig(ctx, c, "node-b", "cluster-two"); err != nil {
		t.Fatalf("PublishNetBoxHostConfig: %v", err)
	}
	got, err := ListNetBoxHostConfig(ctx, c)
	if err != nil {
		t.Fatalf("ListNetBoxHostConfig: %v", err)
	}
	if len(got) != 2 || got["node-a"] != "cluster-one" || got["node-b"] != "cluster-two" {
		t.Fatalf("published values did not round-trip: %v", got)
	}
}

func TestPublishNetBoxHostConfigUpdatesAChangedValue(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := PublishNetBoxHostConfig(ctx, c, "node-a", "cluster-one"); err != nil {
		t.Fatalf("PublishNetBoxHostConfig: %v", err)
	}
	if err := PublishNetBoxHostConfig(ctx, c, "node-a", "cluster-two"); err != nil {
		t.Fatalf("PublishNetBoxHostConfig: %v", err)
	}
	got, err := ListNetBoxHostConfig(ctx, c)
	if err != nil {
		t.Fatalf("ListNetBoxHostConfig: %v", err)
	}
	if got["node-a"] != "cluster-two" {
		t.Fatalf("a changed config must be republished, got %q", got["node-a"])
	}
}

// TestPublishNetBoxHostConfigIsANoOpWhenUnchanged is the reason the publisher
// reads before it writes. It runs on every mirror pass — every 15 minutes on
// every node, forever — and an unconditional UPSERT would restamp updated_at
// each time, churning replication and restamping the LWW key of a row nothing
// changed. `SetHostLabel` and `reconcileHostAddress` both take this shape for
// the same reason.
func TestPublishNetBoxHostConfigIsANoOpWhenUnchanged(t *testing.T) {
	c := mustTestClient(t)
	ctx := context.Background()

	if err := PublishNetBoxHostConfig(ctx, c, "node-a", "cluster-one"); err != nil {
		t.Fatalf("PublishNetBoxHostConfig: %v", err)
	}
	rows, err := c.Query(ctx, `SELECT updated_at FROM netbox_host_config WHERE host_name = 'node-a'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read updated_at: %v (%d rows)", err, len(rows))
	}
	first := rows[0].String("updated_at")

	before := mutationLogDepth(t, c)
	if err := PublishNetBoxHostConfig(ctx, c, "node-a", "cluster-one"); err != nil {
		t.Fatalf("re-publish: %v", err)
	}
	if after := mutationLogDepth(t, c); after != before {
		t.Fatalf("re-publishing an unchanged value wrote %d replicated statement(s); it must write none",
			after-before)
	}
	rows, err = c.Query(ctx, `SELECT updated_at FROM netbox_host_config WHERE host_name = 'node-a'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("re-read updated_at: %v (%d rows)", err, len(rows))
	}
	if rows[0].String("updated_at") != first {
		t.Fatalf("updated_at was restamped on an unchanged republish: %q -> %q",
			first, rows[0].String("updated_at"))
	}
}

func mutationLogDepth(t *testing.T, c *Client) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT COUNT(*) AS n FROM mutation_log`)
	if err != nil {
		t.Fatalf("count mutation_log: %v", err)
	}
	return rows[0].Int("n")
}
