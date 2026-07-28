package corrosion

import "testing"

// TestUnresolvedTieTables: the per-table breakdown splits the table\x00pk keys correctly so a
// divergence report can attribute a mismatched table to deliberate safety-fault ties.
func TestUnresolvedTieTables(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	defer c.Close()

	c.tieMu.Lock()
	c.unresolvedTies = map[string]string{
		unresolvedKey("vms", "a"):      "h1",
		unresolvedKey("vms", "b"):      "h2",
		unresolvedKey("vm_locks", "c"): "h3",
	}
	c.tieMu.Unlock()

	got := c.UnresolvedTieTables()
	if got["vms"] != 2 {
		t.Errorf("vms ties = %d, want 2", got["vms"])
	}
	if got["vm_locks"] != 1 {
		t.Errorf("vm_locks ties = %d, want 1", got["vm_locks"])
	}
	if len(got) != 2 {
		t.Errorf("distinct tables = %d, want 2 (%v)", len(got), got)
	}
}
