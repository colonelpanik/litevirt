package corrosion

import (
	"context"
	"testing"
)

// TestRelocateContainer_RefusesClobber proves RelocateContainer fails (without
// deleting the source) when the target already holds a live same-name container.
func TestRelocateContainer_RefusesClobber(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)

	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "src", Name: "web", State: "running", Image: "a:1"}); err != nil {
		t.Fatal(err)
	}
	if err := UpsertContainer(ctx, c, ContainerRecord{HostName: "dst", Name: "web", State: "running", Image: "b:1"}); err != nil {
		t.Fatal(err)
	}

	if err := RelocateContainer(ctx, c, "src", "web", "dst"); err == nil {
		t.Fatal("RelocateContainer must refuse to clobber an existing target container")
	}
	// Source must NOT have been deleted, and the target's unrelated container intact.
	if srcRow, _ := GetContainer(ctx, c, "src", "web"); srcRow == nil {
		t.Fatal("source must be preserved when relocation is refused")
	}
	if dstRow, _ := GetContainer(ctx, c, "dst", "web"); dstRow == nil || dstRow.Image != "b:1" {
		t.Fatalf("target container must be untouched, got %+v", dstRow)
	}
}
