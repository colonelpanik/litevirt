package corrosion

import (
	"context"
	"testing"
)

func TestUpsertAndGetStack(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	s := StackRecord{
		Name:        "mystack",
		ComposeHash: "abc123",
		ComposeYAML: "name: mystack\nvms: {}",
		State:       "active",
	}
	if err := UpsertStack(ctx, c, s); err != nil {
		t.Fatalf("UpsertStack: %v", err)
	}

	got, err := GetStack(ctx, c, "mystack")
	if err != nil {
		t.Fatalf("GetStack: %v", err)
	}
	if got == nil {
		t.Fatal("GetStack returned nil")
	}
	if got.Name != "mystack" || got.ComposeHash != "abc123" {
		t.Errorf("unexpected stack: %+v", got)
	}
}

func TestUpsertStack_Updates(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	s := StackRecord{Name: "s1", ComposeHash: "v1", ComposeYAML: "...", State: "active"}
	if err := UpsertStack(ctx, c, s); err != nil {
		t.Fatalf("UpsertStack v1: %v", err)
	}

	s.ComposeHash = "v2"
	s.ComposeYAML = "updated"
	if err := UpsertStack(ctx, c, s); err != nil {
		t.Fatalf("UpsertStack v2: %v", err)
	}

	got, _ := GetStack(ctx, c, "s1")
	if got.ComposeHash != "v2" || got.ComposeYAML != "updated" {
		t.Errorf("upsert did not update: %+v", got)
	}
}

func TestListStacks(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	for _, name := range []string{"alpha", "beta", "gamma"} {
		if err := UpsertStack(ctx, c, StackRecord{
			Name: name, ComposeHash: "x", ComposeYAML: "...", State: "active",
		}); err != nil {
			t.Fatalf("UpsertStack %s: %v", name, err)
		}
	}

	stacks, err := ListStacks(ctx, c)
	if err != nil {
		t.Fatalf("ListStacks: %v", err)
	}
	if len(stacks) != 3 {
		t.Errorf("expected 3 stacks, got %d", len(stacks))
	}
}

func TestDeleteStackRecord(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	if err := UpsertStack(ctx, c, StackRecord{
		Name: "gone", ComposeHash: "x", ComposeYAML: "...", State: "active",
	}); err != nil {
		t.Fatalf("UpsertStack: %v", err)
	}

	if err := DeleteStackRecord(ctx, c, "gone"); err != nil {
		t.Fatalf("DeleteStackRecord: %v", err)
	}

	got, _ := GetStack(ctx, c, "gone")
	if got != nil {
		t.Error("expected nil after delete, got stack record")
	}
}

func TestGetStack_NotFound(t *testing.T) {
	c, err := NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	ctx := context.Background()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}

	got, err := GetStack(ctx, c, "nonexistent")
	if err != nil {
		t.Fatalf("GetStack: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for missing stack, got %+v", got)
	}
}
