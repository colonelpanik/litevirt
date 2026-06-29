package corrosion

import (
	"context"
	"testing"
)

func TestUpsertNetwork_Insert(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	r := NetworkRecord{
		Name:      "prod-net",
		StackName: "mystack",
		Type:      "bridge",
		Config:    `{"cidr":"10.0.0.0/24"}`,
	}
	if err := UpsertNetwork(ctx, c, r); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}

	got, err := GetNetwork(ctx, c, "prod-net")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if got == nil {
		t.Fatal("GetNetwork returned nil")
	}
	if got.Name != "prod-net" {
		t.Errorf("Name = %q, want prod-net", got.Name)
	}
	if got.StackName != "mystack" {
		t.Errorf("StackName = %q, want mystack", got.StackName)
	}
	if got.Type != "bridge" {
		t.Errorf("Type = %q, want bridge", got.Type)
	}
	if got.Config != `{"cidr":"10.0.0.0/24"}` {
		t.Errorf("Config = %q", got.Config)
	}
	if got.CreatedAt == "" {
		t.Error("CreatedAt should be set")
	}
	if got.UpdatedAt == "" {
		t.Error("UpdatedAt should be set")
	}
}

func TestUpsertNetwork_Update(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	r := NetworkRecord{
		Name:      "prod-net",
		StackName: "mystack",
		Type:      "bridge",
		Config:    `{"cidr":"10.0.0.0/24"}`,
	}
	if err := UpsertNetwork(ctx, c, r); err != nil {
		t.Fatalf("UpsertNetwork insert: %v", err)
	}

	// Update config and type
	r.Type = "overlay"
	r.Config = `{"cidr":"10.0.1.0/24","vni":100}`
	r.StackName = "otherstack"
	if err := UpsertNetwork(ctx, c, r); err != nil {
		t.Fatalf("UpsertNetwork update: %v", err)
	}

	got, err := GetNetwork(ctx, c, "prod-net")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if got.Type != "overlay" {
		t.Errorf("Type = %q after update, want overlay", got.Type)
	}
	if got.Config != `{"cidr":"10.0.1.0/24","vni":100}` {
		t.Errorf("Config = %q after update", got.Config)
	}
	if got.StackName != "otherstack" {
		t.Errorf("StackName = %q after update, want otherstack", got.StackName)
	}
}

func TestUpsertNetwork_RevivedAfterDelete(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	r := NetworkRecord{Name: "revive-net", Type: "bridge", Config: "{}"}
	if err := UpsertNetwork(ctx, c, r); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}
	if err := DeleteNetwork(ctx, c, "revive-net"); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}

	// Re-upsert should clear deleted_at
	r.Config = `{"new":true}`
	if err := UpsertNetwork(ctx, c, r); err != nil {
		t.Fatalf("UpsertNetwork re-insert: %v", err)
	}

	got, err := GetNetwork(ctx, c, "revive-net")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if got == nil {
		t.Fatal("expected network to be revived after re-upsert, got nil")
	}
	if got.Config != `{"new":true}` {
		t.Errorf("Config = %q, want {\"new\":true}", got.Config)
	}
}

func TestListNetworks(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	nets := []NetworkRecord{
		{Name: "net-a", Type: "bridge", Config: "{}"},
		{Name: "net-b", Type: "overlay", Config: "{}"},
		{Name: "net-c", Type: "bridge", Config: "{}"},
	}
	for _, n := range nets {
		if err := UpsertNetwork(ctx, c, n); err != nil {
			t.Fatalf("UpsertNetwork %s: %v", n.Name, err)
		}
	}

	list, err := ListNetworks(ctx, c)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 networks, got %d", len(list))
	}
}

func TestListNetworks_FilterByType(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	nets := []NetworkRecord{
		{Name: "br-1", Type: "bridge", Config: "{}"},
		{Name: "br-2", Type: "bridge", Config: "{}"},
		{Name: "ol-1", Type: "overlay", Config: "{}"},
	}
	for _, n := range nets {
		if err := UpsertNetwork(ctx, c, n); err != nil {
			t.Fatalf("UpsertNetwork %s: %v", n.Name, err)
		}
	}

	list, err := ListNetworks(ctx, c)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}

	// Client-side filter by type
	var bridges int
	for _, n := range list {
		if n.Type == "bridge" {
			bridges++
		}
	}
	if bridges != 2 {
		t.Errorf("expected 2 bridge networks, got %d", bridges)
	}
}

func TestListNetworks_Empty(t *testing.T) {
	c := testClient(t)

	list, err := ListNetworks(context.Background(), c)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 networks, got %d", len(list))
	}
}

func TestGetNetwork_Exists(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := UpsertNetwork(ctx, c, NetworkRecord{
		Name: "my-net", Type: "bridge", Config: `{"cidr":"10.0.0.0/24"}`,
	}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}

	got, err := GetNetwork(ctx, c, "my-net")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil network")
	}
	if got.Name != "my-net" {
		t.Errorf("Name = %q, want my-net", got.Name)
	}
}

func TestGetNetwork_NotFound(t *testing.T) {
	c := testClient(t)

	got, err := GetNetwork(context.Background(), c, "nonexistent")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for missing network, got %+v", got)
	}
}

func TestDeleteNetwork_SoftDelete(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := UpsertNetwork(ctx, c, NetworkRecord{
		Name: "doomed", Type: "bridge", Config: "{}",
	}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}

	if err := DeleteNetwork(ctx, c, "doomed"); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}

	// Should not appear in GetNetwork
	got, err := GetNetwork(ctx, c, "doomed")
	if err != nil {
		t.Fatalf("GetNetwork: %v", err)
	}
	if got != nil {
		t.Error("expected nil after soft delete")
	}

	// Should not appear in ListNetworks
	list, err := ListNetworks(ctx, c)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(list) != 0 {
		t.Errorf("expected 0 networks after delete, got %d", len(list))
	}
}

func TestDeleteNetwork_PreservesOthers(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := UpsertNetwork(ctx, c, NetworkRecord{Name: "keep", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}
	if err := UpsertNetwork(ctx, c, NetworkRecord{Name: "remove", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}

	if err := DeleteNetwork(ctx, c, "remove"); err != nil {
		t.Fatalf("DeleteNetwork: %v", err)
	}

	list, err := ListNetworks(ctx, c)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 network, got %d", len(list))
	}
	if list[0].Name != "keep" {
		t.Errorf("remaining network = %q, want keep", list[0].Name)
	}
}

func TestCountVMsOnNetwork_NoVMs(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := UpsertNetwork(ctx, c, NetworkRecord{Name: "empty-net", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}

	count, err := CountVMsOnNetwork(ctx, c, "empty-net")
	if err != nil {
		t.Fatalf("CountVMsOnNetwork: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 VMs, got %d", count)
	}
}

func TestCountVMsOnNetwork_WithVMs(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := UpsertNetwork(ctx, c, NetworkRecord{Name: "busy-net", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatalf("UpsertNetwork: %v", err)
	}

	// Insert vm_interfaces directly
	now := "2024-01-01T00:00:00Z"
	for _, vm := range []string{"vm-1", "vm-2", "vm-3"} {
		err := c.Execute(ctx,
			`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at)
			 VALUES (?, ?, 0, ?, ?)`, vm, "busy-net", "aa:bb:cc:dd:ee:ff", now)
		if err != nil {
			t.Fatalf("insert vm_interface %s: %v", vm, err)
		}
	}

	count, err := CountVMsOnNetwork(ctx, c, "busy-net")
	if err != nil {
		t.Fatalf("CountVMsOnNetwork: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 VMs, got %d", count)
	}
}

func TestCountVMsOnNetwork_ExcludesDeleted(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	now := "2024-01-01T00:00:00Z"

	// Active interface
	c.Execute(ctx,
		`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at)
		 VALUES (?, ?, 0, ?, ?)`, "vm-active", "test-net", "aa:bb:cc:dd:ee:01", now)

	// Soft-deleted interface
	c.Execute(ctx,
		`INSERT INTO vm_interfaces (vm_name, network_name, ordinal, mac, updated_at, deleted_at)
		 VALUES (?, ?, 0, ?, ?, ?)`, "vm-deleted", "test-net", "aa:bb:cc:dd:ee:02", now, now)

	count, err := CountVMsOnNetwork(ctx, c, "test-net")
	if err != nil {
		t.Fatalf("CountVMsOnNetwork: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 VM (excluding deleted), got %d", count)
	}
}

func TestCountVMsOnNetwork_NonexistentNetwork(t *testing.T) {
	c := testClient(t)

	count, err := CountVMsOnNetwork(context.Background(), c, "no-such-net")
	if err != nil {
		t.Fatalf("CountVMsOnNetwork: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0, got %d", count)
	}
}

func TestMigrateLegacyNetworkNames(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Insert a legacy unscoped network owned by a stack.
	err := UpsertNetwork(ctx, c, NetworkRecord{
		Name:      "LAN",
		StackName: "mystack",
		Type:      "bridge",
		Config:    `{"interface":"LAN"}`,
	})
	if err != nil {
		t.Fatalf("insert legacy network: %v", err)
	}

	// Insert an already-scoped network (should be skipped).
	err = UpsertNetwork(ctx, c, NetworkRecord{
		Name:      "other_mgmt",
		StackName: "other",
		Type:      "bridge",
		Config:    `{"interface":"mgmt"}`,
	})
	if err != nil {
		t.Fatalf("insert scoped network: %v", err)
	}

	// Insert a standalone network with no stack (should warn, not migrate).
	err = UpsertNetwork(ctx, c, NetworkRecord{
		Name:      "standalone",
		StackName: "",
		Type:      "bridge",
		Config:    `{}`,
	})
	if err != nil {
		t.Fatalf("insert standalone network: %v", err)
	}

	// Run migration.
	if err := MigrateLegacyNetworkNames(ctx, c); err != nil {
		t.Fatalf("MigrateLegacyNetworkNames: %v", err)
	}

	// Legacy network should now be scoped.
	got, err := GetNetwork(ctx, c, "mystack_LAN")
	if err != nil {
		t.Fatalf("GetNetwork scoped: %v", err)
	}
	if got == nil {
		t.Fatal("expected mystack_LAN to exist after migration")
	}
	if got.StackName != "mystack" {
		t.Errorf("StackName = %q, want mystack", got.StackName)
	}

	// Old name should no longer exist.
	old, _ := GetNetwork(ctx, c, "LAN")
	if old != nil {
		t.Error("old name LAN should not exist after migration")
	}

	// Already-scoped should be unchanged.
	scoped, _ := GetNetwork(ctx, c, "other_mgmt")
	if scoped == nil {
		t.Fatal("other_mgmt should still exist")
	}

	// Standalone should be unchanged.
	sa, _ := GetNetwork(ctx, c, "standalone")
	if sa == nil {
		t.Fatal("standalone should still exist")
	}

	// Running migration again should be idempotent.
	if err := MigrateLegacyNetworkNames(ctx, c); err != nil {
		t.Fatalf("second MigrateLegacyNetworkNames: %v", err)
	}
	got2, _ := GetNetwork(ctx, c, "mystack_LAN")
	if got2 == nil {
		t.Fatal("mystack_LAN should still exist after second migration")
	}
}

func TestScopeSpecNetworkNames(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		stackName string
		want      string
		changed   bool
	}{
		{
			name:      "basic scoping",
			input:     `{"network":[{"name":"LAN","model":"virtio"}]}`,
			stackName: "mystack",
			want:      `{"network":[{"name":"mystack_LAN","model":"virtio"}]}`,
			changed:   true,
		},
		{
			name:      "already scoped",
			input:     `{"network":[{"name":"mystack_LAN","model":"virtio"}]}`,
			stackName: "mystack",
			want:      `{"network":[{"name":"mystack_LAN","model":"virtio"}]}`,
			changed:   false,
		},
		{
			name:      "no network field",
			input:     `{"cpu":2,"memory":1024}`,
			stackName: "mystack",
			want:      `{"cpu":2,"memory":1024}`,
			changed:   false,
		},
		{
			name:      "multiple networks",
			input:     `{"network":[{"name":"mgmt"},{"name":"data"}]}`,
			stackName: "s1",
			want:      `{"network":[{"name":"s1_mgmt"},{"name":"s1_data"}]}`,
			changed:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, changed := scopeSpecNetworkNames(tt.input, tt.stackName)
			if changed != tt.changed {
				t.Errorf("changed = %v, want %v", changed, tt.changed)
			}
			if got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// TestNetworkProjectRoundTrip: the v37 project column round-trips through
// Upsert/Get/List, and an absent value reads back as "" (global).
func TestNetworkProjectRoundTrip(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := UpsertNetwork(ctx, c, NetworkRecord{Name: "owned", Type: "bridge", Config: "{}", Project: "acme"}); err != nil {
		t.Fatalf("UpsertNetwork(owned): %v", err)
	}
	if err := UpsertNetwork(ctx, c, NetworkRecord{Name: "shared", Type: "bridge", Config: "{}"}); err != nil {
		t.Fatalf("UpsertNetwork(shared): %v", err)
	}
	owned, _ := GetNetwork(ctx, c, "owned")
	if owned == nil || owned.Project != "acme" {
		t.Fatalf("owned.Project = %+v, want acme", owned)
	}
	shared, _ := GetNetwork(ctx, c, "shared")
	if shared == nil || shared.Project != "" {
		t.Fatalf("shared.Project = %+v, want \"\" (global)", shared)
	}
	list, _ := ListNetworks(ctx, c)
	got := map[string]string{}
	for _, n := range list {
		got[n.Name] = n.Project
	}
	if got["owned"] != "acme" || got["shared"] != "" {
		t.Errorf("ListNetworks projects = %v, want owned=acme shared=\"\"", got)
	}
}

// TestStoragePoolProjectRoundTrip: the v37 project column round-trips for pools.
func TestStoragePoolProjectRoundTrip(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	if err := UpsertStoragePool(ctx, c, StoragePoolRecord{HostName: "h1", Name: "owned", Driver: "local", State: "active", Project: "acme"}); err != nil {
		t.Fatalf("UpsertStoragePool(owned): %v", err)
	}
	if err := UpsertStoragePool(ctx, c, StoragePoolRecord{HostName: "h1", Name: "shared", Driver: "local", State: "active"}); err != nil {
		t.Fatalf("UpsertStoragePool(shared): %v", err)
	}
	owned, ok, _ := GetStoragePool(ctx, c, "h1", "owned")
	if !ok || owned.Project != "acme" {
		t.Fatalf("owned pool Project = %q (ok=%v), want acme", owned.Project, ok)
	}
	shared, ok, _ := GetStoragePool(ctx, c, "h1", "shared")
	if !ok || shared.Project != "" {
		t.Fatalf("shared pool Project = %q (ok=%v), want \"\" (global)", shared.Project, ok)
	}
}
