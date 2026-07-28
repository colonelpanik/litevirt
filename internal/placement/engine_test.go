package placement

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func testDB(t *testing.T) *corrosion.Client {
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

func insertHost(t *testing.T, c *corrosion.Client, h corrosion.HostRecord) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), c, h); err != nil {
		t.Fatalf("InsertHost %q: %v", h.Name, err)
	}
}

func TestSelect_SingleHost(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name:     "node1",
		Address:  "10.0.0.1",
		State:    "active",
		CPUTotal: 16,
		MemTotal: 32768,
	})

	host, err := Select(context.Background(), db, Request{VMName: "vm1", CPUNeeded: 2, MemMiBNeeded: 1024})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "node1" {
		t.Errorf("got host %q, want node1", host)
	}
}

func TestSelect_NoHostsInsufficientCPU(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name:     "small",
		Address:  "10.0.0.1",
		State:    "active",
		CPUTotal: 2,
		MemTotal: 4096,
	})

	_, err := Select(context.Background(), db, Request{VMName: "vm1", CPUNeeded: 8, MemMiBNeeded: 1024})
	if err == nil {
		t.Fatal("expected error when no host has enough CPU")
	}
}

// TestSelect_SkipsWitnessHosts verifies that witness/tiebreaker hosts are
// excluded from placement candidates even when active and resource-rich.
// Witnesses vote in quorum but never run workloads; see operating-model.md.
func TestSelect_SkipsWitnessHosts(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "witness-1", Address: "10.0.0.99", State: "active",
		CPUTotal: 32, MemTotal: 65536, Role: "witness",
	})
	insertHost(t, db, corrosion.HostRecord{
		Name: "worker-1", Address: "10.0.0.1", State: "active",
		CPUTotal: 4, MemTotal: 4096, Role: "worker",
	})

	host, err := Select(context.Background(), db,
		Request{VMName: "vm1", CPUNeeded: 1, MemMiBNeeded: 512})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "worker-1" {
		t.Errorf("Select chose %q, want worker-1 (witness must be excluded even with more resources)", host)
	}
}

// TestSelect_PinHost_RejectsWitness verifies that pinning a VM to a witness
// host fails with a clear error.
func TestSelect_PinHost_RejectsWitness(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "witness-1", Address: "10.0.0.99", State: "active",
		CPUTotal: 32, MemTotal: 65536, Role: "witness",
	})
	_, err := Select(context.Background(), db,
		Request{VMName: "vm1", PinHost: "witness-1"})
	if err == nil {
		t.Fatal("Select should reject pin to witness")
	}
}

func TestSelect_SkipsInactiveHosts(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "offline", Address: "10.0.0.1", State: "offline", CPUTotal: 32, MemTotal: 65536,
	})
	insertHost(t, db, corrosion.HostRecord{
		Name: "active", Address: "10.0.0.2", State: "active", CPUTotal: 32, MemTotal: 65536,
	})

	host, err := Select(context.Background(), db, Request{VMName: "vm1"})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "active" {
		t.Errorf("got %q, want active", host)
	}
}

func TestSelect_PinHost(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active", CPUTotal: 16, MemTotal: 32768,
	})
	insertHost(t, db, corrosion.HostRecord{
		Name: "node2", Address: "10.0.0.2", State: "active", CPUTotal: 16, MemTotal: 32768,
	})

	host, err := Select(context.Background(), db, Request{VMName: "vm1", PinHost: "node2"})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "node2" {
		t.Errorf("PinHost: got %q, want node2", host)
	}
}

func TestSelect_PinHost_NotFound(t *testing.T) {
	db := testDB(t)
	_, err := Select(context.Background(), db, Request{VMName: "vm1", PinHost: "missing"})
	if err == nil {
		t.Fatal("expected error for unknown pinned host")
	}
}

func TestSelect_PinHost_Inactive(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "draining", Address: "10.0.0.1", State: "draining", CPUTotal: 16, MemTotal: 32768,
	})
	_, err := Select(context.Background(), db, Request{VMName: "vm1", PinHost: "draining"})
	if err == nil {
		t.Fatal("expected error for inactive pinned host")
	}
}

func TestSelect_PinnedHostStillEnforcesHardConstraints(t *testing.T) {
	strictCapacity := corrosion.CapacityPolicy{
		CPUOvercommit:    1,
		MemOvercommit:    1,
		CPUReserve:       0,
		MemReserveMiB:    0,
		MemReservePct:    0,
		VMMemOverheadMiB: 0,
	}
	tests := []struct {
		name  string
		setup func(*testing.T, *corrosion.Client)
		req   Request
	}{
		{
			name: "required label",
			setup: func(t *testing.T, db *corrosion.Client) {
				insertHost(t, db, corrosion.HostRecord{
					Name: "node1", Address: "10.0.0.1", State: "active",
					CPUTotal: 8, MemTotal: 8192,
					Labels: map[string]string{"zone": "west"},
				})
			},
			req: Request{
				VMName: "vm1", PinHost: "node1",
				RequireLabels: map[string]string{"zone": "east"},
			},
		},
		{
			name: "anti-affinity",
			setup: func(t *testing.T, db *corrosion.Client) {
				insertHost(t, db, corrosion.HostRecord{
					Name: "node1", Address: "10.0.0.1", State: "active",
					CPUTotal: 8, MemTotal: 8192,
				})
				if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
					Name: "peer", HostName: "node1", State: "running",
					CPUActual: 1, MemActual: 512,
				}, nil, nil); err != nil {
					t.Fatalf("InsertVM: %v", err)
				}
			},
			req: Request{
				VMName: "vm1", PinHost: "node1",
				AntiAffinity: []string{"peer"},
			},
		},
		{
			name: "max per node",
			setup: func(t *testing.T, db *corrosion.Client) {
				insertHost(t, db, corrosion.HostRecord{
					Name: "node1", Address: "10.0.0.1", State: "active",
					CPUTotal: 8, MemTotal: 8192,
				})
				if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
					Name: "web-1", HostName: "node1", State: "running",
					CPUActual: 1, MemActual: 512,
				}, nil, nil); err != nil {
					t.Fatalf("InsertVM: %v", err)
				}
			},
			req: Request{
				VMName: "web-2", VMBaseName: "web", PinHost: "node1",
				MaxPerNode: 1,
			},
		},
		{
			name: "strict spread",
			setup: func(t *testing.T, db *corrosion.Client) {
				insertHost(t, db, corrosion.HostRecord{
					Name: "node1", Address: "10.0.0.1", State: "active",
					CPUTotal: 4, MemTotal: 4096,
				})
				if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
					Name: "busy", HostName: "node1", State: "running",
					CPUActual: 2, MemActual: 2048,
				}, nil, nil); err != nil {
					t.Fatalf("InsertVM: %v", err)
				}
			},
			req: Request{
				VMName: "vm1", PinHost: "node1", Policy: PolicySpreadStrict,
				CPUNeeded: 1, MemMiBNeeded: 512, Capacity: strictCapacity,
			},
		},
		{
			name: "insufficient capacity",
			setup: func(t *testing.T, db *corrosion.Client) {
				insertHost(t, db, corrosion.HostRecord{
					Name: "node1", Address: "10.0.0.1", State: "active",
					CPUTotal: 2, MemTotal: 2048,
				})
			},
			req: Request{
				VMName: "vm1", PinHost: "node1",
				CPUNeeded: 3, MemMiBNeeded: 1024, Capacity: strictCapacity,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := testDB(t)
			tt.setup(t, db)
			if _, err := Select(context.Background(), db, tt.req); err == nil {
				t.Fatalf("pinned host bypassed %s hard constraint", tt.name)
			}
		})
	}
}

func TestSelect_RequireLabels(t *testing.T) {
	db := testDB(t)
	// node1 has no labels, node2 has zone=us-east
	if err := db.Execute(context.Background(),
		`INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, cpu_total, mem_total, labels, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"node1", "10.0.0.1", "root", 22, 7443, "active", "", 16, 32768, "", "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z",
	); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(context.Background(),
		`INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial, cpu_total, mem_total, labels, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"node2", "10.0.0.2", "root", 22, 7443, "active", "", 16, 32768, `{"zone":"us-east"}`, "2024-01-01T00:00:00Z", "2024-01-01T00:00:00Z",
	); err != nil {
		t.Fatal(err)
	}

	host, err := Select(context.Background(), db, Request{
		VMName:        "vm1",
		RequireLabels: map[string]string{"zone": "us-east"},
	})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "node2" {
		t.Errorf("got %q, want node2", host)
	}
}

func TestSelect_RequireLabels_NoneMatch(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active", CPUTotal: 16, MemTotal: 32768,
	})

	_, err := Select(context.Background(), db, Request{
		VMName:        "vm1",
		RequireLabels: map[string]string{"zone": "us-east"},
	})
	if err == nil {
		t.Fatal("expected error when no host matches required labels")
	}
}

func TestSelect_Spread(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", State: "active", CPUTotal: 32, MemTotal: 65536,
	})
	insertHost(t, db, corrosion.HostRecord{
		Name: "node2", Address: "10.0.0.2", State: "active", CPUTotal: 32, MemTotal: 65536,
	})

	// With spread=true and no existing VMs, both nodes start at score 100.
	// Tie is broken by name (node1 < node2).
	host, err := Select(context.Background(), db, Request{VMName: "vm1", Spread: true})
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "node1" {
		t.Errorf("spread tie-break: got %q, want node1", host)
	}
}

func TestLabelsMatch(t *testing.T) {
	tests := []struct {
		host     map[string]string
		required map[string]string
		want     bool
	}{
		{map[string]string{"zone": "us-east"}, map[string]string{"zone": "us-east"}, true},
		{map[string]string{"zone": "us-east", "env": "prod"}, map[string]string{"zone": "us-east"}, true},
		{map[string]string{"zone": "us-west"}, map[string]string{"zone": "us-east"}, false},
		{map[string]string{}, map[string]string{"zone": "us-east"}, false},
		{map[string]string{"zone": "us-east"}, map[string]string{}, true},
	}
	for _, tt := range tests {
		got := labelsMatch(tt.host, tt.required)
		if got != tt.want {
			t.Errorf("labelsMatch(%v, %v) = %v, want %v", tt.host, tt.required, got, tt.want)
		}
	}
}
