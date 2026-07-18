package corrosion

import (
	"context"
	"fmt"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// TestHistoricalLedgerComplete is the no-delete CI rule: every shape the parameterized
// historical families still generate MUST be registered (in the current or historical ledger).
// A missing one means a checked-in historical entry was deleted while its emitter is still a
// supported peer — which would back-pressure that peer's stream during a rolling upgrade. To
// retire a family, remove it from HistoricalShapes AND the ledger only once its FirstEmitter is
// no longer supported (see RemovalHorizon).
func TestHistoricalLedgerComplete(t *testing.T) {
	for _, hs := range HistoricalShapes() {
		le, err := LedgerEntryFor(hs.SQL)
		if err != nil {
			t.Fatalf("derive historical shape %q: %v", hs.SQL, err)
		}
		if _, ok := LedgerLookup(le.Fingerprint); !ok {
			t.Errorf("historical shape (family %s, first emitter %s) is NOT registered — do not delete a "+
				"historical entry while its emitter is a supported peer; regenerate with "+
				"`stmtshapecheck -emit-historical`: %q", hs.Family, hs.FirstEmitter, hs.SQL)
		}
	}
}

// TestLegacyTransformerOneTokenVariationRejected: a one-token variation of either legacy
// transformer must NOT match the exact allowlist (and thus back-pressures, not silently
// mis-applies).
func TestLegacyTransformerOneTokenVariationRejected(t *testing.T) {
	variations := []string{
		// crl_versions: function name altered by one token.
		`INSERT OR REPLACE INTO crl_versions (host, version, updated_at) VALUES (?, ?, datetimex('now'))`,
		// crl_versions: a column renamed.
		`INSERT OR REPLACE INTO crl_versions (host, versionx, updated_at) VALUES (?, ?, datetime('now'))`,
		// gc-reap: a status literal altered.
		`UPDATE runtime_action_proofs SET deleted_at = ?, updated_at = ? WHERE deleted_at IS NULL AND status IN ('completed','failedx') AND ` + tsMsSQL("updated_at") + ` < ?`,
	}
	for _, sql := range variations {
		if _, ok := legacyTransformerFor(sql); ok {
			t.Errorf("a one-token variation matched a legacy transformer (must not): %q", sql)
		}
	}
}

// TestOneTokenVariationNotRegistered: a one-token variation of a registered historical family
// shape must not itself be registered.
func TestOneTokenVariationNotRegistered(t *testing.T) {
	variations := []string{
		`UPDATE hosts SET regionx = ?, updated_at = ? WHERE name = ?`,                                        // ConfigureHost field renamed
		`UPDATE ip_sets SET deleted_at = ?, updated_at = ? WHERE stack_namex = ? AND deleted_at IS NULL`,     // firewall predicate col renamed
		`UPDATE vm_disks SET vm_namex = ?, updated_at = ? WHERE vm_name = ?`,                                 // VM-rename SET col renamed
		`UPDATE network_vteps SET network_name = ?, updated_at = ? WHERE network_name = ? AND deleted_at = ?`, // network-rename predicate altered
	}
	for _, sql := range variations {
		fp, err := FingerprintSQL(sql)
		if err != nil {
			continue // unparseable ⇒ rejected anyway
		}
		if _, ok := LedgerLookup(fp); ok {
			t.Errorf("a one-token variation is registered (must not be): %q", sql)
		}
	}
}

// TestHistoricalFamiliesApply replays a representative registered statement from each historical
// family and confirms it applies (not back-pressures) — the mixed-version horizon works.
func TestHistoricalFamiliesApply(t *testing.T) {
	const oldTS = "1000000000000-0000-n1"
	const newTS = "3000000000000-0000-n2"

	t.Run("configure_host", func(t *testing.T) {
		c := mustTestClient(t)
		ctx := context.Background()
		if err := c.Execute(ctx, `INSERT INTO hosts (name, address, ssh_user, cert_serial, region, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			"h1", "10.0.0.1", "root", "s1", "old-region", "2020-01-01T00:00:00Z", oldTS); err != nil {
			t.Fatalf("seed: %v", err)
		}
		r := NewReplicator(c, "", RelayConfig{})
		stmts := fmt.Sprintf(`[{"SQL":"UPDATE hosts SET region = ?, updated_at = ? WHERE name = ?","Params":["new-region","%s","h1"]}]`, newTS)
		if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: newTS, Origin: "o", Stmts: stmts}}); err != nil {
			t.Fatalf("configure_host historical shape must apply, got: %v", err)
		}
		rows, _ := c.Query(ctx, "SELECT region FROM hosts WHERE name = ?", "h1")
		if len(rows) == 0 || rows[0].String("region") != "new-region" {
			t.Error("region not updated by the historical ConfigureHost shape")
		}
	})

	t.Run("stack_firewall_teardown", func(t *testing.T) {
		c := mustTestClient(t)
		ctx := context.Background()
		if err := c.Execute(ctx, `INSERT INTO ip_sets (id, name, stack_name, created_at, updated_at) VALUES (?, ?, ?, ?, ?)`,
			"is1", "web", "stackA", "2020-01-01T00:00:00Z", oldTS); err != nil {
			t.Fatalf("seed: %v", err)
		}
		r := NewReplicator(c, "", RelayConfig{})
		stmts := fmt.Sprintf(`[{"SQL":"UPDATE ip_sets SET deleted_at = ?, updated_at = ? WHERE stack_name = ? AND deleted_at IS NULL","Params":["2026-01-01T00:00:00Z","%s","stackA"]}]`, newTS)
		if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: newTS, Origin: "o", Stmts: stmts}}); err != nil {
			t.Fatalf("firewall historical shape must apply, got: %v", err)
		}
		rows, _ := c.Query(ctx, "SELECT deleted_at FROM ip_sets WHERE id = ?", "is1")
		if len(rows) == 0 || rows[0].String("deleted_at") == "" {
			t.Error("ip_sets not tombstoned by the historical firewall shape")
		}
	})

	t.Run("vm_rename", func(t *testing.T) {
		c := mustTestClient(t)
		ctx := context.Background()
		if err := c.Execute(ctx, `INSERT INTO vm_disks (vm_name, disk_name, host_name, path, updated_at) VALUES (?, ?, ?, ?, ?)`,
			"old-vm", "disk0", "h", "/p", oldTS); err != nil {
			t.Fatalf("seed: %v", err)
		}
		r := NewReplicator(c, "", RelayConfig{})
		stmts := fmt.Sprintf(`[{"SQL":"UPDATE vm_disks SET vm_name = ?, updated_at = ? WHERE vm_name = ?","Params":["new-vm","%s","old-vm"]}]`, newTS)
		if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: newTS, Origin: "o", Stmts: stmts}}); err != nil {
			t.Fatalf("vm_rename historical shape must apply, got: %v", err)
		}
		rows, _ := c.Query(ctx, "SELECT disk_name FROM vm_disks WHERE vm_name = ?", "new-vm")
		if len(rows) != 1 {
			t.Errorf("vm_disks not rekeyed to new-vm (per-row-LWW row-scoped rekey), got %d rows", len(rows))
		}
	})

	t.Run("network_rename", func(t *testing.T) {
		c := mustTestClient(t)
		ctx := context.Background()
		if err := c.Execute(ctx, `INSERT INTO network_vteps (network_name, host_name, vtep_ip, vni, updated_at) VALUES (?, ?, ?, ?, ?)`,
			"old-net", "h", "10.0.0.1", 100, oldTS); err != nil {
			t.Fatalf("seed: %v", err)
		}
		r := NewReplicator(c, "", RelayConfig{})
		stmts := fmt.Sprintf(`[{"SQL":"UPDATE network_vteps SET network_name = ?, updated_at = ? WHERE network_name = ? AND deleted_at IS NULL","Params":["new-net","%s","old-net"]}]`, newTS)
		if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{Seq: 1, Hlc: newTS, Origin: "o", Stmts: stmts}}); err != nil {
			t.Fatalf("network_rename historical shape must apply, got: %v", err)
		}
		rows, _ := c.Query(ctx, "SELECT host_name FROM network_vteps WHERE network_name = ?", "new-net")
		if len(rows) != 1 {
			t.Errorf("network_vteps not rekeyed to new-net, got %d rows", len(rows))
		}
	})
}
