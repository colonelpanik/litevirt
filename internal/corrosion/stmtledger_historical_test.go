package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// compatibilityDigest is a FROZEN digest over the IDENTITY of every historical shape (family,
// fingerprint, disposition, category) and every legacy transformer (id, normalized SQL) — not
// just their counts. Changing a column, predicate, or disposition of a supported prior-release
// shape (even one that keeps the family size) changes this digest, so the no-delete rule can't
// silently swap out an old compatibility shape for an equal-sized replacement. Update it only
// with a deliberate, reviewed compatibility change (e.g. a release ages out of the horizon).
//
// Updated for v44 (workload lifecycle + scoped notification routing): the
// containers upsert/re-key and notification-route insert gained additive columns.
// Their v1.3.0 shapes were ADDED to the historical families rather than dropped,
// so supported peers and retained WAL continue to apply. No existing historical
// identity was removed or changed. The immediate schema-v43 InsertHost shape was
// subsequently added after v44 appended capacity_policy_hash. The authority-
// fenced workload writers also retain their immediately preceding VM insert and
// VM/container delete shapes for rolling upgrades and retained WAL, including
// the strict live-container tombstone emitted by DeleteContainerStrict.
const compatibilityDigest = "b9e5e9477d362f4f373b2ede27852cfca0e8c1800d09870a0b8e2b10380b5598"

// computeCompatibilityDigest hashes the sorted identity tuples of the historical shapes and
// legacy transformers.
func computeCompatibilityDigest(t *testing.T) string {
	t.Helper()
	var lines []string
	for _, hs := range HistoricalShapes() {
		le, err := LedgerEntryFor(hs.SQL)
		if err != nil {
			t.Fatalf("derive %q: %v", hs.SQL, err)
		}
		lines = append(lines, fmt.Sprintf("H|%s|%s|%s|%s", hs.Family, le.Fingerprint, le.Disposition, le.Category))
	}
	for key, lt := range legacyTransformers {
		lines = append(lines, fmt.Sprintf("L|%s|%s", lt.id, key))
	}
	sort.Strings(lines)
	h := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(h[:])
}

// TestCompatibilityDigestFrozen freezes the identities of the supported prior-release shapes
// and legacy transformers (finding 1).
func TestCompatibilityDigestFrozen(t *testing.T) {
	got := computeCompatibilityDigest(t)
	if got != compatibilityDigest {
		t.Errorf("compatibility digest changed: got %s, frozen %s\n"+
			"A supported prior-release shape's identity (family/fingerprint/disposition/category) or a legacy\n"+
			"transformer changed. If this is a deliberate, reviewed compatibility change, update compatibilityDigest.", got, compatibilityDigest)
	}
}

// supportedReleaseFamilyManifest pins the expected shape count per historical family, FROZEN
// while its release is a supported peer. It is an INDEPENDENT check the shape generator can't
// silently redefine: deleting a family from both HistoricalShapes and the ledger, or changing a
// family's size, fails against this manifest. Edit it only when a release ages out of the
// upgrade/WAL-retention horizon (a deliberate act). Counts are the raw HistoricalShapes
// expansion (before dedup against the current ledger).
var supportedReleaseFamilyManifest = map[string]int{
	"configure_host_v130":                   127, // 2^7-1 non-empty subsets of the 7 ConfigureHost fields
	"stack_firewall_teardown_v130":          4,   // ip_sets / cluster_firewall_rules / host_firewall_rules / firewall_defaults
	"vm_rename_v130":                        3,   // vm_interfaces / vm_disks / ip_allocations
	"network_rename_v130":                   3,   // network_vteps / ip_allocations / vm_interfaces
	"vm_disks_insert_v130":                  1,   // pre-hardware-foundation vm_disks upsert (narrower column list)
	"insert_host_v130":                      1,   // pre-capacity-policy hosts insert (narrower column list)
	"insert_host_v43":                       1,   // capacity overrides present, before v44 capacity-policy fingerprint
	"configure_host_fixed_v130":             1,   // pre-capacity-policy fixed ConfigureHost UPDATE (7 COALESCE columns)
	"containers_upsert_v130":                1,   // pre-v44 container upsert without lifecycle fencing columns
	"containers_rekey_v130":                 1,   // pre-v44 container re-key without lifecycle fencing columns
	"notification_routes_insert_v130":       1,   // pre-v44 route insert without subject/project selectors
	"insert_vm_pre_authority":               1,   // VM insert before owner/generation columns were carried
	"delete_vm_pre_authority":               1,   // VM tombstone before authority guard columns
	"delete_container_pre_authority":        1,   // container tombstone before authority guard columns
	"delete_container_strict_pre_authority": 1,   // strict live-container tombstone before authority guard columns
	"pci_release_by_vm_v130":                1,   // pre-branch cluster-wide clear of a VM's PCI ownership by vm_name
}

// supportedLegacyTransformerIDs pins the legacy transformers frozen for legacyTransformerHorizon.
var supportedLegacyTransformerIDs = []string{"crl_versions_datetime_now", "gc_spent_proof_tsms"}

// TestSupportedReleaseFamilyManifest cross-checks HistoricalShapes against the frozen manifest,
// breaking the circularity of a self-referential no-delete rule (finding 3).
func TestSupportedReleaseFamilyManifest(t *testing.T) {
	got := map[string]int{}
	for _, hs := range HistoricalShapes() {
		got[hs.Family]++
	}
	for fam, want := range supportedReleaseFamilyManifest {
		if got[fam] != want {
			t.Errorf("family %s: HistoricalShapes generates %d shapes, the frozen manifest pins %d — a family must not gain/lose shapes (or be deleted) while its emitter is a supported peer; change the manifest only once the release ages out of the horizon", fam, got[fam], want)
		}
	}
	for fam := range got {
		if _, ok := supportedReleaseFamilyManifest[fam]; !ok {
			t.Errorf("family %s generated by HistoricalShapes is not pinned in the manifest", fam)
		}
	}
}

// TestLegacyTransformerManifest enforces legacyTransformerHorizon: the registered legacy
// transformers must exactly match the frozen supported set (finding 3).
func TestLegacyTransformerManifest(t *testing.T) {
	got := map[string]bool{}
	for _, lt := range legacyTransformers {
		got[lt.id] = true
	}
	for _, id := range supportedLegacyTransformerIDs {
		if !got[id] {
			t.Errorf("legacy transformer %q (frozen for %s) is missing — do not remove while its emitter is a supported peer", id, legacyTransformerHorizon)
		}
	}
	if len(got) != len(supportedLegacyTransformerIDs) {
		t.Errorf("registered legacy transformers = %d, manifest pins %d", len(got), len(supportedLegacyTransformerIDs))
	}
}

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

// TestHistoricalLedgerNonEmpty guards the emit-historical regression (finding 2): the generated
// ledger must be non-empty, and every historical-ONLY shape (a HistoricalShape absent from the
// current ledger) must be present in historicalLedger — which fails if the generator ever
// filters on LedgerLookup (both maps) instead of CurrentLedgerHas.
func TestHistoricalLedgerNonEmpty(t *testing.T) {
	if len(historicalLedger) == 0 {
		t.Fatal("historicalLedger is empty — the generator likely filtered on LedgerLookup instead of CurrentLedgerHas")
	}
	for _, hs := range HistoricalShapes() {
		le, err := LedgerEntryFor(hs.SQL)
		if err != nil {
			t.Fatalf("derive %q: %v", hs.SQL, err)
		}
		if CurrentLedgerHas(le.Fingerprint) {
			continue // shared with the current build; lives in stmtLedger
		}
		if _, ok := historicalLedger[le.Fingerprint]; !ok {
			t.Errorf("historical-only shape missing from historicalLedger (regenerate): %q", hs.SQL)
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
		`UPDATE hosts SET regionx = ?, updated_at = ? WHERE name = ?`,                                         // ConfigureHost field renamed
		`UPDATE ip_sets SET deleted_at = ?, updated_at = ? WHERE stack_namex = ? AND deleted_at IS NULL`,      // firewall predicate col renamed
		`UPDATE vm_disks SET vm_namex = ?, updated_at = ? WHERE vm_name = ?`,                                  // VM-rename SET col renamed
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

// v43 widened configureHostSQL (4 new capacity COALESCE columns), so the
// current tree stopped emitting the v1.3.0-fixed 7-column UPDATE shape. A
// prior-release peer still emits it; the historical ledger must keep
// recognising it or ConfigureHost from that peer back-pressures and stalls
// its replication stream during a rolling upgrade.
func TestHistoricalLedgerKeepsFixedConfigureHostShape(t *testing.T) {
	oldSQL := `UPDATE hosts SET ` +
		`fence_strategy = COALESCE(?, fence_strategy), ` +
		`ipmi_address = COALESCE(?, ipmi_address), ` +
		`ipmi_user = COALESCE(?, ipmi_user), ` +
		`ipmi_pass = COALESCE(?, ipmi_pass), ` +
		`watchdog_dev = COALESCE(?, watchdog_dev), ` +
		`role = COALESCE(?, role), ` +
		`region = COALESCE(?, region), ` +
		`updated_at = ? ` +
		`WHERE name = ?`
	// SQL intentionally restated verbatim (not dereferenced from HistoricalShapes)
	// so a typo in the registered entry cannot self-certify — the package's
	// established shape-retention pattern (see release_corpus_test.go).
	mustResolve(t, "pre-v43 fixed ConfigureHost", oldSQL)
}

func TestHistoricalLedgerKeepsV43InsertHostShapeAndReceiverFields(t *testing.T) {
	const oldSQL = `INSERT INTO hosts (name, address, ssh_user, ssh_port, grpc_port, state, cert_serial,
			cpu_total, mem_total, disk_total, fence_strategy, version, role,
			cpu_overcommit, mem_overcommit, cpu_reserve, mem_reserve_mib,
			created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	fp, err := FingerprintSQL(oldSQL)
	if err != nil {
		t.Fatalf("fingerprint v43 InsertHost: %v", err)
	}
	const wantFingerprint = "stmtshape/v1:d383c54470d1d0692c38cdb7a55624d4ec6828dd7ff533ff5757e824f7fffd11"
	if fp != wantFingerprint {
		t.Fatalf("v43 InsertHost fingerprint = %q, want %q", fp, wantFingerprint)
	}
	if _, ok := LedgerLookup(fp); !ok {
		t.Fatalf("v43 InsertHost shape %s is not registered", fp)
	}

	const oldTS = "1000000000000-0000-n1"
	const newTS = "3000000000000-0000-n2"
	c := mustTestClient(t)
	ctx := context.Background()
	if err := c.Execute(ctx,
		`INSERT INTO hosts
		 (name, address, ssh_user, cert_serial, capacity_policy_hash, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"h1", "10.0.0.1", "root", "serial", "sha256:receiver-policy",
		"2020-01-01T00:00:00Z", oldTS); err != nil {
		t.Fatalf("seed receiver host: %v", err)
	}

	stmts, err := json.Marshal([]Statement{{
		SQL: oldSQL,
		Params: []interface{}{
			"h1", "10.0.0.2", "admin", 2222, 7444, "active", "serial-2",
			8, 16384, 1024, "strict", "v43", "worker",
			1.5, 1.25, 2, 1024,
			"2020-01-01T00:00:00Z", newTS,
		},
	}})
	if err != nil {
		t.Fatalf("marshal v43 InsertHost mutation: %v", err)
	}
	r := NewReplicator(c, "", RelayConfig{})
	if _, err := r.ApplyRemoteMutations(ctx, []*pb.MutationEntry{{
		Seq: 1, Hlc: newTS, Origin: "v43-peer", Stmts: string(stmts),
	}}); err != nil {
		t.Fatalf("v43 InsertHost historical shape must apply: %v", err)
	}

	rows, err := c.Query(ctx,
		`SELECT address, ssh_user, cpu_overcommit, mem_overcommit,
		        cpu_reserve, mem_reserve_mib, capacity_policy_hash
		 FROM hosts WHERE name = ?`, "h1")
	if err != nil || len(rows) != 1 {
		t.Fatalf("read updated receiver host: rows=%d err=%v", len(rows), err)
	}
	if rows[0].String("address") != "10.0.0.2" || rows[0].String("ssh_user") != "admin" ||
		rows[0].Float("cpu_overcommit") != 1.5 || rows[0].Float("mem_overcommit") != 1.25 ||
		rows[0].Int("cpu_reserve") != 2 || rows[0].Int("mem_reserve_mib") != 1024 ||
		rows[0].String("capacity_policy_hash") != "sha256:receiver-policy" {
		t.Fatalf("v43 host apply lost current or receiver-only fields: %#v", rows[0])
	}
}
