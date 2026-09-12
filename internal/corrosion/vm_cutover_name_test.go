package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The cutover shape. `lv cutover` tombstones the VM being replaced and then gives
// its replacement that name. `vms.name` is the PRIMARY KEY and DeleteVM is a SOFT
// delete, so the tombstoned row still holds the key — as does every child table
// DeleteVM tombstones, each on its own composite PK. Every pre-existing cutover
// test drove the case where the replaced VM does not exist, which has no
// tombstone and therefore no collision, which is why this went unnoticed.
//
// The tests here also pin the three ways the obvious fix — purging the tombstone
// in the same batch as the rekey — is wrong. See ErrRenameTargetOccupied.

// testClientVMReplace is a client that has latched vm_replace_v1, so it will APPLY
// a replicated guarded replace instead of rejecting the shape. A receiver without
// it refuses — which is the rollout guarantee, and has its own test.
func testClientVMReplace(t *testing.T) *Client {
	t.Helper()
	c := testClient(t)
	c.SetVMReplaceAccept(func() bool { return true })
	return c
}

// cutover drives what CutoverVM drives at the database layer.
func cutover(t *testing.T, c *Client, replaced, replacement string) {
	t.Helper()
	ctx := context.Background()
	if err := DeleteVM(ctx, c, replaced); err != nil {
		t.Fatalf("DeleteVM %q: %v", replaced, err)
	}
	if err := ReplaceVM(ctx, c, replacement, replaced, prepareCutover(t, c, replaced, replacement)); err != nil {
		t.Fatalf("ReplaceVM %q → %q: %v", replacement, replaced, err)
	}
}

// prepareCutover journals the cleanup manifest the transition has to authorize.
// A test that skipped it would be exercising a transition production cannot
// perform: ReplaceVM refuses without one, because committing the transition
// without the authorization would displace the only record of what the replaced
// VM owned.
func prepareCutover(t *testing.T, c *Client, replaced, replacement string) VMReplacePrepared {
	t.Helper()
	ctx := context.Background()
	src, err := GetVM(ctx, c, replacement)
	if err != nil || src == nil {
		t.Fatalf("read the replacement %q: %+v err=%v", replacement, src, err)
	}
	disks, err := GetDeletedVMDisks(ctx, c, replaced)
	if err != nil {
		t.Fatalf("read the replaced VM's disks: %v", err)
	}
	prepared, _, err := PrepareVMReplace(ctx, c, VMReplaceManifest{
		ReplacedVM: replaced, Replacement: replacement, HostName: src.HostName, Disks: disks,
		ReplacementIncarnation: src.CreatedAt,
		ReplacementSpec:        src.Spec,
		ReplacementState:       src.State,
	}, src.OwnerEpoch)
	if err != nil {
		t.Fatalf("PrepareVMReplace: %v", err)
	}
	return prepared
}

// walEntries returns every mutation the client has logged, oldest first, as
// replication entries a receiver would be handed.
func walEntries(t *testing.T, c *Client, origin string) []*pb.MutationEntry {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT seq, hlc, stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	out := make([]*pb.MutationEntry, 0, len(rows))
	for _, r := range rows {
		out = append(out, &pb.MutationEntry{
			Seq: int64(r.Int("seq")), Hlc: r.String("hlc"),
			Origin: origin, Stmts: r.String("stmts"),
		})
	}
	return out
}

func TestCutoverGivesTheReplacementATombstonedName(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()

	// Both carry children, because DeleteVM tombstones vm_interfaces and vm_disks
	// too and each collides on its own composite PK during the rekey — the parent
	// row is not the only thing holding the name.
	if err := InsertVM(ctx, c,
		VMRecord{Name: "app", HostName: "h1", Spec: `{"cpu":2}`, State: "running"},
		[]InterfaceRecord{{VMName: "app", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:01"}},
		[]DiskRecord{{VMName: "app", DiskName: "root", HostName: "h1", Path: "/disks/a.qcow2", SizeBytes: 1 << 30, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM replaced: %v", err)
	}
	if err := InsertVM(ctx, c,
		VMRecord{Name: "app-next", HostName: "h1", Spec: `{"cpu":4}`, State: "running"},
		[]InterfaceRecord{{VMName: "app-next", NetworkName: "default", Ordinal: 0, MAC: "52:54:00:aa:bb:02"}},
		[]DiskRecord{{VMName: "app-next", DiskName: "root", HostName: "h1", Path: "/disks/b.qcow2", SizeBytes: 1 << 30, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM replacement: %v", err)
	}

	before := func(name string) (created string, epoch, gen int64) {
		t.Helper()
		vm, err := GetVM(ctx, c, name)
		if err != nil || vm == nil {
			t.Fatalf("read %q before the cutover: %+v err=%v", name, vm, err)
		}
		return vm.CreatedAt, vm.OwnerEpoch, vm.SpecGeneration
	}
	replacedCreated, replacedEpoch, replacedGen := before("app")
	replacementCreated, replacementEpoch, replacementGen := before("app-next")

	cutover(t, c, "app", "app-next")

	got, err := GetVM(ctx, c, "app")
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if got == nil {
		t.Fatal(`no live VM named "app" after the cutover — the replacement did not take the name`)
	}
	// The rename patches the spec's own "name" field, so compare the field that
	// distinguishes the two incarnations rather than the whole document.
	if !strings.Contains(got.Spec, `"cpu":4`) {
		t.Fatalf(`VM "app" carries spec %q, want the replacement's (cpu 4)`, got.Spec)
	}
	if gone, err := GetVM(ctx, c, "app-next"); err != nil {
		t.Fatalf("GetVM old name: %v", err)
	} else if gone != nil {
		t.Fatal("the replacement is still live under its temporary name")
	}

	// The children must have moved too, and must be the REPLACEMENT's.
	ifaces, err := GetVMInterfaces(ctx, c, "app")
	if err != nil {
		t.Fatalf("GetVMInterfaces: %v", err)
	}
	if len(ifaces) != 1 || ifaces[0].MAC != "52:54:00:aa:bb:02" {
		t.Fatalf(`interfaces on "app" = %+v, want exactly the replacement's MAC`, ifaces)
	}
	disks, err := GetVMDisks(ctx, c, "app")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 1 || disks[0].Path != "/disks/b.qcow2" {
		t.Fatalf(`disks on "app" = %+v, want exactly the replacement's path`, disks)
	}

	// The two invariants the whole transition rests on.
	//
	// The row at the contested name carries the REPLACEMENT's incarnation, not the
	// replaced VM's. created_at IS the incarnation identity the anti-entropy merge
	// decides from, and a delete is terminal for its own incarnation — so inheriting
	// the replaced VM's stamp would let a delayed replay of its tombstone kill the
	// replacement as "the same incarnation, already deleted".
	if got.CreatedAt != replacementCreated {
		t.Errorf("VM \"app\" carries created_at %q, want the replacement's %q — a delayed "+
			"tombstone of the replaced VM would read as the same incarnation and kill it",
			got.CreatedAt, replacementCreated)
	}
	if got.CreatedAt == replacedCreated {
		t.Errorf("VM \"app\" inherited the REPLACED VM's incarnation %q", replacedCreated)
	}
	// And its authority exceeds BOTH inputs, because a both-live conflict at this
	// name is decided on owner/generation alone: a stale copy of either VM that
	// still outranked it would simply overwrite the replacement.
	if got.OwnerEpoch <= replacedEpoch || got.OwnerEpoch <= replacementEpoch {
		t.Errorf("owner epoch = %d, want above both inputs (replaced %d, replacement %d)",
			got.OwnerEpoch, replacedEpoch, replacementEpoch)
	}
	if got.SpecGeneration <= replacedGen || got.SpecGeneration <= replacementGen {
		t.Errorf("spec generation = %d, want above both inputs (replaced %d, replacement %d)",
			got.SpecGeneration, replacedGen, replacementGen)
	}
	// The replacement's own rows are TOMBSTONED, not deleted — the tombstone is what
	// tells a lagging peer the temporary name is retired rather than merely unseen.
	rows, err := c.Query(ctx, `SELECT deleted_at FROM vms WHERE name = 'app-next'`)
	if err != nil {
		t.Fatalf("read the replacement's old row: %v", err)
	}
	if len(rows) != 1 || rows[0].String("deleted_at") == "" {
		t.Fatalf(`row at "app-next" = %+v, want one row tombstoned`, rows)
	}
}

// A replacement that kept the original's MAC re-derives the tombstone's exact
// vm_nics primary key, because DeterministicNICID mixes vm_name with the MAC and
// both VMs have the same MAC. Excluding vm_nics from the fix on the theory that
// the MACs must differ leaves the original destructive failure in place —
// CreateVM accepts a supplied MAC, and two stopped VMs can hold the same address.
func TestCutoverWithTheSameMAC(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	const mac = "52:54:00:aa:bb:01"
	for _, name := range []string{"app", "app-next"} {
		if err := InsertVMWithHardware(ctx, c,
			VMRecord{Name: name, HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil,
			[]NICRecord{{
				VMName: name, ID: DeterministicNICID(name, mac),
				NetworkName: "default", MAC: mac, Ordinal: 0,
			}}, nil, true,
		); err != nil {
			t.Fatalf("InsertVMWithHardware %q: %v", name, err)
		}
	}

	cutover(t, c, "app", "app-next")

	nics, err := c.Query(ctx, `SELECT id, deleted_at FROM vm_nics WHERE vm_name = ?`, "app")
	if err != nil {
		t.Fatalf("read nics: %v", err)
	}
	if len(nics) != 1 || nics[0].String("deleted_at") != "" {
		t.Fatalf(`vm_nics on "app" = %+v, want exactly the replacement's live NIC`, nics)
	}
	if want := DeterministicNICID("app", mac); nics[0].String("id") != want {
		t.Fatalf("NIC id = %q, want the re-derived %q", nics[0].String("id"), want)
	}
	// The replaced VM's tombstoned NIC sat on exactly this key — the id mixes the
	// name with the MAC, and the MAC is shared — so the upsert displaced it at that
	// one key rather than colliding with it.
	if rows, err := c.Query(ctx, `SELECT deleted_at FROM vm_nics WHERE vm_name = 'app-next'`); err != nil {
		t.Fatalf("read the replacement's old NIC: %v", err)
	} else if len(rows) != 1 || rows[0].String("deleted_at") == "" {
		t.Fatalf(`vm_nics on "app-next" = %+v, want one row tombstoned`, rows)
	}
}

// A child key the replacement does NOT claim must keep its tombstone. Vacating
// it — by purging it, or by relocating it along with the rest — leaves nothing to
// reject a stale pre-delete full-state row with, so a disk the replaced VM had
// and the replacement does not comes back on top of the replacement.
//
// Both VMs are given the same spec on purpose: the rename patches spec.name, so
// after the cutover the incoming payload's parent identity-hashes equal to the
// local one and the anti-entropy child-authority check admits the stale child.
// That is the adversarial case; a test where the specs differ cannot reach it.
func TestCutoverKeepsTheTombstonesItIsNotReplacing(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	if err := InsertVM(ctx, c,
		VMRecord{Name: "app", HostName: "h1", Spec: `{"name":"app"}`, State: "stopped"}, nil,
		[]DiskRecord{{VMName: "app", DiskName: "extra", HostName: "h1", Path: "/old-extra.qcow2", StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM replaced: %v", err)
	}
	stale := c.DumpStateBytes()
	if err := InsertVM(ctx, c,
		VMRecord{Name: "app-next", HostName: "h1", Spec: `{"name":"app-next"}`, State: "stopped"}, nil, nil,
	); err != nil {
		t.Fatalf("InsertVM replacement: %v", err)
	}

	cutover(t, c, "app", "app-next")

	if err := c.MergeStateBytesLWW(stale); err != nil {
		t.Fatalf("merge stale full state: %v", err)
	}
	disks, err := GetVMDisks(ctx, c, "app")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	if len(disks) != 0 {
		t.Fatalf("the replaced VM's disk came back on its replacement: %+v", disks)
	}
}

// A delayed rename replayed on a peer that never saw the source name must not
// erase a deletion that peer has already applied.
//
// The rekey is LWW-gated on the OLD name and matches no row at all there, so
// anything the batch does unconditionally — a tombstone purge — takes effect with
// no replacement written, the batch still commits, and the next stale full-state
// merge resurrects the VM.
func TestDelayedRenameReplayKeepsANewerDeletion(t *testing.T) {
	src, dst := testClient(t), testClientVMReplace(t)
	ctx := context.Background()

	if err := InsertVM(ctx, src,
		VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil,
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := RenameVM(ctx, src, "app-next", "app"); err != nil {
		t.Fatalf("RenameVM: %v", err)
	}
	delayed := walEntries(t, src, "source")
	delayed = delayed[len(delayed)-1:] // the rename, held back
	live := src.DumpStateBytes()       // a copy from before the delete
	if err := DeleteVM(ctx, src, "app"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	// dst learns the final, deleted state first, then replays the rename.
	if err := dst.MergeStateBytesLWW(src.DumpStateBytes()); err != nil {
		t.Fatalf("merge final state: %v", err)
	}
	if _, err := NewReplicator(dst, "", RelayConfig{}).ApplyRemoteMutations(ctx, delayed); err != nil {
		t.Fatalf("replay the delayed rename: %v", err)
	}
	rows, err := dst.Query(ctx, `SELECT deleted_at FROM vms WHERE name = 'app'`)
	if err != nil {
		t.Fatalf("read app: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("the delayed rename erased the newer deletion and replaced it with nothing")
	}
	if err := dst.MergeStateBytesLWW(live); err != nil {
		t.Fatalf("merge stale pre-delete state: %v", err)
	}
	if vm, err := GetVM(ctx, dst, "app"); err != nil {
		t.Fatalf("GetVM: %v", err)
	} else if vm != nil {
		t.Fatalf("stale pre-delete full state resurrected the deleted VM: %+v", vm)
	}
}

// Every statement a cutover replicates must already be a shape the previous
// release's receiver authorizes, and none of them may be a hard delete.
//
// A shape absent from a receiver's ledger is rejected as an "unregistered
// replicated statement shape", the batch rolls back, and nothing acknowledges —
// which stops that peer's ordered stream advancing to any later mutation.
// Registering a shape in the NEW binary does not teach an older peer to accept
// it, and there is no mechanism that can: the historical ledger only runs the
// other way (an old sender's shape kept acceptable to a new receiver). So a
// cutover has to be expressible in shapes that are already out there.
func TestCutoverReplicatesNoNewShapeAndNoHardDelete(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	const mac = "52:54:00:aa:bb:01"
	for _, name := range []string{"app", "app-next"} {
		if err := InsertVMWithHardware(ctx, c,
			VMRecord{Name: name, HostName: "h1", Spec: `{}`, State: "stopped"}, nil,
			[]DiskRecord{{VMName: name, DiskName: "root", HostName: "h1", Path: "/disks/" + name + ".qcow2", StorageType: "local"}},
			[]NICRecord{{
				VMName: name, ID: DeterministicNICID(name, mac),
				NetworkName: "default", MAC: mac, Ordinal: 0,
			}}, nil, true,
		); err != nil {
			t.Fatalf("InsertVMWithHardware %q: %v", name, err)
		}
	}
	before := len(walEntries(t, c, "source"))

	cutover(t, c, "app", "app-next")

	entries := walEntries(t, c, "source")[before:]
	if len(entries) == 0 {
		t.Fatal("the cutover replicated nothing")
	}
	seen := 0
	for _, e := range entries {
		var stmts []Statement
		if err := json.Unmarshal([]byte(e.Stmts), &stmts); err != nil {
			t.Fatalf("decode entry seq=%d: %v", e.Seq, err)
		}
		for _, stmt := range stmts {
			seen++
			sh, _, err := parseResolved(stmt.SQL)
			if err != nil {
				t.Fatalf("parse %q: %v", stmt.SQL, err)
			}
			if sh.Kind == KindDelete {
				t.Errorf("the cutover replicates a HARD DELETE, which a receiver applies "+
					"unconditionally even when the write meant to replace the row does not land: %q", stmt.SQL)
			}
			if _, ok := LedgerLookup(stmtFingerprint(sh)); !ok {
				t.Errorf("the cutover replicates an unregistered shape (%s %s): %q",
					sh.Kind, sh.Table, stmt.SQL)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no statements inspected — the assertions above were vacuous")
	}
}

// RenameVM itself must refuse an occupied key rather than fail mid-batch on a
// UNIQUE constraint, and must refuse having changed nothing: in the cutover the
// caller has already torn down the replacement's predecessor, so a late failure
// is what turns this bug destructive.
func TestRenameVMRefusesAnOccupiedTargetKey(t *testing.T) {
	const mac = "52:54:00:aa:bb:01"
	// Each case seeds "app" (already tombstoned) so that exactly ONE key the
	// rename of "app-next" needs is held.
	cases := []struct {
		name  string
		table string
		seed  func(t *testing.T, c *Client)
	}{{
		name: "parent row", table: "vms",
		seed: func(t *testing.T, c *Client) {
			mustInsertVM(t, c, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
		},
	}, {
		name: "interface", table: "vm_interfaces",
		seed: func(t *testing.T, c *Client) {
			mustInsertVM(t, c, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"},
				[]InterfaceRecord{{VMName: "app", NetworkName: "default", Ordinal: 0, MAC: mac}}, nil)
		},
	}, {
		name: "disk", table: "vm_disks",
		seed: func(t *testing.T, c *Client) {
			mustInsertVM(t, c, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil,
				[]DiskRecord{{VMName: "app", DiskName: "root", HostName: "h1", Path: "/disks/a.qcow2", StorageType: "local"}})
		},
	}, {
		name: "NIC with the same MAC", table: "vm_nics",
		seed: func(t *testing.T, c *Client) {
			if err := InsertVMWithHardware(context.Background(), c,
				VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil,
				[]NICRecord{{VMName: "app", ID: DeterministicNICID("app", mac), NetworkName: "default", MAC: mac, Ordinal: 0}},
				nil, true); err != nil {
				t.Fatalf("InsertVMWithHardware: %v", err)
			}
		},
	}}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := testClient(t)
			ctx := context.Background()
			tc.seed(t, c)
			// The replacement mirrors the seeded child so their keys collide.
			switch tc.table {
			case "vm_interfaces":
				mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"},
					[]InterfaceRecord{{VMName: "app-next", NetworkName: "default", Ordinal: 0, MAC: mac}}, nil)
			case "vm_disks":
				mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil,
					[]DiskRecord{{VMName: "app-next", DiskName: "root", HostName: "h1", Path: "/disks/b.qcow2", StorageType: "local"}})
			case "vm_nics":
				if err := InsertVMWithHardware(ctx, c,
					VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil,
					[]NICRecord{{VMName: "app-next", ID: DeterministicNICID("app-next", mac), NetworkName: "default", MAC: mac, Ordinal: 0}},
					nil, true); err != nil {
					t.Fatalf("InsertVMWithHardware: %v", err)
				}
			default:
				mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "stopped"}, nil, nil)
			}
			if err := DeleteVM(ctx, c, "app"); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}

			// RenameVM must refuse, naming the table that holds the key, and must
			// leave the database untouched.
			before := vmTableSnapshot(t, c)
			err := RenameVM(ctx, c, "app-next", "app")
			if !errors.Is(err, ErrRenameTargetOccupied) {
				t.Fatalf("RenameVM error = %v, want ErrRenameTargetOccupied", err)
			}
			if after := vmTableSnapshot(t, c); after != before {
				t.Fatalf("a refused rename wrote to the database:\nbefore=%s\nafter =%s", before, after)
			}
			// DeleteVM tombstones the parent too, so the parent refusal above is
			// the one that fires first. Drive the CHILD key on its own by really
			// vacating the parent in the same batch — a first leg that moves the
			// parent tombstone and NO child — otherwise this test would pass with
			// every child check deleted.
			if tc.table != "vms" {
				cErr := execVMRekey(ctx, c, c.NowTS(),
					vmRekeyPass{
						oldName: "app", newName: "app.retired.childcheck",
						keep: func(string, string) bool { return false },
					},
					vmRekeyPass{oldName: "app-next", newName: "app", parentVacated: true})
				if !errors.Is(cErr, ErrRenameTargetOccupied) {
					t.Fatalf("child-key check error = %v, want ErrRenameTargetOccupied", cErr)
				}
				if !strings.Contains(cErr.Error(), tc.table) {
					t.Errorf("error %q does not name the colliding table %q", cErr, tc.table)
				}
				if after := vmTableSnapshot(t, c); after != before {
					t.Fatalf("a refused child rekey wrote to the database:\nbefore=%s\nafter =%s", before, after)
				}
			}

			// ReplaceVM resolves the very same collision, by moving that
			// tombstone aside — this is the case the fix exists for.
			if err := ReplaceVM(ctx, c, "app-next", "app", prepareCutover(t, c, "app", "app-next")); err != nil {
				t.Fatalf("ReplaceVM over a %s collision: %v", tc.table, err)
			}
			if vm, err := GetVM(ctx, c, "app"); err != nil || vm == nil {
				t.Fatalf(`no live VM named "app" after ReplaceVM: %+v err=%v`, vm, err)
			}
		})
	}
}

// A LIVE occupant is not a cutover — only DeleteVM may decide a workload can be
// tombstoned, so ReplaceVM must not do it implicitly.
func TestReplaceVMRefusesALiveOccupant(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	mustInsertVM(t, c, VMRecord{Name: "app", HostName: "h1", Spec: `{}`, State: "running"}, nil, nil)
	mustInsertVM(t, c, VMRecord{Name: "app-next", HostName: "h1", Spec: `{}`, State: "running"}, nil, nil)
	before := vmTableSnapshot(t, c)
	if err := ReplaceVM(ctx, c, "app-next", "app", prepareCutover(t, c, "app", "app-next")); err == nil {
		t.Fatal("ReplaceVM took the name of a live VM")
	}
	if after := vmTableSnapshot(t, c); after != before {
		t.Fatalf("a refused ReplaceVM wrote to the database:\nbefore=%s\nafter =%s", before, after)
	}
}

func mustInsertVM(t *testing.T, c *Client, vm VMRecord, ifaces []InterfaceRecord, disks []DiskRecord) {
	t.Helper()
	if err := InsertVM(context.Background(), c, vm, ifaces, disks); err != nil {
		t.Fatalf("InsertVM %q: %v", vm.Name, err)
	}
}

// vmTableSnapshot renders every VM row and child row, so a test can prove a
// refused call wrote nothing at all.
func vmTableSnapshot(t *testing.T, c *Client) string {
	t.Helper()
	ctx := context.Background()
	var b strings.Builder
	for _, q := range []string{
		`SELECT name, spec, updated_at, deleted_at FROM vms ORDER BY name`,
		`SELECT vm_name, network_name, updated_at, deleted_at FROM vm_interfaces ORDER BY vm_name, network_name`,
		`SELECT vm_name, disk_name, path, updated_at, deleted_at FROM vm_disks ORDER BY vm_name, disk_name`,
		`SELECT vm_name, id, mac, updated_at, deleted_at FROM vm_nics ORDER BY vm_name, id`,
	} {
		rows, err := c.Query(ctx, q)
		if err != nil {
			t.Fatalf("snapshot %q: %v", q, err)
		}
		for _, r := range rows {
			b.WriteString(r.String("vm_name") + "|" + r.String("name") + "|" +
				r.String("network_name") + r.String("disk_name") + r.String("id") + "|" +
				r.String("path") + r.String("mac") + r.String("spec") + "|" +
				r.String("updated_at") + "|" + r.String("deleted_at") + "\n")
		}
	}
	return b.String()
}
