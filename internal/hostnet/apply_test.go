package hostnet

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// fakeSystem records every host-touching action so the tests assert the
// PROTOCOL — ordering, refusals, rollback — not netplan mechanics.
type fakeSystem struct {
	events []string

	file       string
	fileExists bool
	foreign    map[string]string
	iface      string // cluster interface for any ip

	netplanErr error // NetplanAvailable result
	applyErr   error // ApplyWithRevert hard error
	confirmErr error // ConfirmConnectivity result
	writeErr   error // WriteManagedFile failure

	// onWrite runs at the START of WriteManagedFile, so a test can assert
	// what must already be durable by the time the host's config changes.
	onWrite func()
}

func (f *fakeSystem) NetplanAvailable() error { return f.netplanErr }
func (f *fakeSystem) ReadManagedFile() (string, bool, error) {
	return f.file, f.fileExists, nil
}
func (f *fakeSystem) WriteManagedFile(content string) error {
	if f.onWrite != nil {
		f.onWrite()
	}
	if f.writeErr != nil {
		return f.writeErr
	}
	f.events = append(f.events, "write-file")
	f.file, f.fileExists = content, true
	return nil
}
func (f *fakeSystem) RemoveManagedFile() error {
	f.events = append(f.events, "remove-file")
	f.file, f.fileExists = "", false
	return nil
}
func (f *fakeSystem) ForeignFiles() (map[string]string, error) { return f.foreign, nil }
func (f *fakeSystem) ClusterInterface(string) (string, error)  { return f.iface, nil }
func (f *fakeSystem) ApplyWithRevert(ctx context.Context, _ time.Duration, confirm func(context.Context) error) (bool, error) {
	f.events = append(f.events, "apply")
	if f.applyErr != nil {
		return false, f.applyErr
	}
	if err := confirm(ctx); err != nil {
		f.events = append(f.events, "revert")
		return false, nil
	}
	f.events = append(f.events, "accept")
	return true, nil
}
func (f *fakeSystem) ConfirmConnectivity(context.Context) error { return f.confirmErr }

// journaledFakeSystem wraps the journal so the test can see write ordering.
type testRig struct {
	db  *corrosion.Client
	sys *fakeSystem
	ap  *Applier
}

func newRig(t *testing.T) *testRig {
	t.Helper()
	db, err := corrosion.NewTestClient()
	if err != nil {
		t.Fatalf("NewTestClient: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	j, err := opjournal.Open(t.TempDir())
	if err != nil {
		t.Fatalf("journal: %v", err)
	}
	sys := &fakeSystem{iface: "net1"}
	return &testRig{db: db, sys: sys, ap: &Applier{
		DB: db, HostName: "h1", AdvertiseIP: "10.77.0.11",
		Journal: j, Sys: sys, RevertWindow: time.Second,
	}}
}

func (r *testRig) upsert(t *testing.T, rec corrosion.HostNetworkRecord) {
	t.Helper()
	rec.HostName = "h1"
	if err := corrosion.UpsertHostNetwork(context.Background(), r.db, rec); err != nil {
		t.Fatalf("upsert %s: %v", rec.Name, err)
	}
}

func (r *testRig) row(t *testing.T, name string) corrosion.HostNetworkRecord {
	t.Helper()
	rec, err := corrosion.GetHostNetwork(context.Background(), r.db, "h1", name)
	if err != nil || rec == nil {
		t.Fatalf("row %s: rec=%v err=%v", name, rec, err)
	}
	return *rec
}

func TestApplyHappyPath(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.upsert(t, corrosion.HostNetworkRecord{Name: "vmbr0", Kind: "bridge", Members: []string{"eth1"}})

	// The journal record must be durable BEFORE the host's config changes —
	// that ordering is the crash-recovery guarantee, so it is pinned here at
	// the moment of the first file write.
	journalFirst := false
	r.sys.onWrite = func() {
		_, found, _ := r.ap.Journal.Read(r.ap.journalID())
		journalFirst = found
	}
	if err := r.ap.Apply(ctx, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if !journalFirst {
		t.Fatal("the journal entry must exist before the managed file is written")
	}
	r.sys.onWrite = nil
	// Protocol order: the durable journal record precedes the file write,
	// which precedes the apply — there is no instant of changed-config
	// without a restore record.
	got := strings.Join(r.sys.events, ",")
	if got != "write-file,apply,accept" {
		t.Fatalf("event order: %s", got)
	}
	if !strings.Contains(r.sys.file, "vmbr0:") {
		t.Fatalf("managed file not rendered: %q", r.sys.file)
	}
	rec := r.row(t, "vmbr0")
	if rec.State != corrosion.HostNetworkApplied || rec.Generation != 1 {
		t.Fatalf("after apply: state=%q generation=%d", rec.State, rec.Generation)
	}
	if _, found, _ := r.ap.Journal.Read(r.ap.journalID()); found {
		t.Fatal("journal entry must be consumed by a completed apply")
	}

	// Idempotent re-apply: the file already matches → no netplan run, and the
	// generation is NOT re-minted (it counts confirmed applies, not calls).
	r.sys.events = nil
	if err := r.ap.Apply(ctx, ""); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if len(r.sys.events) != 0 {
		t.Fatalf("a no-op apply must not touch the system: %v", r.sys.events)
	}
	if rec := r.row(t, "vmbr0"); rec.Generation != 1 {
		t.Fatalf("no-op apply re-minted the generation: %d", rec.Generation)
	}
}

func TestApplyRollsBackOnFailedConfirm(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.upsert(t, corrosion.HostNetworkRecord{Name: "vmbr0", Kind: "bridge"})
	r.sys.file, r.sys.fileExists = "# previous\n", true
	r.sys.confirmErr = errors.New("gateway unreachable")

	err := r.ap.Apply(ctx, "")
	if err == nil {
		t.Fatal("a failed confirm must surface as an error")
	}
	if r.sys.file != "# previous\n" {
		t.Fatalf("the previous file must be restored, got %q", r.sys.file)
	}
	rec := r.row(t, "vmbr0")
	if rec.State != corrosion.HostNetworkRolledBack || rec.Generation != 0 {
		t.Fatalf("after rollback: state=%q generation=%d", rec.State, rec.Generation)
	}
	if rec.LastError == "" {
		t.Fatal("the rollback must record its cause")
	}
	if _, found, _ := r.ap.Journal.Read(r.ap.journalID()); found {
		t.Fatal("a settled rollback must consume the journal entry")
	}

	// When ManagedFile did NOT exist before, restore means REMOVE — leaving
	// our failed render behind would re-apply it on the next boot.
	r2 := newRig(t)
	r2.upsert(t, corrosion.HostNetworkRecord{Name: "vmbr0", Kind: "bridge"})
	r2.sys.confirmErr = errors.New("gateway unreachable")
	if err := r2.ap.Apply(ctx, ""); err == nil {
		t.Fatal("expected rollback error")
	}
	if r2.sys.fileExists {
		t.Fatalf("restore of a previously-absent file must remove it, got %q", r2.sys.file)
	}
}

func TestApplyRefusals(t *testing.T) {
	ctx := context.Background()

	// Foreign-file conflict: refused, nothing touched.
	r := newRig(t)
	r.upsert(t, corrosion.HostNetworkRecord{Name: "eth2", Kind: "ethernet"})
	r.sys.foreign = map[string]string{"/etc/netplan/50-cloud-init.yaml": "network:\n  version: 2\n  ethernets:\n    eth2: {dhcp4: true}\n"}
	err := r.ap.Apply(ctx, "")
	if err == nil || !strings.Contains(err.Error(), "50-cloud-init.yaml") {
		t.Fatalf("conflict refusal must name the file: %v", err)
	}
	if len(r.sys.events) != 0 {
		t.Fatalf("a refused apply must not touch the system: %v", r.sys.events)
	}
	if rec := r.row(t, "eth2"); rec.State != corrosion.HostNetworkDesired {
		t.Fatalf("a refused apply must not move row state: %q", rec.State)
	}

	// Self-cutoff: refused without force; refused with the WRONG force name;
	// applies when force names the cluster interface.
	r = newRig(t)
	r.upsert(t, corrosion.HostNetworkRecord{Name: "vmbr0", Kind: "bridge", Members: []string{"net1"}})
	if err := r.ap.Apply(ctx, ""); err == nil || !strings.Contains(err.Error(), "net1") {
		t.Fatalf("cutoff refusal must name the carrier: %v", err)
	}
	if err := r.ap.Apply(ctx, "eth9"); err == nil {
		t.Fatal("force naming the wrong interface must still refuse")
	}
	if err := r.ap.Apply(ctx, "net1"); err != nil {
		t.Fatalf("force naming the carrier must proceed: %v", err)
	}
	if rec := r.row(t, "vmbr0"); rec.State != corrosion.HostNetworkApplied {
		t.Fatalf("forced apply outcome: %q", rec.State)
	}

	// Non-netplan host: refused before anything else.
	r = newRig(t)
	r.upsert(t, corrosion.HostNetworkRecord{Name: "vmbr0", Kind: "bridge"})
	r.sys.netplanErr = errors.New("no /etc/netplan")
	if err := r.ap.Apply(ctx, ""); err == nil || !strings.Contains(err.Error(), "netplan-managed") {
		t.Fatalf("non-netplan refusal: %v", err)
	}

	// In-flight barrier: an existing journal entry refuses a second apply.
	r = newRig(t)
	r.upsert(t, corrosion.HostNetworkRecord{Name: "vmbr0", Kind: "bridge"})
	if err := r.ap.Journal.Write(opjournal.Entry{
		OperationID: r.ap.journalID(), Kind: journalKind, ResourceID: "h1", Stage: "applying",
		Artifacts: map[string]string{artPrevExists: "false"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.ap.Apply(ctx, ""); err == nil || !strings.Contains(err.Error(), "in flight") {
		t.Fatalf("in-flight barrier: %v", err)
	}
}

func TestRecoverRestoresACrashedApply(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.upsert(t, corrosion.HostNetworkRecord{Name: "vmbr0", Kind: "bridge"})

	// Simulate the crash window faithfully: rows had been marked applying and
	// the journal written before the file changed — the daemon died after
	// that, before any outcome. (Recovery deliberately rolls back only rows
	// stuck 'applying'; rows in other states did not belong to the attempt.)
	if err := corrosion.SetHostNetworkState(ctx, r.db, "h1", "vmbr0", corrosion.HostNetworkApplying, ""); err != nil {
		t.Fatal(err)
	}
	if err := r.ap.Journal.Write(opjournal.Entry{
		OperationID: r.ap.journalID(), Kind: journalKind, ResourceID: "h1", Stage: "applying",
		Artifacts: map[string]string{artPrevFile: "# previous\n", artPrevExists: "true"},
	}); err != nil {
		t.Fatal(err)
	}
	r.sys.file, r.sys.fileExists = "# half-applied render\n", true

	if err := r.ap.Recover(ctx); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if r.sys.file != "# previous\n" {
		t.Fatalf("recovery must restore the previous file, got %q", r.sys.file)
	}
	rec := r.row(t, "vmbr0")
	if rec.State != corrosion.HostNetworkRolledBack || !strings.Contains(rec.LastError, "crashed") {
		t.Fatalf("recovery must record the rollback: %+v", rec)
	}
	if _, found, _ := r.ap.Journal.Read(r.ap.journalID()); found {
		t.Fatal("recovery must consume the journal entry")
	}

	// No journal entry → Recover is a no-op.
	r.sys.events = nil
	if err := r.ap.Recover(ctx); err != nil || len(r.sys.events) != 0 {
		t.Fatalf("idle recover must do nothing: err=%v events=%v", err, r.sys.events)
	}
}

// A failed apply must not smear rolled_back onto rows it wasn't changing: an
// applied neighbor's config is IN the restored file, so its row stays
// truthfully applied. Found on the lab — a refused new bridge stamped
// rolled_back onto an untouched, still-live one.
func TestFailedApplyLeavesAppliedNeighborsAlone(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	// vmbr0 applied and live.
	r.upsert(t, corrosion.HostNetworkRecord{Name: "vmbr0", Kind: "bridge"})
	if err := r.ap.Apply(ctx, ""); err != nil {
		t.Fatalf("first apply: %v", err)
	}

	// A NEW intent fails its confirm.
	r.upsert(t, corrosion.HostNetworkRecord{Name: "vmbr1", Kind: "bridge"})
	r.sys.confirmErr = errors.New("gateway unreachable")
	if err := r.ap.Apply(ctx, ""); err == nil {
		t.Fatal("expected rollback error")
	}

	if rec := r.row(t, "vmbr1"); rec.State != corrosion.HostNetworkRolledBack {
		t.Fatalf("the changing row must be rolled_back: %q", rec.State)
	}
	rec := r.row(t, "vmbr0")
	if rec.State != corrosion.HostNetworkApplied || rec.Generation != 1 {
		t.Fatalf("the untouched applied neighbor must STAY applied: state=%q gen=%d", rec.State, rec.Generation)
	}
	if !strings.Contains(r.sys.file, "vmbr0:") || strings.Contains(r.sys.file, "vmbr1:") {
		t.Fatalf("restored file must carry vmbr0 only: %q", r.sys.file)
	}
}
