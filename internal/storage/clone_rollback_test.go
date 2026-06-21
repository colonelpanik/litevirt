package storage

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// recordedCall captures one runner invocation.
type recordedCall struct {
	name string
	args []string
}

// stubRunner builds a cmdRunner that records every call and delegates the
// success/failure decision to fn (keyed on the subcommand, args[0]).
func stubRunner(fn func(sub string) ([]byte, error)) (cmdRunner, *[]recordedCall) {
	calls := &[]recordedCall{}
	r := func(_ context.Context, name string, args ...string) ([]byte, error) {
		*calls = append(*calls, recordedCall{name: name, args: args})
		sub := ""
		if len(args) > 0 {
			sub = args[0]
		}
		return fn(sub)
	}
	return r, calls
}

func subcommands(calls []recordedCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		if len(c.args) > 0 {
			out = append(out, c.args[0])
		}
	}
	return out
}

func hasSub(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// ── A1: Ceph CreateDisk must NOT return a blank disk on clone failure ─────────

func TestCephCreateDisk_CloneFailureRollsBackAndErrors(t *testing.T) {
	run, calls := stubRunner(func(sub string) ([]byte, error) {
		switch sub {
		case "create", "rm":
			return nil, nil // create succeeds; rollback rm succeeds
		case "clone":
			return []byte("rbd: clone: source snapshot not protected"), errors.New("exit status 1")
		}
		return nil, nil
	})
	d := &cephDriver{pool: "rbd", run: run}

	path, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName: "vm1", DiskName: "root", SizeBytes: 1 << 30, SourceImage: "rbd/golden@v1",
	})
	if err == nil {
		t.Fatalf("expected error on clone failure, got path=%q nil err", path)
	}
	if path != "" {
		t.Errorf("expected empty path on failure, got %q", path)
	}
	subs := subcommands(*calls)
	if !hasSub(subs, "create") || !hasSub(subs, "clone") {
		t.Errorf("expected create+clone attempts, got %v", subs)
	}
	if !hasSub(subs, "rm") {
		t.Errorf("expected rollback 'rm' of the empty image, got %v", subs)
	}
}

func TestCephCreateDisk_NoSourceImage_Succeeds(t *testing.T) {
	run, calls := stubRunner(func(sub string) ([]byte, error) { return nil, nil })
	d := &cephDriver{pool: "rbd", run: run}

	path, err := d.CreateDisk(context.Background(), DiskOptions{VMName: "vm1", DiskName: "root", SizeBytes: 1 << 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if path == "" {
		t.Error("expected a path")
	}
	if subs := subcommands(*calls); hasSub(subs, "clone") || hasSub(subs, "rm") {
		t.Errorf("no clone/rm expected when SourceImage is empty, got %v", subs)
	}
}

func TestCephCreateDisk_CloneSuccess_NoRollback(t *testing.T) {
	run, calls := stubRunner(func(sub string) ([]byte, error) { return nil, nil })
	d := &cephDriver{pool: "rbd", run: run}

	_, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName: "vm1", DiskName: "root", SizeBytes: 1 << 30, SourceImage: "rbd/golden@v1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subs := subcommands(*calls); hasSub(subs, "rm") {
		t.Errorf("no rollback expected on clone success, got %v", subs)
	}
}

// ── A2: ZFS CreateDisk must fail loudly on (unimplemented) source-image clone ──

func TestZFSCreateDisk_SourceImageUnimplemented(t *testing.T) {
	// run must never be reached — we reject before any zfs exec.
	run, calls := stubRunner(func(sub string) ([]byte, error) {
		t.Fatalf("zfs should not run for an unimplemented source-image clone (sub=%q)", sub)
		return nil, nil
	})
	d := &zfsDriver{dataset: "tank/litevirt", run: run}

	path, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName: "vm1", DiskName: "root", SizeBytes: 1 << 30, SourceImage: "tank/litevirt/golden@v1",
	})
	if err == nil {
		t.Fatalf("expected error, got path=%q nil err", path)
	}
	if !errors.Is(err, ErrUnimplemented) {
		t.Errorf("expected ErrUnimplemented, got %v", err)
	}
	if path != "" {
		t.Errorf("expected empty path, got %q", path)
	}
	if len(*calls) != 0 {
		t.Errorf("expected no zfs calls, got %v", subcommands(*calls))
	}
}

// ── A3: ZFS snapshot-roll must surface errors instead of swallowing them ──────

func TestZFSRollPrev_Success(t *testing.T) {
	run, calls := stubRunner(func(sub string) ([]byte, error) { return nil, nil })
	d := &zfsDriver{dataset: "tank", run: run}

	if err := d.rollPrevSnapshot(context.Background(), "tank/x@litevirt-replicate-prev"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := subcommands(*calls)
	want := []string{"snapshot", "destroy", "rename"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("roll sequence = %v, want %v", got, want)
	}
}

func TestZFSRollPrev_DestroyRealErrorAborts(t *testing.T) {
	run, calls := stubRunner(func(sub string) ([]byte, error) {
		if sub == "destroy" {
			return []byte("cannot destroy: dataset is busy"), errors.New("exit status 1")
		}
		return nil, nil
	})
	d := &zfsDriver{dataset: "tank", run: run}

	err := d.rollPrevSnapshot(context.Background(), "tank/x@litevirt-replicate-prev")
	if err == nil {
		t.Fatal("expected error when destroy fails for a real reason")
	}
	if !strings.Contains(err.Error(), "destroy") {
		t.Errorf("error should mention destroy, got %v", err)
	}
	if subs := subcommands(*calls); hasSub(subs, "rename") {
		t.Error("rename must NOT run after a failed destroy (would leave a stale base)")
	}
}

func TestZFSRollPrev_FirstRunToleratesMissingPrev(t *testing.T) {
	run, _ := stubRunner(func(sub string) ([]byte, error) {
		if sub == "destroy" {
			// First replication: prev snapshot doesn't exist yet — tolerated.
			return []byte("could not find any snapshots to destroy; does not exist"), errors.New("exit status 1")
		}
		return nil, nil
	})
	d := &zfsDriver{dataset: "tank", run: run}

	if err := d.rollPrevSnapshot(context.Background(), "tank/x@litevirt-replicate-prev"); err != nil {
		t.Fatalf("missing-prev on first run should be tolerated, got %v", err)
	}
}
