package storage

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// fakeRBD models the one rbd semantic this test turns on: `rbd clone` refuses a
// destination that already exists. A runner that accepts every subcommand would
// pass no matter what order CreateDisk issues them in, which is exactly how the
// original ordering defect survived the existing tests.
type fakeRBD struct {
	images map[string]bool // "pool/image" → exists
	calls  []string        // subcommands in the order they were issued
}

func newFakeRBD(existing ...string) *fakeRBD {
	f := &fakeRBD{images: map[string]bool{}}
	for _, e := range existing {
		f.images[e] = true
	}
	return f
}

func (f *fakeRBD) run(_ context.Context, _ string, args ...string) ([]byte, error) {
	// Skip the auth flags rbdArgs prepends (--id/--conf/--keyring, each with a value).
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "--") {
		i += 2
	}
	if i >= len(args) {
		return nil, fmt.Errorf("no subcommand in %v", args)
	}
	sub := args[i]
	rest := args[i+1:]
	f.calls = append(f.calls, sub)

	switch sub {
	case "create":
		// The destination is the last positional argument.
		dest := rest[len(rest)-1]
		if f.images[dest] {
			return []byte("rbd: create error: (17) File exists"), fmt.Errorf("exit status 17")
		}
		f.images[dest] = true
		return nil, nil
	case "clone":
		src, dest := rest[0], rest[1]
		if !f.images[strings.SplitN(src, "@", 2)[0]] {
			return []byte("rbd: error opening source image"), fmt.Errorf("exit status 2")
		}
		if f.images[dest] {
			return []byte("rbd: clone error: (17) File exists"), fmt.Errorf("exit status 17")
		}
		f.images[dest] = true
		return nil, nil
	case "rm":
		dest := rest[len(rest)-1]
		delete(f.images, dest)
		return nil, nil
	}
	return nil, nil
}

// TestCephCreateDisk_CloneDoesNotPreCreateTheDestination is the #204 regression.
// CreateDisk used to run `rbd create <name>` unconditionally and then
// `rbd clone <src> <name>` onto that same name, so every image-backed VM
// creation on ceph failed with "File exists".
func TestCephCreateDisk_CloneDoesNotPreCreateTheDestination(t *testing.T) {
	f := newFakeRBD("litevirt/ubuntu-24.04")
	d := &cephDriver{pool: "litevirt", opts: map[string]string{}, run: f.run}

	path, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName:      "vm1",
		DiskName:    "root",
		SizeBytes:   10 << 30,
		SourceImage: "litevirt/ubuntu-24.04@base",
	})
	if err != nil {
		t.Fatalf("clone-from-image create failed: %v (calls: %v)", err, f.calls)
	}
	if want := "rbd:litevirt/vm1-root"; path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	for _, c := range f.calls {
		if c == "create" {
			t.Errorf("issued `rbd create` on the clone path; calls: %v", f.calls)
		}
	}
	if !f.images["litevirt/vm1-root"] {
		t.Errorf("destination image was not created; calls: %v", f.calls)
	}
}

// A plain (no source image) create must still go through `rbd create`.
func TestCephCreateDisk_WithoutASourceStillCreates(t *testing.T) {
	f := newFakeRBD()
	d := &cephDriver{pool: "litevirt", opts: map[string]string{}, run: f.run}

	if _, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName: "vm2", DiskName: "data", SizeBytes: 1 << 30,
	}); err != nil {
		t.Fatalf("plain create failed: %v (calls: %v)", err, f.calls)
	}
	if len(f.calls) != 1 || f.calls[0] != "create" {
		t.Errorf("calls = %v, want exactly one create", f.calls)
	}
	if !f.images["litevirt/vm2-data"] {
		t.Error("destination image was not created")
	}
}

// rbd can only clone a SNAPSHOT. A bare image name (which is what the VM create
// path passes today — spec.Image, e.g. "ubuntu-24.04") must be refused BEFORE
// anything is allocated, rather than leaving an orphan image behind like the
// create-first ordering did.
func TestCephCreateDisk_RefusesANonSnapshotSourceWithoutAllocating(t *testing.T) {
	f := newFakeRBD("litevirt/ubuntu-24.04")
	d := &cephDriver{pool: "litevirt", opts: map[string]string{}, run: f.run}

	_, err := d.CreateDisk(context.Background(), DiskOptions{
		VMName: "vm3", DiskName: "root", SizeBytes: 1 << 30,
		SourceImage: "ubuntu-24.04",
	})
	if err == nil {
		t.Fatalf("expected a refusal for a non-snapshot source; calls: %v", f.calls)
	}
	if len(f.calls) != 0 {
		t.Errorf("refusal allocated something first; calls: %v", f.calls)
	}
	if f.images["litevirt/vm3-root"] {
		t.Error("destination image was left behind by a refused create")
	}
}
