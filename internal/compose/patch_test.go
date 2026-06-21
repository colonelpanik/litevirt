package compose

import (
	"strings"
	"testing"
)

func TestPatchDiskStorage_Longform(t *testing.T) {
	in := "name: s\nvms:\n  db:\n    image: ubuntu\n    disks:\n      data:\n        size: 100G\n        storage: hot\n"
	out, changed, err := PatchDiskStorage(in, "db", "data", "nvme-2t")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if !strings.Contains(out, "storage: nvme-2t") || strings.Contains(out, "storage: hot") {
		t.Fatalf("storage not replaced:\n%s", out)
	}
	if !strings.Contains(out, "size: 100G") {
		t.Fatalf("size lost:\n%s", out)
	}
}

func TestPatchDiskStorage_ShortformExpands(t *testing.T) {
	in := "name: s\nvms:\n  db:\n    image: ubuntu\n    disks:\n      data: 100G\n"
	out, changed, err := PatchDiskStorage(in, "db", "data", "nvme-2t")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	// Re-parse: the expanded shortform must round-trip to size + storage.
	f, perr := ParseBytes([]byte(out))
	if perr != nil {
		t.Fatalf("reparse: %v\n%s", perr, out)
	}
	d := f.VMs["db"].Disks["data"]
	if d.Storage != "nvme-2t" {
		t.Errorf("storage = %q, want nvme-2t\n%s", d.Storage, out)
	}
	if d.Size != "100G" {
		t.Errorf("size = %q, want 100G (lost on expand)\n%s", d.Size, out)
	}
}

func TestPatchDiskStorage_NoopWhenAlreadySet(t *testing.T) {
	in := "name: s\nvms:\n  db:\n    image: ubuntu\n    disks:\n      data:\n        size: 100G\n        storage: nvme-2t\n"
	out, changed, err := PatchDiskStorage(in, "db", "data", "nvme-2t")
	if err != nil || changed {
		t.Fatalf("expected no-op: changed=%v err=%v", changed, err)
	}
	if out != in {
		t.Errorf("no-op must return input unchanged")
	}
}

func TestPatchDiskStorage_MissingVM(t *testing.T) {
	// When the VM itself isn't in the compose there's nothing to patch.
	in := "name: s\nvms:\n  db:\n    image: ubuntu\n    disks:\n      data: 100G\n"
	_, changed, err := PatchDiskStorage(in, "web", "data", "x")
	if err != nil || changed {
		t.Errorf("missing VM: expected no change, got changed=%v err=%v", changed, err)
	}
}

func TestPatchDiskStorage_CreatesImplicitDisk(t *testing.T) {
	// A VM with no disks: block at all (implicit root disk from the image):
	// moving its disk must materialize disks.<name>.storage so the placement
	// survives `compose up`.
	t.Run("no disks block", func(t *testing.T) {
		in := "name: s\nvms:\n  db:\n    image: ubuntu\n"
		out, changed, err := PatchDiskStorage(in, "db", "root", "nvme-2t")
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		f, perr := ParseBytes([]byte(out))
		if perr != nil {
			t.Fatalf("reparse: %v\n%s", perr, out)
		}
		if got := f.VMs["db"].Disks["root"].Storage; got != "nvme-2t" {
			t.Fatalf("disks.root.storage = %q, want nvme-2t\n%s", got, out)
		}
	})

	// A VM with a disks: block that doesn't yet list the moved disk: add it,
	// preserving the existing entries.
	t.Run("disk absent from existing block", func(t *testing.T) {
		in := "name: s\nvms:\n  db:\n    image: ubuntu\n    disks:\n      data: 100G\n"
		out, changed, err := PatchDiskStorage(in, "db", "root", "nvme-2t")
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v", changed, err)
		}
		f, perr := ParseBytes([]byte(out))
		if perr != nil {
			t.Fatalf("reparse: %v\n%s", perr, out)
		}
		if got := f.VMs["db"].Disks["root"].Storage; got != "nvme-2t" {
			t.Fatalf("created disks.root.storage = %q, want nvme-2t\n%s", got, out)
		}
		if _, ok := f.VMs["db"].Disks["data"]; !ok {
			t.Fatalf("existing disk 'data' lost:\n%s", out)
		}
	})
}
