package libvirt

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// redirectSwtpmBase points libvirtSwtpmBase at a temp dir for the test (the real
// /var/lib/libvirt/swtpm is root-owned).
func redirectSwtpmBase(t *testing.T) string {
	t.Helper()
	old := libvirtSwtpmBase
	base := t.TempDir()
	libvirtSwtpmBase = base
	t.Cleanup(func() { libvirtSwtpmBase = old })
	return base
}

func seedFirmware(t *testing.T, dataDir, vm, uuid string, nvram, tpm bool) {
	t.Helper()
	if nvram {
		p := NvramPath(dataDir, vm)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("NVRAM-"+vm), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if tpm {
		d := filepath.Join(LibvirtSwtpmDir(uuid), "tpm2")
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "tpm2-00.permall"), []byte("TPM-"+uuid), 0o600); err != nil {
			t.Fatal(err)
		}
		// swtpm leaves a runtime .lock file in the state dir; it must NOT be carried.
		if err := os.WriteFile(filepath.Join(d, ".lock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFirmwareBundle_RoundTrip(t *testing.T) {
	redirectSwtpmBase(t)
	for _, tc := range []struct{ nvram, tpm bool }{
		{true, true}, {true, false}, {false, true},
	} {
		src := t.TempDir()
		seedFirmware(t, src, "src", "uuid-src", tc.nvram, tc.tpm)

		var buf bytes.Buffer
		has, err := WriteFirmwareBundle(src, "src", "uuid-src", &buf)
		if err != nil {
			t.Fatalf("write bundle (nvram=%v tpm=%v): %v", tc.nvram, tc.tpm, err)
		}
		if !has {
			t.Fatalf("expected state present (nvram=%v tpm=%v)", tc.nvram, tc.tpm)
		}

		// Restore into a DIFFERENT vm name + uuid (proves name/uuid re-addressing).
		dst := t.TempDir()
		if err := ReadFirmwareBundle(&buf, dst, "dst", "uuid-dst"); err != nil {
			t.Fatalf("read bundle: %v", err)
		}
		if tc.nvram {
			got, _ := os.ReadFile(NvramPath(dst, "dst"))
			if string(got) != "NVRAM-src" {
				t.Errorf("nvram restored = %q, want NVRAM-src", got)
			}
		}
		if tc.tpm {
			got, _ := os.ReadFile(filepath.Join(LibvirtSwtpmDir("uuid-dst"), "tpm2", "tpm2-00.permall"))
			if string(got) != "TPM-uuid-src" {
				t.Errorf("swtpm restored = %q, want TPM-uuid-src", got)
			}
			// The per-UUID dir must be world-traversable (0711) so the dropped-
			// privilege swtpm user can reach its state (live-drill regression).
			fi, err := os.Stat(LibvirtSwtpmDir("uuid-dst"))
			if err != nil {
				t.Fatalf("stat restored swtpm dir: %v", err)
			}
			if perm := fi.Mode().Perm(); perm != 0o711 {
				t.Errorf("restored swtpm dir mode = %o, want 711", perm)
			}
			// The runtime .lock must NOT have been carried into the restore.
			if _, err := os.Stat(filepath.Join(LibvirtSwtpmDir("uuid-dst"), "tpm2", ".lock")); !os.IsNotExist(err) {
				t.Errorf("restored swtpm state must not contain a .lock file (err=%v)", err)
			}
		}
	}
}

func TestWriteFirmwareBundle_NoState(t *testing.T) {
	redirectSwtpmBase(t)
	has, err := WriteFirmwareBundle(t.TempDir(), "novm", "nouuid", &bytes.Buffer{})
	if err != nil || has {
		t.Fatalf("expected (false,nil) for a VM with no firmware state, got (%v,%v)", has, err)
	}
}

func TestWipeFirmwareState(t *testing.T) {
	redirectSwtpmBase(t)
	dataDir := t.TempDir()
	seedFirmware(t, dataDir, "vm", "uuid-w", true, true)
	if !HasNvram(dataDir, "vm") || !HasTPMState("uuid-w") {
		t.Fatal("seed failed")
	}
	WipeFirmwareState(dataDir, "vm", "uuid-w")
	if HasNvram(dataDir, "vm") {
		t.Error("nvram not wiped")
	}
	if HasTPMState("uuid-w") {
		t.Error("swtpm state not wiped")
	}
}

func TestReadFirmwareBundle_RejectsOversizedNvram(t *testing.T) {
	redirectSwtpmBase(t)
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	// Header claims a huge size; actual data is small. The size check must fire.
	tw.WriteHeader(&tar.Header{Name: "nvram", Mode: 0o600, Size: 128 << 20, Typeflag: tar.TypeReg})
	tw.Write([]byte("small"))
	tw.Close()
	if err := ReadFirmwareBundle(&b, t.TempDir(), "vm", "uuid"); err == nil {
		t.Fatal("expected rejection of oversized nvram member, got nil")
	}
}

func TestRestore_OverExistingState(t *testing.T) {
	redirectSwtpmBase(t)
	// Bundle from a source.
	src := t.TempDir()
	seedFirmware(t, src, "src", "uuid-s", true, true)
	var buf bytes.Buffer
	if _, err := WriteFirmwareBundle(src, "src", "uuid-s", &buf); err != nil {
		t.Fatal(err)
	}
	// Destination already has DIFFERENT firmware state — restore must swap it.
	dst := t.TempDir()
	seedFirmware(t, dst, "dst", "uuid-d", true, true)
	os.WriteFile(NvramPath(dst, "dst"), []byte("OLD-NVRAM"), 0o600)
	if err := ReadFirmwareBundle(&buf, dst, "dst", "uuid-d"); err != nil {
		t.Fatalf("restore over existing: %v", err)
	}
	got, _ := os.ReadFile(NvramPath(dst, "dst"))
	if string(got) != "NVRAM-src" {
		t.Errorf("nvram after swap = %q, want NVRAM-src", got)
	}
	// No backup files left behind on success.
	if _, err := os.Stat(NvramPath(dst, "dst") + ".bak"); err == nil {
		t.Error("nvram .bak left behind after successful swap")
	}
	if _, err := os.Stat(LibvirtSwtpmDir("uuid-d") + ".bak"); err == nil {
		t.Error("swtpm .bak left behind after successful swap")
	}
}

func TestRetainedFirmwareMarker(t *testing.T) {
	redirectSwtpmBase(t)
	dataDir := t.TempDir()
	if _, ok := ReadRetainedFirmwareMarker(dataDir, "vm"); ok {
		t.Fatal("unexpected marker before write")
	}
	if err := WriteRetainedFirmwareMarker(dataDir, "vm", "uuid-keep"); err != nil {
		t.Fatal(err)
	}
	got, ok := ReadRetainedFirmwareMarker(dataDir, "vm")
	if !ok || got != "uuid-keep" {
		t.Fatalf("marker = %q,%v, want uuid-keep,true", got, ok)
	}
	// WipeFirmwareState clears the marker too.
	WipeFirmwareState(dataDir, "vm", "uuid-keep")
	if _, ok := ReadRetainedFirmwareMarker(dataDir, "vm"); ok {
		t.Error("marker not removed by WipeFirmwareState")
	}
}

// ReadFirmwareBundle must reject untrusted/slip entries (a backup-repo bundle).
func TestReadFirmwareBundle_RejectsSlip(t *testing.T) {
	redirectSwtpmBase(t)
	mk := func(build func(tw *tar.Writer)) *bytes.Buffer {
		var b bytes.Buffer
		tw := tar.NewWriter(&b)
		build(tw)
		tw.Close()
		return &b
	}
	cases := map[string]*bytes.Buffer{
		"escaping swtpm path": mk(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "swtpm/../../etc/evil", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}),
		"dotdot-prefixed nvram": mk(func(tw *tar.Writer) {
			// Must be rejected, NOT silently re-rooted to "nvram".
			tw.WriteHeader(&tar.Header{Name: "../nvram", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}),
		"absolute nvram": mk(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "/nvram", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}),
		"symlink member": mk(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "nvram", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink})
		}),
		"unexpected entry": mk(func(tw *tar.Writer) {
			tw.WriteHeader(&tar.Header{Name: "evil", Mode: 0o600, Size: 1, Typeflag: tar.TypeReg})
			tw.Write([]byte("x"))
		}),
	}
	for name, buf := range cases {
		if err := ReadFirmwareBundle(buf, t.TempDir(), "vm", "uuid-x"); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
}
