package safename

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	good := []string{"vm1", "my-vm", "my_vm.qcow2", "A.B-C_1", "_default", strings.Repeat("a", maxNameLen)}
	for _, s := range good {
		if err := ValidateName(s); err != nil {
			t.Errorf("ValidateName(%q) = %v, want nil", s, err)
		}
	}
	bad := []string{"", ".", "..", "a/b", "../x", "/abs", "a\x00b", "a b", "café", "a:b", strings.Repeat("a", maxNameLen+1)}
	for _, s := range bad {
		if err := ValidateName(s); err == nil {
			t.Errorf("ValidateName(%q) = nil, want error", s)
		}
	}
}

func TestTypedWrappers(t *testing.T) {
	if err := ValidateVMName("ok"); err != nil {
		t.Errorf("ValidateVMName ok: %v", err)
	}
	if err := ValidateDiskName("../escape"); err == nil {
		t.Error("ValidateDiskName should reject traversal")
	}
	if err := ValidatePoolName("a/b"); err == nil {
		t.Error("ValidatePoolName should reject slash")
	}
}

func TestCanonicalProjectName(t *testing.T) {
	cases := map[string]string{
		"":                "/",
		"/":               "/",
		"_default":        "/_default",
		"/_default":       "/_default",
		"acme":            "/acme",
		"acme/team-foo":   "/acme/team-foo",
		"/acme/team-foo":  "/acme/team-foo",
		"/acme/team-foo/": "/acme/team-foo",
		"Acme/Team":       "/Acme/Team", // uppercase preserved (compat)
	}
	for in, want := range cases {
		got, err := CanonicalProjectName(in)
		if err != nil {
			t.Errorf("CanonicalProjectName(%q) error: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("CanonicalProjectName(%q) = %q, want %q", in, got, want)
		}
	}
	bad := []string{"acme/../etc", "a//b", "acme/..", "../x", "a/./b", "ok/bad name"}
	for _, in := range bad {
		if _, err := CanonicalProjectName(in); err == nil {
			t.Errorf("CanonicalProjectName(%q) = nil error, want error", in)
		}
	}
}

func TestProjectRBACPath(t *testing.T) {
	cases := map[string]string{
		"/":             "/projects",
		"/_default":     "/projects/_default",
		"/acme/team":    "/projects/acme/team",
	}
	for in, want := range cases {
		if got := ProjectRBACPath(in); got != want {
			t.Errorf("ProjectRBACPath(%q) = %q, want %q", in, got, want)
		}
	}
	// End-to-end: the default project must produce the exact legacy path.
	canon, _ := CanonicalProjectName("_default")
	if got := ProjectRBACPath(canon) + "/vms/web"; got != "/projects/_default/vms/web" {
		t.Errorf("default vm path = %q", got)
	}
}

func TestValidateChunkID(t *testing.T) {
	if err := ValidateChunkID(strings.Repeat("a", 64)); err != nil {
		t.Errorf("64 hex should be valid: %v", err)
	}
	for _, s := range []string{"", "ABCD", strings.Repeat("a", 63), strings.Repeat("g", 64), strings.Repeat("A", 64), "../" + strings.Repeat("a", 61)} {
		if err := ValidateChunkID(s); err == nil {
			t.Errorf("ValidateChunkID(%q) = nil, want error", s)
		}
	}
}

func TestValidateTimestamp(t *testing.T) {
	if err := ValidateTimestamp("2026-06-26T12:00:00Z"); err != nil {
		t.Errorf("RFC3339 should be valid: %v", err)
	}
	for _, s := range []string{"", "2026-06-26", "2026/06/26T12:00:00Z", "../etc", "12:00:00"} {
		if err := ValidateTimestamp(s); err == nil {
			t.Errorf("ValidateTimestamp(%q) = nil, want error", s)
		}
	}
}

func TestSafeJoin(t *testing.T) {
	root := "/srv/data"
	good := map[string]string{
		"a.qcow2":   "/srv/data/a.qcow2",
		"sub/b.iso": "/srv/data/sub/b.iso",
	}
	for in, want := range good {
		got, err := SafeJoin(root, in)
		if err != nil || got != want {
			t.Errorf("SafeJoin(%q,%q) = %q,%v want %q,nil", root, in, got, err, want)
		}
	}
	for _, in := range []string{"../escape", "../../etc/passwd", "a/../../b"} {
		if _, err := SafeJoin(root, in); err == nil {
			t.Errorf("SafeJoin(%q,%q) = nil error, want escape error", root, in)
		}
	}
	// An absolute part is absorbed under root by filepath.Join (contained, not
	// an escape) — callers that must reject absolute inputs validate the name
	// (or use cleanMemberName) before joining.
	if got, err := SafeJoin(root, "/etc/passwd"); err != nil || got != "/srv/data/etc/passwd" {
		t.Errorf("SafeJoin(%q,/etc/passwd) = %q,%v want /srv/data/etc/passwd,nil", root, got, err)
	}
	if _, err := SafeJoin("", "x"); err == nil {
		t.Error("SafeJoin empty root should error")
	}
}

func TestContains(t *testing.T) {
	if !Contains("/a/b", "/a/b/c") || !Contains("/a/b", "/a/b") {
		t.Error("Contains should accept self and child")
	}
	if Contains("/a/b", "/a/c") || Contains("/a/b", "/a") {
		t.Error("Contains should reject sibling/parent")
	}
}

// --- tar extraction ---

type tarEnt struct {
	name     string
	typeflag byte
	mode     int64
	body     string
	linkname string
}

func buildTar(t *testing.T, ents []tarEnt) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range ents {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Linkname: e.linkname}
		if e.typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("WriteHeader %q: %v", e.name, err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatalf("Write %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtractFlatTar(t *testing.T) {
	dest := t.TempDir()
	data := buildTar(t, []tarEnt{
		{name: "dir/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "dir/file.txt", typeflag: tar.TypeReg, mode: 0o644, body: "hello"},
	})
	if err := ExtractFlatTar(bytes.NewReader(data), dest); err != nil {
		t.Fatalf("ExtractFlatTar: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dest, "dir/file.txt"))
	if err != nil || string(b) != "hello" {
		t.Errorf("extracted file = %q,%v", b, err)
	}

	// Symlinks and devices are rejected.
	for _, ent := range []tarEnt{
		{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
		{name: "dev", typeflag: tar.TypeChar},
		{name: "../escape", typeflag: tar.TypeReg, body: "x"},
		{name: "/abs", typeflag: tar.TypeReg, body: "x"},
	} {
		d := buildTar(t, []tarEnt{ent})
		if err := ExtractFlatTar(bytes.NewReader(d), t.TempDir()); err == nil {
			t.Errorf("ExtractFlatTar accepted %q, want error", ent.name)
		}
	}
}

func TestExtractRootfsTar_Good(t *testing.T) {
	dest := t.TempDir()
	data := buildTar(t, []tarEnt{
		{name: "ct/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "ct/rootfs/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "ct/rootfs/usr/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "ct/rootfs/usr/bin/", typeflag: tar.TypeDir, mode: 0o755},
		{name: "ct/rootfs/usr/bin/sh", typeflag: tar.TypeReg, mode: 0o755, body: "#!/bin/sh"},
		{name: "ct/rootfs/bin", typeflag: tar.TypeSymlink, linkname: "/usr/bin"},
		{name: "ct/rootfs/usr/bin/ln2", typeflag: tar.TypeLink, linkname: "ct/rootfs/usr/bin/sh"},
	})
	if err := ExtractRootfsTar(bytes.NewReader(data), dest, "ct"); err != nil {
		t.Fatalf("ExtractRootfsTar: %v", err)
	}
	// exec bit preserved
	fi, err := os.Lstat(filepath.Join(dest, "ct/rootfs/usr/bin/sh"))
	if err != nil || fi.Mode().Perm()&0o100 == 0 {
		t.Errorf("exec bit not preserved: %v %v", fi.Mode(), err)
	}
	// symlink preserved verbatim
	ln, err := os.Readlink(filepath.Join(dest, "ct/rootfs/bin"))
	if err != nil || ln != "/usr/bin" {
		t.Errorf("symlink = %q,%v want /usr/bin", ln, err)
	}
}

func TestExtractRootfsTar_Rejections(t *testing.T) {
	tests := []struct {
		name string
		ents []tarEnt
	}{
		{"traversal", []tarEnt{{name: "ct/../../etc/x", typeflag: tar.TypeReg, body: "x"}}},
		{"absolute", []tarEnt{{name: "/etc/x", typeflag: tar.TypeReg, body: "x"}}},
		{"device", []tarEnt{{name: "ct/dev/sda", typeflag: tar.TypeBlock}}},
		{"write-through-symlink", []tarEnt{
			{name: "ct/etc", typeflag: tar.TypeSymlink, linkname: "/etc"},
			{name: "ct/etc/passwd", typeflag: tar.TypeReg, body: "pwned"},
		}},
		{"symlink-escapes-root", []tarEnt{
			{name: "ct/evil", typeflag: tar.TypeSymlink, linkname: "../../../../etc/shadow"},
		}},
		{"symlink-escapes-subtree", []tarEnt{
			// Stays under dest but leaves the "ct" subtree → still rejected.
			{name: "ct/rootfs/x", typeflag: tar.TypeSymlink, linkname: "../../other/secret"},
		}},
		{"hardlink-escapes-subtree", []tarEnt{
			// Hardlink target resolves under dest but outside the "ct" subtree.
			{name: "ct/link", typeflag: tar.TypeLink, linkname: "other/secret"},
		}},
		{"hardlink-to-missing", []tarEnt{
			{name: "ct/a", typeflag: tar.TypeLink, linkname: "ct/later"},
		}},
		{"hardlink-escapes-root", []tarEnt{
			{name: "ct/a", typeflag: tar.TypeLink, linkname: "../../../etc/passwd"},
		}},
		{"wrong-top", []tarEnt{
			{name: "other/file", typeflag: tar.TypeReg, body: "x"},
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			data := buildTar(t, tc.ents)
			if err := ExtractRootfsTar(bytes.NewReader(data), t.TempDir(), "ct"); err == nil {
				t.Errorf("ExtractRootfsTar accepted %s, want error", tc.name)
			}
		})
	}
}
