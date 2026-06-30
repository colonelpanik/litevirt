package libvirt

import "testing"

// srcOf re-parses domain XML and returns the <source file> for a target dev — used
// to assert RewriteDiskSourceFile's effect without depending on quote style or
// formatting (the encoder re-canonicalizes).
func srcOf(t *testing.T, domXML, dev string) string {
	t.Helper()
	infos, err := parseDiskSourceInfos(domXML)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, d := range infos {
		if d.dev == dev {
			return d.file
		}
	}
	return ""
}

func TestRewriteDiskSourceFile_SourceBeforeTarget(t *testing.T) {
	// libvirt emits <source> before <target>; the rewrite must still key on the dev.
	in := `<domain type="kvm"><name>vm</name><devices>` +
		`<disk type="file" device="disk"><driver name="qemu" type="qcow2"/>` +
		`<source file="/old/root.qcow2"/><target dev="vda" bus="virtio"/></disk>` +
		`</devices></domain>`
	out, changed, err := RewriteDiskSourceFile(in, "vda", "/old/root.qcow2", "/new/root.qcow2")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got := srcOf(t, out, "vda"); got != "/new/root.qcow2" {
		t.Fatalf("vda source = %q, want /new/root.qcow2", got)
	}
}

func TestRewriteDiskSourceFile_MultipleDisks(t *testing.T) {
	in := `<domain><devices>` +
		`<disk><source file="/p/a.qcow2"/><target dev="vda"/></disk>` +
		`<disk><source file="/p/b.qcow2"/><target dev="vdb"/></disk>` +
		`</devices></domain>`
	out, changed, err := RewriteDiskSourceFile(in, "vdb", "/p/b.qcow2", "/q/b.qcow2")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got := srcOf(t, out, "vdb"); got != "/q/b.qcow2" {
		t.Fatalf("vdb source = %q, want /q/b.qcow2", got)
	}
	if got := srcOf(t, out, "vda"); got != "/p/a.qcow2" {
		t.Fatalf("vda source changed to %q, must be untouched", got)
	}
}

func TestRewriteDiskSourceFile_EscapedPath(t *testing.T) {
	// A path with an XML-special char must round-trip via decoded values.
	in := `<domain><devices>` +
		`<disk><source file="/old/a&amp;b.qcow2"/><target dev="vda"/></disk>` +
		`</devices></domain>`
	out, changed, err := RewriteDiskSourceFile(in, "vda", "/old/a&b.qcow2", "/new/a&b.qcow2")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got := srcOf(t, out, "vda"); got != "/new/a&b.qcow2" {
		t.Fatalf("vda source = %q, want /new/a&b.qcow2", got)
	}
}

func TestRewriteDiskSourceFile_MixedDomainSkipsNonFileDisks(t *testing.T) {
	// A file disk + an empty cdrom (no source) + a block disk (source dev, no file).
	in := `<domain><devices>` +
		`<disk type="file" device="disk"><source file="/old/root.qcow2"/><target dev="vda"/></disk>` +
		`<disk type="file" device="cdrom"><target dev="sda"/><readonly/></disk>` +
		`<disk type="block" device="disk"><source dev="/dev/sdb"/><target dev="vdb"/></disk>` +
		`</devices></domain>`
	out, changed, err := RewriteDiskSourceFile(in, "vda", "/old/root.qcow2", "/new/root.qcow2")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got := srcOf(t, out, "vda"); got != "/new/root.qcow2" {
		t.Fatalf("vda source = %q, want /new/root.qcow2", got)
	}
	if got := srcOf(t, out, "sda"); got != "" {
		t.Fatalf("cdrom sda gained a file source %q", got)
	}
}

func TestRewriteDiskSourceFile_RequestedDevIsNonFile(t *testing.T) {
	in := `<domain><devices>` +
		`<disk type="block" device="disk"><source dev="/dev/sdb"/><target dev="vdb"/></disk>` +
		`</devices></domain>`
	if _, _, err := RewriteDiskSourceFile(in, "vdb", "/old/x.qcow2", "/new/x.qcow2"); err == nil {
		t.Fatal("expected error rewriting a non-file-backed disk")
	}
}

func TestRewriteDiskSourceFile_MissingDev(t *testing.T) {
	in := `<domain><devices>` +
		`<disk><source file="/p/a.qcow2"/><target dev="vda"/></disk>` +
		`</devices></domain>`
	if _, _, err := RewriteDiskSourceFile(in, "vdz", "/p/a.qcow2", "/q/a.qcow2"); err == nil {
		t.Fatal("expected error for missing target dev")
	}
}

func TestRewriteDiskSourceFile_UnexpectedSource(t *testing.T) {
	in := `<domain><devices>` +
		`<disk><source file="/other.qcow2"/><target dev="vda"/></disk>` +
		`</devices></domain>`
	if _, _, err := RewriteDiskSourceFile(in, "vda", "/old/root.qcow2", "/new/root.qcow2"); err == nil {
		t.Fatal("expected error: dev source is neither old nor new")
	}
}

func TestRewriteDiskSourceFile_EmptyDevUnique(t *testing.T) {
	in := `<domain><devices>` +
		`<disk><source file="/old/root.qcow2"/><target dev="vda"/></disk>` +
		`<disk><source file="/old/data.qcow2"/><target dev="vdb"/></disk>` +
		`</devices></domain>`
	out, changed, err := RewriteDiskSourceFile(in, "", "/old/data.qcow2", "/new/data.qcow2")
	if err != nil || !changed {
		t.Fatalf("changed=%v err=%v", changed, err)
	}
	if got := srcOf(t, out, "vdb"); got != "/new/data.qcow2" {
		t.Fatalf("vdb source = %q, want /new/data.qcow2", got)
	}
}

func TestRewriteDiskSourceFile_EmptyDevAmbiguous(t *testing.T) {
	// Two disks share the same source — refuse rather than guess.
	in := `<domain><devices>` +
		`<disk><source file="/shared.qcow2"/><target dev="vda"/></disk>` +
		`<disk><source file="/shared.qcow2"/><target dev="vdb"/></disk>` +
		`</devices></domain>`
	if _, _, err := RewriteDiskSourceFile(in, "", "/shared.qcow2", "/new.qcow2"); err == nil {
		t.Fatal("expected error for ambiguous source match")
	}
}

func TestRewriteDiskSourceFile_Idempotent(t *testing.T) {
	in := `<domain><devices>` +
		`<disk><source file="/new/root.qcow2"/><target dev="vda"/></disk>` +
		`</devices></domain>`
	out, changed, err := RewriteDiskSourceFile(in, "vda", "/old/root.qcow2", "/new/root.qcow2")
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if changed {
		t.Fatal("expected changed=false (already at new path)")
	}
	if out != in {
		t.Fatal("idempotent rewrite must return the input unchanged")
	}
}

func TestRewriteDiskSourceFile_RefusesNamespaces(t *testing.T) {
	in := `<domain type="kvm" xmlns:qemu="http://libvirt.org/schemas/domain/qemu/1.0"><devices>` +
		`<disk><source file="/old/root.qcow2"/><target dev="vda"/></disk>` +
		`</devices></domain>`
	if _, _, err := RewriteDiskSourceFile(in, "vda", "/old/root.qcow2", "/new/root.qcow2"); err == nil {
		t.Fatal("expected refusal for namespaced domain xml")
	}
}

// TestRewriteDiskSourceFile_NamespaceDetectionNotSubstring: a path that merely
// contains the substring "xmlns" must NOT be mistaken for a namespace declaration.
func TestRewriteDiskSourceFile_NamespaceDetectionNotSubstring(t *testing.T) {
	in := `<domain type="kvm"><devices>` +
		`<disk><source file="/pools/xmlns-data/root.qcow2"/><target dev="vda"/></disk>` +
		`</devices></domain>`
	out, changed, err := RewriteDiskSourceFile(in, "vda", "/pools/xmlns-data/root.qcow2", "/new/root.qcow2")
	if err != nil || !changed {
		t.Fatalf("a path containing %q must not be treated as a namespace: changed=%v err=%v", "xmlns", changed, err)
	}
	if got := srcOf(t, out, "vda"); got != "/new/root.qcow2" {
		t.Fatalf("vda source = %q, want /new/root.qcow2", got)
	}
}
