package corrosion

import "testing"

func TestContainerCreateSpec_RoundTrip(t *testing.T) {
	spec := ContainerCreateSpec{
		Template: "download", Distro: "alpine", Release: "3.19", Arch: "amd64",
		Networks: []ContainerNetwork{{Name: "eth0", Bridge: "br0", IP: "10.1.2.3", MAC: "52:54:00:ab:cd:ef"}},
	}
	got := DecodeCreateSpec(EncodeCreateSpec(spec))
	if got.Template != "download" || got.Distro != "alpine" || got.Release != "3.19" || got.Arch != "amd64" {
		t.Fatalf("round-trip lost scalar fields: %+v", got)
	}
	if len(got.Networks) != 1 || got.Networks[0].Bridge != "br0" || got.Networks[0].IP != "10.1.2.3" || got.Networks[0].MAC != "52:54:00:ab:cd:ef" {
		t.Fatalf("round-trip lost networks: %+v", got.Networks)
	}
}

func TestContainerCreateSpec_EmptyAndGarbage(t *testing.T) {
	zero := func(s ContainerCreateSpec) bool {
		return s.Template == "" && s.Distro == "" && s.Release == "" && s.Arch == "" && len(s.Networks) == 0
	}
	if s := EncodeCreateSpec(ContainerCreateSpec{}); s != "" {
		t.Fatalf("empty spec must encode to \"\", got %q", s)
	}
	if got := DecodeCreateSpec(""); !zero(got) {
		t.Fatalf("decode of \"\" must be zero, got %+v", got)
	}
	if got := DecodeCreateSpec("{not json"); !zero(got) {
		t.Fatalf("decode of garbage must be zero, got %+v", got)
	}
}

func TestRelocateRestoreMarker(t *testing.T) {
	// Build + parse round-trip (with token).
	d := RelocateRestoreDetail("surv-1", "tokXYZ")
	if d != "relocate-restore:surv-1:tokXYZ" {
		t.Fatalf("detail = %q", d)
	}
	tgt, tok, ok := RelocateRestoreMarker("relocating", d)
	if !ok || tgt != "surv-1" || tok != "tokXYZ" {
		t.Fatalf("parse = (%q,%q,%v), want (surv-1,tokXYZ,true)", tgt, tok, ok)
	}

	// Legacy marker without a token parses with token="".
	if tgt, tok, ok := RelocateRestoreMarker("relocating", "relocate-restore:surv-1"); !ok || tgt != "surv-1" || tok != "" {
		t.Fatalf("legacy parse = (%q,%q,%v), want (surv-1,\"\",true)", tgt, tok, ok)
	}

	// Not a relocate-restore marker.
	if _, _, ok := RelocateRestoreMarker("running", "relocate-restore:x:y"); ok {
		t.Fatal("non-relocating state must not parse")
	}
	if _, _, ok := RelocateRestoreMarker("relocating", "relocate-recreate"); ok {
		t.Fatal("a non-restore detail must not parse")
	}
}
