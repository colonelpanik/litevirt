package lxc

import "testing"

func TestRegistryHost(t *testing.T) {
	cases := []struct {
		ref  string
		want string
	}{
		{"alpine", "docker.io"},
		{"alpine:3.19", "docker.io"},
		{"library/alpine", "docker.io"},
		{"library/alpine:3.19", "docker.io"},
		{"docker.io/library/alpine:3.19", "docker.io"},
		{"ghcr.io/org/x", "ghcr.io"},
		{"ghcr.io/org/x:v1", "ghcr.io"},
		{"docker://ghcr.io/org/x", "ghcr.io"},
		{"registry:5000/team/img:v1", "registry:5000"},
		{"registry.local:5000/team/img", "registry.local:5000"},
		{"localhost:5000/x", "localhost:5000"},
		{"localhost/x", "localhost"},
		{"oci:/var/lib/litevirt/oci/alpine:3.19", ""},
	}
	for _, c := range cases {
		if got := RegistryHost(c.ref); got != c.want {
			t.Errorf("RegistryHost(%q) = %q, want %q", c.ref, got, c.want)
		}
	}
}

func TestNormalizeRegistry(t *testing.T) {
	cases := []struct{ in, want string }{
		{"ghcr.io", "ghcr.io"},
		{"docker.io", "docker.io"},
		{"index.docker.io", "docker.io"},
		{"registry-1.docker.io", "docker.io"},
		{"registry:5000", "registry:5000"},
		{"https://ghcr.io", "ghcr.io"},
		{"docker://ghcr.io", "ghcr.io"},
		{"docker.io/library/alpine", "docker.io"},
		{"oci:/var/lib/litevirt/oci/x:1", ""},
	}
	for _, c := range cases {
		if got := NormalizeRegistry(c.in); got != c.want {
			t.Errorf("NormalizeRegistry(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRegistryStoreMatchesPull confirms a credential stored against the
// registry argument resolves for the corresponding pulled image: the SET path
// (NormalizeRegistry) and the PULL path (RegistryHost) must agree on the key.
func TestRegistryStoreMatchesPull(t *testing.T) {
	pairs := []struct{ stored, pulled string }{
		{"docker.io", "alpine:3.19"},
		{"docker.io", "docker.io/library/alpine"},
		{"ghcr.io", "ghcr.io/org/x:v1"},
		{"registry:5000", "registry:5000/team/img"},
	}
	for _, p := range pairs {
		if NormalizeRegistry(p.stored) != RegistryHost(p.pulled) {
			t.Errorf("stored %q (=%q) != pulled %q (=%q)",
				p.stored, NormalizeRegistry(p.stored), p.pulled, RegistryHost(p.pulled))
		}
	}
}

// TestRegistryHostMatchesParseOCITag confirms the registry/port split stays
// consistent with parseOCITag — a ref with a registry port must not have its
// port mistaken for a tag, and vice versa.
func TestRegistryHostMatchesParseOCITag(t *testing.T) {
	if reg, tag := RegistryHost("registry.local:5000/team/img:v1"), parseOCITag("registry.local:5000/team/img:v1"); reg != "registry.local:5000" || tag != "v1" {
		t.Errorf("got reg=%q tag=%q, want registry.local:5000 / v1", reg, tag)
	}
	if reg, tag := RegistryHost("registry.local:5000/team/img"), parseOCITag("registry.local:5000/team/img"); reg != "registry.local:5000" || tag != "latest" {
		t.Errorf("got reg=%q tag=%q, want registry.local:5000 / latest", reg, tag)
	}
}
