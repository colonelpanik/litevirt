package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The capability-latch model requires CONFIG UNIFORMITY: a token is advertised
// only while a host's enforcement.* flag is on, so a host added (or re-added)
// with a config missing the enforcement block silently weakens the cluster.
// Observed live 2026-08-01: re-admitted node-4's generated config had no
// enforcement block, its daemon never ran setupAuditSigning, and every audit
// row it wrote was reported as tampering cluster-wide — twice, surviving a key
// rotation, until the flag was appended by hand. The setup env must carry the
// adding node's enforcement block to the new host.

func TestEnforcementYAMLFrom_ExtractsTheBlock(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(
		"host_name: \"node-1\"\n"+
			"enforcement:\n"+
			"    audit_signature: true\n"+
			"    operation_protocol: true\n"+
			"gossip_port: 7946\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	got := enforcementYAMLFrom(cfg)
	want := "enforcement:\n    audit_signature: true\n    operation_protocol: true\n"
	if got != want {
		t.Fatalf("enforcementYAMLFrom = %q, want %q", got, want)
	}

	// No block → empty, so the script appends nothing.
	if err := os.WriteFile(cfg, []byte("host_name: \"n\"\n"), 0o600); err != nil {
		t.Fatalf("rewrite config: %v", err)
	}
	if got := enforcementYAMLFrom(cfg); got != "" {
		t.Fatalf("config without enforcement produced %q, want empty", got)
	}

	// Unreadable file → empty, never an error path that blocks an add.
	if got := enforcementYAMLFrom(filepath.Join(dir, "absent.yaml")); got != "" {
		t.Fatalf("missing config produced %q, want empty", got)
	}
}

func TestSetupScriptEnv_CarriesEnforcementBase64(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte(
		"enforcement:\n    audit_signature: true\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	old := daemonConfigPath
	daemonConfigPath = cfg
	t.Cleanup(func() { daemonConfigPath = old })

	env := setupScriptEnv("node-9", "10.0.0.9", "[]")
	var b64 string
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, "ENFORCEMENT_B64="); ok {
			b64 = v
		}
	}
	if b64 == "" {
		t.Fatalf("setup env carries no ENFORCEMENT_B64; a host added from this node "+
			"boots without the cluster's enforcement flags: %v", env)
	}
	// The value must be a single shell-safe token (the remote path joins env
	// with spaces into one command line).
	if strings.ContainsAny(b64, " \n\t'\"") {
		t.Fatalf("ENFORCEMENT_B64 is not a single shell-safe token: %q", b64)
	}
	dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("ENFORCEMENT_B64 does not decode: %v", err)
	}
	if string(dec) != "enforcement:\n    audit_signature: true\n" {
		t.Fatalf("decoded block = %q", dec)
	}

	// The setup script must actually consume it.
	if !strings.Contains(setupScriptContent, `"${ENFORCEMENT_B64}" | base64 -d >> /etc/litevirt/config.yaml`) {
		t.Fatal("the setup script never appends the propagated enforcement block to the daemon config")
	}
}
