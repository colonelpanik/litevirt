package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadClusterConfig_AMalformedConfigSaysSo.
//
// A daemon config that fails to parse fell through to "LV_HOST not set", which
// says the file is ABSENT when it is present and broken. Found rebuilding the lab:
// an edit left two join_peers keys, yaml refused the duplicate, and every lv
// command on that node reported LV_HOST not set while the daemon was running fine
// three feet away. The message sends you to configure a remote target instead of
// to the one line that is actually wrong.
func TestLoadClusterConfig_AMalformedConfigSaysSo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Two join_peers keys — exactly what a careless edit produces.
	if err := os.WriteFile(path, []byte(
		"grpc_port: 7443\njoin_peers: [\"10.0.2.15:7946\"]\njoin_peers:\n  - 10.77.0.11:7946\n"), 0644); err != nil {
		t.Fatal(err)
	}
	old := daemonConfigPath
	daemonConfigPath = path
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "")

	_, err := LoadClusterConfig()
	if err == nil {
		t.Fatal("a config with a duplicate key parsed cleanly")
	}
	if strings.Contains(err.Error(), "LV_HOST not set") {
		t.Fatalf("a present-but-unparseable config reports %q\n"+
			"that says the file is missing, so the operator goes looking for an env var "+
			"instead of the broken line", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file that failed to parse: %v", err)
	}
}

// TestLoadClusterConfig_AValidConfigStillWorks guards the fix from over-correcting
// into refusing a config it should accept.
func TestLoadClusterConfig_AValidConfigStillWorks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("grpc_port: 7443\npki_dir: /etc/litevirt/pki\n"), 0644); err != nil {
		t.Fatal(err)
	}
	old := daemonConfigPath
	daemonConfigPath = path
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "")

	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("a valid local daemon config was rejected: %v", err)
	}
	if !cfg.Local || cfg.GRPCPort != 7443 {
		t.Fatalf("want local mode on port 7443, got %+v", cfg)
	}
}
