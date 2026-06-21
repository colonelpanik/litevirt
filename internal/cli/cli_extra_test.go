package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSSHTarget_UserOnly(t *testing.T) {
	host, user, err := parseSSHTarget("myhost.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "myhost.local" {
		t.Errorf("host = %q, want myhost.local", host)
	}
	if user != "root" {
		t.Errorf("user = %q, want root (default)", user)
	}
}

func TestParseSSHTarget_IPv6(t *testing.T) {
	host, user, err := parseSSHTarget("root@[::1]:22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "::1" {
		t.Errorf("host = %q, want ::1", host)
	}
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
}

func TestParseSSHTarget_WithDomain(t *testing.T) {
	host, user, err := parseSSHTarget("admin@node1.cluster.local")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if host != "node1.cluster.local" {
		t.Errorf("host = %q, want node1.cluster.local", host)
	}
	if user != "admin" {
		t.Errorf("user = %q, want admin", user)
	}
}

func TestConfigDir_CustomEnv(t *testing.T) {
	t.Setenv("LV_CONFIG_DIR", "/my/custom/dir")
	dir := ConfigDir()
	if dir != "/my/custom/dir" {
		t.Errorf("ConfigDir() = %q, want /my/custom/dir", dir)
	}
}

func TestPKIDir_DependsOnConfigDir(t *testing.T) {
	t.Setenv("LV_CONFIG_DIR", "/opt/litevirt")
	dir := PKIDir()
	if dir != "/opt/litevirt/pki" {
		t.Errorf("PKIDir() = %q, want /opt/litevirt/pki", dir)
	}
}

func TestLoadClusterConfig_CustomHost(t *testing.T) {
	old := daemonConfigPath
	daemonConfigPath = "/nonexistent/config.yaml"
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "admin@10.0.50.20")
	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("LoadClusterConfig: %v", err)
	}
	if cfg.DefaultHost != "admin@10.0.50.20" {
		t.Errorf("DefaultHost = %q", cfg.DefaultHost)
	}
	if cfg.GRPCPort != 7443 {
		t.Errorf("GRPCPort = %d", cfg.GRPCPort)
	}
}

func TestLoadClusterConfig_Empty(t *testing.T) {
	old := daemonConfigPath
	daemonConfigPath = "/nonexistent/config.yaml"
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "")
	_, err := LoadClusterConfig()
	if err == nil {
		t.Error("expected error when LV_HOST is empty")
	}
	if !strings.Contains(err.Error(), "LV_HOST not set") {
		t.Errorf("error message = %q", err.Error())
	}
}

func TestLoadClusterConfig_LocalMode(t *testing.T) {
	// Write a minimal daemon config to a temp file.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte("host_name: node1\ngrpc_port: 9443\npki_dir: /custom/pki\n"), 0644)

	old := daemonConfigPath
	daemonConfigPath = cfgPath
	t.Cleanup(func() { daemonConfigPath = old })

	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("LoadClusterConfig: %v", err)
	}
	if !cfg.Local {
		t.Error("expected Local = true")
	}
	if cfg.GRPCPort != 9443 {
		t.Errorf("GRPCPort = %d, want 9443", cfg.GRPCPort)
	}
	if cfg.PKIDir != "/custom/pki" {
		t.Errorf("PKIDir = %q, want /custom/pki", cfg.PKIDir)
	}
	if cfg.DefaultHost != "" {
		t.Errorf("DefaultHost = %q, want empty in local mode", cfg.DefaultHost)
	}
}

func TestLoadClusterConfig_LocalModeDefaults(t *testing.T) {
	// Config without grpc_port/pki_dir should use defaults.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfgPath, []byte("host_name: node1\n"), 0644)

	old := daemonConfigPath
	daemonConfigPath = cfgPath
	t.Cleanup(func() { daemonConfigPath = old })

	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("LoadClusterConfig: %v", err)
	}
	if cfg.GRPCPort != 7443 {
		t.Errorf("GRPCPort = %d, want 7443", cfg.GRPCPort)
	}
	if cfg.PKIDir != "/etc/litevirt/pki" {
		t.Errorf("PKIDir = %q, want /etc/litevirt/pki", cfg.PKIDir)
	}
}

func TestGetSetupScript_ContainsKeyPhrases(t *testing.T) {
	script, err := getSetupScript()
	if err != nil {
		t.Fatalf("getSetupScript: %v", err)
	}
	phrases := []string{
		"set -euo pipefail",
		"apt-get",
		"dnf",
		"libvirtd",
		"/var/lib/litevirt",
		"/etc/litevirt",
		"HOST_NAME",
		"grpc_port",
		"pki_dir",
		"vfio-pci",
		"udev",
	}
	for _, phrase := range phrases {
		if !strings.Contains(script, phrase) {
			t.Errorf("setup script missing phrase %q", phrase)
		}
	}
}

func TestConfigDir_Default_NoEnv(t *testing.T) {
	t.Setenv("LV_CONFIG_DIR", "")
	dir := ConfigDir()
	home, _ := os.UserHomeDir()
	if !strings.HasPrefix(dir, home) {
		t.Errorf("ConfigDir() = %q, expected it to start with $HOME (%s)", dir, home)
	}
	if !strings.HasSuffix(dir, ".config/litevirt") {
		t.Errorf("ConfigDir() = %q, expected it to end with .config/litevirt", dir)
	}
}

func TestParseSSHTarget_MultipleAtSigns(t *testing.T) {
	// Edge case: "@" in hostnames shouldn't be valid, but the parser splits on the first @.
	host, user, err := parseSSHTarget("user@host@extra")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if user != "user" {
		t.Errorf("user = %q, want user", user)
	}
	// The rest after first @ is the host.
	if host != "host@extra" {
		t.Errorf("host = %q, want host@extra", host)
	}
}

func TestParseSSHTarget_PortStripping(t *testing.T) {
	host, _, err := parseSSHTarget("root@10.0.0.1:22")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if host != "10.0.0.1" {
		t.Errorf("host = %q, want 10.0.0.1 (port stripped)", host)
	}
}

func TestParseSSHTarget_HostOnly_NoPort(t *testing.T) {
	host, user, err := parseSSHTarget("192.168.1.100")
	if err != nil {
		t.Fatalf("error: %v", err)
	}
	if host != "192.168.1.100" {
		t.Errorf("host = %q", host)
	}
	if user != "root" {
		t.Errorf("user = %q, want root", user)
	}
}
