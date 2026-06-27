package cli

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"testing"
)

func TestParseSSHTarget_Basic(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantUser string
		wantErr  bool
	}{
		{"root@10.0.50.10", "10.0.50.10", "root", false},
		{"admin@192.168.1.1", "192.168.1.1", "admin", false},
		{"deploy@host.example.com", "host.example.com", "deploy", false},
		{"10.0.50.10", "10.0.50.10", "root", false},
		{"root@10.0.50.10:2222", "10.0.50.10", "root", false},
		{"user@host:22", "host", "user", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			host, user, err := parseSSHTarget(tt.input)
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if host != tt.wantHost {
				t.Errorf("host = %s, want %s", host, tt.wantHost)
			}
			if user != tt.wantUser {
				t.Errorf("user = %s, want %s", user, tt.wantUser)
			}
		})
	}
}

func TestConfigDir_Default(t *testing.T) {
	// Unset env var to test default
	t.Setenv("LV_CONFIG_DIR", "")

	dir := ConfigDir()
	home, _ := os.UserHomeDir()
	expected := home + "/.config/litevirt"
	if dir != expected {
		t.Errorf("ConfigDir() = %s, want %s", dir, expected)
	}
}

func TestConfigDir_Env(t *testing.T) {
	t.Setenv("LV_CONFIG_DIR", "/custom/config")
	dir := ConfigDir()
	if dir != "/custom/config" {
		t.Errorf("ConfigDir() = %s, want /custom/config", dir)
	}
}

func TestPKIDir(t *testing.T) {
	t.Setenv("LV_CONFIG_DIR", "/test/config")
	dir := PKIDir()
	if dir != "/test/config/pki" {
		t.Errorf("PKIDir() = %s, want /test/config/pki", dir)
	}
}

func TestLocalCLIClientPKITargets_SudoUser(t *testing.T) {
	dir := t.TempDir()
	userHome := filepath.Join(dir, "alice")
	t.Setenv("LV_CONFIG_DIR", filepath.Join(dir, "root-config"))
	t.Setenv("SUDO_USER", "alice")

	oldLookup := lookupUserByName
	lookupUserByName = func(name string) (*osuser.User, error) {
		if name != "alice" {
			t.Fatalf("lookup user = %q, want alice", name)
		}
		return &osuser.User{Uid: "1000", Gid: "1001", HomeDir: userHome}, nil
	}
	t.Cleanup(func() { lookupUserByName = oldLookup })

	targets, err := localCLIClientPKITargets()
	if err != nil {
		t.Fatalf("localCLIClientPKITargets: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("len(targets) = %d, want 2", len(targets))
	}
	if targets[0].dir != filepath.Join(dir, "root-config", "pki") || !targets[0].chown {
		t.Errorf("first target = %+v, want custom LV_CONFIG_DIR target chowned to sudo user", targets[0])
	}
	if targets[1].dir != filepath.Join(userHome, ".config", "litevirt", "pki") || !targets[1].chown {
		t.Errorf("second target = %+v, want sudo user's default config dir", targets[1])
	}
	if targets[1].uid != 1000 || targets[1].gid != 1001 {
		t.Errorf("sudo target uid/gid = %d/%d, want 1000/1001", targets[1].uid, targets[1].gid)
	}
}

func TestInstallCLIClientBundle_CopiesOnlyClientBundle(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.MkdirAll(src, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key", "host.crt", "host.key"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}

	if err := installCLIClientBundle(src, cliPKITarget{dir: dst}); err != nil {
		t.Fatalf("installCLIClientBundle: %v", err)
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		if _, err := os.Stat(filepath.Join(dst, name)); err != nil {
			t.Errorf("expected %s to be installed: %v", name, err)
		}
	}
	for _, name := range []string{"host.crt", "host.key"} {
		if _, err := os.Stat(filepath.Join(dst, name)); !os.IsNotExist(err) {
			t.Errorf("%s should not be installed in CLI bundle", name)
		}
	}
	if st, err := os.Stat(filepath.Join(dst, "client.key")); err != nil {
		t.Fatal(err)
	} else if st.Mode().Perm() != 0600 {
		t.Errorf("client.key mode = %o, want 0600", st.Mode().Perm())
	}
}

func TestGetSetupScript(t *testing.T) {
	script, err := getSetupScript()
	if err != nil {
		t.Fatalf("getSetupScript: %v", err)
	}
	if script == "" {
		t.Error("setup script should not be empty")
	}
	// Verify key contents
	checks := []string{
		"#!/bin/bash",
		"qemu-kvm",
		"libvirt",
		"litevirtd",
		"config.yaml",
	}
	for _, check := range checks {
		if !contains(script, check) {
			t.Errorf("setup script missing %q", check)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestLoadClusterConfig_NoEnv(t *testing.T) {
	old := daemonConfigPath
	daemonConfigPath = "/nonexistent/config.yaml"
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "")
	_, err := LoadClusterConfig()
	if err == nil {
		t.Error("expected error when LV_HOST is not set")
	}
}

func TestLoadClusterConfig_WithEnv(t *testing.T) {
	old := daemonConfigPath
	daemonConfigPath = "/nonexistent/config.yaml"
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "root@10.0.50.10")
	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("LoadClusterConfig: %v", err)
	}
	if cfg.DefaultHost != "root@10.0.50.10" {
		t.Errorf("DefaultHost = %s", cfg.DefaultHost)
	}
	if cfg.GRPCPort != 7443 {
		t.Errorf("GRPCPort = %d, want 7443", cfg.GRPCPort)
	}
}
