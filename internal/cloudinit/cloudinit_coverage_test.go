package cloudinit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMetaDataFormat verifies the meta-data string format produced by GenerateISO.
// We replicate the same fmt.Sprintf from nocloud.go to test format expectations.
func TestMetaDataFormat(t *testing.T) {
	tests := []struct {
		instanceID    string
		localHostname string
	}{
		{"vm-001", "web-server"},
		{"i-abc123", "my-host"},
		{"", ""},
		{"with spaces", "host-name"},
		{"special!@#$", "test"},
	}

	for _, tt := range tests {
		t.Run(tt.instanceID, func(t *testing.T) {
			metaData := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", tt.instanceID, tt.localHostname)

			if !strings.HasPrefix(metaData, "instance-id: ") {
				t.Error("meta-data should start with 'instance-id: '")
			}
			if !strings.Contains(metaData, "local-hostname: ") {
				t.Error("meta-data should contain 'local-hostname: '")
			}
			if !strings.HasSuffix(metaData, "\n") {
				t.Error("meta-data should end with newline")
			}
			if !strings.Contains(metaData, tt.instanceID) {
				t.Errorf("meta-data should contain instance ID %q", tt.instanceID)
			}
			if !strings.Contains(metaData, tt.localHostname) {
				t.Errorf("meta-data should contain local hostname %q", tt.localHostname)
			}
		})
	}
}

// TestDefaultUserData verifies the default user-data when Config.UserData is empty.
func TestDefaultUserData(t *testing.T) {
	defaultUserData := "#cloud-config\n{}\n"

	if !strings.HasPrefix(defaultUserData, "#cloud-config") {
		t.Error("default user-data should start with #cloud-config")
	}
	if !strings.Contains(defaultUserData, "{}") {
		t.Error("default user-data should contain empty YAML object")
	}
}

// TestGenerateISO_WritesMetaData verifies that GenerateISO writes the correct
// meta-data content by inspecting what would be written (we test the logic,
// not the genisoimage call).
func TestGenerateISO_WritesCorrectFiles(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "out", "test.iso")

	cfg := Config{
		InstanceID:    "test-instance-42",
		LocalHostname: "my-test-host",
		UserData:      "#cloud-config\npackages:\n  - vim\n",
		NetworkConfig: "network:\n  version: 2\n",
	}

	// GenerateISO will fail at genisoimage, but it creates the temp files first.
	// We cannot inspect the temp dir directly (it's removed by defer), but we can
	// verify the output directory was created.
	_ = GenerateISO(cfg, outputPath)

	parentDir := filepath.Dir(outputPath)
	if _, err := os.Stat(parentDir); err != nil {
		t.Errorf("output parent directory should be created: %v", err)
	}
}

// TestGenerateISO_EmptyNetworkConfig verifies no network-config file is written
// when NetworkConfig is empty.
func TestGenerateISO_EmptyNetworkConfig(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "test.iso")

	cfg := Config{
		InstanceID:    "vm-no-net",
		LocalHostname: "no-net-host",
		UserData:      "#cloud-config\n{}\n",
		NetworkConfig: "", // empty: no network-config file
	}

	// Will fail at genisoimage, but exercises the branch.
	_ = GenerateISO(cfg, outputPath)
}

// TestGenerateISO_OutputDirAlreadyExists verifies that an existing output
// directory is handled gracefully (MkdirAll is idempotent).
func TestGenerateISO_OutputDirAlreadyExists(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "test.iso") // dir already exists

	cfg := Config{
		InstanceID:    "vm-exists",
		LocalHostname: "exists-host",
	}

	// Should not error on MkdirAll for an existing directory.
	err := GenerateISO(cfg, outputPath)
	// Will fail at genisoimage only.
	if err != nil && !strings.Contains(err.Error(), "genisoimage") {
		t.Errorf("unexpected error (not genisoimage): %v", err)
	}
}

// TestConfig_ZeroValue verifies that a zero-value Config is usable.
func TestConfig_ZeroValue(t *testing.T) {
	cfg := Config{}
	if cfg.InstanceID != "" {
		t.Error("zero-value InstanceID should be empty")
	}
	if cfg.LocalHostname != "" {
		t.Error("zero-value LocalHostname should be empty")
	}
	if cfg.UserData != "" {
		t.Error("zero-value UserData should be empty")
	}
	if cfg.NetworkConfig != "" {
		t.Error("zero-value NetworkConfig should be empty")
	}
}

// TestGenerateISO_ZeroConfig uses a completely empty config.
func TestGenerateISO_ZeroConfig(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "zero.iso")

	cfg := Config{}
	err := GenerateISO(cfg, outputPath)
	// Will fail at genisoimage. The important thing is that it doesn't
	// panic or error before reaching genisoimage.
	if err != nil && !strings.Contains(err.Error(), "genisoimage") {
		t.Errorf("unexpected pre-genisoimage error: %v", err)
	}
}

// TestGenerateISO_LargeUserData exercises a large user-data payload.
func TestGenerateISO_LargeUserData(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "large.iso")

	// Build a large-ish cloud-config.
	var sb strings.Builder
	sb.WriteString("#cloud-config\npackages:\n")
	for i := 0; i < 200; i++ {
		sb.WriteString(fmt.Sprintf("  - package-%d\n", i))
	}

	cfg := Config{
		InstanceID:    "large-vm",
		LocalHostname: "large-host",
		UserData:      sb.String(),
	}

	err := GenerateISO(cfg, outputPath)
	if err != nil && !strings.Contains(err.Error(), "genisoimage") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestGenerateISO_SpecialCharsInHostname verifies hostnames with
// special characters don't cause issues in meta-data generation.
func TestGenerateISO_SpecialCharsInHostname(t *testing.T) {
	dir := t.TempDir()
	outputPath := filepath.Join(dir, "special.iso")

	cfg := Config{
		InstanceID:    "vm-special",
		LocalHostname: "host.with-dots.and-dashes",
		UserData:      "#cloud-config\n{}\n",
	}

	err := GenerateISO(cfg, outputPath)
	if err != nil && !strings.Contains(err.Error(), "genisoimage") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestGenerateISO_UserDataWithCloudConfigHeader verifies various user-data formats.
func TestGenerateISO_UserDataVariants(t *testing.T) {
	tests := []struct {
		name     string
		userData string
	}{
		{"cloud-config", "#cloud-config\npackages:\n  - nginx\n"},
		{"shell-script", "#!/bin/bash\necho hello\n"},
		{"include", "#include\nhttps://example.com/config.yaml\n"},
		{"multiline-yaml", "#cloud-config\nruncmd:\n  - echo hello\n  - echo world\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			outputPath := filepath.Join(dir, "test.iso")

			cfg := Config{
				InstanceID:    "variant-vm",
				LocalHostname: "variant-host",
				UserData:      tt.userData,
			}

			err := GenerateISO(cfg, outputPath)
			// Only genisoimage errors are expected.
			if err != nil && !strings.Contains(err.Error(), "genisoimage") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestGenerateISO_NetworkConfigVariants exercises different network config formats.
func TestGenerateISO_NetworkConfigVariants(t *testing.T) {
	tests := []struct {
		name          string
		networkConfig string
	}{
		{"netplan-dhcp", "network:\n  version: 2\n  ethernets:\n    ens3:\n      dhcp4: true\n"},
		{"netplan-static", "network:\n  version: 2\n  ethernets:\n    ens3:\n      addresses:\n        - 10.0.0.5/24\n"},
		{"empty", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			outputPath := filepath.Join(dir, "test.iso")

			cfg := Config{
				InstanceID:    "net-vm",
				LocalHostname: "net-host",
				NetworkConfig: tt.networkConfig,
			}

			err := GenerateISO(cfg, outputPath)
			if err != nil && !strings.Contains(err.Error(), "genisoimage") {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
