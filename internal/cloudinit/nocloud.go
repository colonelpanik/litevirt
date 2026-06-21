package cloudinit

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Config holds cloud-init data for a VM.
type Config struct {
	InstanceID    string
	LocalHostname string
	UserData      string // #cloud-config YAML
	NetworkConfig string // optional netplan config
}

// GenerateISO creates a NoCloud cloud-init ISO at the given path.
// Uses genisoimage to create a CDROM with label "cidata".
func GenerateISO(cfg Config, outputPath string) error {
	tmpDir, err := os.MkdirTemp("", "litevirt-cloudinit-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// meta-data
	metaData := fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", cfg.InstanceID, cfg.LocalHostname)
	if err := os.WriteFile(filepath.Join(tmpDir, "meta-data"), []byte(metaData), 0644); err != nil {
		return fmt.Errorf("write meta-data: %w", err)
	}

	// user-data
	userData := cfg.UserData
	if userData == "" {
		userData = "#cloud-config\n{}\n"
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "user-data"), []byte(userData), 0644); err != nil {
		return fmt.Errorf("write user-data: %w", err)
	}

	// network-config (optional)
	if cfg.NetworkConfig != "" {
		if err := os.WriteFile(filepath.Join(tmpDir, "network-config"), []byte(cfg.NetworkConfig), 0644); err != nil {
			return fmt.Errorf("write network-config: %w", err)
		}
	}

	// Ensure output directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	// Generate ISO
	args := []string{
		"-output", outputPath,
		"-volid", "cidata",
		"-joliet",
		"-rock",
		tmpDir,
	}

	cmd := exec.Command("genisoimage", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("genisoimage: %s: %w", string(output), err)
	}

	return nil
}
