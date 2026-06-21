package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse_FileBasedValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	yaml := `name: test
vms:
  web:
    image: ubuntu
    cpu: 2
    memory: 1G
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}
	f, err := Parse(path)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(f.VMs) != 1 {
		t.Errorf("VMs = %d, want 1", len(f.VMs))
	}
}

func TestParse_FileNotFound(t *testing.T) {
	_, err := Parse("/nonexistent/compose.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestParse_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(path, []byte("{{invalid yaml"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Parse(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}
