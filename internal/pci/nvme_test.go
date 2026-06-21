package pci

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanNVMeNamespaces(t *testing.T) {
	// Create a fake sysfs tree for NVMe.
	tmp := t.TempDir()
	old := nvmeClassPath
	nvmeClassPath = tmp
	defer func() { nvmeClassPath = old }()

	// Create controller nvme0 with namespace nvme0n1.
	ctrl := filepath.Join(tmp, "nvme0")
	os.MkdirAll(ctrl, 0755)

	ns := filepath.Join(ctrl, "nvme0n1")
	os.MkdirAll(ns, 0755)

	// Write size (1000 blocks of 512 bytes = 512000 bytes).
	os.WriteFile(filepath.Join(ns, "size"), []byte("1000\n"), 0644)
	os.WriteFile(filepath.Join(ns, "state"), []byte("live\n"), 0644)

	namespaces, err := ScanNVMeNamespaces()
	if err != nil {
		t.Fatalf("ScanNVMeNamespaces: %v", err)
	}

	if len(namespaces) != 1 {
		t.Fatalf("expected 1 namespace, got %d", len(namespaces))
	}

	ns0 := namespaces[0]
	if ns0.Controller != "nvme0" {
		t.Errorf("controller = %q, want nvme0", ns0.Controller)
	}
	if ns0.NSID != 1 {
		t.Errorf("NSID = %d, want 1", ns0.NSID)
	}
	if ns0.SizeBytes != 512000 {
		t.Errorf("SizeBytes = %d, want 512000", ns0.SizeBytes)
	}
	if ns0.State != "live" {
		t.Errorf("State = %q, want live", ns0.State)
	}
}

func TestScanNVMeNamespaces_NoControllers(t *testing.T) {
	tmp := t.TempDir()
	old := nvmeClassPath
	nvmeClassPath = tmp
	defer func() { nvmeClassPath = old }()

	namespaces, err := ScanNVMeNamespaces()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(namespaces) != 0 {
		t.Fatalf("expected 0 namespaces, got %d", len(namespaces))
	}
}

func TestScanNVMeNamespaces_MultipleNamespaces(t *testing.T) {
	tmp := t.TempDir()
	old := nvmeClassPath
	nvmeClassPath = tmp
	defer func() { nvmeClassPath = old }()

	ctrl := filepath.Join(tmp, "nvme0")
	os.MkdirAll(ctrl, 0755)

	for _, name := range []string{"nvme0n1", "nvme0n2", "nvme0n3"} {
		ns := filepath.Join(ctrl, name)
		os.MkdirAll(ns, 0755)
		os.WriteFile(filepath.Join(ns, "size"), []byte("2048\n"), 0644)
		os.WriteFile(filepath.Join(ns, "state"), []byte("live\n"), 0644)
	}

	namespaces, err := ScanNVMeNamespaces()
	if err != nil {
		t.Fatalf("ScanNVMeNamespaces: %v", err)
	}

	if len(namespaces) != 3 {
		t.Fatalf("expected 3 namespaces, got %d", len(namespaces))
	}

	for _, ns := range namespaces {
		if ns.SizeBytes != 2048*512 {
			t.Errorf("namespace %d: SizeBytes = %d, want %d", ns.NSID, ns.SizeBytes, 2048*512)
		}
	}
}
