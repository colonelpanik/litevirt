package pki

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func setupCA(t *testing.T) (caPath, keyPath, dir string) {
	t.Helper()
	dir = t.TempDir()
	caPath = filepath.Join(dir, "ca.crt")
	keyPath = filepath.Join(dir, "ca.key")
	if err := GenerateCA(caPath, keyPath); err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	return caPath, keyPath, dir
}

func TestGenerateCRL_CreatesFile(t *testing.T) {
	caPath, keyPath, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")

	err := GenerateCRL(caPath, keyPath, crlPath, []string{"1a2b3c"})
	if err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}
	if _, err := os.Stat(crlPath); err != nil {
		t.Fatalf("CRL file not created: %v", err)
	}
}

func TestLoadCRL_RoundTrip(t *testing.T) {
	caPath, keyPath, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")

	serials := []string{"1a", "2b", "3c"}
	if err := GenerateCRL(caPath, keyPath, crlPath, serials); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}

	loaded, err := LoadCRL(crlPath)
	if err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	if len(loaded) != 3 {
		t.Fatalf("expected 3 serials, got %d: %v", len(loaded), loaded)
	}
}

func TestLoadCRL_FileNotFound(t *testing.T) {
	_, err := LoadCRL("/nonexistent/crl.pem")
	if err == nil {
		t.Fatal("expected error for missing CRL file")
	}
}

func TestIsCertRevoked_True(t *testing.T) {
	caPath, keyPath, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")

	serial := "deadbeef"
	if err := GenerateCRL(caPath, keyPath, crlPath, []string{serial}); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}

	s := new(big.Int)
	s.SetString(serial, 16)
	if !IsCertRevoked(dir, s) {
		t.Error("expected certificate to be revoked")
	}
}

func TestIsCertRevoked_False(t *testing.T) {
	caPath, keyPath, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")

	if err := GenerateCRL(caPath, keyPath, crlPath, []string{"aaa"}); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}

	s := new(big.Int)
	s.SetString("bbb", 16)
	if IsCertRevoked(dir, s) {
		t.Error("expected certificate to NOT be revoked")
	}
}

func TestIsCertRevoked_NoCRL(t *testing.T) {
	dir := t.TempDir() // no CRL file
	s := new(big.Int)
	s.SetString("123", 16)
	if IsCertRevoked(dir, s) {
		t.Error("no CRL should mean not revoked")
	}
}

func TestAppendToCRL_NewSerial(t *testing.T) {
	caPath, keyPath, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")

	// First serial.
	if err := AppendToCRL(caPath, keyPath, crlPath, "aaa"); err != nil {
		t.Fatalf("AppendToCRL first: %v", err)
	}
	// Second serial.
	if err := AppendToCRL(caPath, keyPath, crlPath, "bbb"); err != nil {
		t.Fatalf("AppendToCRL second: %v", err)
	}

	loaded, err := LoadCRL(crlPath)
	if err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("expected 2 serials, got %d: %v", len(loaded), loaded)
	}
}

func TestAppendToCRL_DuplicateSkipped(t *testing.T) {
	caPath, keyPath, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")

	if err := AppendToCRL(caPath, keyPath, crlPath, "aaa"); err != nil {
		t.Fatalf("AppendToCRL: %v", err)
	}
	// Append same serial again — should be a no-op.
	if err := AppendToCRL(caPath, keyPath, crlPath, "aaa"); err != nil {
		t.Fatalf("AppendToCRL duplicate: %v", err)
	}

	loaded, err := LoadCRL(crlPath)
	if err != nil {
		t.Fatalf("LoadCRL: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("expected 1 serial after duplicate, got %d", len(loaded))
	}
}

func TestCRLVersion_ValidCRL(t *testing.T) {
	caPath, keyPath, dir := setupCA(t)
	crlPath := filepath.Join(dir, "crl.pem")

	if err := GenerateCRL(caPath, keyPath, crlPath, []string{"abc"}); err != nil {
		t.Fatalf("GenerateCRL: %v", err)
	}

	ver := CRLVersion(crlPath)
	if ver <= 0 {
		t.Errorf("CRLVersion = %d, expected > 0", ver)
	}
}

func TestCRLVersion_MissingFile(t *testing.T) {
	ver := CRLVersion("/nonexistent/crl.pem")
	if ver != 0 {
		t.Errorf("CRLVersion for missing file = %d, want 0", ver)
	}
}

func TestCRLVersion_InvalidFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	os.WriteFile(path, []byte("not a PEM"), 0644)

	ver := CRLVersion(path)
	if ver != 0 {
		t.Errorf("CRLVersion for invalid file = %d, want 0", ver)
	}
}
