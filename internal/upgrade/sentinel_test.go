package upgrade

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSentinelRoundTrip(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "litevirt")

	if _, ok := Read(bin); ok {
		t.Fatal("Read on a fresh path should report no sentinel")
	}

	if err := Arm(bin, "v1.0.30"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	if _, err := os.Stat(SentinelPath(bin)); err != nil {
		t.Fatalf("sentinel file missing after Arm: %v", err)
	}

	s, ok := Read(bin)
	if !ok {
		t.Fatal("Read should find the armed sentinel")
	}
	if s.PrevVersion != "v1.0.30" {
		t.Errorf("PrevVersion = %q, want v1.0.30", s.PrevVersion)
	}
	if s.Attempt != 0 {
		t.Errorf("fresh sentinel Attempt = %d, want 0", s.Attempt)
	}

	BumpAttempt(bin, s)
	s2, ok := Read(bin)
	if !ok || s2.Attempt != 1 {
		t.Fatalf("after BumpAttempt: ok=%v attempt=%d, want true/1", ok, s2.Attempt)
	}
	if s2.PrevVersion != "v1.0.30" {
		t.Errorf("BumpAttempt lost PrevVersion: %q", s2.PrevVersion)
	}

	Clear(bin)
	if _, ok := Read(bin); ok {
		t.Fatal("Read after Clear should report no sentinel")
	}
}

func TestReadMalformedSentinel(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "litevirt")
	if err := os.WriteFile(SentinelPath(bin), []byte("{not json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, ok := Read(bin); ok {
		t.Fatal("malformed sentinel should not parse")
	}
}
