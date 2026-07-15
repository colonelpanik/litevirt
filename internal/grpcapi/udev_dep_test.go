package grpcapi

import (
	"os"
	"path/filepath"
	"testing"
)

const knownLitevirtUdevRule = `# litevirt: notify daemon on PCI device add/remove events.
ACTION=="add", SUBSYSTEM=="pci", RUN+="/usr/bin/curl -s -X POST http://127.0.0.1:7446/api/v1/hosts/rescan || true"
`

func TestIsLitevirtUdevRule(t *testing.T) {
	if !isLitevirtUdevRule(knownLitevirtUdevRule) {
		t.Error("known litevirt rule not recognized")
	}
	if isLitevirtUdevRule("# something else entirely\nACTION==\"add\"\n") {
		t.Error("foreign file misidentified as the litevirt rule")
	}
}

func TestRemoveStaleUdevRuleAt_KnownRemoved(t *testing.T) {
	p := filepath.Join(t.TempDir(), "99-litevirt-pci.rules")
	if err := os.WriteFile(p, []byte(knownLitevirtUdevRule), 0o644); err != nil {
		t.Fatal(err)
	}
	if !removeStaleUdevRuleAt(p) {
		t.Fatal("expected the known rule to be removed")
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("known litevirt rule not deleted")
	}
}

func TestRemoveStaleUdevRuleAt_ForeignUntouched(t *testing.T) {
	p := filepath.Join(t.TempDir(), "99-litevirt-pci.rules")
	foreign := "# operator's own rule\nACTION==\"add\", SUBSYSTEM==\"pci\", RUN+=\"/opt/custom.sh\"\n"
	if err := os.WriteFile(p, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	if removeStaleUdevRuleAt(p) {
		t.Fatal("a foreign file must not be removed")
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != foreign {
		t.Error("foreign file was modified or deleted")
	}
}
