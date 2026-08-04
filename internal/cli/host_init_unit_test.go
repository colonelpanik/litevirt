package cli

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/systemdunit"
)

// The installer and the upgrade path each carried their own copy of the systemd
// units, with a comment asking that they "drift together". Nothing enforced it and
// they drifted: the installer kept StartLimitBurst=3/600s and a rollback unit with
// no sentinel gate at all, so on any node created by `lv host init` and never
// upgraded, three restarts inside ten minutes would downgrade a healthy binary and
// burn the only .old. The upgrade path rewrites the unit, but only during an
// upgrade, so nothing ever repaired a freshly-installed node.
//
// This is the guard that was missing. It is deliberately a byte-for-byte
// containment check rather than a property check: a property check would have
// passed on the old text for every property nobody thought to assert, which is
// exactly how the sentinel gate went missing here while being tested over in
// internal/grpcapi.

func TestInstallerShipsTheCanonicalUnits(t *testing.T) {
	script, err := getSetupScript()
	if err != nil {
		t.Fatalf("getSetupScript: %v", err)
	}
	for name, body := range map[string]string{
		"main unit":           systemdunit.Main,
		"rollback unit":       systemdunit.Rollback,
		"needrestart drop-in": systemdunit.Needrestart,
	} {
		if !strings.Contains(script, body) {
			t.Errorf("the installer script does not contain the canonical %s verbatim; "+
				"a fresh node would be installed with something else", name)
		}
	}
}

// TestInstallerCarriesNoStaleUnitText catches the specific settings that went
// stale, in case a future edit reintroduces them alongside the canonical text
// rather than instead of it.
func TestInstallerCarriesNoStaleUnitText(t *testing.T) {
	script, err := getSetupScript()
	if err != nil {
		t.Fatalf("getSetupScript: %v", err)
	}
	for _, stale := range []string{"StartLimitBurst=3", "Restart=on-failure"} {
		if strings.Contains(script, stale) {
			t.Errorf("installer script still contains %q", stale)
		}
	}
	// The ungated rollback is the dangerous one: it restores .old on ANY failed
	// state. Every restore in the script must be preceded by the sentinel check.
	if strings.Contains(script, "mv /usr/local/bin/litevirt.old") &&
		!strings.Contains(script, "litevirt.upgrade-pending") {
		t.Error("the installer's rollback restores .old without checking the .upgrade-pending " +
			"sentinel — a restart storm on a healthy binary would downgrade it")
	}
}
