package health

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/litevirt/litevirt/internal/safename"
)

// Phase 4 runtime markers: each landed ownership transition mirrors the DB's
// owner epoch into a host-local, root-owned marker file
// (<containersRoot>/<name>/owner_epoch, 0600). The marker is what lets a
// REJOINED node see that its local runtime state belongs to a superseded
// generation without trusting its own — possibly stale — replica: the DB copy
// a dead node carries back is exactly the thing that lied in the observed
// dual-run. Enforcement (refusing stale-row self-heal restarts on a
// marker/DB mismatch) activates only under owner_epoch_v1; until then the
// markers are written and converged but never gate an action.

// ownerEpochMarkerFile is the per-container marker filename.
const ownerEpochMarkerFile = "owner_epoch"

// WriteContainerOwnerEpochMarker records the container's current ownership
// generation on this host. Written through a temp file + rename so a crash
// mid-write can never leave a half-written marker that reads as garbage.
func WriteContainerOwnerEpochMarker(containersRoot, name string, epoch int64) error {
	if err := safename.ValidateContainerName(name); err != nil {
		return err
	}
	dir := filepath.Join(containersRoot, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create marker dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ownerEpochMarkerFile+".tmp-*")
	if err != nil {
		return fmt.Errorf("create marker temp: %w", err)
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod marker: %w", err)
	}
	if _, err := tmp.WriteString(strconv.FormatInt(epoch, 10) + "\n"); err != nil {
		tmp.Close()
		return fmt.Errorf("write marker: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close marker: %w", err)
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, ownerEpochMarkerFile))
}

// ReadContainerOwnerEpochMarker reads the marker. (0,false,nil) when absent —
// pre-epoch containers have none, and nothing may fail closed on that before
// owner_epoch_v1 latches. Corrupt content is an ERROR, never epoch 0: garbage
// read as the zero generation would authorize exactly the stale actions the
// marker exists to refuse.
func ReadContainerOwnerEpochMarker(containersRoot, name string) (int64, bool, error) {
	if err := safename.ValidateContainerName(name); err != nil {
		return 0, false, err
	}
	raw, err := os.ReadFile(filepath.Join(containersRoot, name, ownerEpochMarkerFile))
	if os.IsNotExist(err) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	epoch, perr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if perr != nil {
		return 0, false, fmt.Errorf("corrupt owner-epoch marker for %q: %w", name, perr)
	}
	return epoch, true, nil
}

// RemoveContainerOwnerEpochMarker clears the marker when the container leaves
// this host for good (delete / relocation source cleanup). Missing is fine.
func RemoveContainerOwnerEpochMarker(containersRoot, name string) error {
	if err := safename.ValidateContainerName(name); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(containersRoot, name, ownerEpochMarkerFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
