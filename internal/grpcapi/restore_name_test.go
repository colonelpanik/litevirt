package grpcapi

import "testing"

// TestValidRestoreName is the B2 regression: the restore name validator must
// reject anything that could escape dataDir via filepath.Join, while accepting
// ordinary names (incl. embedded dots/dashes that aren't traversal).
func TestValidRestoreName(t *testing.T) {
	good := []string{"vm1", "my-vm_2", "Web.01", "a", "snapshot-2026", "a..b", "...", "-rf"}
	bad := []string{
		"",           // empty
		".",          // current dir
		"..",         // parent dir (the traversal primitive)
		"../etc",     // explicit traversal
		"a/b",        // slash
		"foo/../bar", // slash + traversal
		`a\b`,        // backslash
		"vm name",    // space
		"vm;rm",      // shell metachar
		"naïve",      // non-ascii
		"a\x00b",     // NUL
	}
	for _, n := range good {
		if !validRestoreName(n) {
			t.Errorf("validRestoreName(%q) = false, want true", n)
		}
	}
	for _, n := range bad {
		if validRestoreName(n) {
			t.Errorf("validRestoreName(%q) = true, want false (path-traversal / unsafe)", n)
		}
	}
}
