// Package secretfile writes files whose contents are secret — private keys,
// credential files — with the two properties os.WriteFile does not give you.
package secretfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write replaces path with data, atomically, at no more than perm.
//
// Two things go wrong with the obvious `os.WriteFile(path, data, perm)`:
//
//   - Its mode is applied only when it CREATES the file, and even then the
//     umask masks it. Writing over a file left loose by a restore, a
//     config-management copy, or an earlier run under a different umask keeps
//     the old mode, so a secret lands in a world-readable file with nothing in
//     the output to say so.
//
//   - Adding an os.Chmod afterwards does not fix it. WriteFile truncates in
//     place, so the secret is already in the previously-readable inode before
//     the chmod runs; a descriptor opened beforehand keeps reading across it,
//     and there is a window for new opens. It also cannot write a 0400 file at
//     all — it fails with "permission denied" before reaching the chmod.
//
// So the content goes to a fresh 0600 temp file in the same directory, gets the
// mode explicitly (not through the umask), and is renamed over the target. The
// rename is atomic and gives the new content a new inode: a reader holding the
// old descriptor sees only the old bytes, and no reader ever observes a
// partially-written or briefly-loose secret.
//
// perm is a CEILING, not an assignment. An existing file's mode is intersected
// with it, so an operator who hardened a key to 0400 keeps 0400 and a re-write
// never widens what it finds. internal/pki.TightenKeyMode established that rule
// for key material; this extends it to every secret the daemon and CLI write.
func Write(path string, data []byte, perm os.FileMode) error {
	perm = perm.Perm()
	if fi, err := os.Stat(path); err == nil {
		perm &= fi.Mode().Perm()
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat %s: %w", path, err)
	}

	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp")
	if err != nil {
		return fmt.Errorf("create temp file beside %s: %w", path, err)
	}
	tmp := f.Name()
	// Runs on every failure path. After a successful rename the temp name is
	// gone, so the Remove is a harmless no-op.
	defer func() {
		f.Close()
		os.Remove(tmp)
	}()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", tmp, err)
	}
	// Explicit, because CreateTemp's 0600 is itself umask-masked.
	if err := f.Chmod(perm); err != nil {
		return fmt.Errorf("set mode %04o on %s: %w", perm, tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}
