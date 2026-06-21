package qcow2

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type fakeCloser struct{ err error }

func (f fakeCloser) Close() error { return f.err }

// TestCloseAndCleanup is the C2 regression: a Close (fsync) failure on a fresh
// qcow2 must surface as the returned error and the suspect file must be removed,
// instead of being silently dropped.
func TestCloseAndCleanup(t *testing.T) {
	t.Run("close error surfaces and file removed", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "img")
		if err := os.WriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		err := closeAndCleanup(fakeCloser{err: errors.New("fsync failed")}, p, nil)
		if err == nil || !strings.Contains(err.Error(), "fsync failed") {
			t.Fatalf("want wrapped close error, got %v", err)
		}
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Error("file should be removed when Close fails")
		}
	})

	t.Run("clean close keeps file, no error", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "img")
		if err := os.WriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := closeAndCleanup(fakeCloser{}, p, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if _, statErr := os.Stat(p); statErr != nil {
			t.Errorf("file should remain on clean close: %v", statErr)
		}
	})

	t.Run("prior error preserved over close error, file removed", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "img")
		if err := os.WriteFile(p, []byte("data"), 0644); err != nil {
			t.Fatal(err)
		}
		prior := errors.New("write header failed")
		err := closeAndCleanup(fakeCloser{err: errors.New("also a close error")}, p, prior)
		if !errors.Is(err, prior) {
			t.Fatalf("prior error should be preserved, got %v", err)
		}
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Error("file should be removed when the overall result is an error")
		}
	})
}
