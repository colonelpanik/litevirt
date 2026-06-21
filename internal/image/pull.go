package image

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// PullProgress reports download progress.
type PullProgress struct {
	BytesDownloaded int64
	TotalBytes      int64
	ProgressPct     float32
	Status          string
	Error           string
}

// Pull downloads an image from a URL to the local store.
func Pull(store *Store, name, url, checksum string, progressCh chan<- PullProgress) error {
	defer close(progressCh)

	destPath := store.ImagePath(name)
	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return fmt.Errorf("create image dir: %w", err)
	}

	progressCh <- PullProgress{Status: "downloading"}

	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: HTTP %d", resp.StatusCode)
	}

	tmpPath := destPath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer func() {
		f.Close()
		os.Remove(tmpPath) // clean up on error
	}()

	hasher := sha256.New()
	writer := io.MultiWriter(f, hasher)

	var downloaded int64
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, err := writer.Write(buf[:n]); err != nil {
				return fmt.Errorf("write: %w", err)
			}
			downloaded += int64(n)
			var pct float32
			if resp.ContentLength > 0 {
				pct = float32(downloaded) / float32(resp.ContentLength) * 100
			}
			progressCh <- PullProgress{
				BytesDownloaded: downloaded,
				TotalBytes:      resp.ContentLength,
				ProgressPct:     pct,
				Status:          "downloading",
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
	}

	f.Close()

	// Verify checksum if provided
	if checksum != "" {
		progressCh <- PullProgress{Status: "verifying checksum"}
		got := "sha256:" + hex.EncodeToString(hasher.Sum(nil))
		expected := checksum
		if !strings.HasPrefix(expected, "sha256:") {
			expected = "sha256:" + expected
		}
		if got != expected {
			os.Remove(tmpPath) // explicit cleanup on checksum failure (#28)
			return fmt.Errorf("checksum mismatch: got %s, expected %s", got, expected)
		}
	}

	// Move to final location
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	progressCh <- PullProgress{
		BytesDownloaded: downloaded,
		TotalBytes:      downloaded,
		ProgressPct:     100,
		Status:          "complete",
	}

	return nil
}
