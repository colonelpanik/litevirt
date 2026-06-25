package vmimport

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Archive resource caps (DoS guards). An OVA is an uncompressed tar whose disk
// members are legitimately large, so the ceilings are generous — they exist to
// stop a pathological archive (millions of members, absurd sizes) from filling
// the import staging dir before any quota check runs.
const (
	maxArchiveMembers   = 4096
	maxArchiveTotalSize = 8 << 40 // 8 TiB across all members
	maxMemberSize       = 4 << 40 // 4 TiB single member
)

// safeJoin cleans a tar member name and joins it under dest, rejecting absolute
// paths and "../" traversal (tar-slip). Returns the absolute destination path.
func safeJoin(dest, name string) (string, error) {
	clean := filepath.Clean("/" + strings.ReplaceAll(name, "\\", "/")) // force-relative
	clean = strings.TrimPrefix(clean, "/")
	if clean == "" || clean == "." {
		return "", fmt.Errorf("empty archive member name")
	}
	target := filepath.Join(dest, clean)
	// Ensure the result is still under dest (defends against any residual escape).
	rel, err := filepath.Rel(dest, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive member %q escapes destination", name)
	}
	return target, nil
}

// UnpackOVA extracts an OVA tar stream into dest (slip-safe, capped) and returns
// the path to the single .ovf descriptor. Symlink/hardlink/device members are
// rejected. Disk members and the descriptor land flat under dest.
func UnpackOVA(r io.Reader, dest string) (ovfPath string, err error) {
	tr := tar.NewReader(r)
	var (
		members int
		total   int64
	)
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", fmt.Errorf("read ova tar: %w", e)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue // flat layout; directories are not needed
		case tar.TypeReg, tar.TypeRegA:
			// extract below
		default:
			return "", fmt.Errorf("ova member %q has disallowed type %d (symlink/hardlink/device not permitted)", hdr.Name, hdr.Typeflag)
		}
		members++
		if members > maxArchiveMembers {
			return "", fmt.Errorf("ova exceeds member cap (%d)", maxArchiveMembers)
		}
		if hdr.Size > maxMemberSize {
			return "", fmt.Errorf("ova member %q exceeds size cap", hdr.Name)
		}
		target, e := safeJoin(dest, hdr.Name)
		if e != nil {
			return "", e
		}
		// Flatten: keep only the base name so split-VMDK extents + descriptor sit
		// beside each other (OVF hrefs are relative basenames).
		target = filepath.Join(dest, filepath.Base(target))
		n, e := writeCapped(target, tr, &total)
		if e != nil {
			return "", e
		}
		_ = n
		if strings.EqualFold(filepath.Ext(target), ".ovf") {
			ovfPath = target
		}
	}
	if ovfPath == "" {
		return "", fmt.Errorf("no .ovf descriptor found in OVA")
	}
	return ovfPath, nil
}

// writeCapped copies src to a new file at path, enforcing the cumulative total cap.
func writeCapped(path string, src io.Reader, total *int64) (int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return 0, fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()
	lr := &cappedReader{r: src, total: total}
	n, err := io.Copy(f, lr)
	if err != nil {
		return n, err
	}
	if err := f.Sync(); err != nil {
		return n, fmt.Errorf("sync %s: %w", path, err)
	}
	return n, nil
}

// cappedReader fails once the cumulative bytes read across the archive exceed
// maxArchiveTotalSize.
type cappedReader struct {
	r     io.Reader
	total *int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.total += int64(n)
	if *c.total > maxArchiveTotalSize {
		return n, fmt.Errorf("archive exceeds total size cap (%d bytes)", maxArchiveTotalSize)
	}
	return n, err
}

// InspectOVA reads the tar only until the .ovf member and returns its bytes
// (does not extract the multi-GB disks) — for the --inspect dry run.
func InspectOVA(r io.Reader) ([]byte, error) {
	tr := tar.NewReader(r)
	for {
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return nil, fmt.Errorf("read ova tar: %w", e)
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		if strings.EqualFold(filepath.Ext(hdr.Name), ".ovf") {
			if hdr.Size > 64<<20 {
				return nil, fmt.Errorf("ovf descriptor implausibly large (%d bytes)", hdr.Size)
			}
			return io.ReadAll(io.LimitReader(tr, 64<<20))
		}
	}
	return nil, fmt.Errorf("no .ovf descriptor found in OVA")
}
