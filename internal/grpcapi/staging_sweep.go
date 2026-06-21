package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// stagingTempPrefixes are the os.CreateTemp prefixes used by streaming
// operations (replicate / ISO upload / image import / restore). They are
// normally removed by a deferred cleanup on the error/success path — which a
// hard crash (SIGKILL, power loss) of the daemon skips, leaking the temp file
// with nothing to ever remove it. Repeated crashes then fill the pool/image
// dirs. We sweep stale ones on startup.
var stagingTempPrefixes = []string{".repl-", ".upload-", "import-", "restore-", ".promote-"}

// sweepStaleStagingTemps removes leftover staging temp files older than maxAge
// from dir, returning the count removed. The age guard avoids racing a genuinely
// in-flight operation (there shouldn't be one at startup, but it's cheap
// insurance if this is ever called periodically).
func sweepStaleStagingTemps(dir string, maxAge time.Duration, now time.Time) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if !strings.HasSuffix(n, ".tmp") || !hasStagingPrefix(n) {
			continue
		}
		info, err := e.Info()
		if err != nil || now.Sub(info.ModTime()) < maxAge {
			continue
		}
		if os.Remove(filepath.Join(dir, n)) == nil {
			removed++
		}
	}
	return removed
}

func hasStagingPrefix(name string) bool {
	for _, p := range stagingTempPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// SweepStaleStaging removes leaked operation staging temp files from this host's
// pool, image, and disk directories. Called once at startup so a daemon that was
// killed mid-replicate/upload/import/restore doesn't leak staging files forever.
func (s *Server) SweepStaleStaging(ctx context.Context) {
	dirs := map[string]struct{}{
		filepath.Join(s.dataDir, "images"): {},
		filepath.Join(s.dataDir, "disks"):  {},
	}
	if pools, err := corrosion.ListStoragePoolsForHost(ctx, s.db, s.hostName); err == nil {
		for _, p := range pools {
			if !isFileBasedDriver(p.Driver) {
				continue
			}
			if dir, derr := fileBasedPoolDir(s.dataDir, StoragePoolRef{Driver: p.Driver, Source: p.Source, Target: p.Target}); derr == nil {
				dirs[dir] = struct{}{}
			}
		}
	}
	total := 0
	for dir := range dirs {
		total += sweepStaleStagingTemps(dir, time.Hour, time.Now())
	}
	if total > 0 {
		slog.Info("startup: swept stale staging temp files (leaked by a prior hard crash)", "removed", total)
	}
}
