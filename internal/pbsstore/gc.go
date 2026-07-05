package pbsstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// GCStats summarises a mark-and-sweep pass.
type GCStats struct {
	ManifestsScanned int
	ChunksReferenced int   // unique chunks reached from any manifest
	ChunksOnDisk     int   // chunks present in chunks/ at scan time
	ChunksDeleted    int   // chunks removed because no manifest pointed at them
	ChunksSkippedYoung int // unreferenced chunks retained because within the grace window
	BytesReclaimed   int64 // total bytes of deleted chunks
}

// DefaultChunkGracePeriod is how long an unreferenced chunk is retained
// before GC is allowed to sweep it. It exists to close the push/GC race:
// PushDisk writes content-addressed chunks incrementally and only writes
// the manifest that references them once every chunk has landed, so a
// chunk emitted by an in-flight push looks like garbage until its manifest
// appears. Any chunk younger than this window is left alone, matching
// Proxmox Backup Server's own chunk grace discipline. This is the robust,
// cross-host-safe guard (an flock is unreliable over NFS and only a
// same-host push takes one); coordination leases are an additional, not a
// substitute, protection.
const DefaultChunkGracePeriod = 24 * time.Hour

// GCOptions tunes a sweep. The zero value is NOT the safe default — use
// GC (which applies DefaultChunkGracePeriod) unless you explicitly want a
// different grace (e.g. 0 in a test that asserts the sweep mechanic).
type GCOptions struct {
	// ChunkGracePeriod: an unreferenced chunk whose mtime is younger than
	// this is retained rather than deleted. Zero sweeps every unreferenced
	// chunk regardless of age (unsafe against a concurrent push).
	ChunkGracePeriod time.Duration
}

// GC performs a mark-and-sweep over the repository with the default chunk
// grace period. See GCWithOptions.
func GC(ctx context.Context, r *Repo) (GCStats, error) {
	return GCWithOptions(ctx, r, GCOptions{ChunkGracePeriod: DefaultChunkGracePeriod})
}

// GCWithOptions performs a mark-and-sweep over the repository:
//  1. Walks every manifest and collects the union of chunk ids.
//  2. Walks chunks/aa/aabbcc... and deletes any chunk not in the union
//     that is also older than opts.ChunkGracePeriod.
//
// GC is safe to run concurrently with reads (GetChunk on a deleted
// chunk returns an error which the caller already handles). The grace
// period makes it safe against a concurrent PushDisk in another process
// or on another host: a chunk emitted by an in-flight (or very recently
// completed) push whose manifest hasn't landed yet is younger than the
// window and is retained. Cluster-level coordination (a leader-election
// lease keyed by the repo path) is still recommended to avoid two GC
// passes racing each other, but is no longer required for push safety.
func GCWithOptions(ctx context.Context, r *Repo, opts GCOptions) (GCStats, error) {
	var stats GCStats
	manifests, err := r.ListManifests()
	if err != nil {
		return stats, fmt.Errorf("list manifests: %w", err)
	}
	live := make(map[string]struct{})
	for _, m := range manifests {
		stats.ManifestsScanned++
		for _, c := range m.AllChunks() {
			live[c.ID] = struct{}{}
		}
	}
	stats.ChunksReferenced = len(live)

	cutoff := time.Now().Add(-opts.ChunkGracePeriod)
	chunksRoot := filepath.Join(r.root, "chunks")
	err = filepath.WalkDir(chunksRoot, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			if errors.Is(werr, os.ErrNotExist) {
				return nil
			}
			return werr
		}
		if d.IsDir() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		stats.ChunksOnDisk++
		// Recover chunk id from filename (last path component).
		id := filepath.Base(path)
		if _, ok := live[id]; ok {
			return nil
		}
		// Skip in-flight tmp files written by PutChunk.
		if strings.HasSuffix(id, ".tmp") {
			return nil
		}
		st, sErr := d.Info()
		if sErr != nil {
			return nil
		}
		// Retain a chunk that is younger than the grace window — it may
		// belong to a push whose manifest has not yet landed. Only sweep
		// once it has been unreferenced-and-quiescent for the full window.
		if opts.ChunkGracePeriod > 0 && st.ModTime().After(cutoff) {
			stats.ChunksSkippedYoung++
			return nil
		}
		if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return fmt.Errorf("delete unreferenced chunk %s: %w", id, rmErr)
		}
		stats.ChunksDeleted++
		stats.BytesReclaimed += st.Size()
		return nil
	})
	if err != nil {
		return stats, err
	}
	return stats, nil
}

// VerifyStats summarises a verification pass.
type VerifyStats struct {
	ChunksChecked int
	Mismatches    []string // ids whose on-disk content disagrees with their filename
	Missing       []string // chunk ids referenced by a manifest but absent from chunks/
}

// Verify recomputes every chunk's BLAKE3 against its filename and
// records any mismatch. Also reports manifest references whose chunk
// is missing — useful after a partial restore from off-site backup.
func Verify(ctx context.Context, r *Repo) (VerifyStats, error) {
	var stats VerifyStats
	manifests, err := r.ListManifests()
	if err != nil {
		return stats, err
	}
	seen := make(map[string]struct{})
	for _, m := range manifests {
		for _, c := range m.AllChunks() {
			if _, ok := seen[c.ID]; ok {
				continue
			}
			seen[c.ID] = struct{}{}
			select {
			case <-ctx.Done():
				return stats, ctx.Err()
			default:
			}
			stats.ChunksChecked++
			_, err := r.GetChunk(c.ID)
			if errors.Is(err, ErrChunkMismatch) {
				stats.Mismatches = append(stats.Mismatches, c.ID)
				continue
			}
			if errors.Is(err, os.ErrNotExist) || (err != nil && strings.Contains(err.Error(), "no such file")) {
				stats.Missing = append(stats.Missing, c.ID)
				continue
			}
			if err != nil {
				return stats, fmt.Errorf("verify %s: %w", c.ID, err)
			}
		}
	}
	return stats, nil
}

// RetentionPolicy expresses Proxmox-style keep N daily/weekly/monthly/yearly.
// Zero means unlimited for that bucket.
type RetentionPolicy struct {
	KeepLast    int
	KeepDaily   int
	KeepWeekly  int
	KeepMonthly int
	KeepYearly  int
}

// PrunePlan is the intended outcome of a retention pass — a list of
// manifest paths that may be deleted. Callers apply the plan with
// ApplyPrune (or hand it back to a UI for confirmation).
type PrunePlan struct {
	Keep   []Manifest
	Delete []Manifest
}

// PlanPrune applies the policy per VM+disk pair and returns the plan
// without touching anything on disk.
func PlanPrune(r *Repo, policy RetentionPolicy) (PrunePlan, error) {
	manifests, err := r.ListManifests()
	if err != nil {
		return PrunePlan{}, err
	}
	// Group by (VMName, DiskName); within each group sort newest first.
	groups := map[string][]Manifest{}
	for _, m := range manifests {
		key := m.VMName + "/" + m.DiskName
		groups[key] = append(groups[key], m)
	}
	var plan PrunePlan
	for _, group := range groups {
		sort.Slice(group, func(i, j int) bool { return group[i].Timestamp > group[j].Timestamp })
		keep, drop := selectByPolicy(group, policy)
		plan.Keep = append(plan.Keep, keep...)
		plan.Delete = append(plan.Delete, drop...)
	}
	return plan, nil
}

// ApplyPrune deletes the manifests in plan.Delete from disk. Chunks
// orphaned by the deletion remain until GC runs — this lets us undo a
// mistaken prune by restoring the manifest from a backup if it was
// noticed before the next GC cycle.
func ApplyPrune(r *Repo, plan PrunePlan) error {
	for _, m := range plan.Delete {
		path := filepath.Join(r.root, "snapshots", m.VMName,
			fmt.Sprintf("%s-%s.manifest.json", filenameSafeTS(m.Timestamp), m.DiskName))
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove manifest %s: %w", path, err)
		}
	}
	return nil
}

// selectByPolicy decides which manifests to keep given a chronologically
// descending input slice. The buckets cascade — once KeepLast slots are
// filled the same manifest may also satisfy daily/weekly etc.
func selectByPolicy(snapshots []Manifest, p RetentionPolicy) (keep, drop []Manifest) {
	keepSet := map[string]bool{}
	keepInBucket := func(b map[string]struct{}, key string, limit int, m Manifest) {
		if limit <= 0 {
			return
		}
		if _, ok := b[key]; ok {
			return
		}
		if len(b) >= limit {
			return
		}
		b[key] = struct{}{}
		keepSet[m.Timestamp] = true
	}
	daily := map[string]struct{}{}
	weekly := map[string]struct{}{}
	monthly := map[string]struct{}{}
	yearly := map[string]struct{}{}
	last := 0
	for _, m := range snapshots {
		if last < p.KeepLast {
			keepSet[m.Timestamp] = true
			last++
		}
		t, err := time.Parse(time.RFC3339, m.Timestamp)
		if err != nil {
			continue
		}
		dKey := t.Format("2006-01-02")
		yr, wk := t.ISOWeek()
		wKey := fmt.Sprintf("%d-W%02d", yr, wk)
		mKey := t.Format("2006-01")
		yKey := t.Format("2006")
		keepInBucket(daily, dKey, p.KeepDaily, m)
		keepInBucket(weekly, wKey, p.KeepWeekly, m)
		keepInBucket(monthly, mKey, p.KeepMonthly, m)
		keepInBucket(yearly, yKey, p.KeepYearly, m)
	}
	for _, m := range snapshots {
		if keepSet[m.Timestamp] {
			keep = append(keep, m)
		} else {
			drop = append(drop, m)
		}
	}
	return keep, drop
}
