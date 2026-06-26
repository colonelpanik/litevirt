package pbsstore

import (
	"context"
	"fmt"
	"io"
	"sort"
)

// DirtyRegions describes which byte ranges of a disk have changed since
// the parent snapshot. The interface is intentionally narrow so a real
// implementation can wrap a libvirt block-dirty-bitmap, while tests
// supply a hand-built mock.
type DirtyRegions interface {
	// IsDirty reports whether [offset, offset+length) intersects any
	// region that's been written since the parent snapshot. May report
	// false positives (it's safe to push a chunk we didn't need to);
	// must NEVER report false negatives, or restore would silently
	// produce stale data.
	IsDirty(offset, length int64) bool
}

// PushIncremental writes a new snapshot whose chunks are either:
//   - newly emitted from src (when DirtyRegions says the chunk is dirty), or
//   - inherited verbatim from the parent manifest's chunk refs.
//
// The result is a self-contained Manifest — restore code does not
// special-case incrementals; it just follows chunk refs.
//
// Caller responsibilities:
//   - parent must be the manifest the bitmap is "based on" (matches
//     the bitmap's reference point).
//   - src must be a stream of the *current* full disk; we choose
//     whether to consume each chunk's bytes based on the bitmap.
//   - bitmap.IsDirty must be conservative (false-positives only).
func PushIncremental(
	ctx context.Context,
	repo *Repo,
	src io.Reader,
	parent *Manifest,
	bitmap DirtyRegions,
	opts PushOptions,
) (*Manifest, error) {
	if parent == nil {
		return nil, fmt.Errorf("parent manifest required for incremental push")
	}
	if bitmap == nil {
		return nil, fmt.Errorf("dirty-region bitmap required for incremental push")
	}
	if opts.VMName == "" || opts.DiskName == "" {
		return nil, fmt.Errorf("vm + disk name required")
	}

	// Fast path: when the source supports random access (a real disk file
	// or *bytes.Reader), seek past clean regions so we never READ them —
	// this is the actual read-I/O the dirty bitmap saves. Falls through to
	// the sequential reader below for non-seekable sources.
	if ra, okRA := src.(io.ReaderAt); okRA {
		if sk, okSk := src.(io.Seeker); okSk {
			return pushIncrementalSeek(ctx, repo, ra, sk, parent, bitmap, opts)
		}
	}

	// Build an offset → ChunkRef map of the parent manifest so we can
	// inherit refs for clean regions in O(1).
	parentByOffset := make(map[int64]ChunkRef, len(parent.Chunks))
	for _, c := range parent.Chunks {
		parentByOffset[c.Offset] = c
	}

	m := &Manifest{
		VMName:     opts.VMName,
		DiskName:   opts.DiskName,
		Timestamp:  opts.Timestamp,
		BasedOn:    parent.Timestamp,
		BitmapName:     opts.BitmapName,
		VMSpecJSON:     opts.VMSpecJSON,
		DomainXML:      opts.DomainXML,
		FirmwareChunks: opts.FirmwareChunks,
	}
	buf := make([]byte, ChunkSize)
	var prog PushProgress
	err := ReadChunks(src, buf, func(off int64, data []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		size := int64(len(data))
		if !bitmap.IsDirty(off, size) {
			// Reuse parent ref if it lines up. Falling through to the
			// dirty path is the conservative answer when the parent's
			// chunk boundaries don't match (e.g. disk was resized).
			if pc, ok := parentByOffset[off]; ok && pc.Size == size {
				m.Chunks = append(m.Chunks, pc)
				m.TotalSize += pc.Size
				prog.BytesProcessed += pc.Size
				prog.BytesRead += pc.Size // sequential source: already read
				prog.ChunksTotal++
				prog.ChunksDeduped++
				if opts.Progress != nil {
					opts.Progress(prog)
				}
				return nil
			}
		}
		chunk := append([]byte(nil), data...)
		id, created, err := repo.PutChunk(chunk)
		if err != nil {
			return fmt.Errorf("put chunk at offset %d: %w", off, err)
		}
		m.Chunks = append(m.Chunks, ChunkRef{ID: id, Size: size, Offset: off})
		m.TotalSize += size
		prog.BytesProcessed += size
		prog.BytesRead += size
		prog.ChunksTotal++
		if created {
			prog.BytesNew += size
		} else {
			prog.ChunksDeduped++
		}
		if opts.Progress != nil {
			opts.Progress(prog)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := repo.PutManifest(m); err != nil {
		return nil, fmt.Errorf("write incremental manifest: %w", err)
	}
	return m, nil
}

// pushIncrementalSeek is the random-access incremental path: it walks the
// disk in ChunkSize windows and, for clean windows that line up with a
// parent chunk, inherits the parent ref WITHOUT reading the bytes —
// turning the dirty bitmap into real read-I/O savings. Dirty (or
// unaligned, or beyond-parent) windows are ReadAt'd and stored.
//
// The source's current size (via Seek-to-end) is authoritative, so a disk
// that grew since the parent is fully covered (the tail is treated as
// dirty), and a disk that shrank stops at the new size.
func pushIncrementalSeek(
	ctx context.Context,
	repo *Repo,
	ra io.ReaderAt,
	sk io.Seeker,
	parent *Manifest,
	bitmap DirtyRegions,
	opts PushOptions,
) (*Manifest, error) {
	size, err := sk.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("seek source size: %w", err)
	}

	parentByOffset := make(map[int64]ChunkRef, len(parent.Chunks))
	for _, c := range parent.Chunks {
		parentByOffset[c.Offset] = c
	}

	m := &Manifest{
		VMName:     opts.VMName,
		DiskName:   opts.DiskName,
		Timestamp:  opts.Timestamp,
		BasedOn:    parent.Timestamp,
		BitmapName:     opts.BitmapName,
		VMSpecJSON:     opts.VMSpecJSON,
		DomainXML:      opts.DomainXML,
		FirmwareChunks: opts.FirmwareChunks,
	}
	buf := make([]byte, ChunkSize)
	var prog PushProgress
	for off := int64(0); off < size; off += ChunkSize {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		csize := int64(ChunkSize)
		if off+csize > size {
			csize = size - off
		}
		// Clean + aligned with a parent chunk → inherit, no read.
		if !bitmap.IsDirty(off, csize) {
			if pc, ok := parentByOffset[off]; ok && pc.Size == csize {
				m.Chunks = append(m.Chunks, pc)
				m.TotalSize += pc.Size
				prog.BytesProcessed += pc.Size
				prog.ChunksTotal++
				prog.ChunksDeduped++
				if opts.Progress != nil {
					opts.Progress(prog)
				}
				continue
			}
		}
		// Dirty (or no matching parent ref): read just this window.
		n, rerr := ra.ReadAt(buf[:csize], off)
		if rerr != nil && rerr != io.EOF {
			return nil, fmt.Errorf("read at offset %d: %w", off, rerr)
		}
		chunk := append([]byte(nil), buf[:n]...)
		id, created, perr := repo.PutChunk(chunk)
		if perr != nil {
			return nil, fmt.Errorf("put chunk at offset %d: %w", off, perr)
		}
		m.Chunks = append(m.Chunks, ChunkRef{ID: id, Size: int64(n), Offset: off})
		m.TotalSize += int64(n)
		prog.BytesProcessed += int64(n)
		prog.BytesRead += int64(n)
		prog.ChunksTotal++
		if created {
			prog.BytesNew += int64(n)
		} else {
			prog.ChunksDeduped++
		}
		if opts.Progress != nil {
			opts.Progress(prog)
		}
	}
	if err := repo.PutManifest(m); err != nil {
		return nil, fmt.Errorf("write incremental manifest: %w", err)
	}
	return m, nil
}

// RangeBitmap is an in-memory DirtyRegions implementation backed by a
// sorted slice of half-open intervals. Useful for tests and for small
// dirty-region lists pulled out of libvirt before they're applied.
type RangeBitmap struct {
	ranges []dirtyRange
}

type dirtyRange struct{ start, end int64 } // [start, end)

// NewRangeBitmap builds a bitmap from a list of (offset, length) pairs.
// Overlapping ranges are merged so IsDirty is O(log N) per call.
func NewRangeBitmap(spans [][2]int64) *RangeBitmap {
	rs := make([]dirtyRange, 0, len(spans))
	for _, s := range spans {
		if s[1] <= 0 {
			continue
		}
		rs = append(rs, dirtyRange{s[0], s[0] + s[1]})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].start < rs[j].start })
	merged := rs[:0]
	for _, r := range rs {
		if len(merged) > 0 && r.start <= merged[len(merged)-1].end {
			if r.end > merged[len(merged)-1].end {
				merged[len(merged)-1].end = r.end
			}
			continue
		}
		merged = append(merged, r)
	}
	return &RangeBitmap{ranges: merged}
}

// IsDirty returns true if [offset, offset+length) intersects any span.
// Binary-search lookup keeps the call O(log N).
func (b *RangeBitmap) IsDirty(offset, length int64) bool {
	if length <= 0 {
		return false
	}
	end := offset + length
	idx := sort.Search(len(b.ranges), func(i int) bool {
		return b.ranges[i].end > offset
	})
	if idx >= len(b.ranges) {
		return false
	}
	return b.ranges[idx].start < end
}

// AlwaysDirty is a DirtyRegions that says every chunk is dirty — i.e.
// degrades to a full backup. Useful as a fallback when libvirt reports
// the bitmap is invalid (the parent snapshot must be re-pushed in full).
type AlwaysDirty struct{}

func (AlwaysDirty) IsDirty(int64, int64) bool { return true }
