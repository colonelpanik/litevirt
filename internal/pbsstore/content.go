package pbsstore

import (
	"context"
	"fmt"
	"io"
)

// PushFromSource backs up GUEST-VISIBLE disk content read from src (an
// io.ReaderAt over the guest disk in guest-virtual address space, e.g. a
// libvirt pull-mode NBD export). It chunks only the windows covered by
// readExtents:
//
//   - Full backup (parent == nil): readExtents are the allocated, non-zero
//     regions. Windows outside them are holes — skipped, so the manifest is
//     sparse and a 10 GiB disk with 2 GiB of data backs up ~2 GiB.
//   - Incremental (parent != nil): readExtents are the dirty regions since
//     the parent checkpoint. Clean windows are inherited from the parent's
//     chunk refs (or left as holes where the parent had none).
//
// size is the guest virtual size and becomes the manifest TotalSize, so a
// restore recreates a correctly-sized sparse disk. This is the correct,
// address-space-consistent counterpart to libvirt's guest-virtual dirty
// bitmap (unlike the older qcow2-container PushFile/PushIncremental).
func PushFromSource(
	ctx context.Context,
	repo *Repo,
	src io.ReaderAt,
	size int64,
	readExtents [][2]int64,
	parent *Manifest,
	opts PushOptions,
) (*Manifest, error) {
	if opts.VMName == "" || opts.DiskName == "" {
		return nil, fmt.Errorf("vm + disk name required")
	}
	bitmap := NewRangeBitmap(readExtents)

	parentByOffset := make(map[int64]ChunkRef)
	basedOn := ""
	if parent != nil {
		basedOn = parent.Timestamp
		for _, c := range parent.Chunks {
			parentByOffset[c.Offset] = c
		}
	}

	m := &Manifest{
		VMName:     opts.VMName,
		DiskName:   opts.DiskName,
		Timestamp:  opts.Timestamp,
		BasedOn:    basedOn,
		BitmapName: opts.BitmapName,
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
		prog.BytesProcessed += csize

		if !bitmap.IsDirty(off, csize) {
			// Clean window.
			if parent == nil {
				// Full backup: not allocated → hole. Skip (restore zeros).
				continue
			}
			if pc, ok := parentByOffset[off]; ok {
				if pc.Size == csize {
					// Unchanged since parent → inherit its ref, no read.
					m.Chunks = append(m.Chunks, pc)
					prog.ChunksTotal++
					prog.ChunksDeduped++
					if opts.Progress != nil {
						opts.Progress(prog)
					}
					continue
				}
				// Parent ref size mismatch (e.g. resized last chunk) —
				// fall through and read to stay correct.
			} else {
				// Clean + no parent chunk → hole in parent too. Skip.
				continue
			}
		}

		// Dirty / allocated window: read the guest bytes and chunk them.
		n, rerr := src.ReadAt(buf[:csize], off)
		if rerr != nil && rerr != io.EOF {
			return nil, fmt.Errorf("read source at offset %d: %w", off, rerr)
		}
		chunk := append([]byte(nil), buf[:n]...)
		id, created, perr := repo.PutChunk(chunk)
		if perr != nil {
			return nil, fmt.Errorf("put chunk at offset %d: %w", off, perr)
		}
		m.Chunks = append(m.Chunks, ChunkRef{ID: id, Size: int64(n), Offset: off})
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
	// TotalSize is the guest virtual size (sparse): restore truncates to it
	// and writes chunks at their offsets, leaving holes zero.
	m.TotalSize = size
	if err := repo.PutManifest(m); err != nil {
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	return m, nil
}
