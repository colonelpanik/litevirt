package pbsstore

import (
	"context"
	"fmt"
	"io"
	"os"
)

// PushOptions controls a snapshot push.
type PushOptions struct {
	// VMName / DiskName / Timestamp populate the resulting Manifest.
	VMName    string
	DiskName  string
	Timestamp string

	// BasedOn is the timestamp of an earlier snapshot whose manifest is
	// the parent for incremental backups. Empty = full.
	BasedOn string

	// BitmapName records the libvirt checkpoint/dirty-bitmap that this
	// snapshot established (the reference point the *next* incremental
	// diffs against). Empty = no checkpoint (AlwaysDirty fallback).
	BitmapName string

	// VMSpecJSON, when set, embeds the source VM's serialized pb.VMSpec
	// into the manifest so a live restore can reconstruct the domain
	// without the source cluster. Captured on the root disk only.
	VMSpecJSON string

	// DomainXML, when set, embeds the live domain XML at backup time for
	// fidelity/debugging. Best-effort; restore prefers VMSpecJSON.
	DomainXML string

	// ContainerSpecJSON, when set, embeds a serialized container spec so a
	// container restore can recreate the cluster row from the manifest alone.
	ContainerSpecJSON string

	// FirmwareChunks, when set, references the content-addressed firmware-state
	// bundle (UEFI NVRAM + swtpm) for a Secure-Boot/vTPM VM, captured on the
	// root disk so a restore materializes BitLocker-binding firmware (G1).
	FirmwareChunks []ChunkRef

	// Progress, if non-nil, is called once per chunk after the chunk
	// has been written or deduped against the repo. Use it to drive
	// gRPC stream progress.
	Progress func(PushProgress)
}

// PushProgress is the per-chunk callback payload.
type PushProgress struct {
	BytesProcessed int64 // running total of logical disk bytes covered
	BytesNew       int64 // running total of *new* bytes written to repo
	BytesRead      int64 // running total of bytes actually read from the
	// source disk. For an incremental push over a seekable source this is
	// only the dirty regions — the read-I/O the dirty bitmap saves. For a
	// full or sequential push it equals BytesProcessed.
	ChunksTotal   int // running count of chunks emitted
	ChunksDeduped int // running count of chunks already in repo
}

// PushDisk reads the entire byte stream of `src`, splits into ChunkSize
// blocks, dedupes against the repo, writes a manifest, and returns it.
//
// The push is *atomic at the manifest level*: chunks land in the repo
// incrementally (interruption-safe — they're content-addressed so
// retrying produces the same ids), but the manifest is only written
// after every chunk has been confirmed present.
func PushDisk(ctx context.Context, repo *Repo, src io.Reader, opts PushOptions) (*Manifest, error) {
	if opts.VMName == "" || opts.DiskName == "" {
		return nil, fmt.Errorf("vm name and disk name required")
	}
	m := &Manifest{
		VMName:            opts.VMName,
		DiskName:          opts.DiskName,
		Timestamp:         opts.Timestamp,
		BasedOn:           opts.BasedOn,
		BitmapName:        opts.BitmapName,
		VMSpecJSON:        opts.VMSpecJSON,
		DomainXML:         opts.DomainXML,
		ContainerSpecJSON: opts.ContainerSpecJSON,
		FirmwareChunks:    opts.FirmwareChunks,
	}

	buf := make([]byte, ChunkSize)
	var prog PushProgress
	err := ReadChunks(src, buf, func(off int64, data []byte) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		// Copy into a fresh slice so PutChunk can keep the bytes; the
		// caller-supplied buffer is reused on the next iteration.
		chunk := append([]byte(nil), data...)
		id, created, err := repo.PutChunk(chunk)
		if err != nil {
			return fmt.Errorf("put chunk at offset %d: %w", off, err)
		}
		m.Chunks = append(m.Chunks, ChunkRef{
			ID: id, Size: int64(len(chunk)), Offset: off,
		})
		m.TotalSize += int64(len(chunk))
		prog.BytesProcessed += int64(len(chunk))
		prog.BytesRead += int64(len(chunk))
		prog.ChunksTotal++
		if created {
			prog.BytesNew += int64(len(chunk))
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
		return nil, fmt.Errorf("write manifest: %w", err)
	}
	return m, nil
}

// PushFile is a convenience wrapper around PushDisk that opens a path
// and pushes its contents.
func PushFile(ctx context.Context, repo *Repo, path string, opts PushOptions) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open source: %w", err)
	}
	defer f.Close()
	return PushDisk(ctx, repo, f, opts)
}

// RestoreOptions controls a manifest-driven restore.
type RestoreOptions struct {
	// Progress, if non-nil, is called after each chunk is written.
	Progress func(RestoreProgress)
}

// RestoreProgress is the per-chunk restore payload.
type RestoreProgress struct {
	BytesWritten int64
	ChunksDone   int
	ChunksTotal  int
}

// RestoreToFile rebuilds a disk from a manifest by streaming each
// chunk back in order. The destination is created (or truncated) and
// punctuated with seeks so sparse holes from the source survive.
func RestoreToFile(ctx context.Context, repo *Repo, m *Manifest, dst string, opts RestoreOptions) error {
	if m == nil {
		return fmt.Errorf("nil manifest")
	}
	// The manifest is untrusted repo data; validate its structure before any
	// chunk is read or written (defense in depth over GetManifest).
	if err := ValidateManifest(m); err != nil {
		return fmt.Errorf("invalid manifest: %w", err)
	}
	// Restore into a sibling temp file and atomic-rename only after the full
	// disk is materialized, so a missing/corrupt chunk mid-stream (GC bug,
	// bit rot, name-present-but-corrupt off-site sync) can NEVER truncate or
	// partially overwrite an existing destination — the in-place DR double-fault
	// from the bug sweep. The temp is in dst's directory so the rename stays on
	// one filesystem (and replaces the dir entry atomically; a VM still holding
	// the old inode is unaffected, unlike the old truncate-in-place).
	tmp := dst + ".restore-tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return fmt.Errorf("open restore temp: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if m.TotalSize > 0 {
		if err := f.Truncate(m.TotalSize); err != nil {
			return fmt.Errorf("truncate restore temp: %w", err)
		}
	}
	prog := RestoreProgress{ChunksTotal: len(m.Chunks)}
	for _, ref := range m.Chunks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		data, err := repo.GetChunk(ref.ID)
		if err != nil {
			return fmt.Errorf("get chunk %s at offset %d: %w", ref.ID, ref.Offset, err)
		}
		// The chunk's real content must match the size the manifest declared —
		// a valid-but-larger chunk must not write past the ref's declared extent.
		if int64(len(data)) != ref.Size {
			return fmt.Errorf("chunk %s is %d bytes but manifest declares %d", ref.ID, len(data), ref.Size)
		}
		if _, err := f.WriteAt(data, ref.Offset); err != nil {
			return fmt.Errorf("write at offset %d: %w", ref.Offset, err)
		}
		prog.BytesWritten += int64(len(data))
		prog.ChunksDone++
		if opts.Progress != nil {
			opts.Progress(prog)
		}
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync restore temp: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close restore temp: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return fmt.Errorf("commit restore (rename to %s): %w", dst, err)
	}
	committed = true
	return nil
}
