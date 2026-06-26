package pbsstore

import (
	"fmt"
	"io"

	"github.com/litevirt/litevirt/internal/safename"
)

// PutBytes content-addresses an arbitrary in-memory blob (e.g. a VM
// firmware-state bundle: UEFI NVRAM + swtpm tar) into the chunk store,
// returning ordered ChunkRefs whose concatenation reproduces b. It reuses the
// same content-addressed chunk store as disk data, so an unchanged firmware
// bundle dedups across snapshots and incrementals. A nil/empty blob yields no
// refs. The offsets are blob-relative (not disk offsets) — read it back with
// ReadBytesTo, which walks the refs in order.
func (r *Repo) PutBytes(b []byte) ([]ChunkRef, error) {
	var refs []ChunkRef
	for off := 0; off < len(b); off += ChunkSize {
		end := off + ChunkSize
		if end > len(b) {
			end = len(b)
		}
		chunk := append([]byte(nil), b[off:end]...)
		id, _, err := r.PutChunk(chunk)
		if err != nil {
			return nil, fmt.Errorf("put blob chunk at %d: %w", off, err)
		}
		refs = append(refs, ChunkRef{ID: id, Size: int64(end - off), Offset: int64(off)})
	}
	return refs, nil
}

// ReadBytesTo reassembles a blob stored by PutBytes into w, in ref order. Each
// chunk is hash-verified by GetChunk, so a corrupted firmware bundle is caught
// before it's materialized onto a host.
func (r *Repo) ReadBytesTo(refs []ChunkRef, w io.Writer) error {
	for _, ref := range refs {
		if err := safename.ValidateChunkID(ref.ID); err != nil {
			return err
		}
		data, err := r.GetChunk(ref.ID)
		if err != nil {
			return fmt.Errorf("read blob chunk %s: %w", ref.ID, err)
		}
		// Enforce the declared size so a valid-but-larger chunk can't inflate the
		// materialized blob (e.g. a firmware bundle) beyond its manifest extent.
		if int64(len(data)) != ref.Size {
			return fmt.Errorf("blob chunk %s is %d bytes but ref declares %d", ref.ID, len(data), ref.Size)
		}
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	return nil
}
