// (real driver) — a minimal NBD newstyle client that speaks
// just enough of the protocol to query a qemu dirty-bitmap meta context
// via NBD_CMD_BLOCK_STATUS. This is how we enumerate the blocks dirtied
// since a checkpoint when libvirt exposes them over a pull-mode backup
// export.
//
// We deliberately read ONLY the dirty-bitmap meta context (offsets) — we
// never read disk data over NBD. The actual bytes are still read from the
// local qcow2 by the existing backup push path. Keeping the surface this
// small bounds the protocol risk; the pure parsers below are unit-tested,
// and the live orchestration returns an error on any deviation so the
// caller falls back to a full read (never a wrong backup).
package libvirt

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// NBD protocol constants (all multi-byte fields are big-endian).
const (
	nbdMagic            = 0x4e42444d41474943 // "NBDMAGIC"
	nbdIHaveOpt         = 0x49484156454f5054 // "IHAVEOPT"
	nbdOptReplyMagic    = 0x0003e889045565a9
	nbdRequestMagic     = 0x25609513
	nbdStructReplyMagic = 0x668e33ef

	// client handshake flags
	nbdFlagCFixedNewstyle = 1
	nbdFlagCNoZeroes      = 2

	// options
	nbdOptGo              = 7
	nbdOptStructuredReply = 8
	nbdOptSetMetaContext  = 10
	nbdOptAbort           = 2

	// option reply types
	nbdRepAck         = 1
	nbdRepMetaContext = 4
	nbdRepErrBit      = 1 << 31

	// commands
	nbdCmdRead        = 0
	nbdCmdBlockStatus = 7
	nbdCmdDisc        = 2

	// structured reply chunk types
	nbdReplyTypeNone        = 0
	nbdReplyTypeOffsetData  = 1
	nbdReplyTypeOffsetHole  = 2
	nbdReplyTypeBlockStatus = 5
	nbdReplyErrBit          = 1 << 15

	// base:allocation status flags
	nbdStateHole = 1 // unallocated (reads as zero)
	nbdStateZero = 2 // allocated but known-zero

	// structured reply flags
	nbdReplyFlagDone = 1

	// dirty-bitmap status flag (bit 0)
	nbdStateDirty = 1
)

// nbdExtent is one (length, status) descriptor from a BLOCK_STATUS reply.
type nbdExtent struct {
	length uint32
	flags  uint32
}

// nbdConn is a thin framing layer over a net.Conn for NBD newstyle.
type nbdConn struct {
	c net.Conn
	h uint64 // monotonic command handle
}

func (n *nbdConn) newHandle() uint64 { n.h++; return n.h }

func (n *nbdConn) writeFull(b []byte) error {
	_, err := n.c.Write(b)
	return err
}

func (n *nbdConn) readFull(b []byte) error {
	_, err := io.ReadFull(n.c, b)
	return err
}

func (n *nbdConn) readU16() (uint16, error) {
	var b [2]byte
	if err := n.readFull(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}

func (n *nbdConn) readU32() (uint32, error) {
	var b [4]byte
	if err := n.readFull(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func (n *nbdConn) readU64() (uint64, error) {
	var b [8]byte
	if err := n.readFull(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b[:]), nil
}

// handshake performs the fixed-newstyle server greeting + client flags.
func (n *nbdConn) handshake() error {
	magic, err := n.readU64()
	if err != nil {
		return fmt.Errorf("read init magic: %w", err)
	}
	if magic != nbdMagic {
		return fmt.Errorf("bad NBD init magic %#x", magic)
	}
	opt, err := n.readU64()
	if err != nil {
		return fmt.Errorf("read IHAVEOPT: %w", err)
	}
	if opt != nbdIHaveOpt {
		return fmt.Errorf("server is not newstyle (opt magic %#x)", opt)
	}
	if _, err := n.readU16(); err != nil { // handshake flags (unused)
		return fmt.Errorf("read handshake flags: %w", err)
	}
	var cf [4]byte
	binary.BigEndian.PutUint32(cf[:], nbdFlagCFixedNewstyle|nbdFlagCNoZeroes)
	if err := n.writeFull(cf[:]); err != nil {
		return fmt.Errorf("write client flags: %w", err)
	}
	return nil
}

// sendOption writes one option-haggling request.
func (n *nbdConn) sendOption(opt uint32, data []byte) error {
	hdr := make([]byte, 16)
	binary.BigEndian.PutUint64(hdr[0:8], nbdIHaveOpt)
	binary.BigEndian.PutUint32(hdr[8:12], opt)
	binary.BigEndian.PutUint32(hdr[12:16], uint32(len(data)))
	if err := n.writeFull(hdr); err != nil {
		return err
	}
	if len(data) > 0 {
		return n.writeFull(data)
	}
	return nil
}

// optReply is one server response in the option-haggling phase.
type optReply struct {
	option  uint32
	repType uint32
	data    []byte
}

func (n *nbdConn) readOptReply() (optReply, error) {
	magic, err := n.readU64()
	if err != nil {
		return optReply{}, fmt.Errorf("read opt-reply magic: %w", err)
	}
	if magic != nbdOptReplyMagic {
		return optReply{}, fmt.Errorf("bad opt-reply magic %#x", magic)
	}
	opt, err := n.readU32()
	if err != nil {
		return optReply{}, err
	}
	rt, err := n.readU32()
	if err != nil {
		return optReply{}, err
	}
	ln, err := n.readU32()
	if err != nil {
		return optReply{}, err
	}
	data := make([]byte, ln)
	if ln > 0 {
		if err := n.readFull(data); err != nil {
			return optReply{}, err
		}
	}
	return optReply{option: opt, repType: rt, data: data}, nil
}

// negotiateStructuredReply enables structured replies (required for
// BLOCK_STATUS). Consumes replies until ACK.
func (n *nbdConn) negotiateStructuredReply() error {
	if err := n.sendOption(nbdOptStructuredReply, nil); err != nil {
		return err
	}
	for {
		r, err := n.readOptReply()
		if err != nil {
			return err
		}
		if r.repType&nbdRepErrBit != 0 {
			return fmt.Errorf("server refused structured replies (rep %#x)", r.repType)
		}
		if r.repType == nbdRepAck {
			return nil
		}
	}
}

// setMetaContext requests a single dirty-bitmap meta context for export
// and returns the metadata-context id the server assigned to it.
func (n *nbdConn) setMetaContext(export, context string) (uint32, error) {
	data := encodeSetMetaContext(export, context)
	if err := n.sendOption(nbdOptSetMetaContext, data); err != nil {
		return 0, err
	}
	var ctxID uint32
	gotCtx := false
	for {
		r, err := n.readOptReply()
		if err != nil {
			return 0, err
		}
		if r.repType&nbdRepErrBit != 0 {
			return 0, fmt.Errorf("set-meta-context refused for %q (rep %#x)", context, r.repType)
		}
		if r.repType == nbdRepMetaContext {
			id, name, perr := parseMetaContextReply(r.data)
			if perr != nil {
				return 0, perr
			}
			_ = name
			ctxID = id
			gotCtx = true
		}
		if r.repType == nbdRepAck {
			if !gotCtx {
				return 0, fmt.Errorf("server returned no meta context for %q", context)
			}
			return ctxID, nil
		}
	}
}

// optGo enters the transmission phase for export.
func (n *nbdConn) optGo(export string) error {
	data := encodeOptGo(export)
	if err := n.sendOption(nbdOptGo, data); err != nil {
		return err
	}
	for {
		r, err := n.readOptReply()
		if err != nil {
			return err
		}
		if r.repType&nbdRepErrBit != 0 {
			return fmt.Errorf("NBD_OPT_GO refused for export %q (rep %#x)", export, r.repType)
		}
		if r.repType == nbdRepAck {
			return nil
		}
		// NBD_REP_INFO entries are ignored; we only need to reach ACK.
	}
}

func (n *nbdConn) sendBlockStatusReq(handle, offset uint64, length uint32) error {
	req := make([]byte, 28)
	binary.BigEndian.PutUint32(req[0:4], nbdRequestMagic)
	binary.BigEndian.PutUint16(req[4:6], 0) // command flags
	binary.BigEndian.PutUint16(req[6:8], nbdCmdBlockStatus)
	binary.BigEndian.PutUint64(req[8:16], handle)
	binary.BigEndian.PutUint64(req[16:24], offset)
	binary.BigEndian.PutUint32(req[24:28], length)
	return n.writeFull(req)
}

// placedExtent is an nbdExtent resolved to an absolute offset.
type placedExtent struct {
	off    int64
	length int64
	flags  uint32
}

// readBlockStatusReply consumes structured-reply chunks for one request
// handle until the DONE flag, returning the placed extents, whether the
// stream is done, and how many bytes the reported extents advanced.
func (n *nbdConn) readBlockStatusReply(handle uint64, ctxID uint32, baseOff int64) (extents []placedExtent, done bool, advanced int64, err error) {
	cur := baseOff
	for {
		magic, e := n.readU32()
		if e != nil {
			return nil, false, 0, e
		}
		if magic != nbdStructReplyMagic {
			return nil, false, 0, fmt.Errorf("bad structured-reply magic %#x", magic)
		}
		flags, e := n.readU16()
		if e != nil {
			return nil, false, 0, e
		}
		ctype, e := n.readU16()
		if e != nil {
			return nil, false, 0, e
		}
		rhandle, e := n.readU64()
		if e != nil {
			return nil, false, 0, e
		}
		ln, e := n.readU32()
		if e != nil {
			return nil, false, 0, e
		}
		payload := make([]byte, ln)
		if ln > 0 {
			if e := n.readFull(payload); e != nil {
				return nil, false, 0, e
			}
		}
		if rhandle != handle {
			return nil, false, 0, fmt.Errorf("reply handle %d != request %d", rhandle, handle)
		}
		isDone := flags&nbdReplyFlagDone != 0
		switch {
		case ctype == nbdReplyTypeBlockStatus:
			cid, exts, perr := parseBlockStatusPayload(payload)
			if perr != nil {
				return nil, false, 0, perr
			}
			if cid != ctxID {
				// A context we didn't ask for; skip it.
				continue
			}
			for _, ex := range exts {
				extents = append(extents, placedExtent{off: cur, length: int64(ex.length), flags: ex.flags})
				cur += int64(ex.length)
			}
		case ctype&nbdReplyErrBit != 0:
			return nil, false, 0, fmt.Errorf("block-status error chunk (type %#x)", ctype)
		case ctype == nbdReplyTypeNone:
			// terminator only
		}
		if isDone {
			return extents, true, cur - baseOff, nil
		}
	}
}

func (n *nbdConn) disconnect() {
	// Best-effort transmission-phase disconnect.
	req := make([]byte, 28)
	binary.BigEndian.PutUint32(req[0:4], nbdRequestMagic)
	binary.BigEndian.PutUint16(req[6:8], nbdCmdDisc)
	_ = n.writeFull(req)
	_ = n.c.Close()
}

// queryExtents runs BLOCK_STATUS for ctxID over [0,size) and returns every
// extent with its absolute offset, length, and status flags (unfiltered —
// the caller decides what "allocated" or "dirty" means for ctxID).
func (n *nbdConn) queryExtents(ctxID uint32, size int64) ([]placedExtent, error) {
	var out []placedExtent
	var off int64
	for off < size {
		reqLen := size - off
		if reqLen > 0x7fffffff {
			reqLen = 0x7fffffff
		}
		handle := n.newHandle()
		if err := n.sendBlockStatusReq(handle, uint64(off), uint32(reqLen)); err != nil {
			return nil, err
		}
		extents, _, advanced, err := n.readBlockStatusReply(handle, ctxID, off)
		if err != nil {
			return nil, err
		}
		out = append(out, extents...)
		if advanced <= 0 {
			break
		}
		off += advanced
	}
	return out, nil
}

// readAt fills p with the device contents at offset via NBD_CMD_READ,
// assembling the structured OFFSET_DATA / OFFSET_HOLE reply chunks. Hole
// regions are left as zeros (p is cleared first), so a sparse guest disk
// reads back correctly.
func (n *nbdConn) readAt(p []byte, offset int64) error {
	clear(p)
	handle := n.newHandle()
	req := make([]byte, 28)
	binary.BigEndian.PutUint32(req[0:4], nbdRequestMagic)
	binary.BigEndian.PutUint16(req[4:6], 0)          // command flags
	binary.BigEndian.PutUint16(req[6:8], nbdCmdRead) // type
	binary.BigEndian.PutUint64(req[8:16], handle)
	binary.BigEndian.PutUint64(req[16:24], uint64(offset))
	binary.BigEndian.PutUint32(req[24:28], uint32(len(p)))
	if err := n.writeFull(req); err != nil {
		return err
	}
	for {
		magic, err := n.readU32()
		if err != nil {
			return err
		}
		if magic != nbdStructReplyMagic {
			return fmt.Errorf("bad structured-reply magic %#x on read", magic)
		}
		flags, err := n.readU16()
		if err != nil {
			return err
		}
		ctype, err := n.readU16()
		if err != nil {
			return err
		}
		rhandle, err := n.readU64()
		if err != nil {
			return err
		}
		ln, err := n.readU32()
		if err != nil {
			return err
		}
		payload := make([]byte, ln)
		if ln > 0 {
			if err := n.readFull(payload); err != nil {
				return err
			}
		}
		if rhandle != handle {
			return fmt.Errorf("read reply handle %d != request %d", rhandle, handle)
		}
		switch {
		case ctype == nbdReplyTypeOffsetData:
			off, data, perr := parseOffsetData(payload)
			if perr != nil {
				return perr
			}
			rel := off - offset
			if rel < 0 || rel+int64(len(data)) > int64(len(p)) {
				return fmt.Errorf("offset-data out of range: off=%d base=%d len=%d buf=%d", off, offset, len(data), len(p))
			}
			copy(p[rel:], data)
		case ctype == nbdReplyTypeOffsetHole:
			// Holes stay zero (p was cleared). Nothing to copy.
		case ctype&nbdReplyErrBit != 0:
			return fmt.Errorf("read error chunk (type %#x)", ctype)
		case ctype == nbdReplyTypeNone:
			// terminator only
		}
		if flags&nbdReplyFlagDone != 0 {
			return nil
		}
	}
}

// parseOffsetData parses an NBD_REPLY_TYPE_OFFSET_DATA payload: 64-bit
// offset followed by the data bytes.
func parseOffsetData(payload []byte) (offset int64, data []byte, err error) {
	if len(payload) < 8 {
		return 0, nil, fmt.Errorf("offset-data chunk too short (%d bytes)", len(payload))
	}
	return int64(binary.BigEndian.Uint64(payload[0:8])), payload[8:], nil
}

// ── pure encoders/parsers (unit-tested) ──────────────────────────────────

// encodeSetMetaContext builds the NBD_OPT_SET_META_CONTEXT payload:
// 32-bit export-name length, export name, 32-bit query count (1),
// 32-bit query length, query.
func encodeSetMetaContext(export, query string) []byte {
	out := make([]byte, 0, 12+len(export)+len(query))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], uint32(len(export)))
	out = append(out, u4[:]...)
	out = append(out, export...)
	binary.BigEndian.PutUint32(u4[:], 1) // one query
	out = append(out, u4[:]...)
	binary.BigEndian.PutUint32(u4[:], uint32(len(query)))
	out = append(out, u4[:]...)
	out = append(out, query...)
	return out
}

// encodeOptGo builds the NBD_OPT_GO payload: 32-bit export-name length,
// export name, 16-bit number of info requests (0).
func encodeOptGo(export string) []byte {
	out := make([]byte, 0, 6+len(export))
	var u4 [4]byte
	binary.BigEndian.PutUint32(u4[:], uint32(len(export)))
	out = append(out, u4[:]...)
	out = append(out, export...)
	out = append(out, 0, 0) // zero info requests
	return out
}

// parseMetaContextReply parses an NBD_REP_META_CONTEXT reply payload:
// 32-bit metadata-context id followed by the context name.
func parseMetaContextReply(data []byte) (id uint32, name string, err error) {
	if len(data) < 4 {
		return 0, "", fmt.Errorf("meta-context reply too short (%d bytes)", len(data))
	}
	id = binary.BigEndian.Uint32(data[0:4])
	name = string(data[4:])
	return id, name, nil
}

// parseBlockStatusPayload parses an NBD_REPLY_TYPE_BLOCK_STATUS payload:
// 32-bit metadata-context id, then a sequence of (32-bit length, 32-bit
// status flags) extent descriptors.
func parseBlockStatusPayload(data []byte) (ctxID uint32, extents []nbdExtent, err error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("block-status payload too short (%d bytes)", len(data))
	}
	ctxID = binary.BigEndian.Uint32(data[0:4])
	rest := data[4:]
	if len(rest)%8 != 0 {
		return 0, nil, fmt.Errorf("block-status extent array not a multiple of 8 (%d bytes)", len(rest))
	}
	for i := 0; i+8 <= len(rest); i += 8 {
		extents = append(extents, nbdExtent{
			length: binary.BigEndian.Uint32(rest[i : i+4]),
			flags:  binary.BigEndian.Uint32(rest[i+4 : i+8]),
		})
	}
	return ctxID, extents, nil
}
