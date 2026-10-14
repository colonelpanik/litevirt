// tamper-evident audit log handlers.
//
// VerifyAuditChain replays every host's hash sub-chain end-to-end and
// checks the row signatures, sequence numbers and signed chain heads on
// top of it. ExportAuditChain emits a JSON blob suitable for WORM offload.
//
// Neither RPC mutates the chain. Verify is admin-only because the
// result has compliance implications; Export is admin-only because
// it leaks every audit event ever recorded.

package grpcapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func (s *Server) VerifyAuditChain(ctx context.Context, _ *emptypb.Empty) (*pb.VerifyAuditChainResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	res, err := verifyChain(ctx, s)
	// Every finding is passed through, not summarised into a verdict here.
	// The client decides how to present them, and a partial result is still
	// worth returning when the verify itself failed part-way: the rows it did
	// check are evidence too.
	resp := &pb.VerifyAuditChainResponse{
		RowsChecked:      int32(res.RowsChecked),
		BrokenAtId:       res.BrokenAt,
		BrokenAtKind:     res.BrokenKind,
		UnsignedRows:     int32(res.Unsigned),
		UnverifiableRows: int32(res.Unverifiable),
		BadSignature:     res.BadSignature,
		UnknownKeyId:     res.UnknownKeyID,
		SeqGaps:          res.SeqGaps,
		Laundered:        res.Laundered,
		UnattributedRows: int32(res.Unattributed),
		TruncatedHosts:   res.TruncatedHosts,
		RetiredKeyUse:    res.RetiredKeyUse,
		HeadMismatch:     res.HeadMismatch,

		UnsignedAfterSigned: res.UnsignedAfterSigned,
		NeverAdopted:        res.NeverAdopted,
		AmbiguousRows:       res.Ambiguous,
		OrphanedRows:        res.Orphans,

		Tampered:   res.Tampered(),
		Forked:     res.Forked(),
		Unverified: res.Unverified(),
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}

// exportPageDefault / exportPageMax bound one page of an audit export.
//
// The export is a unary RPC against the daemon's 64 MiB send cap, so a chain
// worth attesting to does not fit in one message. Without paging the only
// workaround is a since/until window, and that produces a fragment whose first
// row links to a row outside it — silently converting a complete attestation
// into one that cannot be verified at all, exactly on the clusters where it
// matters most.
const (
	exportPageDefault = 5000
	exportPageMax     = 50000
)

// exportCursor is the position of the last row a page emitted, in the verifier's
// own order. All four parts travel: seq alone is not unique on a host once a row
// that InsertAuditLog did not write is present, and such a row is precisely what
// an attestation exists to reveal.
type exportCursor struct {
	Host string `json:"h"`
	Seq  int64  `json:"s"`
	TS   string `json:"t"`
	ID   string `json:"i"`
	// Now is the clock reading a relative bound (--since 24h) was resolved
	// against on the first page. Every later page resolves it against the same
	// instant, so the pages of one export answer one window rather than one
	// that slides while the client pages. Absent from a cursor an older daemon
	// minted; such a page resolves against its own clock, as before.
	Now string `json:"n,omitempty"`
}

func (c exportCursor) encode() string {
	b, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeExportCursor(raw string) (exportCursor, error) {
	var c exportCursor
	if raw == "" {
		return c, nil
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return c, fmt.Errorf("malformed cursor: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("malformed cursor: %w", err)
	}
	return c, nil
}

func (s *Server) ExportAuditChain(ctx context.Context, req *pb.ExportAuditChainRequest) (*pb.ExportAuditChainResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	after, err := decodeExportCursor(req.Cursor)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	now := time.Now().UTC()
	if after.Now != "" {
		if t, perr := time.Parse(time.RFC3339Nano, after.Now); perr == nil {
			now = t
		}
	}
	window, err := parseTimeWindow(req.Since, req.Until, now)
	if err != nil {
		return nil, err
	}
	limit := int(req.Limit)
	if limit <= 0 {
		limit = exportPageDefault
	}
	if limit > exportPageMax {
		limit = exportPageMax
	}

	// Ordered and projected to match VerifyAuditChain, because that is what the
	// export is for: docs/audit-log.md tells operators to ship this to WORM
	// storage so an external system can re-verify without the daemon. A host's
	// sub-chain is walked by seq, so a file ordered by stamp replays a chain the
	// daemon calls intact and reports a break on it, and one with no seq column
	// leaves the external checker no way to recover the order itself.
	//
	// The cursor predicate is the ORDER BY written out longhand rather than a row
	// value, which not every SQLite build accepts.
	//
	// The window is applied as instants, not text (corrosion.TimeWindow).
	where := `(? = '' OR host_name > ? OR (host_name = ? AND (seq > ? OR (seq = ? AND (timestamp > ? OR (timestamp = ? AND id > ?))))))`
	args := []any{req.Cursor, after.Host, after.Host, after.Seq, after.Seq, after.TS, after.TS, after.ID}
	if pred, pargs := window.Predicate("timestamp"); pred != "" {
		where = pred + " AND " + where
		args = append(pargs, args...)
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result,
		        prev_hash, content_hash, key_id, signature, seq
		 FROM audit_log
		 WHERE `+where+`
		 ORDER BY host_name ASC, seq ASC, timestamp ASC, id ASC
		 LIMIT ?`,
		append(args, limit+1)...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list audit_log: %v", err)
	}
	more := len(rows) > limit
	if more {
		rows = rows[:limit]
	}
	out := make([]map[string]string, 0, len(rows))
	var last exportCursor
	// Seq gaps, reported rather than silently emitted.
	//
	// A host's sub-chain is walked by seq and each row's prev_hash names the
	// previous one, so a missing seq makes the export replay as a BREAK. That
	// is indistinguishable from tampering to an external verifier, which is the
	// one thing this document exists to tell apart.
	//
	// A gap is ordinary: replication can deliver a partitioned host's backlog
	// out of order, so seq 3 can still be in flight while 4 and 5 have landed.
	// Once the cursor passes 5, seq 3 is below it and is never exported at all.
	// The rows that ARE here are still worth shipping, so the page carries them
	// and says what is missing instead of pretending the chain is whole.
	//
	// A window is not a gap. --since/--until filter by timestamp while the walk
	// is by seq, and a host's stamps are not monotone in seq (its clock can step
	// back), so a window can leave out a row in the middle of a run it keeps.
	// That row is in the table; calling it missing tells the operator rows were
	// deleted. Under a window, only the seqs not in the table outside it are
	// reported.
	windowed := !window.IsOpen()
	var gaps []map[string]string
	prevHost, prevSeq := after.Host, after.Seq
	for _, r := range rows {
		host, seq := r.String("host_name"), r.Int64("seq")
		// Only within one host, and only for v45+ rows: seq is 0 for rows
		// written before it existed, and those are reported as not
		// tamper-evident by the verifier anyway.
		if host == prevHost && prevSeq > 0 && seq > prevSeq+1 {
			missing := [][2]int64{{prevSeq + 1, seq - 1}}
			if windowed {
				if missing, err = s.seqsAbsentOutsideWindow(ctx, host, prevSeq+1, seq-1, window); err != nil {
					return nil, err
				}
			}
			for _, m := range missing {
				gaps = append(gaps, map[string]string{
					"host_name":    host,
					"after_seq":    strconv.FormatInt(m[0]-1, 10),
					"before_seq":   strconv.FormatInt(m[1]+1, 10),
					"missing_from": strconv.FormatInt(m[0], 10),
					"missing_to":   strconv.FormatInt(m[1], 10),
				})
			}
		}
		prevHost, prevSeq = host, seq
	}
	for _, r := range rows {
		out = append(out, map[string]string{
			"id":           r.String("id"),
			"timestamp":    r.String("timestamp"),
			"username":     r.String("username"),
			"host_name":    r.String("host_name"),
			"action":       r.String("action"),
			"target":       r.String("target"),
			"detail":       r.String("detail"),
			"result":       r.String("result"),
			"prev_hash":    r.String("prev_hash"),
			"content_hash": r.String("content_hash"),
			"key_id":       r.String("key_id"),
			"signature":    r.String("signature"),
			"seq":          strconv.FormatInt(r.Int64("seq"), 10),
		})
		last = exportCursor{
			Host: r.String("host_name"), Seq: r.Int64("seq"),
			TS: r.String("timestamp"), ID: r.String("id"),
			Now: now.Format(time.RFC3339Nano),
		}
	}

	doc := map[string]any{"rows": out}
	if len(gaps) > 0 {
		// Named "seq_gaps" so a verifier that does not know the key still sees
		// an unexpected field rather than a silently short chain.
		doc["seq_gaps"] = gaps
	}
	if req.Cursor == "" {
		if err := s.addExportEvidence(ctx, doc); err != nil {
			return nil, err
		}
	}
	body, mErr := json.Marshal(doc)
	if mErr != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", mErr)
	}
	resp := &pb.ExportAuditChainResponse{
		Json:     string(body),
		RowCount: int32(len(out)),
	}
	if more {
		resp.NextCursor = last.encode()
	}
	return resp, nil
}

// parseTimeWindow reads a request's since/until bounds (corrosion.ParseTimeWindow)
// and refuses one that names no instant. It used to be compared to the stored
// stamps verbatim, as text, which returned a silently wrong listing instead.
//
// now is what a relative bound (24h) counts back from.
func parseTimeWindow(since, until string, now time.Time) (corrosion.TimeWindow, error) {
	w, err := corrosion.ParseTimeWindow(since, until, now)
	if err != nil {
		return w, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return w, nil
}

// seqsAbsentOutsideWindow returns, as inclusive ranges, the seqs in [from, to]
// that host has no row for OUTSIDE the since/until window — the part of a
// windowed export's hole that is a real gap rather than rows the window left
// out.
//
// The window has to be drawn exactly where the export drew it, or a row the
// export left out reads here as inside the window, is not found "outside" it,
// and is reported as a deletion. Both therefore take the same TimeWindow.
func (s *Server) seqsAbsentOutsideWindow(ctx context.Context, host string, from, to int64, window corrosion.TimeWindow) ([][2]int64, error) {
	pred, pargs := window.Predicate("timestamp")
	if pred == "" {
		// No window: nothing is outside it, so every seq in the hole is absent.
		pred = "1"
	}
	rows, err := s.db.Query(ctx,
		`SELECT DISTINCT seq FROM audit_log
		 WHERE host_name = ? AND seq BETWEEN ? AND ?
		   AND NOT (`+pred+`)
		 ORDER BY seq ASC`,
		append([]any{host, from, to}, pargs...)...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list audit_log outside the window: %v", err)
	}
	var out [][2]int64
	next := from
	for _, r := range rows {
		if seq := r.Int64("seq"); seq > next {
			out = append(out, [2]int64{next, seq - 1})
			next = seq + 1
		} else if seq == next {
			next++
		}
	}
	if next <= to {
		out = append(out, [2]int64{next, to})
	}
	return out, nil
}

// addExportEvidence attaches the state VerifyAuditChain reasons over. It rides
// on the first page only: these tables are a handful of rows per host, and
// repeating them per page would be noise in a document assembled by the client.
//
// Nothing here filters deleted_at, and that is the point. A chain head is the
// only construct that detects a truncated tail — the chain links backward, so
// cutting the last N rows leaves every surviving link verifying — which makes
// deleting the heads the efficient attack. The daemon's answer is that a
// tombstone is INERT: VerifyAuditChain does not filter deleted_at on any of
// these tables (see TestAuditEvidence_ATombstoneIsInert). An export that
// honoured the tombstone would hand that attack straight back, reporting clean
// on precisely the cluster the daemon reports as tampered.
func (s *Server) addExportEvidence(ctx context.Context, doc map[string]any) error {
	for key, query := range map[string]string{
		"chain_heads":   `SELECT host_name, epoch, seq, head_hash, key_id, signature, created_at, deleted_at FROM audit_chain_heads ORDER BY host_name ASC, epoch ASC, seq ASC`,
		"signing_keys":  `SELECT key_id, host_name, cert_pem, created_at, deleted_at FROM audit_signing_keys ORDER BY host_name ASC, key_id ASC`,
		"key_lifecycle": `SELECT host_name, key_id, event, at_seq, by_key_id, signature, created_at, deleted_at FROM audit_key_lifecycle ORDER BY host_name ASC, at_seq ASC`,
	} {
		rows, err := s.db.Query(ctx, query)
		if err != nil {
			return status.Errorf(codes.Internal, "list %s: %v", key, err)
		}
		table := make([]map[string]string, 0, len(rows))
		for _, r := range rows {
			row := map[string]string{}
			for _, col := range r.Columns {
				row[col] = r.String(col)
			}
			table = append(table, row)
		}
		doc[key] = table
	}

	// The cluster CA, without which a replay can read a cert_pem but cannot tell
	// whether this cluster issued it — VerifyRow requires each certificate to
	// chain to the CA, and the daemon reads that from local disk. The CA
	// CERTIFICATE is public by construction: every node and CLI already holds it.
	// Absence is reported, not silently tolerated, because an export missing it
	// cannot reproduce the UnknownKeyID class of finding.
	ca, err := os.ReadFile(filepath.Join(s.pkiDir, "ca.crt"))
	if err != nil {
		slog.Warn("audit export: cluster CA unreadable; the export cannot be checked against it",
			"pki_dir", s.pkiDir, "error", err)
		doc["ca_pem"] = ""
		return nil
	}
	doc["ca_pem"] = string(ca)
	return nil
}

// verifyChain bridges to corrosion.VerifyAuditChain — kept in this
// package so the gRPC handler's error wrapping stays close to the
// RPC contract.
func verifyChain(ctx context.Context, s *Server) (corrosion.AuditVerifyResult, error) {
	// The result is passed through unchanged: collapsing it here would lose
	// the distinction between "rows predate signing" and "rows were edited",
	// which is the whole point of the check.
	if s == nil || s.db == nil {
		return corrosion.AuditVerifyResult{}, fmt.Errorf("server not initialised")
	}
	return verifyChainImpl(ctx, s)
}

// RetireAuditKey retires a host's audit signing key on its behalf.
//
// The daemon signs its own retirement whenever an operator turns
// enforcement.audit_signature off, so the routine rollback needs nothing from
// here. This exists for a host that cannot speak for itself — its key is lost or
// unreadable, the machine is gone, or it is being decommissioned. Left alone,
// such a host keeps a published certificate declaring that its rows are signed,
// and every unsigned row it ever wrote is reported as evidence on every node
// with no way to close it out.
//
// It runs on the CA node because signing for another host means minting a
// certificate carrying that host's CN, which is exactly what holding the cluster
// CA authorises and nothing else does. The certificate is published so peers can
// verify the retirement; the key behind it signs twice and is then destroyed —
// once for the host's key, once for itself, so the certificate minted to end a
// contract cannot become a new one.
func (s *Server) RetireAuditKey(ctx context.Context, req *pb.RetireAuditKeyRequest) (*pb.RetireAuditKeyResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.GetHostName() == "" {
		return nil, status.Error(codes.InvalidArgument, "host_name required")
	}
	host := req.GetHostName()

	verifier, err := corrosion.LoadAuditVerifier(s.pkiDir)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "load cluster CA: %v", err)
	}
	live, err := corrosion.LiveAuditKeyIDs(ctx, s.db, verifier, host)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	// Every live key, not just the newest. A host is under contract while ANY of
	// its keys is unretired, so closing one and reporting success left the
	// contract standing and every node still reporting TAMPERED.
	//
	// The caller names which one. Retiring several in one call would give them a
	// single boundary, and they do not have one — a rotation that half-completed
	// leaves two keys whose chains reached different sequences, and the whole point
	// of the boundary is that it is per key. Refusing without a selector, which is
	// what this did, was worse still: an operator was told to "retire them one at a
	// time" by a command that gave them no way to name one, so a host with two live
	// keys could not be retired at all. That state is not exotic — it is what a
	// failed rotation leaves, which is precisely when this command gets run.
	if selected := req.GetKeyId(); selected != "" {
		if !slices.Contains(live, selected) {
			return nil, status.Errorf(codes.FailedPrecondition,
				"host %q has no live signing certificate %q; live keys are %v (an already-retired "+
					"key needs no retiring, and one that was never published cannot be named here)",
				host, selected, live)
		}
		live = []string{selected}
	} else if len(live) > 1 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %q has %d live signing certificates (%v); pass --key-id to retire one, and "+
				"re-run until none remain, or the contract stays open", host, len(live), live)
	}
	active, ok := "", len(live) == 1
	if ok {
		active = live[0]
	}
	if !ok {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %q has no live audit signing certificate: it either never published one or "+
				"its key is already retired, so there is nothing to retire", host)
	}
	// The boundary is the sequence the host's chain has REACHED, read from
	// replicated state. Everything up to there was legitimately written under the
	// key; anything above it is the finding this retirement raises.
	// Floored, and excluding the key being retired. This RPC is usually served by
	// a node that is NOT the one being retired, so its replica of that host's log
	// can lag badly — recording the boundary from it would put every row between
	// the two past the boundary the moment anti-entropy caught up, permanently.
	seq, err := corrosion.FlooredHostTailSeq(ctx, s.db, verifier, host, active)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	// An operator-chosen boundary replaces the derived one, and skips the
	// lagging-replica refusal below.
	//
	// It has to exist. That refusal counts heads signed by the key being retired,
	// deliberately — a host's heads are signed by its own keys, so excluding them is
	// what let a stale replica pin a boundary three rows low on the lab. The cost is
	// that whoever holds a leaked key publishes one head at any sequence they like
	// and retirement then refuses on every node forever: heads are append-only,
	// tombstones are inert, and the anti-entropy guard refuses rewrites, so the
	// claim cannot be withdrawn. Without an override the leaked key disables the
	// command that exists to retire it.
	//
	// Handing the decision to the CA holder is the honest resolution for the WRITE:
	// phase 2 needs a certificate minted with the CA private key, which lives on no
	// node, and both signatures cover this exact sequence, so a substituted value
	// cannot be replayed. Phase 1 is reachable by any admin caller, but it writes
	// nothing.
	derivedSeq := seq
	if req.AtSeq != nil {
		override := req.GetAtSeq()
		// Presence, not a zero sentinel, so 0 stays expressible — "this key signed
		// nothing valid" is the right boundary for a key believed leaked from the
		// moment it was minted. A negative sequence is malformed, and must be refused
		// rather than quietly falling through to the derived path with a success
		// response, which is what a `> 0` gate did.
		if override < 0 {
			return nil, status.Errorf(codes.InvalidArgument,
				"at_seq must be a sequence number, got %d", override)
		}
		// Raising a boundary and lowering one are not the same operation, and this is
		// the only place that can tell them apart. Raising cannot condemn anything:
		// rows above the boundary are the finding, so a higher boundary forgives more.
		// Lowering is unrecoverable — append-only records, earliest retirement wins —
		// so every row between the supplied sequence and the chain's real extent
		// becomes a permanent finding on every node. A mistyped sequence is otherwise
		// indistinguishable from a deliberate one, and the legitimate reason to go
		// lower is real (a key known to have leaked partway through its life), so this
		// asks rather than refuses.
		if override < derivedSeq && !req.GetForce() {
			return nil, status.Errorf(codes.FailedPrecondition,
				"refusing to retire %s's key at sequence %d: this node can already see its "+
					"chain reaching %d, so %d row(s) it signed would become retired-key use "+
					"findings on every node, permanently and with no way to raise the boundary "+
					"again. If that is what you mean — the key is known to have leaked partway "+
					"through its life — pass --force. If you meant to get past a chain head that "+
					"claims more than the log holds, the boundary you want is at or above %d",
				host, override, derivedSeq, derivedSeq-override, derivedSeq)
		}
		slog.Warn("retiring an audit signing key at an operator-supplied boundary; the derived "+
			"one and the lagging-replica check are both bypassed. Rows this host signed above "+
			"the boundary will be reported as retired-key use on every node, permanently",
			"host", host, "key_id", active, "at_seq", override, "derived_seq", derivedSeq,
			"forced", req.GetForce())
		seq = override
	} else if attested, behind, berr := corrosion.AuditReplicaIsBehind(ctx, s.db, verifier, host); berr != nil {
		return nil, status.Errorf(codes.Internal, "%v", berr)
	} else if behind {
		return nil, status.Errorf(codes.FailedPrecondition,
			"this node's copy of %s's audit log ends at %d but a signed chain head attests to "+
				"%d; retiring now would put %d legitimately signed rows past the boundary, "+
				"permanently. Wait for replication to catch up, or run this from a node that is "+
				"current. If no node can ever be current — a head signed by the key you are "+
				"retiring can claim any sequence at all and cannot be withdrawn, so a leaked key "+
				"can block this indefinitely — then either run `lv host rotate-audit-key %s`, "+
				"which seals what the old key wrote without needing a boundary, or name the "+
				"boundary yourself with --at-seq once you have established how far %s's chain "+
				"actually reached",
			host, seq, attested, attested-seq, host, host)
	}

	// Phase 1: report what would be retired. The operator holds the CA, so they
	// mint and sign; this node only ever verifies.
	if req.GetSignature() == "" {
		return &pb.RetireAuditKeyResponse{RetiredKeyId: active, RetiredAtSeq: seq}, nil
	}

	// Phase 2. The certificate must chain to the cluster CA and name this host —
	// the same rule every other signer is held to — and the signatures must cover
	// exactly the key and sequence reported above, so a stale or substituted
	// phase-1 answer cannot be replayed against a different boundary.
	if err := corrosion.RecordSignedRetirement(ctx, s.db, s.pkiDir, host, active, seq,
		req.GetCertPem(), req.GetSignature(), req.GetSelfSignature(), req.GetCaSignature()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}

	// The detail says whether the boundary was derived or supplied, and what the
	// derived value was. This is the audit log of the audit system: a retirement that
	// bypassed the lagging-replica protection must not read the same as one that did
	// not, or the only record of it is a slog line on whichever node served the RPC.
	detail := fmt.Sprintf("retired key %s at seq %d (derived)", active, seq)
	if req.AtSeq != nil {
		detail = fmt.Sprintf("retired key %s at seq %d (operator-supplied; this node derived %d; "+
			"lagging-replica check bypassed; force=%t)", active, seq, derivedSeq, req.GetForce())
	}
	s.auditAs(ctx, callerUsername(ctx), "audit.key.retire", host, detail, "success")
	return &pb.RetireAuditKeyResponse{RetiredKeyId: active, RetiredAtSeq: seq}, nil
}
