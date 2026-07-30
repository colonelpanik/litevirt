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
	"encoding/json"
	"fmt"
	"log/slog"

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

		Tampered: res.Tampered(),
	}
	if err != nil {
		resp.Error = err.Error()
	}
	return resp, nil
}

func (s *Server) ExportAuditChain(ctx context.Context, req *pb.ExportAuditChainRequest) (*pb.ExportAuditChainResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(ctx,
		`SELECT id, timestamp, username, host_name, action, target, detail, result, prev_hash, content_hash
		 FROM audit_log
		 WHERE (? = '' OR timestamp >= ?)
		   AND (? = '' OR timestamp <= ?)
		 ORDER BY timestamp ASC, id ASC`,
		req.Since, req.Since, req.Until, req.Until)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list audit_log: %v", err)
	}
	out := make([]map[string]string, 0, len(rows))
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
		})
	}
	body, mErr := json.Marshal(map[string]any{"rows": out})
	if mErr != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", mErr)
	}
	return &pb.ExportAuditChainResponse{
		Json:     string(body),
		RowCount: int32(len(out)),
	}, nil
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
	if len(live) > 1 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"host %q has %d live signing certificates (%v); retire them one at a time and "+
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
