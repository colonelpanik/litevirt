package ui

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handleEvents renders the unified cluster Events page: recent cluster-wide
// history (the durable, replicated vm_events table) seeded server-side, with a
// live SSE tail that prepends new events as they happen. This is the single
// global event view — the VM detail page shows the same events filtered to one
// VM. (/activity redirects here for back-compat.)
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && v > 0 {
		limit = v
	}
	data := s.pageData("Events", "events")
	resp, err := s.grpc.ListVMEvents(s.uiBearerCtx(r), &pb.ListVMEventsRequest{Limit: int32(limit)})
	if err != nil {
		slog.Error("ui: list events", "error", err)
		data["Error"] = err.Error()
	} else {
		data["Events"] = resp.GetEvents()
	}
	data["Limit"] = limit
	s.renderPage(w, "events.html", data)
}

// handleEventsStream serves an SSE endpoint that bridges gRPC StreamEvents.
func (s *Server) handleEventsStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	disableStreamWriteTimeout(w) // long-lived tail; don't let the 30s WriteTimeout drop it

	stream, err := s.grpc.StreamEvents(s.uiBearerCtx(r), &pb.StreamEventsRequest{})
	if err != nil {
		slog.Error("SSE: stream events", "error", err)
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
		flusher.Flush()
		return
	}

	for {
		ev, err := stream.Recv()
		if err != nil {
			slog.Debug("SSE: stream ended", "error", err)
			return
		}
		ts := ""
		if ev.Timestamp != nil {
			ts = ev.Timestamp.AsTime().Format("2006-01-02T15:04:05Z")
		}
		payload, _ := json.Marshal(map[string]string{
			"type":      ev.Action,
			"target":    ev.Target,
			"detail":    ev.Detail,
			"username":  ev.Username,
			"timestamp": ts,
		})
		fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Action, payload)
		flusher.Flush()
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	resp, _ := s.grpc.ListAuditLog(s.uiBearerCtx(r), &pb.ListAuditLogRequest{Limit: 500})
	entries := resp.GetEntries()
	data := s.pageData("Audit Log", "audit")

	// task-log filter: ?target=… and ?action=… narrow the
	// view to a single subject/verb. Combined with the existing
	// audit entries this gives operators a per-action history without
	// adding a new RPC.
	target := r.URL.Query().Get("target")
	action := r.URL.Query().Get("action")
	if target != "" || action != "" {
		filtered := entries[:0]
		for _, e := range entries {
			if target != "" && e.Target != target {
				continue
			}
			if action != "" && e.Action != action {
				continue
			}
			filtered = append(filtered, e)
		}
		entries = filtered
		data["FilterTarget"] = target
		data["FilterAction"] = action
	}

	data["AuditEntries"] = entries
	s.renderPage(w, "audit.html", data)
}

// handleAuditVerify walks the audit hash-chain server-side and reports the result
// as a toast. Mirrors `lv audit verify`.
func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	resp, err := s.grpc.VerifyAuditChain(s.uiBearerCtx(r), &emptypb.Empty{})
	if err != nil {
		sendToast(w, "Verify failed: "+err.Error(), "error")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	switch {
	case resp.Error != "":
		sendToast(w, "Verify error: "+resp.Error, "error")
	case resp.Tampered:
		sendToast(w, "Audit chain TAMPERED: "+auditTamperSummary(resp)+
			fmt.Sprintf(" (%d rows checked) — run `lv audit verify` for the affected rows", resp.RowsChecked), "error")
	case resp.Unverified:
		// The third outcome, and a warning rather than an error: part of the log
		// could not be checked, which is not a pass and is not an accusation. It
		// was briefly neither — when `never adopted` stopped counting as tampering
		// this branch did not exist, so a host that had published a signing
		// certificate and could not sign produced a GREEN "intact, all signed"
		// toast here while `lv audit verify` exited 1 on the same result.
		sendToast(w, fmt.Sprintf("Audit chain PARTLY UNVERIFIED (%d rows checked): %s — "+
			"run `lv audit verify` for the detail", resp.RowsChecked, auditUnverifiedSummary(resp)), "warning")
	case resp.UnsignedRows > 0:
		// Deliberately "success", not a warning: unsigned rows are what every
		// cluster looks like before signing was switched on, and colouring that
		// red teaches operators that a red audit toast means nothing.
		sendToast(w, fmt.Sprintf("Audit chain intact: %d rows verified (%d predate tamper-evidence, chain-checked only)",
			resp.RowsChecked, resp.UnsignedRows), "success")
	default:
		sendToast(w, fmt.Sprintf("Audit chain intact: %d rows verified, all signed", resp.RowsChecked), "success")
	}
	w.WriteHeader(http.StatusOK)
}

// auditTamperSummary names every category that fired, with counts. A toast
// cannot hold one line per affected row, so it must at least say WHICH kind of
// interference was found — "chain broken" alone hides a bad signature sitting
// next to it, and those two call for very different responses.
func auditTamperSummary(resp *pb.VerifyAuditChainResponse) string {
	var parts []string
	if resp.BrokenAtId != "" {
		parts = append(parts, "hash mismatch at row "+resp.BrokenAtId)
	}
	for _, c := range []struct {
		label string
		n     int
	}{
		{"bad signature", len(resp.BadSignature)},
		{"unknown key", len(resp.UnknownKeyId)},
		{"sequence gap", len(resp.SeqGaps)},
		{"laundered row", len(resp.Laundered)},
		{"truncated host", len(resp.TruncatedHosts)},
		// The categories a rotation produces. Without them a log rewritten by
		// someone holding a rotated-out key — the case the whole rotation
		// mechanism exists to catch — reached the operator as "unspecified
		// finding", which is the least actionable thing this toast can say.
		{"retired key use", len(resp.RetiredKeyUse)},
		{"chain head mismatch", len(resp.HeadMismatch)},
		{"unsigned row after signing began", len(resp.UnsignedAfterSigned)},
	} {
		if c.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s(s)", c.n, c.label))
		}
	}
	if len(parts) == 0 {
		return "unspecified finding"
	}
	return strings.Join(parts, "; ")
}

// auditUnverifiedSummary names what went unchecked. Kept separate from
// auditTamperSummary rather than folded into it, because the two answer different
// questions and merging them is how `never adopted` ended up being reported as
// evidence of interference in the first place.
func auditUnverifiedSummary(resp *pb.VerifyAuditChainResponse) string {
	var parts []string
	if n := len(resp.NeverAdopted); n > 0 {
		parts = append(parts, fmt.Sprintf("%d host(s) declaring signed rows they cannot sign", n))
	}
	if resp.UnverifiableRows > 0 {
		parts = append(parts, fmt.Sprintf("%d signed row(s) this daemon has no keyring to check", resp.UnverifiableRows))
	}
	if len(parts) == 0 {
		return "part of the log went unchecked"
	}
	return strings.Join(parts, "; ")
}

// handleAuditExport streams the audit chain as a downloadable JSON blob suitable
// for WORM offload. Mirrors `lv audit export [--since --until]`.
func (s *Server) handleAuditExport(w http.ResponseWriter, r *http.Request) {
	resp, err := s.grpc.ExportAuditChain(s.uiBearerCtx(r), &pb.ExportAuditChainRequest{
		Since: r.URL.Query().Get("since"),
		Until: r.URL.Query().Get("until"),
	})
	if err != nil {
		http.Error(w, "Export failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=audit-export.json")
	_, _ = w.Write([]byte(resp.Json))
}
