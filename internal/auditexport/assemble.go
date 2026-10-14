// Package auditexport assembles a paginated audit-chain export into the single
// document its consumers need.
//
// ExportAuditChain pages, because the whole chain does not fit in one unary
// message. Every caller therefore has to walk the cursor, and a caller that
// forgets does not fail — it returns page one, which looks exactly like a
// complete export and is the artifact an operator then ships to WORM storage.
// That silent-truncation shape is why the walk lives here instead of at each
// call site: there is one implementation to get right, and a consumer that
// wants the chain cannot express "the first 5000 rows" by accident.
package auditexport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// FetchPage returns one export page for the given cursor. The empty cursor asks
// for the first page.
type FetchPage func(ctx context.Context, cursor string) (*pb.ExportAuditChainResponse, error)

// MaxAssembledBytes bounds the in-memory audit-chain document.
//
// Assemble builds the WHOLE chain in the caller's heap — the daemon's own, for
// the web UI and the REST gateway. audit_log is append-only with no retention
// prune, so there is no natural bound on the input and the peak allocation is
// several times the document size once marshalling doubles it. Write, which
// `lv audit export` uses to spool to disk, holds one page at a time and has no
// such bound.
//
// A var, not a const, only so a test can shrink it; nothing in production
// reassigns it.
var MaxAssembledBytes = 256 << 20

// Options changes what Write accepts.
type Options struct {
	// AllowGaps writes a chain in which the server reported seq gaps instead of
	// refusing it. Every reported gap, from every page, is listed under the
	// document's "seq_gaps" key. A gap is either replication still catching up
	// or rows deleted from a host's chain; the second is exactly what an
	// investigator needs the export for, and the default refusal would deny it.
	// The document is no attestation: an offline replay reports a chain break
	// at each listed gap, as `lv audit verify` does.
	AllowGaps bool
}

// Assemble follows the cursor to the end and merges every page into one JSON
// document, returning it alongside the total row count. It holds the whole
// document in memory, so it refuses a chain past MaxAssembledBytes, and it
// refuses a chain with reported seq gaps.
func Assemble(ctx context.Context, fetch FetchPage) ([]byte, int, error) {
	var buf bytes.Buffer
	total, err := write(ctx, fetch, &buf, Options{}, MaxAssembledBytes)
	if err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), total, nil
}

// Write follows the cursor to the end and writes the one document to w as the
// pages arrive, returning the total row count. It holds one page at a time,
// plus page one's evidence, so it has no size limit.
//
// Every refusal Assemble makes, Write makes too, but only once the walk is
// done — by then w holds part of a document. A caller must therefore write to a
// spool and keep it only when Write succeeds; `lv audit export` does.
//
// Rows are written in the order the server emitted them, which is the
// verifier's own order — a chain is only checkable in the order its links were
// built. Keys other than "rows" and "seq_gaps" are taken from the first page
// that carries them: the evidence tables and the CA ride on page one, and a
// later page must not be able to replace them. Gaps are reported per page, so
// every page's are kept.
func Write(ctx context.Context, fetch FetchPage, w io.Writer, opt Options) (int, error) {
	return write(ctx, fetch, w, opt, 0)
}

// stickyWriter keeps the first write error, so the walk can write freely and
// check once.
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) write(b []byte) {
	if s.err == nil {
		_, s.err = s.w.Write(b)
	}
}

// write is Write, refusing once the rows held pass limit bytes (0: no limit).
func write(ctx context.Context, fetch FetchPage, dst io.Writer, opt Options, limit int) (int, error) {
	w := &stickyWriter{w: dst}
	doc := map[string]json.RawMessage{}
	var gaps []json.RawMessage
	// The signing keys the rows name, against which page one's evidence is
	// checked at the end: one entry per key, not per row.
	rowKeys := map[string]string{}
	total, bytesHeld, wroteRow := 0, 0, false
	var row bytes.Buffer

	w.write([]byte(`{"rows":[`))
	for cursor, seen := "", map[string]bool{}; ; {
		resp, err := fetch(ctx, cursor)
		if err != nil {
			return 0, fmt.Errorf("export audit chain: %w", err)
		}

		var page map[string]json.RawMessage
		if err := json.Unmarshal([]byte(resp.Json), &page); err != nil {
			return 0, fmt.Errorf("decode export page: %w", err)
		}
		if raw, ok := page["rows"]; ok {
			var pageRows []json.RawMessage
			if err := json.Unmarshal(raw, &pageRows); err != nil {
				return 0, fmt.Errorf("decode export rows: %w", err)
			}
			bytesHeld += len(raw)
			// audit_log is append-only with no retention prune, so the input is
			// unbounded: a two-year-old cluster asked for its whole chain walks
			// every page into memory and then DOUBLES the allocation twice to
			// marshal it. In the daemon that ends with the OOM killer, and
			// because that is SIGKILL the watchdog Heartbeat's deferred disarm
			// never runs -- on a host that still owns workloads the watchdog is
			// left counting while the control plane is down.
			//
			// Refusing, with a remedy that works, is a worse export and a much
			// better failure than letting the kernel decide which process dies.
			if limit > 0 && bytesHeld > limit {
				return 0, fmt.Errorf(
					"audit chain is too large to assemble in memory (%d MiB of rows so far, "+
						"limit %d MiB); export it with `lv audit export --out <file>`, which "+
						"spools to disk as pages arrive and has no size limit",
					bytesHeld>>20, limit>>20)
			}
			for _, r := range pageRows {
				var ref struct {
					KeyID    string `json:"key_id"`
					HostName string `json:"host_name"`
				}
				if err := json.Unmarshal(r, &ref); err != nil {
					return 0, fmt.Errorf("decode export row: %w", err)
				}
				if _, ok := rowKeys[ref.KeyID]; ref.KeyID != "" && !ok {
					rowKeys[ref.KeyID] = ref.HostName
				}
				row.Reset()
				if err := json.Compact(&row, r); err != nil {
					return 0, fmt.Errorf("encode export row: %w", err)
				}
				if wroteRow {
					w.write([]byte(","))
				}
				w.write(row.Bytes())
				wroteRow = true
			}
		}
		for k, v := range page {
			switch k {
			case "rows":
			case "seq_gaps":
				var pageGaps []json.RawMessage
				if err := json.Unmarshal(v, &pageGaps); err != nil {
					return 0, fmt.Errorf("decode export seq_gaps: %w", err)
				}
				gaps = append(gaps, pageGaps...)
			default:
				if _, already := doc[k]; !already {
					doc[k] = v
				}
			}
		}
		total += int(resp.RowCount)

		if resp.NextCursor == "" {
			break
		}
		// The walk is driven by a value the server chooses, so a server that
		// stops advancing must end it rather than hold the request open
		// forever. Erroring beats returning what was collected: a partial
		// document here is the very thing this package exists to prevent.
		if seen[resp.NextCursor] {
			return 0, fmt.Errorf("export audit chain: server repeated cursor %q; refusing to return a partial chain", resp.NextCursor)
		}
		seen[resp.NextCursor] = true
		cursor = resp.NextCursor
	}

	// COMPLETENESS, before returning something that looks authoritative.
	//
	// The evidence tables -- signing_keys, key_lifecycle, chain_heads -- ride on
	// page ONE. A host that rotates its signing key after that page produces
	// rows on later pages signed by a key whose certificate is not in the
	// document, and an external verifier cannot check them at all. It is the
	// same class as a seq gap: the artifact replays as broken, and the operator
	// cannot tell that from tampering.
	//
	// This package exists to refuse a partial chain -- it already errors when a
	// server repeats a cursor -- so an uncheckable one is refused here too,
	// naming the key and the remedy rather than writing a document whose
	// verification will fail later for reasons nobody can attribute.
	if err := checkKeyCoverage(doc, rowKeys); err != nil {
		return 0, err
	}
	if len(gaps) > 0 && !opt.AllowGaps {
		raw, _ := json.Marshal(gaps)
		return 0, fmt.Errorf("export audit chain: the server reported gaps in a host's "+
			"seq sequence (%s); the rows below a gap replay as a chain break, which is "+
			"indistinguishable from tampering. Re-run once replication has caught up. A gap "+
			"that persists is rows missing from the chain: `lv audit export --allow-gaps` "+
			"exports it with every gap listed under seq_gaps, for investigation, not attestation", raw)
	}

	w.write([]byte("]"))
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(gaps) > 0 {
		raw, err := json.Marshal(gaps)
		if err != nil {
			return 0, fmt.Errorf("encode export seq_gaps: %w", err)
		}
		doc["seq_gaps"] = raw
		keys = append(keys, "seq_gaps")
	}
	for _, k := range keys {
		name, _ := json.Marshal(k)
		row.Reset()
		if err := json.Compact(&row, doc[k]); err != nil {
			return 0, fmt.Errorf("encode export %s: %w", k, err)
		}
		w.write([]byte(","))
		w.write(name)
		w.write([]byte(":"))
		w.write(row.Bytes())
	}
	w.write([]byte("}"))
	if w.err != nil {
		return 0, fmt.Errorf("write export: %w", w.err)
	}
	return total, nil
}

// checkKeyCoverage refuses a document whose rows reference a signing key the
// page-one evidence does not carry. rowKeys maps each key_id the rows name to
// a host that used it.
//
// Rows written before v45 have no key_id: they are chain-verified but not
// tamper-evident, and the verifier reports them as such, so an empty key_id is
// not a coverage failure.
func checkKeyCoverage(doc map[string]json.RawMessage, rowKeys map[string]string) error {
	raw, ok := doc["signing_keys"]
	if !ok {
		return nil // no evidence section at all: page one carried none
	}
	var keys []struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return fmt.Errorf("decode signing_keys evidence: %w", err)
	}
	known := make(map[string]bool, len(keys))
	for _, k := range keys {
		known[k.KeyID] = true
	}

	var names []string
	for id, host := range rowKeys {
		if !known[id] {
			names = append(names, id+" ("+host+")")
		}
	}
	if len(names) == 0 {
		return nil
	}
	sort.Strings(names)
	return fmt.Errorf("export audit chain: %d row signing key(s) have no certificate in the "+
		"exported evidence: %s. The evidence tables ride on page one, so a key rotated "+
		"mid-export is absent and those rows cannot be verified offline at all. Re-run the "+
		"export", len(names), strings.Join(names, ", "))
}
