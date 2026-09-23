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
	"context"
	"encoding/json"
	"fmt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// FetchPage returns one export page for the given cursor. The empty cursor asks
// for the first page.
type FetchPage func(ctx context.Context, cursor string) (*pb.ExportAuditChainResponse, error)

// Assemble follows the cursor to the end and merges every page into one JSON
// document, returning it alongside the total row count.
//
// Rows are concatenated in the order the server emitted them, which is the
// verifier's own order — a chain is only checkable in the order its links were
// built. Keys other than "rows" are taken from the first page that carries
// them: the evidence tables and the CA ride on page one, and a later page must
// not be able to replace them.
func Assemble(ctx context.Context, fetch FetchPage) ([]byte, int, error) {
	doc := map[string]json.RawMessage{}
	rows := []json.RawMessage{}
	total := 0

	for cursor, seen := "", map[string]bool{}; ; {
		resp, err := fetch(ctx, cursor)
		if err != nil {
			return nil, 0, fmt.Errorf("export audit chain: %w", err)
		}

		var page map[string]json.RawMessage
		if err := json.Unmarshal([]byte(resp.Json), &page); err != nil {
			return nil, 0, fmt.Errorf("decode export page: %w", err)
		}
		if raw, ok := page["rows"]; ok {
			var pageRows []json.RawMessage
			if err := json.Unmarshal(raw, &pageRows); err != nil {
				return nil, 0, fmt.Errorf("decode export rows: %w", err)
			}
			rows = append(rows, pageRows...)
		}
		for k, v := range page {
			if k == "rows" {
				continue
			}
			if _, already := doc[k]; !already {
				doc[k] = v
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
			return nil, 0, fmt.Errorf("export audit chain: server repeated cursor %q; refusing to return a partial chain", resp.NextCursor)
		}
		seen[resp.NextCursor] = true
		cursor = resp.NextCursor
	}

	merged, err := json.Marshal(rows)
	if err != nil {
		return nil, 0, fmt.Errorf("encode export rows: %w", err)
	}
	doc["rows"] = merged
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, 0, fmt.Errorf("encode export: %w", err)
	}
	return body, total, nil
}
