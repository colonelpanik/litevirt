package corrosion

import (
	"strings"
)

// extractTableName extracts the table name from a SQL statement (INSERT INTO table, UPDATE table,
// DELETE FROM table). It is the lightweight "table-first" step used before a full structural parse
// (parseStmtShape needs the table to look up its PK columns) — by LedgerEntryFor and by the local
// unresolved-tie cleanup entrypoint. Row-identity extraction is done structurally from the parsed
// StmtShape, never by string heuristics.
func extractTableName(sql string) string {
	upper := strings.ToUpper(strings.TrimSpace(sql))
	words := strings.Fields(sql) // preserve original case for table name

	if strings.HasPrefix(upper, "INSERT") {
		// INSERT [OR REPLACE|OR IGNORE] INTO table_name
		for i, w := range words {
			if strings.EqualFold(w, "INTO") && i+1 < len(words) {
				return cleanTableName(words[i+1])
			}
		}
	}

	if strings.HasPrefix(upper, "UPDATE") {
		// UPDATE table_name SET...
		if len(words) >= 2 {
			return cleanTableName(words[1])
		}
	}

	if strings.HasPrefix(upper, "DELETE") {
		// DELETE FROM table_name
		for i, w := range words {
			if strings.EqualFold(w, "FROM") && i+1 < len(words) {
				return cleanTableName(words[i+1])
			}
		}
	}

	return ""
}

func cleanTableName(s string) string {
	// Remove surrounding quotes, parentheses, etc.
	s = strings.Trim(s, "`\"[]")
	// Remove trailing parenthesis if present (e.g. from "table(")
	s = strings.TrimRight(s, "(")
	return s
}
