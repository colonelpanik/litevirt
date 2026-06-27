package corrosion

import (
	"strings"
)

// extractTableName extracts the table name from a SQL statement.
// Handles INSERT INTO table, UPDATE table, DELETE FROM table.
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

// isInsertStatement returns true if the SQL is an INSERT statement.
func isInsertStatement(sql string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "INSERT")
}

// isUpdateStatement returns true if the SQL is an UPDATE statement.
func isUpdateStatement(sql string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "UPDATE")
}

// isDeleteStatement returns true if the SQL is a DELETE statement.
func isDeleteStatement(sql string) bool {
	return strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "DELETE")
}

// replaceInsertStrategy replaces INSERT, INSERT OR REPLACE, INSERT OR IGNORE
// with the given strategy (e.g. "INSERT OR REPLACE").
func replaceInsertStrategy(sql, strategy string) string {
	upper := strings.ToUpper(strings.TrimSpace(sql))
	trimmed := strings.TrimSpace(sql)

	// Find where INTO starts.
	idx := strings.Index(upper, "INTO")
	if idx < 0 {
		return sql
	}

	return strategy + " " + trimmed[idx:]
}

// extractPKFromInsert extracts PK column values from an INSERT statement's params.
// It parses the column list from the SQL and matches PK column positions to params.
func extractPKFromInsert(s Statement, pkCols []string) []interface{} {
	// Find column list between first ( and first )
	sql := s.SQL
	openParen := strings.Index(sql, "(")
	if openParen < 0 {
		return nil
	}
	closeParen := strings.Index(sql[openParen:], ")")
	if closeParen < 0 {
		return nil
	}
	colStr := sql[openParen+1 : openParen+closeParen]
	cols := strings.Split(colStr, ",")
	for i := range cols {
		cols[i] = strings.TrimSpace(cols[i])
	}

	// Map PK column names to their positions.
	result := make([]interface{}, len(pkCols))
	for pi, pk := range pkCols {
		found := false
		for ci, col := range cols {
			if strings.EqualFold(col, pk) && ci < len(s.Params) {
				result[pi] = s.Params[ci]
				found = true
				break
			}
		}
		if !found {
			return nil
		}
	}
	return result
}

func extractUpdatedAtValue(s Statement) (string, bool) {
	if isInsertStatement(s.SQL) {
		return extractColumnValueFromInsert(s, "updated_at")
	}
	if isUpdateStatement(s.SQL) {
		return extractColumnValueFromUpdateSet(s, "updated_at")
	}
	return "", false
}

func extractColumnValueFromInsert(s Statement, want string) (string, bool) {
	sql := s.SQL
	openParen := strings.Index(sql, "(")
	if openParen < 0 {
		return "", false
	}
	closeParen := strings.Index(sql[openParen:], ")")
	if closeParen < 0 {
		return "", false
	}
	colStr := sql[openParen+1 : openParen+closeParen]
	cols := strings.Split(colStr, ",")
	for i, col := range cols {
		if strings.EqualFold(cleanColumnName(col), want) && i < len(s.Params) {
			return coerceString(s.Params[i]), true
		}
	}
	return "", false
}

func extractColumnValueFromUpdateSet(s Statement, want string) (string, bool) {
	upper := strings.ToUpper(s.SQL)
	setIdx := strings.Index(upper, " SET ")
	if setIdx < 0 {
		return "", false
	}
	setStart := setIdx + len(" SET ")
	whereIdx := strings.LastIndex(upper, " WHERE ")
	if whereIdx < 0 || whereIdx < setStart {
		whereIdx = len(s.SQL)
	}

	paramIdx := 0
	for _, assignment := range strings.Split(s.SQL[setStart:whereIdx], ",") {
		parts := strings.SplitN(assignment, "=", 2)
		if len(parts) != 2 {
			paramIdx += strings.Count(assignment, "?")
			continue
		}
		valuePlaceholders := strings.Count(parts[1], "?")
		if strings.EqualFold(cleanColumnName(parts[0]), want) && valuePlaceholders > 0 {
			if paramIdx < len(s.Params) {
				return coerceString(s.Params[paramIdx]), true
			}
			return "", false
		}
		paramIdx += valuePlaceholders
	}
	return "", false
}

func cleanColumnName(s string) string {
	s = strings.TrimSpace(s)
	if dot := strings.LastIndex(s, "."); dot >= 0 {
		s = s[dot+1:]
	}
	return strings.Trim(strings.TrimSpace(s), "`\"[]")
}

// extractPKFromUpdate extracts PK values from an UPDATE... WHERE pk1 = ? AND pk2 = ?
// The PK params are typically the last N params in an UPDATE statement.
func extractPKFromUpdate(s Statement, pkCols []string) []interface{} {
	upper := strings.ToUpper(s.SQL)
	whereIdx := strings.LastIndex(upper, "WHERE")
	if whereIdx < 0 {
		return nil
	}

	whereClause := strings.ToUpper(s.SQL[whereIdx:])

	// Count ? placeholders before WHERE to know where PK params start.
	beforeWhere := s.SQL[:whereIdx]
	paramsBefore := strings.Count(beforeWhere, "?")

	// Count ? in WHERE to know how many PK params there are.
	paramsInWhere := strings.Count(whereClause, "?")

	if paramsBefore+paramsInWhere > len(s.Params) {
		return nil
	}

	// The WHERE clause params are the last paramsInWhere params.
	whereParams := s.Params[paramsBefore : paramsBefore+paramsInWhere]

	// Try to match PK columns to WHERE clause params by column name order.
	// Simple heuristic: if WHERE has the same number of ? as PK columns,
	// assume they're in order.
	if len(whereParams) >= len(pkCols) {
		// Verify the WHERE clause references the PK columns.
		allFound := true
		for _, pk := range pkCols {
			if !strings.Contains(strings.ToUpper(whereClause), strings.ToUpper(pk)) {
				allFound = false
				break
			}
		}
		if allFound {
			return whereParams[:len(pkCols)]
		}
	}

	return nil
}
