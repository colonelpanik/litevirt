package corrosion

// stmtPolicies maps a dynamic-SQL policy id to its finite set of allowed expansion
// fingerprints (each also a ledger entry). Empty: every replicated builder now emits a
// finite, statically-enumerable set of statements, so all shapes live in the generated
// ledger (stmtledger_generated.go) and no //stmtshape:policy directive is required.
var stmtPolicies = map[string][]string{}

// stmtLedger — the checked-in compatibility ledger keyed by stmtshape/v1 fingerprint — is
// GENERATED into stmtledger_generated.go by `go run ./scripts/ci/stmtshapecheck -emit-ledger`,
// which runs deriveDisposition over every replicated builder statement. Regenerate it whenever
// a builder's statement shape changes; the guard fails if a current builder's fingerprint is
// missing.
