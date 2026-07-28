package corrosion

// stmtLedger — the checked-in compatibility ledger keyed by stmtshape/v1 fingerprint — is
// GENERATED into stmtledger_generated.go by `go run ./scripts/ci/stmtshapecheck -emit-ledger`,
// which runs deriveDisposition over every replicated builder statement. Regenerate it whenever
// a builder's statement shape changes; the guard fails if a current builder's fingerprint is
// missing.
