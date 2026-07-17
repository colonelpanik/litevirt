package corrosion

// stmtLedger is the checked-in compatibility ledger, keyed by stmtshape/v1 fingerprint.
// Seed it from `go run ./scripts/ci/stmtshapecheck -root . -report`, then annotate each
// entry's Disposition / Category / activation conditions. The stmtshapecheck guard fails
// if a current builder's fingerprint is missing here.
//
// TEMPORARILY EMPTY — populated in the next step from the builder enumeration.
var stmtLedger = map[string]LedgerEntry{}
