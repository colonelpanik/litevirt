package corrosion

// stmtLedger is the checked-in compatibility ledger, keyed by stmtshape/v1 fingerprint.
// Seed it from `go run ./scripts/ci/stmtshapecheck -root . -report`, then annotate each
// entry's Disposition / Category / activation conditions. The stmtshapecheck guard fails
// if a current builder's fingerprint is missing here.
//
// TEMPORARILY EMPTY — populated from the (now complete, batch- and const-aware) builder
// enumeration once the stmtshapecheck guard is finalized.
var stmtLedger = map[string]LedgerEntry{}

// stmtPolicies maps a dynamic-SQL policy id to its finite set of allowed expansion
// fingerprints (each also a ledger entry). Seeded alongside the ledger.
var stmtPolicies = map[string][]string{}
