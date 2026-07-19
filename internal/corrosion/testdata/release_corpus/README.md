# Release statement-shape corpus

Each `<release>.json` records the distinct replicated statement shapes that a supported prior
release emits, harvested from that release's source tree (not from this repo's historical
families — so it is an independent cross-check that the compatibility ledger covers the
upgrade / WAL-retention horizon). `release_corpus_test.go` asserts every shape fingerprints
identically under the current code and resolves in the ledger.

Each entry is `{ "fingerprint": "stmtshape/v1:<sha256>", "sql": "<statement with ? params>" }`.
Only statement *shapes* are stored — parameters are always `?`, so no data is recorded.

## Regenerating (when a release enters or leaves the supported horizon)

```bash
git worktree add /tmp/vX <tag>            # e.g. v1.3.0
go run ./scripts/ci/stmtshapecheck -root /tmp/vX -report > /tmp/report.txt
# keep the fingerprinted lines (loc \t fingerprint \t Go-quoted-sql), dedup by fingerprint,
# unquote the SQL, and emit a sorted JSON array of {fingerprint, sql} to <release>.json.
git worktree remove /tmp/vX
```

The `-report` output also lists the release's DYNAMIC builders (SQL built at runtime, not a
string literal) and PARSE-ERR shapes (a receiver-evaluated expression the strict parser
rejects). Those cannot appear in the static corpus; they are enumerated to their concrete
shapes and asserted covered in `TestReleaseCorpus_*_DynamicBuildersCovered` (via the historical
families and the legacy transformers).
