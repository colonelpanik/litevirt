# Telemetry fuzzing (continuous)

Coverage-guided fuzz targets live in `internal/obs/fuzz_test.go`:

- `FuzzValidEndpoint`
- `FuzzValidSampleRate`
- `FuzzSafeEndpointForLog`

## Local (`go test -fuzz`)

```bash
make test-fuzz-telemetry FUZZTIME=30s
make test-fuzz-telemetry FUZZTIME=5m   # harder
```

## Continuous (GitHub Actions)

Workflow: `.github/workflows/fuzz-telemetry.yml`

| Trigger | Budget |
|---------|--------|
| PR touching `internal/obs/**` | `2m` per target |
| Nightly cron | `15m` per target |
| Manual `workflow_dispatch` | configurable |

Runs on GitHub-hosted Ubuntu VMs via `scripts/ci/fuzz-telemetry.sh`.

## Shared library / local OSS-Fuzz

Deeper libFuzzer-style builds for the vendor surface live in
[provide-telemetry](https://github.com/provide-io/provide-telemetry):

```bash
# in provide-telemetry (local Docker only — not Google cloud):
./scripts/oss-fuzz-local.sh build
./scripts/oss-fuzz-local.sh run FuzzValidateRate
```

Google OSS-Fuzz **cloud** onboarding remains shelved.
