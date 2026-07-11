#!/usr/bin/env bash
# Continuous / CI entrypoint for coverage-guided telemetry fuzz targets.
# Runs on GitHub-hosted runners (cloud VMs) on a schedule and on PRs that
# touch telemetry code — local stand-in for OSS-Fuzz batch jobs.
#
# Usage:
#   FUZZTIME=2m ./scripts/ci/fuzz-telemetry.sh
#   make test-fuzz-telemetry FUZZTIME=5m
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

FUZZTIME="${FUZZTIME:-2m}"

echo "fuzz-telemetry: FUZZTIME=${FUZZTIME}"
make test-fuzz-telemetry FUZZTIME="${FUZZTIME}"
