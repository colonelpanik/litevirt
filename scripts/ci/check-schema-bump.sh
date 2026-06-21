#!/usr/bin/env bash
#
# CI guard: any growth of the schema arrays in internal/corrosion/schema.go must
# come with a CurrentSchemaVersion bump. Delegates the actual comparison to the
# AST-based tool in scripts/ci/schemacheck.
#
# Resolves the base revision to diff against:
#   - pull_request:  the PR base branch        (GITHUB_BASE_REF)
#   - push:          the previous tip          (GITHUB_EVENT_BEFORE)
#   - local:         origin/main               (override with BASE_REF=...)
#
# If the base revision can't be resolved, or schema.go didn't exist there, the
# check is skipped — there's no "before" for the schema to have grown from.
set -euo pipefail

SCHEMA="internal/corrosion/schema.go"

resolve_base() {
	if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
		# Pull request: fetch and diff against the fork point of the base branch.
		git fetch --quiet --depth=1 origin "$GITHUB_BASE_REF" 2>/dev/null || true
		git rev-parse FETCH_HEAD 2>/dev/null || git rev-parse "origin/$GITHUB_BASE_REF" 2>/dev/null || true
	elif [[ -n "${GITHUB_EVENT_BEFORE:-}" ]]; then
		echo "$GITHUB_EVENT_BEFORE"
	else
		echo "${BASE_REF:-origin/main}"
	fi
}

base="$(resolve_base)"

# An all-zero SHA is GitHub's sentinel for "no previous commit" (new branch /
# first push). Nothing to compare against.
if [[ -z "$base" || "$base" =~ ^0+$ ]]; then
	echo "schema-bump: no base revision to compare against; skipping."
	exit 0
fi
if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
	echo "schema-bump: base revision '$base' not found; skipping."
	exit 0
fi

# Use the merge-base so a PR is compared against where it forked, not the moving
# tip of the base branch. Falls back to the raw base for linear push history.
mergebase="$(git merge-base HEAD "$base" 2>/dev/null || echo "$base")"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
if ! git show "${mergebase}:${SCHEMA}" >"$tmp" 2>/dev/null; then
	echo "schema-bump: $SCHEMA did not exist at $mergebase; skipping."
	exit 0
fi

echo "schema-bump: comparing $SCHEMA against ${mergebase}"
go run ./scripts/ci/schemacheck -base "$tmp" -head "$SCHEMA"
