#!/usr/bin/env bash
#
# CI guard: no statement fingerprint may silently vanish from the replication
# ledgers. When a builder's SQL is widened and stmtledger_generated.go is
# regenerated, the OLD shape's fingerprint disappears from the generated ledger
# — but a supported prior-release peer still emits that shape, and a receiver
# that no longer recognises it back-pressures the peer's stream (fail-closed
# apply). The mechanical rule: every fingerprint present at the merge-base in
# (generated ∪ historical) must still be present at HEAD in that union — i.e.
# a shape leaving the generated ledger must be ADDED to the historical one
# (see internal/corrosion/stmthistorical.go). Caught by review twice in v43
# (InsertHost, ConfigureHost); this makes it a machine's job.
#
# Deliberately aging a release out of the rolling-upgrade horizon removes
# entries for real: set ALLOW_LEDGER_REMOVAL=1 for that one commit.
#
# Base resolution mirrors check-schema-bump.sh:
#   - pull_request:  GITHUB_BASE_REF
#   - push:          GITHUB_EVENT_BEFORE
#   - local:         origin/main (override with BASE_REF=...)
set -euo pipefail

LEDGERS=(
	"internal/corrosion/stmtledger_generated.go"
	"internal/corrosion/stmtledger_historical.go"
)

if [[ "${ALLOW_LEDGER_REMOVAL:-}" == "1" ]]; then
	echo "ledger-drift: ALLOW_LEDGER_REMOVAL=1 — skipping (deliberate horizon removal)."
	exit 0
fi

resolve_base() {
	if [[ -n "${GITHUB_BASE_REF:-}" ]]; then
		git fetch --quiet --depth=1 origin "$GITHUB_BASE_REF" 2>/dev/null || true
		git rev-parse FETCH_HEAD 2>/dev/null || git rev-parse "origin/$GITHUB_BASE_REF" 2>/dev/null || true
	elif [[ -n "${GITHUB_EVENT_BEFORE:-}" ]]; then
		echo "$GITHUB_EVENT_BEFORE"
	else
		echo "${BASE_REF:-origin/main}"
	fi
}

base="$(resolve_base)"
if [[ -z "$base" || "$base" =~ ^0+$ ]]; then
	echo "ledger-drift: no base revision to compare against; skipping."
	exit 0
fi
if ! git rev-parse --verify --quiet "${base}^{commit}" >/dev/null; then
	echo "ledger-drift: base revision '$base' not found; skipping."
	exit 0
fi
mergebase="$(git merge-base HEAD "$base" 2>/dev/null || echo "$base")"

fingerprints() { # $1 = revision ("" for worktree)
	local rev="$1" f
	for f in "${LEDGERS[@]}"; do
		if [[ -z "$rev" ]]; then
			cat "$f" 2>/dev/null || true
		else
			git show "${rev}:${f}" 2>/dev/null || true
		fi
	done | grep -o 'stmtshape/v1:[0-9a-f]\{64\}' | sort -u
}

base_fps="$(fingerprints "$mergebase")"
if [[ -z "$base_fps" ]]; then
	echo "ledger-drift: no ledgers at $mergebase; skipping."
	exit 0
fi

missing="$(comm -23 <(echo "$base_fps") <(fingerprints ""))"
if [[ -n "$missing" ]]; then
	echo "ledger-drift: fingerprints present at ${mergebase} are GONE from HEAD's ledgers:"
	echo "$missing" | sed 's/^/  /'
	echo ""
	echo "A supported prior-release peer may still emit these shapes; removing them"
	echo "back-pressures that peer's replication stream. Move the old shape into"
	echo "internal/corrosion/stmthistorical.go (see insert_host_v130 /"
	echo "configure_host_fixed_v130) and regenerate, or — only for a deliberate"
	echo "upgrade-horizon removal — re-run with ALLOW_LEDGER_REMOVAL=1."
	exit 1
fi
echo "ledger-drift: OK — all ${mergebase} ledger fingerprints still recognised at HEAD."
