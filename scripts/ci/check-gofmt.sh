#!/usr/bin/env bash
# Fail the build on any tracked .go file gofmt would rewrite.
#
# Formatting drifts silently: nothing rejected it, so it accumulated to 77 files
# — 26 of them production — and then any broad `gofmt -w` mixed unrelated
# realignment into whatever change happened to be in flight. That noise is worse
# than the drift, because it hides the real diff from review.
#
# Tracked files only. `gofmt -l .` would walk .worktrees/ and vendor/, which are
# gitignored and not ours to format.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

unformatted="$(git ls-files '*.go' -z | xargs -0 gofmt -l)"

if [ -n "$unformatted" ]; then
	count="$(printf '%s\n' "$unformatted" | wc -l | tr -d ' ')"
	echo "gofmt: FAIL — $count tracked .go file(s) are not gofmt-clean:" >&2
	printf '  %s\n' $unformatted >&2
	echo >&2
	echo "Fix with:" >&2
	echo "    git ls-files '*.go' -z | xargs -0 gofmt -w" >&2
	exit 1
fi

echo "gofmt: every tracked .go file is gofmt-clean; OK"
