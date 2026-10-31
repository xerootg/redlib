#!/bin/bash
# Checks the supply-chain rules for this fork's own CI files (audit findings
# #20 and #21). Nachtalb's workflows are not checked: they are not ours.
#
#   scripts/check-fork-ci.sh
#
# Rules for .github/workflows/fork-container.yml:
#   - every `uses:` is pinned by a full 40-character commit SHA, with the tag
#     it was resolved from in a trailing comment (`# v4.7.0`)
#   - a top-level `permissions: {}` and a `permissions:` block on every job

set -u
cd "$(dirname "$0")/.." || exit 1

fail=0
err() {
  echo "FAIL: $*" >&2
  fail=1
}

wf=.github/workflows/fork-container.yml

while IFS= read -r line; do
  if ! grep -qE 'uses:[[:space:]]+[^@[:space:]]+@[0-9a-f]{40}[[:space:]]+#[[:space:]]*[^[:space:]]+' <<<"$line"; then
    err "$wf: action not pinned by full SHA with a tag comment: ${line#"${line%%[![:space:]]*}"}"
  fi
done < <(grep -E '^[[:space:]]*(-[[:space:]]+)?uses:' "$wf")

grep -qE '^permissions:[[:space:]]*\{\}[[:space:]]*$' "$wf" || err "$wf: missing top-level 'permissions: {}'"

# Each job (a two-space-indented key under `jobs:`) must carry its own permissions.
while IFS= read -r job; do
  err "$wf: job '$job' has no permissions block"
done < <(awk '
  /^jobs:/ { injobs = 1; next }
  injobs && /^[^[:space:]#]/ { injobs = 0 }
  injobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { if (job != "" && !perm) print job; job = $1; sub(/:$/, "", job); perm = 0; next }
  injobs && /^    permissions:/ { perm = 1 }
  END { if (job != "" && !perm) print job }
' "$wf")

exit "$fail"
