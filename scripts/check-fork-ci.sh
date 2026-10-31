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
#
# Rules for Dockerfile.distroless:
#   - every external base image is pinned by `@sha256:` digest next to its tag
#     (stage references and build-arg templated images are exempt)
#
# And .github/dependabot.yml must have a `docker` entry, so the digests above
# get bumped instead of rotting.
#
# Finding #21 also wants an advisory gate: deny.toml must exist and the test
# job must run cargo-deny.

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

df=Dockerfile.distroless

while IFS= read -r line; do
  err "$df: base image not pinned by @sha256 digest: $line"
done < <(awk '
  toupper($1) == "FROM" {
    img = ""
    for (i = 2; i <= NF; i++) if ($i !~ /^--/) { img = $i; break }
    exempt = (img == "scratch" || img in stage || img ~ /\$\{/)
    if (!exempt && img !~ /@sha256:[0-9a-f]{64}$/) print $0
    for (i = 2; i < NF; i++) if (toupper($i) == "AS") stage[$(i + 1)] = 1
  }
' "$df")

grep -qE '^[[:space:]]*-[[:space:]]+package-ecosystem:[[:space:]]*"?docker"?[[:space:]]*$' .github/dependabot.yml || err ".github/dependabot.yml: no docker ecosystem entry"

[ -f deny.toml ] || err "deny.toml: missing (cargo-deny config with the accepted advisories)"
grep -qE 'cargo-deny-action@[0-9a-f]{40}' "$wf" || err "$wf: test job does not run cargo-deny"

exit "$fail"
