#!/usr/bin/env bash
# Prints the test filters for the tests listed in scripts/network-tests.txt.
#   scripts/network-tests.sh skip   -> --skip <test> ... (for the offline run)
#   scripts/network-tests.sh only   -> <test> ...        (for the live run)
#   scripts/network-tests.sh check  -> fails if a listed test no longer exists,
#                                      so a rename can't silently un-skip it
set -euo pipefail
cd "$(dirname "$0")/.."
mapfile -t tests < <(grep -v '^\s*#' scripts/network-tests.txt | grep -v '^\s*$')
case "${1:-}" in
skip) for t in "${tests[@]}"; do printf -- '--skip %s ' "$t"; done ;;
only) printf '%s ' "${tests[@]}" ;;
check)
	missing=0
	for t in "${tests[@]}"; do
		name=${t%::}; name=${name##*::}
		if [[ $t == *:: ]]; then
			grep -rqE "mod ${name}\b" src || { echo "missing module: $t"; missing=1; }
		else
			grep -rqE "fn ${name}\b" src || { echo "missing test: $t"; missing=1; }
		fi
	done
	exit $missing ;;
*) echo "usage: $0 skip|only|check" >&2; exit 2 ;;
esac
