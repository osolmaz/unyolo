#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
baseline="$root/brokers/github/slophammer-crap-baseline.tsv"
report="$(mktemp)"
trap 'rm -f "$report"' EXIT

set +e
(cd "$root" && "${SLOPHAMMER_GO:-slophammer-go}" crap .) >"$report" 2>&1
status=$?
set -e

if [[ "$status" -ne 1 ]]; then
	printf 'GitHub CRAP command exited with status %s; expected 1 while exceptions remain.\n' "$status" >&2
	exit 1
fi
if grep -Eqi 'coverage test failed|CRAP analysis failed|failed with exit status|does not include coverage' "$report"; then
	printf 'GitHub CRAP report contains a tool or coverage failure.\n' >&2
	exit 1
fi
if ! grep -q '^CRAP score .* exceeds maximum .* for ' "$report"; then
	printf 'GitHub CRAP command failed without parseable findings.\n' >&2
	exit 1
fi

while IFS=$'\t' read -r path qualified metric maximum; do
	[[ -z "$path" || "$path" == \#* ]] && continue
	if [[ ! -f "$root/$path" ]]; then
		printf 'GitHub CRAP baseline source is missing: %s\n' "$path" >&2
		exit 1
	fi
	package="${qualified%%:*}"
	symbol="${qualified#*:}"
	name="${symbol##*.}"
	if [[ "$metric" != "crap" ]] || ! grep -Eq "^package[[:space:]]+${package}$" "$root/$path"; then
		printf 'GitHub CRAP baseline ownership is invalid: %s in %s\n' "$qualified" "$path" >&2
		exit 1
	fi
	if ! grep -Eq "^func .*${name}\\(" "$root/$path"; then
		printf 'GitHub CRAP baseline function is missing: %s in %s\n' "$qualified" "$path" >&2
		exit 1
	fi
done <"$baseline"

awk -F '\t' '
	FNR == NR {
		if ($0 !~ /^#/ && NF == 4 && $3 == "crap") {
			if ($2 in limit) { printf "duplicate GitHub CRAP baseline entry: %s\n", $2 > "/dev/stderr"; failed = 1 }
			limit[$2] = $4 + 0
			remaining[$2] = 1
	}
	next
	}
	{
		count = split($0, fields, /[[:space:]]+/)
		if (count != 8 || fields[1] != "CRAP" || fields[2] != "score") next
		dot = index(fields[8], ".")
		if (dot == 0) next
		qualified = substr(fields[8], 1, dot - 1) ":" substr(fields[8], dot + 1)
		score = fields[3] + 0
		if (!(qualified in limit)) {
			printf "unapproved GitHub CRAP finding: %s (%s)\n", qualified, score > "/dev/stderr"
			failed = 1
			next
		}
		if (score > limit[qualified]) {
			printf "GitHub CRAP score regressed: %s is %s, allowed %s\n", qualified, score, limit[qualified] > "/dev/stderr"
			failed = 1
		}
		delete remaining[qualified]
	}
	END {
		for (qualified in remaining) {
			printf "stale GitHub CRAP baseline entry: %s\n", qualified > "/dev/stderr"
			failed = 1
		}
		exit failed
	}
' "$baseline" "$report"

printf 'GitHub CRAP findings match the exact non-regression baseline.\n'
