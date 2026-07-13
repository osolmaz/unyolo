#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
broker="$root/brokers/huggingface"
baseline="$broker/slophammer-crap-baseline.tsv"

verify_report() {
	local status="$1"
	local report="$2"
	local allowed="$3"
	local source_root="$4"

	if [[ "$status" -ne 1 ]]; then
		printf 'HF CRAP command exited with status %s; expected 1 while exceptions remain.\n' "$status" >&2
		return 1
	fi
	if grep -Eqi 'coverage test failed|CRAP analysis failed|failed with exit status' "$report"; then
		printf 'HF CRAP report contains a tool or coverage failure.\n' >&2
		return 1
	fi
	if ! grep -q '^CRAP score .* exceeds maximum .* for ' "$report"; then
		printf 'HF CRAP command failed without parseable findings.\n' >&2
		return 1
	fi
	while IFS=$'\t' read -r path symbol metric maximum; do
		[[ -z "$path" || "$path" == \#* ]] && continue
		if [[ ! -f "$source_root/$path" ]]; then
			printf 'HF CRAP baseline source is missing: %s\n' "$path" >&2
			return 1
		fi
		if [[ "$metric" != "crap" ]]; then
			printf 'HF CRAP baseline metric is invalid for %s: %s\n' "$symbol" "$metric" >&2
			return 1
		fi
		local name="${symbol##*.}"
		if ! grep -Eq "func .*${name}\\(" "$source_root/$path"; then
			printf 'HF CRAP baseline function %s is not in %s.\n' "$symbol" "$path" >&2
			return 1
		fi
	done < "$allowed"
	awk -F '\t' '
		FNR == NR {
			if ($0 !~ /^#/ && NF == 4 && $3 == "crap") {
				limit[$2] = $4 + 0
				remaining[$2] = 1
			}
			next
		}
		/^CRAP score [0-9.]+ exceeds maximum [0-9.]+ for / {
			count = split($0, fields, " ")
			score = fields[3] + 0
			symbol = fields[count]
			if (!(symbol in limit)) {
				printf "unapproved HF CRAP finding: %s (%s)\n", symbol, score > "/dev/stderr"
				failed = 1
				next
			}
			if (score > limit[symbol]) {
				printf "HF CRAP score regressed: %s is %s, allowed %s\n", symbol, score, limit[symbol] > "/dev/stderr"
				failed = 1
			}
			delete remaining[symbol]
		}
		END {
			for (symbol in remaining) {
				printf "stale HF CRAP baseline entry: %s\n", symbol > "/dev/stderr"
				failed = 1
			}
			exit failed
		}
	' "$allowed" "$report"
}

if [[ "${1:-}" == "--verify-report" ]]; then
	verify_report "$2" "$3" "$4" "$5"
	exit
fi

report="$(mktemp)"
trap 'rm -f "$report"' EXIT
set +e
(cd "$broker" && "${SLOPHAMMER_GO:-slophammer-go}" crap .) >"$report" 2>&1
status=$?
set -e
if [[ "$status" -eq 0 ]]; then
	if grep -qvE '^(#|[[:space:]]*$)' "$baseline"; then
		printf 'HF CRAP baseline is stale because the unexcepted gate now passes.\n' >&2
		exit 1
	fi
	printf 'HF CRAP scores meet the configured maximum.\n'
	exit
fi
verify_report "$status" "$report" "$baseline" "$broker"
grep '^CRAP score .* exceeds maximum .* for ' "$report"
