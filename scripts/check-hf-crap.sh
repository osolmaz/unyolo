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
	while IFS=$'\t' read -r path qualified metric maximum; do
		[[ -z "$path" || "$path" == \#* ]] && continue
		if [[ ! -f "$source_root/$path" ]]; then
			printf 'HF CRAP baseline source is missing: %s\n' "$path" >&2
			return 1
		fi
		if [[ "$metric" != "crap" ]]; then
			printf 'HF CRAP baseline metric is invalid for %s: %s\n' "$qualified" "$metric" >&2
			return 1
		fi
		local package="${qualified%%:*}"
		local symbol="${qualified#*:}"
		if [[ "$package" == "$qualified" ]] || ! grep -Eq "^package[[:space:]]+${package}$" "$source_root/$path"; then
			printf 'HF CRAP baseline package %s does not own %s.\n' "$package" "$path" >&2
			return 1
		fi
		local name="${symbol##*.}"
		local pattern="func[[:space:]]+${name}\\("
		if [[ "$symbol" == *.* ]]; then
			local receiver="${symbol%%.*}"
			pattern="func[[:space:]]+\\([^)]*${receiver}\\)[[:space:]]+${name}\\("
		fi
		if ! grep -Eq "$pattern" "$source_root/$path"; then
			printf 'HF CRAP baseline function %s is not in %s.\n' "$qualified" "$path" >&2
			return 1
		fi
	done < "$allowed"
	awk -F '\t' '
		FNR == NR {
			if ($0 !~ /^#/ && NF == 4 && $3 == "crap") {
				if ($2 in limit) {
					printf "duplicate HF CRAP baseline entry: %s\n", $2 > "/dev/stderr"
					failed = 1
				}
				limit[$2] = $4 + 0
				remaining[$2] = 1
			}
			next
		}
		{
			count = split($0, fields, /[[:space:]]+/)
			if (count != 5 || fields[3] !~ /^[0-9]+$/ || fields[5] + 0 <= 8) {
				next
			}
			qualified = fields[2] ":" fields[1]
			score = fields[5] + 0
			if (!(qualified in limit)) {
				printf "unapproved HF CRAP finding: %s (%s)\n", qualified, score > "/dev/stderr"
				failed = 1
				next
			}
			if (score > limit[qualified]) {
				printf "HF CRAP score regressed: %s is %s, allowed %s\n", qualified, score, limit[qualified] > "/dev/stderr"
				failed = 1
			}
			delete remaining[qualified]
		}
		END {
			for (qualified in remaining) {
				printf "stale HF CRAP baseline entry: %s\n", qualified > "/dev/stderr"
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
