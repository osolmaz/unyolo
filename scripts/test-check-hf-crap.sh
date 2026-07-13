#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$root/scripts/check-hf-crap.sh"
directory="$(mktemp -d)"
trap 'rm -rf "$directory"' EXIT
mkdir -p "$directory/source"
printf 'package source\nfunc accepted() {}\n' > "$directory/source/accepted.go"
printf 'source/accepted.go\taccepted\tcrap\t9.0\n' > "$directory/baseline.tsv"
printf 'CRAP score 8.5 exceeds maximum 8.0 for accepted\n' > "$directory/report.txt"
"$checker" --verify-report 1 "$directory/report.txt" "$directory/baseline.tsv" "$directory"

printf 'CRAP score 8.5 exceeds maximum 8.0 for unknown\n' > "$directory/report.txt"
if "$checker" --verify-report 1 "$directory/report.txt" "$directory/baseline.tsv" "$directory" 2>/dev/null; then
	printf 'unknown finding was accepted\n' >&2
	exit 1
fi
printf 'coverage test failed with exit status 1\n' > "$directory/report.txt"
if "$checker" --verify-report 1 "$directory/report.txt" "$directory/baseline.tsv" "$directory" 2>/dev/null; then
	printf 'coverage failure was accepted\n' >&2
	exit 1
fi
if "$checker" --verify-report 2 "$directory/report.txt" "$directory/baseline.tsv" "$directory" 2>/dev/null; then
	printf 'tool failure was accepted\n' >&2
	exit 1
fi
printf 'CRAP score 9.1 exceeds maximum 8.0 for accepted\n' > "$directory/report.txt"
if "$checker" --verify-report 1 "$directory/report.txt" "$directory/baseline.tsv" "$directory" 2>/dev/null; then
	printf 'score regression was accepted\n' >&2
	exit 1
fi
printf 'CRAP score 8.5 exceeds maximum 8.0 for unknown\n' > "$directory/report.txt"
if "$checker" --verify-report 1 "$directory/report.txt" "$directory/baseline.tsv" "$directory" 2>/dev/null; then
	printf 'stale baseline was accepted\n' >&2
	exit 1
fi
