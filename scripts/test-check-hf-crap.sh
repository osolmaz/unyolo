#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
checker="$root/scripts/check-hf-crap.sh"
directory="$(mktemp -d)"
trap 'rm -rf "$directory"' EXIT
mkdir -p "$directory/source"
printf 'package source\nfunc accepted() {}\n' > "$directory/source/accepted.go"
printf 'source/accepted.go\tsource:accepted\tcrap\t9.0\n' > "$directory/baseline.tsv"
printf 'accepted source 8 80.0%% 8.5\nCRAP score 8.5 exceeds maximum 8.0 for accepted\n' > "$directory/report.txt"
"$checker" --verify-report 1 "$directory/report.txt" "$directory/baseline.tsv" "$directory"

printf 'unknown source 8 80.0%% 8.5\nCRAP score 8.5 exceeds maximum 8.0 for unknown\n' > "$directory/report.txt"
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
printf 'accepted source 8 70.0%% 9.1\nCRAP score 9.1 exceeds maximum 8.0 for accepted\n' > "$directory/report.txt"
if "$checker" --verify-report 1 "$directory/report.txt" "$directory/baseline.tsv" "$directory" 2>/dev/null; then
	printf 'score regression was accepted\n' >&2
	exit 1
fi
printf 'unknown source 8 80.0%% 8.5\nCRAP score 8.5 exceeds maximum 8.0 for unknown\n' > "$directory/report.txt"
if "$checker" --verify-report 1 "$directory/report.txt" "$directory/baseline.tsv" "$directory" 2>/dev/null; then
	printf 'stale baseline was accepted\n' >&2
	exit 1
fi

printf 'source/accepted.go\tsource:accepted\tcrap\t9.0\nsource/accepted.go\tsource:accepted\tcrap\t9.0\n' > "$directory/baseline.tsv"
printf 'accepted source 8 80.0%% 8.5\nCRAP score 8.5 exceeds maximum 8.0 for accepted\n' > "$directory/report.txt"
if "$checker" --verify-report 1 "$directory/report.txt" "$directory/baseline.tsv" "$directory" 2>/dev/null; then
	printf 'duplicate baseline entry was accepted\n' >&2
	exit 1
fi
