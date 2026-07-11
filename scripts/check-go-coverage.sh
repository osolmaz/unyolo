#!/usr/bin/env bash

set -euo pipefail

minimum_total_coverage="85.0"
coverfile="$(mktemp)"
mapfile -t test_packages < <(go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... | sed '/^$/d')

cleanup() {
  rm -f "$coverfile"
}
trap cleanup EXIT

coverage_total() {
  go tool cover -func="$1" |
    awk '/^total:/ {print substr($3, 1, length($3)-1)}'
}

if ((${#test_packages[@]} == 0)); then
  printf 'No Go packages with tests found.\n' >&2
  exit 1
fi

go test "${test_packages[@]}" -coverprofile="$coverfile"

total="$(coverage_total "$coverfile")"
printf 'Total coverage: %s%%\n' "$total"
awk -v total="$total" -v minimum="$minimum_total_coverage" \
  'BEGIN { exit !(total + 0 >= minimum + 0) }'
