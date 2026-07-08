#!/usr/bin/env bash

set -euo pipefail

minimum_total_coverage="85.0"
coverfile="$(mktemp)"

cleanup() {
  rm -f "$coverfile"
}
trap cleanup EXIT

coverage_total() {
  go tool cover -func="$1" |
    awk '/^total:/ {print substr($3, 1, length($3)-1)}'
}

go test ./... -coverprofile="$coverfile"

total="$(coverage_total "$coverfile")"
printf 'Total coverage: %s%%\n' "$total"
awk -v total="$total" -v minimum="$minimum_total_coverage" \
  'BEGIN { exit !(total + 0 >= minimum + 0) }'
