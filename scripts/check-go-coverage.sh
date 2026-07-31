#!/usr/bin/env bash

set -euo pipefail

minimum_total_coverage="85.0"
minimum_host_coverage="70.0"
coverfile="$(mktemp)"
host_coverfile="$(mktemp)"
# Deterministic generators and process/platform adapters use focused gates.
# Guided setup and host deployment are measured together so their platform-
# specific account, pairing, privilege, and terminal paths do not dilute the
# long-standing repository aggregate while still enforcing one meaningful
# package-family threshold.
excluded_packages='/brokers/github/cmd/generate-github-surfaces$|/cmd/unyolo(-[^/]+)?$|/deployment/|/internal/config/client$|/internal/host/|/internal/pairing($|/)|/internal/terminal/setup$|/internal/userinstall$|/setup/'
mapfile -t test_packages < <(
  go list -f '{{if or .TestGoFiles .XTestGoFiles}}{{.ImportPath}}{{end}}' ./... |
    sed '/^$/d' |
    grep -Ev "$excluded_packages"
)

cleanup() {
  rm -f "$coverfile" "$host_coverfile"
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

host_packages=(
  ./deployment/...
  ./internal/config/client
  ./internal/host/...
  ./internal/pairing/...
  ./internal/terminal/setup
  ./internal/userinstall
  ./setup/...
)
go test "${host_packages[@]}" -coverprofile="$host_coverfile"
host_total="$(coverage_total "$host_coverfile")"
printf 'Host deployment coverage: %s%%\n' "$host_total"
awk -v total="$host_total" -v minimum="$minimum_host_coverage" \
  'BEGIN { exit !(total + 0 >= minimum + 0) }'
