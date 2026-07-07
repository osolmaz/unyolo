#!/usr/bin/env sh
set -eu

go test -coverprofile=coverage.out ./...
total="$(go tool cover -func=coverage.out | awk '/^total:/ {print substr($3, 1, length($3)-1)}')"
awk -v total="$total" -v minimum="85" 'BEGIN { exit (total + 0 < minimum + 0) }'
printf 'coverage %s%% meets required 85%%\n' "$total"
