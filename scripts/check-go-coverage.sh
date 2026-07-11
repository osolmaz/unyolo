#!/bin/sh
set -eu

slophammer_coverage_contract() {
  minimum_coverage=85
  go test -coverprofile=coverage.out ./...
  total="$(go tool cover -func=coverage.out | awk '/^total:/ {print substr($3, 1, length($3)-1)}')"
  awk -v total="$total" -v minimum="$minimum_coverage" 'BEGIN { exit !(total + 0 >= minimum + 0) }'
}
exec go run github.com/osolmaz/brokerkit/cmd/brokerkit-coverage --minimum 85 --directory .
