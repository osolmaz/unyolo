#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

exec go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 generate
