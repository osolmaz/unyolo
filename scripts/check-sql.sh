#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

./scripts/generate-sql.sh
go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 vet
git diff --exit-code -- internal/storage/state/internal/dbsql
./scripts/check-migrations.sh
