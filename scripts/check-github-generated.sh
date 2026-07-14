#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

go run ./brokers/github/cmd/generate-github-surfaces -check
