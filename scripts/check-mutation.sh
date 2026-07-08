#!/usr/bin/env bash

set -euo pipefail

tmp="$(mktemp)"
cp doc.go "$tmp"
cleanup() {
	cp "$tmp" doc.go
	rm -f "$tmp"
	rm -rf target
}
trap cleanup EXIT

slophammer-go mutate . --target doc.go
