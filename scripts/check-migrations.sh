#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
directory="$root/state/migrations"
actual=$(mktemp)
trap 'rm -f "$actual"' EXIT

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

for migration in "$directory"/*.sql; do
  printf '%s  %s\n' "$(hash_file "$migration")" "$(basename "$migration")" >>"$actual"
done

if ! cmp -s "$directory/checksums.txt" "$actual"; then
  echo 'state migration checksums do not match; applied migrations are immutable' >&2
  diff -u "$directory/checksums.txt" "$actual" || true
  exit 1
fi
