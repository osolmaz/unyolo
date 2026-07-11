#!/bin/sh
set -eu

VERSION="${1:-}"
[ -n "$VERSION" ] || {
  echo "usage: scripts/release.sh <version>" >&2
  exit 64
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

exec go run github.com/osolmaz/brokerkit/cmd/brokerkit-release \
  --broker hf-broker \
  --command ./cmd/hf-broker \
  --version "$VERSION" \
  --directory "$ROOT_DIR" \
  --dist "${DIST_DIR:-${ROOT_DIR}/dist}"
