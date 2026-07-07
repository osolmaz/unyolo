#!/bin/sh
set -eu

VERSION="${1:-}"
[ -n "$VERSION" ] || {
  echo "usage: scripts/release.sh <version>" >&2
  exit 64
}

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
DIST_DIR="${DIST_DIR:-${ROOT_DIR}/dist}"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"

build_one() {
  os="$1"
  arch="$2"
  work_dir="${DIST_DIR}/hf-broker_${os}_${arch}"
  mkdir -p "$work_dir"
  echo "Building ${os}/${arch}"
  (
    cd "$ROOT_DIR"
    GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o "${work_dir}/hf-broker" \
      ./cmd/hf-broker
  )
  cp "${ROOT_DIR}/README.md" "${work_dir}/README.md"
  cp "${ROOT_DIR}/LICENSE" "${work_dir}/LICENSE"
  (
    cd "$work_dir"
    tar -czf "${DIST_DIR}/hf-broker_${os}_${arch}.tar.gz" hf-broker README.md LICENSE
  )
}

build_one linux amd64
build_one linux arm64
build_one darwin amd64
build_one darwin arm64

(
  cd "$DIST_DIR"
  rm -f checksums.txt
  for asset in hf-broker_*.tar.gz; do
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum "$asset" >> checksums.txt
    else
      shasum -a 256 "$asset" >> checksums.txt
    fi
  done
)

echo "Release assets written to ${DIST_DIR}"
