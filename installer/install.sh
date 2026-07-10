#!/bin/sh
set -eu

BROKER="${BROKER:-}"
REPO="${REPO:-}"
INSTALL_DIR="${INSTALL_DIR:-}"
VERSION="${VERSION:-}"

fail() {
  label="${BROKER:-broker}"
  echo "${label} install: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

validate_inputs() {
  case "$BROKER" in
    "" | *[!a-z0-9-]*) fail "BROKER must contain only lowercase letters, digits, and hyphens" ;;
  esac
  case "$REPO" in
    */*) ;;
    *) fail "REPO must use owner/name form" ;;
  esac
  owner="${REPO%%/*}"
  name="${REPO#*/}"
  case "${owner}:${name}" in
    :* | *: | *:*/*) fail "REPO must use owner/name form" ;;
  esac
  case "$REPO" in
    *[!A-Za-z0-9._/-]*) fail "REPO contains unsupported characters" ;;
  esac
}

system_name() {
  if [ -n "${BROKERKIT_UNAME_S:-}" ]; then
    echo "$BROKERKIT_UNAME_S"
    return
  fi
  uname -s
}

machine_name() {
  if [ -n "${BROKERKIT_UNAME_M:-}" ]; then
    echo "$BROKERKIT_UNAME_M"
    return
  fi
  uname -m
}

normalize_os() {
  name="$(system_name)"
  case "$name" in
    Linux) echo "linux" ;;
    Darwin) echo "darwin" ;;
    *) fail "unsupported OS: ${name}" ;;
  esac
}

normalize_arch() {
  name="$(machine_name)"
  case "$name" in
    x86_64 | amd64) echo "amd64" ;;
    arm64 | aarch64) echo "arm64" ;;
    *) fail "unsupported architecture: ${name}" ;;
  esac
}

latest_version() {
  url="${BROKERKIT_LATEST_RELEASE_URL:-https://api.github.com/repos/${REPO}/releases/latest}"
  curl -fsSL "$url" |
    sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' |
    head -n 1
}

choose_install_dir() {
  if [ -n "$INSTALL_DIR" ]; then
    echo "$INSTALL_DIR"
    return
  fi
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    echo /usr/local/bin
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    echo /usr/local/bin
    return
  fi
  echo "$HOME/.local/bin"
}

checksum_line() {
  asset="$1"
  checksums="$2"
  awk -v asset="$asset" '$2 == asset { print; found = 1 } END { if (!found) exit 1 }' "$checksums" ||
    fail "checksums.txt does not contain ${asset}"
}

verify_checksum() {
  asset="$1"
  checksums="$2"
  directory="$(dirname "$checksums")"
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$directory" && checksum_line "$asset" "$(basename "$checksums")" | sha256sum -c -)
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    (cd "$directory" && checksum_line "$asset" "$(basename "$checksums")" | shasum -a 256 -c -)
    return
  fi
  fail "missing checksum command: sha256sum or shasum"
}

install_binary() {
  source_path="$1"
  dest_dir="$2"
  mkdir -p "$dest_dir" 2>/dev/null || true
  if [ -w "$dest_dir" ]; then
    install -m 0755 "$source_path" "$dest_dir/${BROKER}"
    return
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo install -d -m 0755 "$dest_dir"
    sudo install -m 0755 "$source_path" "$dest_dir/${BROKER}"
    return
  fi
  fail "cannot write to ${dest_dir}; rerun with INSTALL_DIR set to a writable directory"
}

validate_inputs
need curl
need tar
need install
need awk
need sed
need head
need mktemp
need dirname
need basename

os="$(normalize_os)"
arch="$(normalize_arch)"
if [ -z "$VERSION" ]; then
  VERSION="$(latest_version)"
fi
[ -n "$VERSION" ] || fail "could not resolve latest release version; set VERSION=vX.Y.Z"

asset="${BROKER}_${os}_${arch}.tar.gz"
base_url="${BROKERKIT_RELEASE_BASE_URL:-https://github.com/${REPO}/releases/download/${VERSION}}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

echo "Downloading ${REPO} ${VERSION} for ${os}/${arch}"
curl -fsSL "${base_url}/${asset}" -o "${tmp_dir}/${asset}"
curl -fsSL "${base_url}/checksums.txt" -o "${tmp_dir}/checksums.txt"
verify_checksum "$asset" "${tmp_dir}/checksums.txt"

tar -xzf "${tmp_dir}/${asset}" -C "$tmp_dir"
dest_dir="$(choose_install_dir)"
install_binary "${tmp_dir}/${BROKER}" "$dest_dir"

echo "Installed ${BROKER} to ${dest_dir}/${BROKER}"
if command -v "$BROKER" >/dev/null 2>&1; then
  "$BROKER" --version
elif [ -x "${dest_dir}/${BROKER}" ]; then
  "${dest_dir}/${BROKER}" --version
  echo "Add ${dest_dir} to PATH to run ${BROKER} directly."
fi
