#!/bin/sh
set -eu

BROKER="gh-broker"
REPO="${REPO:-osolmaz/gh-broker}"
INSTALL_DIR="${INSTALL_DIR:-}"
VERSION="${VERSION:-}"

fail() {
  echo "${BROKER} install: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

normalize_os() {
  case "$(uname -s)" in
    Linux) echo "linux" ;;
    Darwin) echo "darwin" ;;
    *) fail "unsupported OS: $(uname -s)" ;;
  esac
}

normalize_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo "amd64" ;;
    arm64 | aarch64) echo "arm64" ;;
    *) fail "unsupported architecture: $(uname -m)" ;;
  esac
}

latest_version() {
  need curl
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
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

verify_checksum() {
  asset="$1"
  checksums="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    grep "  ${asset}$" "$checksums" | sha256sum -c -
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    grep "  ${asset}$" "$checksums" | shasum -a 256 -c -
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

need curl
need tar
need install

os="$(normalize_os)"
arch="$(normalize_arch)"
if [ -z "$VERSION" ]; then
  VERSION="$(latest_version)"
fi
[ -n "$VERSION" ] || fail "could not resolve latest release version; set VERSION=vX.Y.Z"

asset="${BROKER}_${os}_${arch}.tar.gz"
base_url="https://github.com/${REPO}/releases/download/${VERSION}"
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
