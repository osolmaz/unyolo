#!/bin/sh
set -eu

usage() {
  printf '%s\n' 'usage: bootstrap.sh --release brokerkit/vX.Y.Z [setup arguments...]' >&2
  exit 64
}

release=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --release)
      [ "$#" -ge 2 ] || usage
      release=$2
      shift 2
      ;;
    --)
      shift
      break
      ;;
    setup|--*)
      break
      ;;
    *) usage ;;
  esac
done
[ -n "$release" ] || usage
command -v grep >/dev/null 2>&1 || { printf '%s\n' 'bootstrap: grep is required' >&2; exit 1; }
printf '%s\n' "$release" | grep -Eq '^brokerkit/v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$' || usage

command -v curl >/dev/null 2>&1 || { printf '%s\n' 'bootstrap: curl is required' >&2; exit 1; }
command -v gh >/dev/null 2>&1 || { printf '%s\n' 'bootstrap: GitHub CLI is required for attestation verification' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { printf '%s\n' 'bootstrap: tar is required' >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) printf '%s\n' 'bootstrap: unsupported operating system' >&2; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) printf '%s\n' 'bootstrap: unsupported architecture' >&2; exit 1 ;;
esac

asset="brokerkit_${os}_${arch}.tar.gz"
base="https://github.com/osolmaz/brokerkit/releases/download/${release}"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/brokerkit-bootstrap.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM

curl -fL --proto '=https' --tlsv1.2 "$base/$asset" -o "$temporary/$asset"
curl -fL --proto '=https' --tlsv1.2 "$base/checksums.txt" -o "$temporary/checksums.txt"
(
  cd "$temporary"
  expected=$(awk -v name="$asset" '$2 == name { print $1 }' checksums.txt)
  [ -n "$expected" ] || { printf '%s\n' 'bootstrap: release checksum is missing' >&2; exit 1; }
  actual=$(sha256sum "$asset" 2>/dev/null | awk '{print $1}') || actual=$(shasum -a 256 "$asset" | awk '{print $1}')
  [ "$actual" = "$expected" ] || { printf '%s\n' 'bootstrap: release checksum mismatch' >&2; exit 1; }
)
gh attestation verify "$temporary/$asset" \
  --repo osolmaz/brokerkit \
  --signer-workflow osolmaz/brokerkit/.github/workflows/release.yml \
  --source-ref "refs/tags/$release" \
  --deny-self-hosted-runners >/dev/null

tar -xzf "$temporary/$asset" -C "$temporary" brokerkit
[ -f "$temporary/brokerkit" ] && [ ! -L "$temporary/brokerkit" ] || { printf '%s\n' 'bootstrap: release archive is invalid' >&2; exit 1; }
install_dir=${XDG_BIN_HOME:-"$HOME/.local/bin"}
umask 077
mkdir -p "$install_dir"
install -m 0755 "$temporary/brokerkit" "$install_dir/brokerkit.new"
mv -f "$install_dir/brokerkit.new" "$install_dir/brokerkit"

[ -r /dev/tty ] && [ -w /dev/tty ] || { printf '%s\n' 'bootstrap: an interactive terminal is required' >&2; exit 1; }
if [ "$#" -eq 0 ]; then
  set -- setup
elif [ "$1" != setup ]; then
  set -- setup "$@"
fi
exec "$install_dir/brokerkit" "$@" </dev/tty >/dev/tty
