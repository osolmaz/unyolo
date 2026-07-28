#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'bootstrap-root: root is required' >&2; exit 1; }
if [ -z "${SUDO_UID:-}" ] || [ "$SUDO_UID" -eq 0 ]; then
  printf '%s\n' 'bootstrap-root: a distinct invoking user is required' >&2
  exit 1
fi
[ "$#" -eq 1 ] || { printf '%s\n' 'usage: bootstrap-root.sh unyolo/vX.Y.Z' >&2; exit 64; }
release=$1
command -v grep >/dev/null 2>&1 || exit 1
printf '%s\n' "$release" | grep -Eq '^unyolo/v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$' || exit 64

command -v curl >/dev/null 2>&1 || exit 1
command -v gh >/dev/null 2>&1 || exit 1
case "$(uname -s)" in Linux) os=linux ;; Darwin) printf '%s\n' 'bootstrap-root: guided host provisioning currently requires Linux' >&2; exit 1 ;; *) exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) exit 1 ;; esac
asset="unyolo_${os}_${arch}.tar.gz"
base="https://github.com/osolmaz/unyolo/releases/download/${release}"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/unyolo-root-bootstrap.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
key_asset=unyolo-runtime-release.pub
curl -fL --proto '=https' --tlsv1.2 "$base/$asset" -o "$temporary/$asset"
curl -fL --proto '=https' --tlsv1.2 "$base/$key_asset" -o "$temporary/$key_asset"
curl -fL --proto '=https' --tlsv1.2 "$base/checksums.txt" -o "$temporary/checksums.txt"
verify_checksum() {
  expected=$(awk -v name="$1" '$2 == name { print $1 }' "$temporary/checksums.txt")
  [ -n "$expected" ] || exit 1
  actual=$(sha256sum "$temporary/$1" 2>/dev/null | awk '{print $1}') || actual=$(shasum -a 256 "$temporary/$1" | awk '{print $1}')
  [ "$actual" = "$expected" ] || { printf '%s\n' 'bootstrap-root: release checksum mismatch' >&2; exit 1; }
}
verify_attestation() {
  gh attestation verify "$temporary/$1" \
    --repo osolmaz/unyolo \
    --signer-workflow osolmaz/unyolo/.github/workflows/release.yml \
    --source-ref "refs/tags/$release" \
    --deny-self-hosted-runners >/dev/null
}
verify_checksum "$asset"
verify_checksum "$key_asset"
verify_attestation "$asset"
verify_attestation "$key_asset"
case "$os" in
  linux) state=/var/lib/unyolo-host ;;
  darwin) state='/Library/Application Support/unyolo' ;;
esac
install -d -o root -g root -m 0700 "$state"
pinned_key="$state/trusted-release.pub"
if [ -e "$pinned_key" ]; then
  cmp -s "$temporary/$key_asset" "$pinned_key" || { printf '%s\n' 'bootstrap-root: release trust root mismatch' >&2; exit 1; }
else
  install -o root -g root -m 0600 "$temporary/$key_asset" "$pinned_key"
fi
tar -xzf "$temporary/$asset" -C "$temporary" unyolo
build=${release#unyolo/}
destination="/opt/unyolo/bootstrap/$build"
install -d -o root -g root -m 0755 "$destination"
install -o root -g root -m 0755 "$temporary/unyolo" "$destination/unyolo.new"
mv -f "$destination/unyolo.new" "$destination/unyolo"
unset GH_TOKEN
exec "$destination/unyolo" system setup-worker --protocol-stdio
