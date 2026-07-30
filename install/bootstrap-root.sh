#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'bootstrap-root: root is required' >&2; exit 1; }
if [ -z "${SUDO_UID:-}" ] || [ "$SUDO_UID" -eq 0 ]; then
  printf '%s\n' 'bootstrap-root: a distinct invoking user is required' >&2
  exit 1
fi
[ "$#" -eq 1 ] || { printf '%s\n' 'usage: bootstrap-root.sh unyolo/vX.Y.Z' >&2; exit 64; }
release=$1
for tool in awk chown chmod cp curl find grep install mv tar tr wc; do
  command -v "$tool" >/dev/null 2>&1 || exit 1
done
printf '%s\n' "$release" | grep -Eq '^unyolo/v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$' || exit 64

command -v gh >/dev/null 2>&1 || exit 1
case "$(uname -s)" in Linux) os=linux ;; Darwin) printf '%s\n' 'bootstrap-root: guided host provisioning currently requires Linux' >&2; exit 1 ;; *) exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) exit 1 ;; esac
asset="unyolo_${os}_${arch}.tar.gz"
base="https://github.com/osolmaz/unyolo/releases/download/${release}"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/unyolo-root-bootstrap.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
curl -fL --proto '=https' --tlsv1.2 "$base/$asset" -o "$temporary/$asset"
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
archive_digest=$expected
verify_attestation "$asset"
tar -tzf "$temporary/$asset" > "$temporary/archive.list"
tar -tvzf "$temporary/$asset" > "$temporary/archive.types"
awk 'substr($1, 1, 1) != "-" { exit 1 }' "$temporary/archive.types" || { printf '%s\n' 'bootstrap-root: release archive contains a non-regular entry' >&2; exit 1; }
[ "$(wc -l < "$temporary/archive.list" | tr -d ' ')" -eq "$(wc -l < "$temporary/archive.types" | tr -d ' ')" ] || { printf '%s\n' 'bootstrap-root: release archive listing is inconsistent' >&2; exit 1; }
[ "$(wc -l < "$temporary/archive.list" | tr -d ' ')" -le 2048 ] || { printf '%s\n' 'bootstrap-root: release archive contains too many entries' >&2; exit 1; }
awk 'seen[$0]++ { exit 1 }' "$temporary/archive.list" || { printf '%s\n' 'bootstrap-root: release archive contains a duplicate path' >&2; exit 1; }
while IFS= read -r entry; do
  printf '%s\n' "$entry" | grep -Eq '^[A-Za-z0-9._+-]+(/[A-Za-z0-9._+-]+)*$' || { printf '%s\n' 'bootstrap-root: release archive path is unsafe' >&2; exit 1; }
done < "$temporary/archive.list"
mkdir "$temporary/extracted"
tar -xzf "$temporary/$asset" -C "$temporary/extracted"
case "$os" in
  linux) state=/var/lib/unyolo-host ;;
  darwin) state='/Library/Application Support/unyolo' ;;
esac
install -d -o root -g root -m 0700 "$state"
verified_releases="$state/verified-releases"
install -d -o root -g root -m 0700 "$verified_releases"
verified_release="$verified_releases/$archive_digest"
if [ ! -e "$verified_release" ]; then
  verified_new="$verified_release.new.$$"
  install -d -o root -g root -m 0700 "$verified_new"
  cp -R "$temporary/extracted/deployment-kits/templates" "$verified_new/templates"
  chown -R root:root "$verified_new"
  find "$verified_new" -type d -exec chmod 0755 {} +
  find "$verified_new" -type f -exec chmod 0644 {} +
  mv "$verified_new" "$verified_release"
fi
cp "$temporary/extracted/unyolo" "$temporary/unyolo"
build=${release#unyolo/}
destination="/opt/unyolo/bootstrap/$build"
install -d -o root -g root -m 0755 "$destination"
install -o root -g root -m 0755 "$temporary/unyolo" "$destination/unyolo.new"
mv -f "$destination/unyolo.new" "$destination/unyolo"
unset GH_TOKEN
exec "$destination/unyolo" system setup-worker --protocol-stdio
