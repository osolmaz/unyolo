#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || { printf '%s\n' 'bootstrap-root: root is required' >&2; exit 1; }
[ -n "${SUDO_UID:-}" ] && [ "$SUDO_UID" -ne 0 ] || { printf '%s\n' 'bootstrap-root: a distinct sudo invoking user is required' >&2; exit 1; }
[ "$#" -eq 1 ] || { printf '%s\n' 'usage: bootstrap-root.sh brokerkit/vX.Y.Z' >&2; exit 64; }
release=$1
case "$release" in brokerkit/v[0-9]*) ;; *) exit 64 ;; esac

command -v curl >/dev/null 2>&1 || exit 1
command -v gh >/dev/null 2>&1 || exit 1
case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; *) exit 1 ;; esac
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; arm64|aarch64) arch=arm64 ;; *) exit 1 ;; esac
asset="brokerkit_${os}_${arch}.tar.gz"
base="https://github.com/osolmaz/brokerkit/releases/download/${release}"
temporary=$(mktemp -d "${TMPDIR:-/tmp}/brokerkit-root-bootstrap.XXXXXX")
trap 'rm -rf "$temporary"' EXIT HUP INT TERM
curl -fL --proto '=https' --tlsv1.2 "$base/$asset" -o "$temporary/$asset"
curl -fL --proto '=https' --tlsv1.2 "$base/checksums.txt" -o "$temporary/checksums.txt"
expected=$(awk -v name="$asset" '$2 == name { print $1 }' "$temporary/checksums.txt")
[ -n "$expected" ] || exit 1
actual=$(sha256sum "$temporary/$asset" 2>/dev/null | awk '{print $1}') || actual=$(shasum -a 256 "$temporary/$asset" | awk '{print $1}')
[ "$actual" = "$expected" ] || { printf '%s\n' 'bootstrap-root: release checksum mismatch' >&2; exit 1; }
gh attestation verify "$temporary/$asset" --repo osolmaz/brokerkit >/dev/null
tar -xzf "$temporary/$asset" -C "$temporary" brokerkit
build=${release#brokerkit/}
destination="/opt/brokerkit/bootstrap/$build"
install -d -o root -g root -m 0755 "$destination"
install -o root -g root -m 0755 "$temporary/brokerkit" "$destination/brokerkit.new"
mv -f "$destination/brokerkit.new" "$destination/brokerkit"
exec "$destination/brokerkit" system setup-worker --protocol-stdio
