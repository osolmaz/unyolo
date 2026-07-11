#!/bin/sh
set -eu

BROKER=sudo-broker
REPO="${REPO:-osolmaz/brokerkit}"
TAG_PREFIX="${TAG_PREFIX:-sudo-broker/}"
COMPANION_BINARIES="${COMPANION_BINARIES:-sudo-broker-exec}"
BROKERKIT_INSTALLER_REV="${BROKERKIT_INSTALLER_REV:-main}"
BROKERKIT_INSTALLER_URL="${BROKERKIT_INSTALLER_URL:-https://raw.githubusercontent.com/osolmaz/brokerkit/${BROKERKIT_INSTALLER_REV}/installer/install.sh}"
export BROKER REPO TAG_PREFIX COMPANION_BINARIES

if [ -n "${BROKERKIT_INSTALLER_FILE:-}" ]; then
  exec sh "$BROKERKIT_INSTALLER_FILE"
fi

command -v curl >/dev/null 2>&1 || {
  echo "sudo-broker install: missing required command: curl" >&2
  exit 1
}
command -v mktemp >/dev/null 2>&1 || {
  echo "sudo-broker install: missing required command: mktemp" >&2
  exit 1
}

installer_file="$(mktemp)"
trap 'rm -f "$installer_file"' 0
trap 'exit 1' HUP INT TERM
curl -fsSL "$BROKERKIT_INSTALLER_URL" -o "$installer_file"
sh "$installer_file"
