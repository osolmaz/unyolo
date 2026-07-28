#!/bin/sh
set -eu

BROKER=gh-broker
REPO="${REPO:-osolmaz/unyolo}"
TAG_PREFIX="${TAG_PREFIX:-gh-broker/}"
PATH_COMPANION_BINARIES="${PATH_COMPANION_BINARIES:-git-credential-unyolo}"
export BROKER REPO TAG_PREFIX PATH_COMPANION_BINARIES

if [ -n "${UNYOLO_INSTALLER_FILE:-}" ]; then
  exec sh "$UNYOLO_INSTALLER_FILE"
fi

command -v curl >/dev/null 2>&1 || {
  echo "gh-broker install: missing required command: curl" >&2
  exit 1
}
command -v mktemp >/dev/null 2>&1 || {
  echo "gh-broker install: missing required command: mktemp" >&2
  exit 1
}

resolve_tag() {
  if [ -n "${VERSION:-}" ]; then
    case "$VERSION" in "$TAG_PREFIX"*) echo "$VERSION" ;; *) echo "${TAG_PREFIX}${VERSION}" ;; esac
    return
  fi
  curl -fsSL "${UNYOLO_RELEASES_URL:-https://api.github.com/repos/${REPO}/releases?per_page=100}" |
    tr '{' '\n' |
    sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' |
    awk -v prefix="$TAG_PREFIX" 'index($0, prefix) == 1 { print; exit }'
}

referenced_object_sha() {
  tr '{},' '\n' |
    awk '
      found && /"sha"[[:space:]]*:/ {
        value = $0
        sub(/^.*"sha"[[:space:]]*:[[:space:]]*"/, "", value)
        sub(/".*$/, "", value)
        print value
        exit
      }
      /"object"[[:space:]]*:/ { found = 1 }
    '
}

resolve_installer_revision() {
  if [ -n "${UNYOLO_INSTALLER_REV:-}" ]; then
    printf '%s\n' "$UNYOLO_INSTALLER_REV"
    return
  fi
  tag="$SELECTED_TAG"
  [ -n "$tag" ] || { echo "$BROKER install: could not resolve release tag" >&2; exit 1; }
  ref="$(curl -fsSL "${UNYOLO_REF_URL_BASE:-https://api.github.com/repos/${REPO}/git/ref/tags}/${tag}")"
  sha="$(printf '%s' "$ref" | referenced_object_sha)"
  type="$(printf '%s' "$ref" | sed -n 's/.*"type":[[:space:]]*"\([a-z]*\)".*/\1/p' | head -n 1)"
  if [ "$type" = tag ]; then
    object="$(curl -fsSL "${UNYOLO_TAG_URL_BASE:-https://api.github.com/repos/${REPO}/git/tags}/${sha}")"
    sha="$(printf '%s' "$object" | referenced_object_sha)"
  fi
  printf '%s\n' "$sha"
}

SELECTED_TAG=""
if [ -z "${UNYOLO_INSTALLER_REV:-}" ]; then
  SELECTED_TAG="$(resolve_tag)"
  VERSION="$SELECTED_TAG"
  export VERSION
fi
UNYOLO_INSTALLER_REV="$(resolve_installer_revision)"
case "$UNYOLO_INSTALLER_REV" in
  *[!0-9a-f]*)
    echo "$BROKER install: installer revision must be an exact 40-character commit SHA" >&2
    exit 1
    ;;
esac
[ "${#UNYOLO_INSTALLER_REV}" -eq 40 ] || {
  echo "$BROKER install: installer revision must be an exact 40-character commit SHA" >&2
  exit 1
}
UNYOLO_INSTALLER_URL="${UNYOLO_INSTALLER_URL:-${UNYOLO_RAW_URL_BASE:-https://raw.githubusercontent.com/${REPO}}/${UNYOLO_INSTALLER_REV}/install/install.sh}"

installer_file="$(mktemp)"
trap 'rm -f "$installer_file"' 0
trap 'exit 1' HUP INT TERM
curl -fsSL "$UNYOLO_INSTALLER_URL" -o "$installer_file"
sh "$installer_file"
