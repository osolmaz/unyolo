#!/bin/sh
set -eu

fail() {
  printf '%s\n' "bootstrap: $*" >&2
  exit 1
}

usage() {
  printf '%s\n' 'usage: bootstrap.sh --release unyolo/vX.Y.Z [setup arguments...]' >&2
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
    setup|--*) break ;;
    *) usage ;;
  esac
done
[ -n "$release" ] || usage
for tool in curl mktemp cp awk grep sed head tr uname wc; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required"
done
[ "$(printf '%s\n' "$release" | wc -l | tr -d ' ')" -eq 1 ] || usage
printf '%s\n' "$release" | grep -Eq '^unyolo/v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$' || usage
[ -r /dev/tty ] && [ -w /dev/tty ] || fail "an interactive terminal is required"
case "$(uname -s)" in
  Linux) ;;
  Darwin) fail "guided host provisioning currently requires Linux" ;;
  *) fail "unsupported operating system" ;;
esac

repo="${REPO:-osolmaz/unyolo}"
case "$repo" in
  */*) ;;
  *) fail "REPO must use owner/name form" ;;
esac
owner="${repo%%/*}"
name="${repo#*/}"
case "${owner}:${name}" in :* | *: | *:*/*) fail "REPO must use owner/name form" ;; esac
case "$repo" in *[!A-Za-z0-9._/-]* | *..* | /* | */) fail "REPO is invalid" ;; esac

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

resolve_source_commit() {
  if [ -n "${UNYOLO_SOURCE_COMMIT:-}" ]; then
    printf '%s\n' "$UNYOLO_SOURCE_COMMIT"
    return
  fi
  ref_base="${UNYOLO_REF_URL_BASE:-https://api.github.com/repos/${repo}/git/ref/tags}"
  tag_base="${UNYOLO_TAG_URL_BASE:-https://api.github.com/repos/${repo}/git/tags}"
  ref="$(curl -fsSL "${ref_base}/${release}")"
  sha="$(printf '%s' "$ref" | referenced_object_sha)"
  type="$(printf '%s' "$ref" | sed -n 's/.*"type":[[:space:]]*"\([a-z]*\)".*/\1/p' | head -n 1)"
  if [ "$type" = tag ]; then
    object="$(curl -fsSL "${tag_base}/${sha}")"
    sha="$(printf '%s' "$object" | referenced_object_sha)"
  fi
  printf '%s\n' "$sha"
}

source_commit="$(resolve_source_commit)"
case "$source_commit" in *[!0-9a-f]*) fail "release tag did not resolve to an exact commit SHA" ;; esac
[ "${#source_commit}" -eq 40 ] || fail "release tag did not resolve to an exact commit SHA"

umask 077
temporary="$(mktemp -d "${TMPDIR:-/tmp}/unyolo-bootstrap.XXXXXX")"
cleanup() {
  status=$?
  trap - 0 HUP INT TERM
  rm -rf "$temporary"
  exit "$status"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' HUP TERM

installer="$temporary/install.sh"
if [ -n "${UNYOLO_INSTALLER_FILE:-}" ]; then
  cp "$UNYOLO_INSTALLER_FILE" "$installer"
else
  raw_base="${UNYOLO_RAW_URL_BASE:-https://raw.githubusercontent.com/${repo}}"
  curl -fsSL "${raw_base}/${source_commit}/install/install.sh" -o "$installer"
fi

mkdir -p "$temporary/bin" "$temporary/libexec" "$temporary/share/providers" "$temporary/share/deployment-kits"
BROKER=unyolo \
REPO="$repo" \
TAG_PREFIX=unyolo/ \
VERSION="$release" \
INSTALL_DIR="$temporary/bin" \
LIBEXEC_DIR="$temporary/libexec" \
COMPANION_BINARIES=openclaw-unyolo-setup \
DATA_PREFIXES="providers/ deployment-kits/" \
DATA_EXECUTABLE_PREFIXES="deployment-kits/artifacts/" \
DATA_DIR="$temporary/share" \
UNYOLO_INSTALL_RECORD="$temporary/stage.json" \
UNYOLO_SOURCE_COMMIT="$source_commit" \
sh "$installer"

[ -x "$temporary/bin/unyolo" ] || fail "verified release did not stage the unyolo CLI"
[ -f "$temporary/stage.json" ] || fail "verified release did not write a stage record"

if [ "$#" -eq 0 ]; then
  set -- setup
elif [ "$1" != setup ]; then
  set -- setup "$@"
fi
"$temporary/bin/unyolo" "$@" \
  --bootstrap-stage "$temporary" \
  </dev/tty >/dev/tty 2>/dev/tty
