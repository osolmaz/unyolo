#!/bin/sh
#
# unYOLO installer, served from https://unyolo.io/install.sh
#
# Guided host setup:
#
#   curl -fsSL https://unyolo.io/install.sh | sh
#
# Install one broker binary without guided setup:
#
#   curl -fsSL https://unyolo.io/install.sh | sh -s -- github
#
set -eu

fail() {
  printf '%s\n' "unyolo install: $*" >&2
  exit 1
}

repo="${REPO:-osolmaz/unyolo}"
case "$repo" in */*) ;; *) fail "REPO must use owner/name form" ;; esac
owner="${repo%%/*}"
name="${repo#*/}"
case "${owner}:${name}" in :* | *: | *:*/*) fail "REPO must use owner/name form" ;; esac
case "$repo" in *[!A-Za-z0-9._/-]* | *..* | /* | */) fail "REPO is invalid" ;; esac
raw_base="${UNYOLO_RAW_URL_BASE:-https://raw.githubusercontent.com/${repo}}"
component="${1:-}"
for tool in curl mktemp grep awk sed head tr wc; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing required command: $tool"
done
umask 077
temporary="$(mktemp -d "${TMPDIR:-/tmp}/unyolo-launcher.XXXXXX")"
cleanup() {
  status=$?
  trap - 0 HUP INT TERM
  rm -rf "$temporary"
  exit "$status"
}
trap cleanup 0
trap 'exit 130' INT
trap 'exit 143' HUP TERM

# Kept in step with brokers/ by TestWebInstallEndpointListsEveryBroker.
case "$component" in
  github | huggingface | sudo)
    [ "$#" -eq 1 ] || fail "binary-only installation accepts one component name"
    revision="${UNYOLO_REV:-main}"
    curl -fsSL "${raw_base}/${revision}/brokers/${component}/install.sh" -o "$temporary/broker-install.sh"
    sh "$temporary/broker-install.sh"
    exit
    ;;
  "" | setup | --*) ;;
  *)
    printf '%s\n' "unyolo install: unknown component '$component'" >&2
    printf '%s\n' 'usage: curl -fsSL https://unyolo.io/install.sh | sh -s -- <github|huggingface|sudo>' >&2
    exit 64
    ;;
esac

resolve_release() {
  if [ -n "${VERSION:-}" ]; then
    case "$VERSION" in unyolo/*) printf '%s\n' "$VERSION" ;; *) printf 'unyolo/%s\n' "$VERSION" ;; esac
    return
  fi
  releases_url="${UNYOLO_RELEASES_URL:-https://api.github.com/repos/${repo}/releases?per_page=100}"
  curl -fsSL "$releases_url" |
    tr '{' '\n' |
    sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' |
    awk 'index($0, "unyolo/") == 1 { print; exit }'
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

release="$(resolve_release)"
[ "$(printf '%s\n' "$release" | wc -l | tr -d ' ')" -eq 1 ] || fail "could not resolve one exact unyolo release"
printf '%s\n' "$release" | grep -Eq '^unyolo/v[0-9]+\.[0-9]+\.[0-9]+([-+][A-Za-z0-9.-]+)?$' || fail "could not resolve an exact unyolo release"
ref_base="${UNYOLO_REF_URL_BASE:-https://api.github.com/repos/${repo}/git/ref/tags}"
tag_base="${UNYOLO_TAG_URL_BASE:-https://api.github.com/repos/${repo}/git/tags}"
ref="$(curl -fsSL "${ref_base}/${release}")"
source_commit="$(printf '%s' "$ref" | referenced_object_sha)"
type="$(printf '%s' "$ref" | sed -n 's/.*"type":[[:space:]]*"\([a-z]*\)".*/\1/p' | head -n 1)"
if [ "$type" = tag ]; then
  object="$(curl -fsSL "${tag_base}/${source_commit}")"
  source_commit="$(printf '%s' "$object" | referenced_object_sha)"
fi
case "$source_commit" in *[!0-9a-f]*) fail "release tag did not resolve to an exact commit SHA" ;; esac
[ "${#source_commit}" -eq 40 ] || fail "release tag did not resolve to an exact commit SHA"

bootstrap_revision="${UNYOLO_REV:-$source_commit}"
case "$bootstrap_revision" in *[!0-9a-f]*) fail "UNYOLO_REV must be an exact commit SHA" ;; esac
[ "${#bootstrap_revision}" -eq 40 ] || fail "UNYOLO_REV must be an exact commit SHA"

curl -fsSL "${raw_base}/${bootstrap_revision}/install/bootstrap.sh" -o "$temporary/bootstrap.sh"
UNYOLO_SOURCE_COMMIT="$source_commit" sh "$temporary/bootstrap.sh" --release "$release" "$@"
