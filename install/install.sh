#!/bin/sh
set -eu

BROKER="${BROKER:-}"
REPO="${REPO:-}"
INSTALL_DIR="${INSTALL_DIR:-}"
VERSION="${VERSION:-}"
TAG_PREFIX="${TAG_PREFIX:-}"
COMPANION_BINARIES="${COMPANION_BINARIES:-}"
PATH_COMPANION_BINARIES="${PATH_COMPANION_BINARIES:-}"
LIBEXEC_DIR="${LIBEXEC_DIR:-}"
DATA_FILES="${DATA_FILES:-}"
DATA_PREFIXES="${DATA_PREFIXES:-}"
DATA_EXECUTABLE_PREFIXES="${DATA_EXECUTABLE_PREFIXES:-}"
DATA_DIR="${DATA_DIR:-}"
UNYOLO_INSTALL_RECORD="${UNYOLO_INSTALL_RECORD:-}"
UNYOLO_SOURCE_COMMIT="${UNYOLO_SOURCE_COMMIT:-}"
UNYOLO_VERIFY_ONLY="${UNYOLO_VERIFY_ONLY:-false}"
UNYOLO_VERIFY_RELEASE_SET="${UNYOLO_VERIFY_RELEASE_SET:-false}"
UNYOLO_VERIFIER_FILE="${UNYOLO_VERIFIER_FILE:-}"

GH_VERIFIER_VERSION="2.96.0"
GH_VERIFIER_RELEASE="https://github.com/cli/cli/releases/download/v${GH_VERIFIER_VERSION}"

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
    *..* | /* | */) fail "REPO contains unsafe path syntax" ;;
  esac
  case "$TAG_PREFIX" in
    "") ;;
    *[!A-Za-z0-9._/-]*) fail "TAG_PREFIX contains unsupported characters" ;;
    *..* | /*) fail "TAG_PREFIX contains unsafe path syntax" ;;
  esac
  for directory in "$INSTALL_DIR" "$LIBEXEC_DIR" "$DATA_DIR"; do
    case "$directory" in
      "") ;;
      /*) case "$directory/" in *"/../"* | *"/./"* | *"//"*) fail "install directories must be absolute normalized paths" ;; esac ;;
      *) fail "install directories must be absolute normalized paths" ;;
    esac
  done
  for setting in UNYOLO_VERIFY_ONLY UNYOLO_VERIFY_RELEASE_SET; do
    eval "value=\${$setting}"
    case "$value" in
      true | false) ;;
      *) fail "$setting must be true or false" ;;
    esac
  done
  if [ "$UNYOLO_VERIFY_RELEASE_SET" = true ] && [ "$UNYOLO_VERIFY_ONLY" != true ]; then
    fail "UNYOLO_VERIFY_RELEASE_SET requires UNYOLO_VERIFY_ONLY=true"
  fi
  if [ -n "$UNYOLO_VERIFIER_FILE" ]; then
    case "$UNYOLO_VERIFIER_FILE" in
      /*) case "$UNYOLO_VERIFIER_FILE/" in *"/../"* | *"/./"* | *"//"*) fail "UNYOLO_VERIFIER_FILE must be an absolute normalized path" ;; esac ;;
      *) fail "UNYOLO_VERIFIER_FILE must be an absolute normalized path" ;;
    esac
    [ -x "$UNYOLO_VERIFIER_FILE" ] || fail "UNYOLO_VERIFIER_FILE must be executable"
  fi
  for binary in $COMPANION_BINARIES $PATH_COMPANION_BINARIES; do
    case "$binary" in
      "" | *[!a-z0-9-]* | "$BROKER") fail "COMPANION_BINARIES contains an invalid binary name" ;;
    esac
  done
  for data_file in $DATA_FILES; do
    case "$data_file" in
      "" | /* | */ | *..* | *[!A-Za-z0-9._/-]*) fail "DATA_FILES contains an invalid relative path" ;;
    esac
  done
  for data_prefix in $DATA_PREFIXES $DATA_EXECUTABLE_PREFIXES; do
    case "$data_prefix" in
      "" | /* | *..* | *[!A-Za-z0-9._/-]*) fail "release data prefixes must be safe relative directory prefixes ending in /" ;;
      */) ;;
      *) fail "release data prefixes must end in /" ;;
    esac
  done
  for executable_prefix in $DATA_EXECUTABLE_PREFIXES; do
    selected=false
    for data_prefix in $DATA_PREFIXES; do
      case "$executable_prefix" in "$data_prefix"*) selected=true ;; esac
    done
    [ "$selected" = true ] || fail "DATA_EXECUTABLE_PREFIXES must be contained by DATA_PREFIXES"
  done
  if { [ -n "$DATA_FILES" ] || [ -n "$DATA_PREFIXES" ]; } && [ -z "$DATA_DIR" ]; then
    fail "DATA_DIR is required when release data is selected"
  fi
  if [ -n "$UNYOLO_SOURCE_COMMIT" ]; then
    case "$UNYOLO_SOURCE_COMMIT" in *[!0-9a-f]*) fail "UNYOLO_SOURCE_COMMIT must be an exact commit SHA" ;; esac
    [ "${#UNYOLO_SOURCE_COMMIT}" -eq 40 ] || fail "UNYOLO_SOURCE_COMMIT must be an exact commit SHA"
  fi
  if [ -n "$UNYOLO_INSTALL_RECORD" ]; then
    case "$UNYOLO_INSTALL_RECORD" in
      /*) case "$UNYOLO_INSTALL_RECORD/" in *"/../"* | *"/./"* | *"//"*) fail "UNYOLO_INSTALL_RECORD must be an absolute normalized path" ;; esac ;;
      *) fail "UNYOLO_INSTALL_RECORD must be an absolute normalized path" ;;
    esac
    [ -n "$UNYOLO_SOURCE_COMMIT" ] || fail "UNYOLO_SOURCE_COMMIT is required for an install record"
  fi
}

system_name() {
  if [ -n "${UNYOLO_UNAME_S:-}" ]; then
    echo "$UNYOLO_UNAME_S"
    return
  fi
  uname -s
}

machine_name() {
  if [ -n "${UNYOLO_UNAME_M:-}" ]; then
    echo "$UNYOLO_UNAME_M"
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
  if [ -z "$TAG_PREFIX" ]; then
    url="${UNYOLO_LATEST_RELEASE_URL:-https://api.github.com/repos/${REPO}/releases/latest}"
    curl -fsSL "$url" |
      sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' |
      head -n 1
    return
  fi
  url="${UNYOLO_RELEASES_URL:-https://api.github.com/repos/${REPO}/releases?per_page=100}"
  curl -fsSL "$url" |
    tr '{' '\n' |
    sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' |
    awk -v prefix="$TAG_PREFIX" 'index($0, prefix) == 1 { print; exit }'
}

choose_install_dir() {
  if [ -n "$INSTALL_DIR" ]; then
    echo "$INSTALL_DIR"
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

verifier_archive() {
  case "${os}/${arch}" in
    linux/amd64) echo "gh_${GH_VERIFIER_VERSION}_linux_amd64.tar.gz 83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60" ;;
    linux/arm64) echo "gh_${GH_VERIFIER_VERSION}_linux_arm64.tar.gz 06f86ec7103d41993b76cd78072f43595c34aaa56506d971d9860e67140bf909" ;;
    darwin/amd64) echo "gh_${GH_VERIFIER_VERSION}_macOS_amd64.zip 4bd449df9ad639391bc62b8032546f0fe9edcd8526e06682a4f88abd8c5d163c" ;;
    darwin/arm64) echo "gh_${GH_VERIFIER_VERSION}_macOS_arm64.zip f23a0c37d963aacc3bed703ccbd59b41c5ca22101fab7f00eb2b7cad23aba463" ;;
    *) fail "unsupported verifier platform: ${os}/${arch}" ;;
  esac
}

prepare_verifier() {
  if [ -n "$UNYOLO_VERIFIER_FILE" ]; then
    echo "$UNYOLO_VERIFIER_FILE"
    return
  fi

  verifier_record="$(verifier_archive)"
  verifier_asset="${verifier_record%% *}"
  verifier_digest="${verifier_record#* }"
  verifier_archive_path="${tmp_dir}/${verifier_asset}"
  curl -fsSL "${GH_VERIFIER_RELEASE}/${verifier_asset}" -o "$verifier_archive_path"
  printf '%s  %s\n' "$verifier_digest" "$verifier_asset" > "${tmp_dir}/verifier-checksum.txt"
  verify_checksum "$verifier_asset" "${tmp_dir}/verifier-checksum.txt" >&2

  case "$verifier_asset" in
    *.tar.gz) tar -xzf "$verifier_archive_path" -C "$tmp_dir" ;;
    *.zip)
      need unzip
      unzip -q "$verifier_archive_path" -d "$tmp_dir"
      ;;
    *) fail "unsupported verifier archive: ${verifier_asset}" ;;
  esac
  verifier_root="${verifier_asset%.tar.gz}"
  verifier_root="${verifier_root%.zip}"
  verifier="${tmp_dir}/${verifier_root}/bin/gh"
  [ -x "$verifier" ] || fail "pinned provenance verifier is missing its executable"
  echo "$verifier"
}

verify_provenance() {
  verifier="$(prepare_verifier)"
  for subject in "$@"; do
    if [ -n "$UNYOLO_SOURCE_COMMIT" ]; then
      "$verifier" attestation verify "$subject" \
        --repo "$REPO" \
        --signer-workflow "$REPO/.github/workflows/release.yml" \
        --source-ref "refs/tags/$VERSION" \
        --source-digest "$UNYOLO_SOURCE_COMMIT" \
        --deny-self-hosted-runners >/dev/null
    else
      "$verifier" attestation verify "$subject" \
        --repo "$REPO" \
        --signer-workflow "$REPO/.github/workflows/release.yml" \
        --source-ref "refs/tags/$VERSION" \
        --deny-self-hosted-runners >/dev/null
    fi
  done
}

verify_complete_release() {
  set -- "${tmp_dir}/checksums.txt"
  for release_asset in \
    "${BROKER}_linux_amd64.tar.gz" \
    "${BROKER}_linux_arm64.tar.gz" \
    "${BROKER}_darwin_amd64.tar.gz" \
    "${BROKER}_darwin_arm64.tar.gz"
  do
    if [ "$release_asset" != "$asset" ]; then
      curl -fsSL "${base_url}/${release_asset}" -o "${tmp_dir}/${release_asset}"
    fi
    verify_checksum "$release_asset" "${tmp_dir}/checksums.txt"
    validate_archive "${tmp_dir}/${release_asset}" "${tmp_dir}/${release_asset}.list"
    set -- "$@" "${tmp_dir}/${release_asset}"
  done
  if [ "$BROKER" = unyolo ]; then
    for release_asset in unyolo-bootstrap-root.sh; do
      curl -fsSL "${base_url}/${release_asset}" -o "${tmp_dir}/${release_asset}"
      verify_checksum "$release_asset" "${tmp_dir}/checksums.txt"
      set -- "$@" "${tmp_dir}/${release_asset}"
    done
  fi
  curl -fsSL "${base_url}/sbom.spdx.json" -o "${tmp_dir}/sbom.spdx.json"
  set -- "$@" "${tmp_dir}/sbom.spdx.json"
  verify_provenance "$@"
}

install_binary() {
  source_path="$1"
  dest_dir="$2"
  binary_name="$3"
  mkdir -p "$dest_dir" 2>/dev/null ||
    fail "cannot create ${dest_dir}; choose a writable INSTALL_DIR or rerun from an operator-controlled privileged shell"
  [ -w "$dest_dir" ] ||
    fail "cannot write to ${dest_dir}; choose a writable INSTALL_DIR or rerun from an operator-controlled privileged shell"
  install -m 0755 "$source_path" "$dest_dir/${binary_name}" ||
    fail "could not install ${binary_name} in ${dest_dir}"
}

choose_libexec_dir() {
  dest_dir="$1"
  if [ -n "$LIBEXEC_DIR" ]; then
    echo "$LIBEXEC_DIR"
    return
  fi
  echo "$(dirname "$dest_dir")/libexec"
}

validate_archive() {
  archive="$1"
  listing="$2"
  tar -tzf "$archive" > "$listing"
  tar -tvzf "$archive" > "${listing}.types"
  awk 'substr($1, 1, 1) != "-" { exit 1 }' "${listing}.types" || fail "release archive entries must be regular files"
  [ "$(wc -l < "$listing" | tr -d ' ')" -eq "$(wc -l < "${listing}.types" | tr -d ' ')" ] || fail "release archive listing is inconsistent"
  while IFS= read -r entry; do
    case "$entry" in
      "$BROKER" | README.md | LICENSE) ;;
      *)
        allowed=false
        for binary in $COMPANION_BINARIES $PATH_COMPANION_BINARIES; do
          if [ "$entry" = "$binary" ]; then allowed=true; fi
        done
        for data_file in $DATA_FILES; do
          if [ "$entry" = "$data_file" ]; then allowed=true; fi
        done
        for data_prefix in $DATA_PREFIXES; do
          case "$entry" in "$data_prefix"*) allowed=true ;; esac
        done
        [ "$allowed" = true ] || fail "release archive contains unexpected path: ${entry}"
        ;;
    esac
  done < "$listing"
  [ "$(awk -v name="$BROKER" '$0 == name { count++ } END { print count + 0 }' "$listing")" -eq 1 ] || fail "release archive must contain ${BROKER} exactly once"
  for binary in $COMPANION_BINARIES $PATH_COMPANION_BINARIES; do
    [ "$(awk -v name="$binary" '$0 == name { count++ } END { print count + 0 }' "$listing")" -eq 1 ] || fail "release archive must contain ${binary} exactly once"
  done
  for data_file in $DATA_FILES; do
    [ "$(awk -v name="$data_file" '$0 == name { count++ } END { print count + 0 }' "$listing")" -eq 1 ] || fail "release archive must contain ${data_file} exactly once"
  done
  for data_prefix in $DATA_PREFIXES; do
    [ "$(awk -v prefix="$data_prefix" 'index($0, prefix) == 1 { count++ } END { print count + 0 }' "$listing")" -gt 0 ] || fail "release archive contains no data below ${data_prefix}"
  done
}

validate_inputs
need curl
need tar
need install
need awk
need sed
need tr
need head
need mktemp
need dirname
need basename
need wc

os="$(normalize_os)"
arch="$(normalize_arch)"
if [ -z "$VERSION" ]; then
  VERSION="$(latest_version)"
elif [ -n "$TAG_PREFIX" ]; then
  case "$VERSION" in
    "$TAG_PREFIX"*) ;;
    *) VERSION="${TAG_PREFIX}${VERSION}" ;;
  esac
fi
[ -n "$VERSION" ] || fail "could not resolve latest release version; set VERSION=vX.Y.Z"
case "$VERSION" in
  /* | */ | *..* | *[!A-Za-z0-9._/-]*) fail "release tag contains unsupported characters" ;;
esac

asset="${BROKER}_${os}_${arch}.tar.gz"
base_url="${UNYOLO_RELEASE_BASE_URL:-https://github.com/${REPO}/releases/download/${VERSION}}"
umask 077
tmp_dir="$(mktemp -d)"
cleanup_install() {
  status=$?
  trap - 0 HUP INT TERM
  rm -rf "$tmp_dir"
  exit "$status"
}
trap cleanup_install 0
trap 'exit 130' INT
trap 'exit 143' HUP TERM

echo "Downloading ${REPO} ${VERSION} for ${os}/${arch}"
curl -fsSL "${base_url}/${asset}" -o "${tmp_dir}/${asset}"
curl -fsSL "${base_url}/checksums.txt" -o "${tmp_dir}/checksums.txt"
verify_checksum "$asset" "${tmp_dir}/checksums.txt"
if [ "$UNYOLO_VERIFY_RELEASE_SET" = true ]; then
  verify_complete_release
else
  verify_provenance "${tmp_dir}/${asset}" "${tmp_dir}/checksums.txt"
  validate_archive "${tmp_dir}/${asset}" "${tmp_dir}/archive.list"
fi
if [ "$UNYOLO_VERIFY_ONLY" = true ]; then
  echo "Verified ${REPO} ${VERSION} release assets and provenance"
  exit 0
fi
tar -xzf "${tmp_dir}/${asset}" -C "$tmp_dir"
main_dest_dir="$(choose_install_dir)"
install_binary "${tmp_dir}/${BROKER}" "$main_dest_dir" "$BROKER"

if [ -n "$COMPANION_BINARIES" ]; then
  libexec_dir="$(choose_libexec_dir "$main_dest_dir")"
  for binary in $COMPANION_BINARIES; do
    install_binary "${tmp_dir}/${binary}" "$libexec_dir" "$binary"
    echo "Installed ${binary} to ${libexec_dir}/${binary}"
    "${libexec_dir}/${binary}" --version
  done
fi

for binary in $PATH_COMPANION_BINARIES; do
  install_binary "${tmp_dir}/${binary}" "$main_dest_dir" "$binary"
  echo "Installed ${binary} to ${main_dest_dir}/${binary}"
done

install_data_file() {
  data_file="$1"
  data_destination="${DATA_DIR}/${data_file}"
  data_mode=0644
  for executable_prefix in $DATA_EXECUTABLE_PREFIXES; do
    case "$data_file" in "$executable_prefix"*) data_mode=0755 ;; esac
  done
  mkdir -p "$(dirname "$data_destination")" || fail "cannot create data directory for ${data_file}"
  install -m "$data_mode" "${tmp_dir}/${data_file}" "$data_destination" || fail "could not install data file ${data_file}"
}
for data_file in $DATA_FILES; do
  install_data_file "$data_file"
done
if [ -n "$DATA_PREFIXES" ]; then
  while IFS= read -r archive_entry; do
    selected=false
    for data_prefix in $DATA_PREFIXES; do
      case "$archive_entry" in "$data_prefix"*) selected=true ;; esac
    done
    if [ "$selected" = true ]; then
      install_data_file "$archive_entry"
    fi
  done < "${tmp_dir}/archive.list"
fi

if [ -n "$UNYOLO_INSTALL_RECORD" ]; then
  archive_digest="$(checksum_line "$asset" "${tmp_dir}/checksums.txt" | awk '{ print $1 }')"
  record_tmp="${UNYOLO_INSTALL_RECORD}.new.$$"
  printf '{"api_version":"unyolo.io/bootstrap-stage/v1","release":"%s","source_commit":"%s","archive_sha256":"sha256:%s","attestation":{"repository":"%s","workflow":"%s/.github/workflows/release.yml","source_ref":"refs/tags/%s"}}\n' \
    "$VERSION" "$UNYOLO_SOURCE_COMMIT" "$archive_digest" "$REPO" "$REPO" "$VERSION" > "$record_tmp"
  mv -f "$record_tmp" "$UNYOLO_INSTALL_RECORD"
fi

echo "Installed ${BROKER} to ${main_dest_dir}/${BROKER}"
"${main_dest_dir}/${BROKER}" --version
if [ "$(command -v "$BROKER" 2>/dev/null || true)" != "${main_dest_dir}/${BROKER}" ]; then
  echo "Add ${main_dest_dir} to PATH to run ${BROKER} directly."
fi
