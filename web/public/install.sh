#!/bin/sh
#
# unYOLO broker installer, served from https://unyolo.io/install.sh
#
#   curl -fsSL https://unyolo.io/install.sh | sh
#
# With no argument this installs the GitHub broker, which is the one most
# people want first. Name another to install it instead:
#
#   curl -fsSL https://unyolo.io/install.sh | sh -s huggingface
#
# Either way the work is done by that broker's bootstrap in the repository,
# which resolves its latest release to an exact commit and verifies release
# checksums and GitHub build attestations before installing anything.
#
# What this endpoint does not do is pin itself. It reads the bootstrap from the
# default branch. Name a commit you have reviewed to pin that too:
#
#   curl -fsSL https://unyolo.io/install.sh | UNYOLO_REV=<40-char-sha> sh
#
set -eu

REPO="${REPO:-osolmaz/unyolo}"
REV="${UNYOLO_REV:-main}"
RAW_BASE="${UNYOLO_RAW_URL_BASE:-https://raw.githubusercontent.com/${REPO}}"
BROKER="${1:-}"

if [ -z "$BROKER" ]; then
  BROKER=github
  echo "unyolo install: installing the github broker (also available: huggingface, sudo)" >&2
fi

# Kept in step with the brokers/ directory by TestWebInstallEndpointListsEveryBroker.
case "$BROKER" in
  github | huggingface | sudo) ;;
  *)
    echo "unyolo install: unknown broker '$BROKER'" >&2
    echo "usage: curl -fsSL https://unyolo.io/install.sh | sh -s <github|huggingface|sudo>" >&2
    exit 1
    ;;
esac

command -v curl >/dev/null 2>&1 || {
  echo "unyolo install: missing required command: curl" >&2
  exit 1
}

curl -fsSL "${RAW_BASE}/${REV}/brokers/${BROKER}/install.sh" | sh
