#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

if find . -path './brokers' -prune -o -path './.git' -prune -o -name '*.go' -type f -print0 |
  xargs -0 grep -n 'github.com/osolmaz/brokerkit/brokers/'
then
  echo 'shared Go package imports provider code' >&2
  exit 1
fi

for provider in huggingface github sudo; do
  [ -d "brokers/$provider" ] || continue
  for other in huggingface github sudo; do
    [ "$provider" = "$other" ] && continue
    if grep -R -n --include='*.go' "github.com/osolmaz/brokerkit/brokers/$other/" "brokers/$provider"; then
      echo "$provider imports $other provider code" >&2
      exit 1
    fi
  done
done
