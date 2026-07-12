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

if grep -R -n --include='*.ts' --include='*.tsx' -E "from [\"']openclaw/(src|dist)/" plugins/openclaw 2>/dev/null; then
  echo 'OpenClaw plugin imports private host internals' >&2
  exit 1
fi

if [ -d brokers/huggingface/internal/hfoperation ] ||
  grep -R -n --include='*.go' 'brokers/huggingface/internal/hfoperation' . 2>/dev/null
then
  echo 'HF-local operation lifecycle survived the agentops cutover' >&2
  exit 1
fi

if grep -R -n --include='*.go' -E 'operations\.json|store\.WriteJSONAtomic' agentops 2>/dev/null; then
  echo 'agentops must persist only through the shared SQLite state layer' >&2
  exit 1
fi

if grep -R -n --include='*.go' 'github.com/osolmaz/brokerkit/planstore' \
  brokers/huggingface/internal/hfplan 2>/dev/null
then
  echo 'HF plans must persist only through the shared SQLite state layer' >&2
  exit 1
fi

if grep -R -n --include='*.go' 'grants.New(' brokers/huggingface \
  --exclude='*_test.go' 2>/dev/null
then
  echo 'HF grants must persist only through the shared SQLite state layer' >&2
  exit 1
fi

if grep -R -n --include='*.go' -E 'plans\.Bind(At)?\(|store\.Request\(' \
  brokers/huggingface/internal/hfgrant --exclude='*_test.go' 2>/dev/null
then
  echo 'HF request creation must use the atomic plan-plus-grant transaction' >&2
  exit 1
fi

if grep -R -n --include='*.go' -E 'gorm\.io/|github\.com/jmoiron/sqlx|github\.com/mattn/go-sqlite3' \
  . --exclude-dir=.git 2>/dev/null
then
  echo 'BrokerKit state must use database/sql with modernc SQLite and sqlc only' >&2
  exit 1
fi

if grep -R -n -E '"\$ref"[[:space:]]*:[[:space:]]*"\.\.' protocol/openapi 2>/dev/null; then
  echo 'canonical OpenAPI documents must own all payload schemas' >&2
  exit 1
fi

if [ -e plugins/openclaw/scripts/generate-operator-v1.mjs ]; then
  echo 'legacy standalone-schema TypeScript generator survived the OpenAPI cutover' >&2
  exit 1
fi

if grep -R -n --include='*.ts' --include='*.tsx' -E 'mlclaw\.|(telegram|discord|slack)' \
  plugins/openclaw/index.ts plugins/openclaw/src plugins/openclaw/ui/src \
  --exclude='*.test.ts' 2>/dev/null; then
  echo 'OpenClaw production code contains a host- or channel-specific branch' >&2
  exit 1
fi

if grep -R -n --include='*.ts' --include='*.tsx' -E '(huggingface|github|sudo)-broker' \
  plugins/openclaw/index.ts plugins/openclaw/src plugins/openclaw/ui/src \
  --exclude='*.test.ts' 2>/dev/null; then
  echo 'OpenClaw production code contains a provider-specific branch' >&2
  exit 1
fi
