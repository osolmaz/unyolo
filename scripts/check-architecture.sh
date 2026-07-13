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

if [ -d brokers/huggingface/internal/gitproxy/pktline ] ||
  grep -R -n --include='*.go' 'brokers/huggingface/internal/gitproxy/pktline' . 2>/dev/null
then
  echo 'HF-local pkt-line implementation survived the gitx cutover' >&2
	exit 1
fi

if [ -d brokers/huggingface/internal/audit ] ||
  grep -R -n --include='*.go' 'brokers/huggingface/internal/audit' . 2>/dev/null
then
  echo 'HF-local audit implementation survived the shared recorder cutover' >&2
  exit 1
fi

if grep -R -n --include='*.go' 'github.com/go-git/' brokers 2>/dev/null; then
  echo 'providers must use go-git only through the shared gitx boundary' >&2
  exit 1
fi

if grep -R -n --include='*.go' 'compress/zlib' brokers/huggingface/internal/gitproxy 2>/dev/null; then
  echo 'HF-local packfile inflation survived the gitx cutover' >&2
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

if grep -R -n --include='*.go' -E 'grants\.New\(|brokerkit/planstore|planstore\.' \
  brokers/github --exclude='*_test.go' 2>/dev/null
then
  echo 'GH lifecycle state must use the shared SQLite database' >&2
  exit 1
fi

if ! grep -q 'agentAPI.Register' brokers/sudo/internal/routes/server.go ||
	grep -R -n --include='*.go' -E 'api/v1/(requests|executions)|grants\.New\(|brokerkit/planstore|planstore\.' \
		brokers/sudo --exclude='*_test.go' 2>/dev/null
then
	echo 'sudo operations and lifecycle state must use Agent V1 and shared SQLite' >&2
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

if ! grep -q 'github.com/osolmaz/brokerkit/capability' brokers/huggingface/internal/opcatalog/catalog.go ||
  ! grep -A4 'type Descriptor struct' brokers/github/internal/opcatalog/catalog.go | grep -q 'capability.Descriptor'
then
  echo 'provider operation catalogs must use the shared capability descriptor' >&2
  exit 1
fi

if ! grep -q 'githubsurface.Validate' brokers/github/cmd/gh-broker/main.go ||
  ! grep -q 'mcpcatalog.Tools' brokers/github/cmd/gh-broker/mcp.go ||
  [ ! -f brokers/github/internal/inventory/rest-coverage.json ] ||
  [ ! -f brokers/github/internal/inventory/graphql-coverage.json ]
then
  echo 'GH generated catalog startup validation or filtered MCP discovery is missing' >&2
  exit 1
fi

if grep -R -n --include='*.go' --exclude='*_test.go' -E \
  'json:"(graphql|caller|headers)"' brokers/github/cmd/gh-broker brokers/github/internal/httpapi 2>/dev/null
then
  echo 'GH caller boundary accepts a raw transport selector' >&2
  exit 1
fi

if ! grep -q 'github.com/osolmaz/brokerkit/operationruntime' brokers/huggingface/internal/operations/operations.go ||
  grep -R -n --include='*.go' -E 'type Adapter interface|byName map\[string\].*Adapter|type PossiblePartialError struct' \
    brokers/huggingface --exclude='*_test.go' 2>/dev/null
then
  echo 'HF operation adapters and registry must use the shared operationruntime contract' >&2
  exit 1
fi

if grep -R -l --include='*.go' --exclude='*_test.go' -E \
  'func \([^)]*\) startOperationWorker|StateExecuting|operations\.Transition\(' brokers 2>/dev/null |
  grep -v -E '^brokers/(github/internal/httpapi/(agent_operations|runtime)|sudo/internal/routes/agent_operations)\.go$'
then
  echo 'provider-local Agent lifecycle orchestration exists outside the temporary legacy allowlist' >&2
  exit 1
fi

if find brokers -type d \( -name sealedstore -o -name credentialstore -o -name schemautil -o -name securefile \) -print |
  grep .
then
  echo 'provider-local generic operation primitives survived the shared runtime cutover' >&2
  exit 1
fi

if grep -R -n --include='*.go' --exclude='*_test.go' -E \
  'func (inlineSchemaReferences|inlineSchemaMap|startSealedPayloadSweeper)\(' brokers 2>/dev/null
then
  echo 'provider-local generated-surface or sealed-payload lifecycle implementation survived the cutover' >&2
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

if ! grep -q 'operatorwire.RegisterHandlers' operatorapi/api.go ||
  grep -R -n --include='*.go' -E 'serveAuthorized|requestPath\(' operatorapi 2>/dev/null
then
  echo 'Operator V1 must use only generated Echo route registration' >&2
  exit 1
fi

if ! grep -q 'agentwire.RegisterHandlers' agentapi/api.go ||
	grep -R -n --include='*.go' 'agentwire.RegisterHandlers' brokers 2>/dev/null ||
	grep -R -n --include='*.go' 'serveAgentAPI' brokers 2>/dev/null
then
	echo 'Agent V1 must use only shared generated Echo route registration' >&2
  exit 1
fi

if ! grep -q 'agentAPI.Register' brokers/github/internal/httpapi/server.go ||
	grep -R -n --include='*.go' -E 'POST\("/api/repos/:owner/:repo/pulls"|func .*createPullRequest\(' brokers/github 2>/dev/null
then
	echo 'GH discrete operations must use the shared Agent V1 boundary' >&2
	exit 1
fi

if ! grep -q 'operatorwire.NewClient' operatorclient/client.go ||
	! grep -q 'agentwire.NewClient' agentclient/client.go ||
	grep -R -n --include='*.go' 'agentwire.NewClient' brokers 2>/dev/null
then
  echo 'Operator and Agent clients must use generated request builders' >&2
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
