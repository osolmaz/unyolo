#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

if grep -R -n -E 'uses:[[:space:]]+[^[:space:]]+@[^0-9a-f]|uses:[[:space:]]+[^[:space:]]+@[0-9a-f]{1,39}([^0-9a-f]|$)' .github/workflows 2>/dev/null; then
	echo 'GitHub Actions must be pinned to full commit SHAs' >&2
	exit 1
fi

if grep -R -n -E 'npm@latest|node-version:[[:space:]]+"?[0-9]+"?[[:space:]]*$' .github/workflows 2>/dev/null; then
	echo 'release and CI runtimes must use exact tool versions' >&2
	exit 1
fi

if grep -R -n -E '(^|[[:space:]])sudo([[:space:]]|$)' installer/*.sh 2>/dev/null; then
	echo 'convenience installers must never invoke sudo' >&2
	exit 1
fi

if grep -R -n -E 'BROKERKIT_INSTALLER_REV=.*main|raw\.githubusercontent\.com/[^/]+/[^/]+/main/' brokers/*/install.sh 2>/dev/null; then
	echo 'broker installer wrappers must resolve an immutable installer commit' >&2
	exit 1
fi

maintained_examples='README.md
docs/ARCHITECTURE.md
docs/OPERATOR_INBOX.md
docs/OPERATIONS_RUNTIME.md
docs/OWNERSHIP.md
docs/POLICY_CORE.md
docs/SYSTEMD_INSTALL_RUNTIME.md
docs/UNIFIED_BROKER_CONTRACT.md
brokers/github/.env.example
brokers/github/README.md
brokers/github/scope.example.json
brokers/huggingface/README.md
brokers/huggingface/docs/POLICY_PRESETS.md
brokers/huggingface/docs/POLICY_RULES_SPEC.md
brokers/huggingface/docs/SERVICE_SETUP.md
brokers/huggingface/docs/SPECIFICATION.md
brokers/sudo/README.md
brokers/sudo/docs/operations.md
brokers/sudo/policy.example.json
plugins/openclaw/README.md'

# Deliberate word splitting supplies the maintained path list to grep.
# shellcheck disable=SC2086
if grep -n -E '(^|[^0-9])(808[0-5]|1808[0-2])([^0-9]|$)' $maintained_examples 2>/dev/null; then
	echo 'maintained examples must not assign legacy broker ports' >&2
	exit 1
fi

# shellcheck disable=SC2086
if grep -n -E '(^|[^[:alnum:]_-])(bob|onur)([^[:alnum:]_-]|$)' $maintained_examples 2>/dev/null; then
	echo 'maintained examples must use neutral client and operator identities' >&2
	exit 1
fi

# shellcheck disable=SC2086
if grep -n -E '(_BIND_ADDR|_PORT|--bind-addr|--operator-bind-addr|--operator-port|--url([[:space:]]|$))' $maintained_examples 2>/dev/null; then
	echo 'maintained examples must use complete endpoint URIs' >&2
	exit 1
fi

if grep -R -n --include='*.go' --exclude='*_test.go' -E 'Endpoint:[[:space:]]*"tcp://' brokers 2>/dev/null; then
	echo 'production broker defaults must not assign TCP endpoints' >&2
	exit 1
fi

if grep -R -n --include='*.go' --exclude='*_test.go' -E '((HF|GH|SUDO)_BROKER_(BIND_ADDR|PORT|OPERATOR_BIND_ADDR|OPERATOR_PORT)|"(bob|onur)")' brokers 2>/dev/null; then
	echo 'production broker code contains a retired listener field or personal identity default' >&2
	exit 1
fi

if ! grep -q 'BROKERKIT_VERIFY_ONLY: "true"' .github/workflows/release.yml ||
  ! grep -q 'BROKERKIT_VERIFY_RELEASE_SET: "true"' .github/workflows/release.yml ||
  ! grep -q -- '--signer-workflow "$REPO/.github/workflows/release.yml"' installer/install.sh ||
  ! grep -q -- '--deny-self-hosted-runners' installer/install.sh
then
  echo 'release publication and installation must verify pinned artifact provenance' >&2
  exit 1
fi

for admission_server in \
  brokers/huggingface/internal/httpapi/server.go \
  brokers/github/internal/httpapi/server.go \
  brokers/sudo/internal/routes/server.go
do
  if ! grep -q 'admission.NewConfigured' "$admission_server"; then
    echo "$admission_server bypasses shared configured admission control" >&2
    exit 1
  fi
done

if ! grep -q 'router.GET("/metrics"' operatorapi/api.go ||
  grep -R -n --include='*.go' --exclude='*_test.go' '"/metrics"' brokers 2>/dev/null
then
  echo 'metrics must exist only on the shared authenticated operator surface' >&2
  exit 1
fi

if ! grep -q 'captureSystemdInstall' service/install_linux.go ||
  ! grep -q 'captureLaunchdInstall' service/install_darwin.go
then
  echo 'native service installers must preserve transactional credential rollback' >&2
  exit 1
fi

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

if [ -d brokers/github/internal/githubapp ] || [ -d brokers/github/internal/githubapi ] ||
  grep -R -n --include='*.go' -E 'brokers/github/internal/(githubapp|githubapi)' brokers/github 2>/dev/null
then
  echo 'GH custom JWT, installation pagination, or narrow API reader survived the credential cutover' >&2
  exit 1
fi

if ! grep -R -q --include='*.go' 'github.com/bradleyfalzon/ghinstallation/v2' brokers/github/internal/githubauth ||
  ! grep -R -q --include='*.go' 'github.com/google/go-github/v88/github' brokers/github/internal/githubauth
then
  echo 'GH credential handling must use ghinstallation and go-github behind githubauth' >&2
  exit 1
fi

if grep -R -n --include='*.go' -E 'github.com/(google/go-github|bradleyfalzon/ghinstallation)' \
  . --exclude-dir=.git --exclude-dir=brokers 2>/dev/null
then
  echo 'shared packages must not expose GitHub provider types' >&2
  exit 1
fi

if grep -R -n --include='*.go' -E 'github.com/(google/go-github|bradleyfalzon/ghinstallation)' \
  brokers/github --exclude-dir=githubauth 2>/dev/null
then
  echo 'GitHub SDK types must remain behind the githubauth boundary' >&2
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
  grep .
then
	echo 'provider-local Agent lifecycle orchestration survived the shared runtime cutover' >&2
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

if [ ! -f .github/workflows/github-capability-drift.yml ] ||
  [ ! -f brokers/github/cmd/check-github-drift/main.go ] ||
  ! grep -q 'issues: write' .github/workflows/github-capability-drift.yml ||
  grep -q 'generate-github-surfaces' .github/workflows/github-capability-drift.yml
then
  echo 'GitHub capability drift monitoring must remain scheduled, issue-only, and separate from generation' >&2
  exit 1
fi

if ! grep -q 'NewDiagnostics' controlplane/runtime.go ||
  ! grep -q 'Diagnostics:.*s.control.Diagnostics' brokers/huggingface/internal/httpapi/agent_operations.go ||
  ! grep -q 'Diagnostics:.*s.control.Diagnostics' brokers/github/internal/httpapi/agent_operations.go ||
  ! grep -q 'Diagnostics:.*s.control.Diagnostics' brokers/sudo/internal/routes/agent_operations.go
then
  echo 'provider runtimes must use the shared structured diagnostics boundary' >&2
  exit 1
fi
