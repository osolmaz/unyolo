#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

oapi_version=2ed9ad814b45953cfe312dfe3b36823982bd4d28

mkdir -p protocol/operatorwire protocol/agentwire protocol/generated
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${oapi_version} \
  -config protocol/openapi/operator-codegen.yaml \
  -o protocol/operatorwire/generated.go protocol/openapi/operator-v1.yaml
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${oapi_version} \
  -config protocol/openapi/agent-codegen.yaml \
  -o protocol/agentwire/generated.go protocol/openapi/agent-v1.yaml
pnpm exec openapi-typescript protocol/openapi/operator-v1.yaml \
  -o plugins/openclaw/src/generated/openapi-operator-v1.ts
pnpm exec openapi-typescript protocol/openapi/agent-v1.yaml \
  -o protocol/generated/openapi-agent-v1.ts
node protocol/generate-artifacts.mjs
pnpm exec prettier --write \
  plugins/openclaw/src/generated/openapi-operator-v1.ts \
  protocol/generated/openapi-agent-v1.ts
