#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

for document in protocol/openapi/operator-v1.yaml protocol/openapi/agent-v1.yaml protocol/openapi/mcp-v1.yaml; do
  go run github.com/getkin/kin-openapi/cmd/validate@v0.140.0 -- "$document"
done
./scripts/generate-protocol.sh
node protocol/generate-artifacts.mjs --check
git diff --exit-code -- \
  protocol/operatorwire protocol/agentwire protocol/generated \
  protocol/schema protocol/agent-schema protocol/mcp-schema plugins/openclaw/src/generated
