# unYOLO Protocols

This directory holds the canonical wire artifacts for the protocols unYOLO
brokers, clients, and UIs speak. The OpenAPI documents under `openapi/` are
the sole canonical contracts; every payload lives under
`components/schemas`. Storage structs and UI models are not wire
specifications.

- `openapi/operator-v1.yaml` defines Operator V1
  (`unyolo.io/operator/v1`): the protected operator inbox used to list,
  approve, deny, and revoke requests. Provider execution plans and
  credentials are deliberately absent. The same document defines the
  aggregate Operator UI payloads used by the packaged OpenClaw interface and
  delegated hosts: `UISnapshot` is the full authoritative view,
  `UISnapshotEvent` is a cursor-only invalidation for bounded authenticated
  long polling, and `UISummary` drives host badges without exposing request
  details.
- `openapi/agent-v1.yaml` defines Agent Operations V1
  (`unyolo.io/agent/v1`): authenticated agents submit and resume typed
  provider operations without receiving the provider credential. Providers
  own target, argument, execution, and result validation; the shared
  contract owns only identity, idempotency, lifecycle, presentation, and
  safe errors.
- `openapi/mcp-v1.yaml` defines the closed MCP operation documents
  (`unyolo.io/mcp-operation/v1`) that broker MCP servers return for
  transcript-safe operation state and recovery.

The closed JSON Schemas under `schema/`, `agent-schema/`, and `mcp-schema/`,
the generated Go clients and Echo interfaces under `operatorwire/` and
`agentwire/`, and the generated TypeScript types and validators are committed
build artifacts. After editing any canonical document, regenerate them with:

```sh
scripts/generate-protocol.sh
```

`scripts/check-protocol.sh` validates the documents and rejects stale or
invalid generated output.
