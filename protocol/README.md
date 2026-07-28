# unYOLO protocols

This directory is the canonical source for the wire protocols used by unYOLO
brokers and clients. Only the OpenAPI documents under `openapi/` define what
may cross a process boundary between unYOLO components. Storage structs and UI
models remain internal representations.

## Operator V1

`openapi/operator-v1.yaml` defines `unyolo.io/operator/v1`, the protected inbox
for listing and deciding approval requests. Provider credentials and executable
plans never appear on this surface.

The document also defines the OpenClaw UI payloads. `UISnapshot` contains the
current view, `UISnapshotEvent` invalidates a cursor during authenticated long
polling, and `UISummary` supplies badge counts without request details.

## Agent Operations V1

`openapi/agent-v1.yaml` defines `unyolo.io/agent/v1`. Authenticated agents use it
to submit and resume typed operations without receiving a provider credential.
Provider adapters validate each target and its arguments. They also validate
execution results. The shared contract covers identity and idempotency through the full
operation lifecycle. It also defines presentation data and safe errors.

## MCP operation documents

`openapi/mcp-v1.yaml` defines the closed `unyolo.io/mcp-operation/v1` documents
returned by broker MCP servers. These documents provide transcript-safe
operation state and recovery data.

## Generated artifacts

Closed JSON Schemas live under `schema/` and `agent-schema/`. MCP schemas live
under `mcp-schema/`. Generated Go clients and Echo interfaces live under `operatorwire/` and
`agentwire/` while checked-in TypeScript types and validators expose the same
contracts to JavaScript consumers.

After changing a canonical OpenAPI document, regenerate its artifacts with:

```sh
scripts/generate-protocol.sh
```

`scripts/check-protocol.sh` validates the canonical documents and rejects stale
or invalid generated output.
