# BrokerKit Protocols

`openapi/operator-v1.yaml` and `openapi/agent-v1.yaml` are the sole canonical
HTTP contracts. Every payload lives under `components/schemas`. The closed
JSON Schemas under `schema/` and `agent-schema/`, generated Go clients and Echo
interfaces, and generated TypeScript types and validators are committed build
artifacts. Run `scripts/generate-protocol.sh` after editing either document;
CI runs `scripts/check-protocol.sh` and rejects stale or invalid output.

Operator V1 is `brokerkit.io/operator/v1`. Provider execution plans and
credentials are deliberately absent from this protocol.

The same canonical document defines the aggregate Operator UI payloads used by
the packaged OpenClaw interface and delegated hosts. `UISnapshot` is the full
authoritative view; `UISnapshotEvent` is a cursor-only invalidation for bounded
authenticated long polling; and `UISummary` drives host badges without exposing
request details. Provider requests remain nested under `UIRequest` source
metadata so their Operator V1 schema is reused rather than copied.

Agent Operations V1 is `brokerkit.io/agent/v1`. It lets authenticated agents
submit and resume typed provider operations without receiving the provider
credential. Providers own target, argument, execution, and result validation;
the shared contract owns only identity, idempotency, lifecycle, presentation,
and safe errors.
